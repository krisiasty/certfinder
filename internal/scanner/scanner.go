// Package scanner finds X.509 certificates in files.
package scanner

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/sha1" //nolint:gosec // SHA-1 is emitted only as a compatibility fingerprint.
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"runtime"
	"slices"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const (
	// DefaultMaxBytes bounds the initial sniff of large files. Files with a
	// valid PEM match are subsequently read completely. A value of zero in
	// Options disables the initial limit.
	DefaultMaxBytes int64 = 64 << 10
	maxWorkers            = 8
)

// Certificate validity states.
const (
	ValidityValid       = "valid"
	ValidityExpired     = "expired"
	ValidityNotYetValid = "not-yet-valid"
)

// Extended key usage filter names accepted by the scanner.
const (
	UsageAny                            = "any"
	UsageServer                         = "server"
	UsageClient                         = "client"
	UsageCodeSigning                    = "code-signing"
	UsageEmailProtection                = "email-protection"
	UsageIPSECEndSystem                 = "ipsec-end-system"
	UsageIPSECTunnel                    = "ipsec-tunnel"
	UsageIPSECUser                      = "ipsec-user"
	UsageTimestamping                   = "timestamping"
	UsageOCSPSigning                    = "ocsp-signing"
	UsageMicrosoftServerGatedCrypto     = "microsoft-server-gated-crypto"
	UsageNetscapeServerGatedCrypto      = "netscape-server-gated-crypto"
	UsageMicrosoftCommercialCodeSigning = "microsoft-commercial-code-signing"
	UsageMicrosoftKernelCodeSigning     = "microsoft-kernel-code-signing"
)

var pemBegin = []byte("-----BEGIN CERTIFICATE-----")

// Options controls a filesystem scan.
type Options struct {
	MaxBytes       int64
	Workers        int
	Exclude        []string
	Extensions     []string
	OneFileSystem  bool
	FollowSymlinks bool
	OnProgress     func(Progress)
	OnCertificate  func(Certificate)
	filesystemID   func(os.FileInfo) (uint64, bool)
}

// Progress is a point-in-time snapshot of a running scan. Callbacks may be
// invoked concurrently and should return quickly.
type Progress struct {
	FilesDiscovered   int64
	FilesScanned      int64
	FilesCapped       int64
	CertificatesFound int64
	ScanErrors        int64
	DiscoveryComplete bool
}

// Certificate describes one certificate found in a file.
type Certificate struct {
	Path                         string
	Index                        int
	Subject                      string
	Issuer                       string
	SerialNumber                 string
	IsCA                         bool
	SelfSigned                   bool
	SANs                         []string
	KeyUsage                     []string
	ExtendedKeyUsage             []string
	ExtendedKeyUsageUnrestricted bool
	PublicKeyAlgorithm           string
	PublicKeyBits                int
	PublicKeyCurve               string
	SignatureAlgorithm           string
	SHA1Fingerprint              string
	SHA256Fingerprint            string
	SPKISHA256Fingerprint        string
	NotBefore                    time.Time
	NotAfter                     time.Time
}

// ValidityStatus returns the certificate validity state at the supplied time.
func (certificate Certificate) ValidityStatus(at time.Time) string {
	if at.Before(certificate.NotBefore) {
		return ValidityNotYetValid
	}
	if at.After(certificate.NotAfter) {
		return ValidityExpired
	}
	return ValidityValid
}

// FileError is a non-fatal error encountered while scanning one path.
type FileError struct {
	Path string
	Err  error
}

func (e FileError) Error() string {
	return fmt.Sprintf("%s: %v", e.Path, e.Err)
}

func (e FileError) Unwrap() error {
	return e.Err
}

// Report contains all successfully parsed certificates and non-fatal file
// errors. Certificates are sorted by path and their order within each file.
type Report struct {
	Certificates []Certificate
	Errors       []FileError
}

type outcome struct {
	certificates []Certificate
	err          *FileError
	scanned      bool
	capped       bool
}

type progressCounters struct {
	filesDiscovered   atomic.Int64
	filesScanned      atomic.Int64
	filesCapped       atomic.Int64
	certificatesFound atomic.Int64
	scanErrors        atomic.Int64
	discoveryComplete atomic.Bool
}

// Scan recursively scans root. It always follows root itself when root is a
// symlink. Other symlinks are followed only when FollowSymlinks is enabled.
func Scan(ctx context.Context, root string, options Options) (Report, error) {
	if root == "" {
		return Report{}, errors.New("scan path is empty")
	}
	if options.MaxBytes < 0 {
		return Report{}, errors.New("max bytes cannot be negative")
	}
	if options.Workers < 0 {
		return Report{}, errors.New("workers cannot be negative")
	}
	if options.Workers == 0 {
		options.Workers = min(runtime.GOMAXPROCS(0), maxWorkers)
	}
	var err error
	options.Exclude, err = normalizeExcludePatterns(options.Exclude)
	if err != nil {
		return Report{}, err
	}
	options.Extensions, err = normalizeExtensions(options.Extensions)
	if err != nil {
		return Report{}, err
	}
	if options.filesystemID == nil {
		options.filesystemID = platformFilesystemID
	}

	info, err := os.Stat(root)
	if err != nil {
		return Report{}, fmt.Errorf("inspect %q: %w", root, err)
	}
	if !info.Mode().IsRegular() && !info.IsDir() {
		return Report{}, fmt.Errorf("%q is not a regular file or directory", root)
	}
	walkRoot := root
	if linkInfo, linkErr := os.Lstat(root); linkErr == nil && linkInfo.Mode()&os.ModeSymlink != 0 && info.IsDir() {
		walkRoot, err = filepath.EvalSymlinks(root)
		if err != nil {
			return Report{}, fmt.Errorf("resolve %q: %w", root, err)
		}
	}
	var rootFilesystem uint64
	if options.OneFileSystem {
		var supported bool
		rootFilesystem, supported = options.filesystemID(info)
		if !supported {
			return Report{}, fmt.Errorf("one-file-system is not supported on %s", runtime.GOOS)
		}
	}

	jobs := make(chan string, 1024)
	outcomes := make(chan outcome)
	var workerGroup sync.WaitGroup
	var counters progressCounters

	for range options.Workers {
		workerGroup.Add(1)
		go func() {
			defer workerGroup.Done()
			worker(ctx, jobs, outcomes, options.MaxBytes)
		}()
	}

	go func() {
		defer close(jobs)
		if info.Mode().IsRegular() {
			relative := filepath.ToSlash(filepath.Base(root))
			if !isExcluded(relative, options.Exclude) && matchesExtension(root, options.Extensions) {
				queuePath(ctx, root, jobs, &counters, options.OnProgress)
			}
			counters.discoveryComplete.Store(true)
			notifyProgress(options.OnProgress, &counters)
			return
		}
		walker := discoveryWalker{
			ctx:            ctx,
			root:           root,
			walkRoot:       walkRoot,
			options:        options,
			rootFilesystem: rootFilesystem,
			jobs:           jobs,
			outcomes:       outcomes,
			counters:       &counters,
		}
		walker.walk()
		counters.discoveryComplete.Store(true)
		notifyProgress(options.OnProgress, &counters)
	}()

	go func() {
		workerGroup.Wait()
		close(outcomes)
	}()

	var report Report
	for {
		select {
		case result, ok := <-outcomes:
			if !ok {
				notifyProgress(options.OnProgress, &counters)
				sortReport(&report)
				return report, nil
			}
			report.Certificates = append(report.Certificates, result.certificates...)
			if result.scanned {
				counters.filesScanned.Add(1)
				if result.capped {
					counters.filesCapped.Add(1)
				}
				counters.certificatesFound.Add(int64(len(result.certificates)))
			}
			if result.err != nil {
				report.Errors = append(report.Errors, *result.err)
				counters.scanErrors.Add(1)
			}
			notifyProgress(options.OnProgress, &counters)
			if options.OnCertificate != nil {
				for _, certificate := range result.certificates {
					options.OnCertificate(certificate)
				}
			}
		case <-ctx.Done():
			return Report{}, ctx.Err()
		}
	}
}

type discoveryWalker struct {
	ctx            context.Context
	root           string
	walkRoot       string
	options        Options
	rootFilesystem uint64
	jobs           chan<- string
	outcomes       chan<- outcome
	counters       *progressCounters
	visited        map[string]struct{}
}

func (walker *discoveryWalker) walk() {
	if walker.options.FollowSymlinks {
		walker.walkWithSymlinks()
		return
	}
	_ = filepath.WalkDir(walker.walkRoot, walker.visitWithoutSymlinks)
}

func (walker *discoveryWalker) visitWithoutSymlinks(filePath string, entry os.DirEntry, walkErr error) error {
	if err := walker.ctx.Err(); err != nil {
		return err
	}
	displayPath, relative := walker.paths(filePath)
	if walkErr != nil {
		if !walker.reportError(displayPath, walkErr) {
			return walker.ctx.Err()
		}
		if entry != nil && entry.IsDir() {
			return filepath.SkipDir
		}
		return nil
	}
	if relative != "." && isExcluded(relative, walker.options.Exclude) {
		if entry.IsDir() {
			return filepath.SkipDir
		}
		return nil
	}
	if entry.IsDir() {
		if relative != "." && !walker.entryOnRootFilesystem(displayPath, entry) {
			return filepath.SkipDir
		}
		return nil
	}
	if !entry.Type().IsRegular() || !matchesExtension(displayPath, walker.options.Extensions) {
		return nil
	}
	if !walker.entryOnRootFilesystem(displayPath, entry) {
		return nil
	}
	if !queuePath(walker.ctx, displayPath, walker.jobs, walker.counters, walker.options.OnProgress) {
		return walker.ctx.Err()
	}
	return nil
}

func (walker *discoveryWalker) walkWithSymlinks() {
	physicalRoot, err := filepath.Abs(walker.walkRoot)
	if err != nil {
		walker.reportError(walker.root, err)
		return
	}
	physicalRoot, err = filepath.EvalSymlinks(physicalRoot)
	if err != nil {
		walker.reportError(walker.root, err)
		return
	}
	physicalRoot = filepath.Clean(physicalRoot)
	walker.visited = map[string]struct{}{physicalRoot: {}}
	walker.walkDirectory(physicalRoot, walker.root, "")
}

func (walker *discoveryWalker) walkDirectory(physicalDirectory, displayDirectory, relativeDirectory string) bool {
	if walker.ctx.Err() != nil {
		return false
	}
	entries, err := os.ReadDir(physicalDirectory)
	if err != nil {
		return walker.reportError(displayDirectory, err)
	}
	for _, entry := range entries {
		if walker.ctx.Err() != nil {
			return false
		}
		displayPath := filepath.Join(displayDirectory, entry.Name())
		physicalPath := filepath.Join(physicalDirectory, entry.Name())
		relative := path.Join(relativeDirectory, entry.Name())
		if isExcluded(relative, walker.options.Exclude) {
			continue
		}
		if entry.Type()&os.ModeSymlink != 0 {
			if !walker.visitSymlink(physicalPath, displayPath, relative) {
				return false
			}
			continue
		}
		if entry.IsDir() {
			if !walker.entryOnRootFilesystem(displayPath, entry) {
				continue
			}
			physicalPath = filepath.Clean(physicalPath)
			if walker.markVisited(physicalPath) && !walker.walkDirectory(physicalPath, displayPath, relative) {
				return false
			}
			continue
		}
		if !entry.Type().IsRegular() || !matchesExtension(displayPath, walker.options.Extensions) {
			continue
		}
		if !walker.entryOnRootFilesystem(displayPath, entry) {
			continue
		}
		if !queuePath(walker.ctx, displayPath, walker.jobs, walker.counters, walker.options.OnProgress) {
			return false
		}
	}
	return true
}

func (walker *discoveryWalker) visitSymlink(physicalPath, displayPath, relative string) bool {
	info, err := os.Stat(physicalPath)
	if err != nil {
		return walker.reportError(displayPath, err)
	}
	if !walker.infoOnRootFilesystem(displayPath, info) {
		return true
	}
	if info.IsDir() {
		resolved, err := filepath.EvalSymlinks(physicalPath)
		if err != nil {
			return walker.reportError(displayPath, err)
		}
		resolved, err = filepath.Abs(resolved)
		if err != nil {
			return walker.reportError(displayPath, err)
		}
		resolved = filepath.Clean(resolved)
		if walker.markVisited(resolved) {
			return walker.walkDirectory(resolved, displayPath, relative)
		}
		return true
	}
	if !info.Mode().IsRegular() || !matchesExtension(displayPath, walker.options.Extensions) {
		return true
	}
	return queuePath(walker.ctx, displayPath, walker.jobs, walker.counters, walker.options.OnProgress)
}

func (walker *discoveryWalker) paths(filePath string) (displayPath, relative string) {
	relativePath, err := filepath.Rel(walker.walkRoot, filePath)
	if err != nil {
		return filePath, "."
	}
	displayPath = filePath
	if walker.walkRoot != walker.root {
		displayPath = filepath.Join(walker.root, relativePath)
	}
	return displayPath, filepath.ToSlash(relativePath)
}

func (walker *discoveryWalker) entryOnRootFilesystem(displayPath string, entry os.DirEntry) bool {
	if !walker.options.OneFileSystem {
		return true
	}
	info, err := entry.Info()
	if err != nil {
		walker.reportError(displayPath, err)
		return false
	}
	return walker.infoOnRootFilesystem(displayPath, info)
}

func (walker *discoveryWalker) infoOnRootFilesystem(displayPath string, info os.FileInfo) bool {
	if !walker.options.OneFileSystem {
		return true
	}
	filesystem, ok := walker.options.filesystemID(info)
	if !ok {
		walker.reportError(displayPath, errors.New("filesystem identity is unavailable"))
		return false
	}
	return filesystem == walker.rootFilesystem
}

func (walker *discoveryWalker) markVisited(physicalPath string) bool {
	if _, exists := walker.visited[physicalPath]; exists {
		return false
	}
	walker.visited[physicalPath] = struct{}{}
	return true
}

func (walker *discoveryWalker) reportError(displayPath string, err error) bool {
	return sendOutcome(walker.ctx, walker.outcomes, outcome{err: &FileError{Path: displayPath, Err: err}})
}

func queuePath(
	ctx context.Context,
	filePath string,
	jobs chan<- string,
	counters *progressCounters,
	callback func(Progress),
) bool {
	discovered := counters.filesDiscovered.Add(1)
	if discovered == 1 || discovered%100 == 0 {
		notifyProgress(callback, counters)
	}
	if sendPath(ctx, jobs, filePath) {
		return true
	}
	counters.filesDiscovered.Add(-1)
	return false
}

func normalizeExcludePatterns(patterns []string) ([]string, error) {
	result := make([]string, 0, len(patterns))
	for _, pattern := range patterns {
		pattern = strings.TrimSpace(pattern)
		pattern = strings.TrimPrefix(pattern, "./")
		pattern = strings.TrimSuffix(pattern, "/")
		if pattern == "" || path.IsAbs(pattern) || filepath.IsAbs(pattern) {
			return nil, fmt.Errorf("invalid exclude pattern %q: use a relative glob", pattern)
		}
		if _, err := path.Match(pattern, ""); err != nil {
			return nil, fmt.Errorf("invalid exclude pattern %q: %w", pattern, err)
		}
		if !slices.Contains(result, pattern) {
			result = append(result, pattern)
		}
	}
	return result, nil
}

func isExcluded(relative string, patterns []string) bool {
	relative = filepath.ToSlash(relative)
	for _, pattern := range patterns {
		candidate := relative
		if !strings.Contains(pattern, "/") {
			candidate = path.Base(relative)
		}
		matched, _ := path.Match(pattern, candidate)
		if matched {
			return true
		}
	}
	return false
}

func normalizeExtensions(extensions []string) ([]string, error) {
	result := make([]string, 0, len(extensions))
	for _, extension := range extensions {
		extension = strings.ToLower(strings.TrimSpace(extension))
		if extension == "" {
			return nil, errors.New("extension cannot be empty")
		}
		if strings.ContainsAny(extension, `/*?[]\\`) {
			return nil, fmt.Errorf("invalid extension %q", extension)
		}
		if !strings.HasPrefix(extension, ".") {
			extension = "." + extension
		}
		if extension == "." {
			return nil, errors.New("extension cannot be empty")
		}
		result = append(result, extension)
	}
	slices.Sort(result)
	return slices.Compact(result), nil
}

func matchesExtension(filePath string, extensions []string) bool {
	return len(extensions) == 0 || slices.Contains(extensions, strings.ToLower(filepath.Ext(filePath)))
}

func notifyProgress(callback func(Progress), counters *progressCounters) {
	if callback == nil {
		return
	}
	callback(Progress{
		FilesDiscovered:   counters.filesDiscovered.Load(),
		FilesScanned:      counters.filesScanned.Load(),
		FilesCapped:       counters.filesCapped.Load(),
		CertificatesFound: counters.certificatesFound.Load(),
		ScanErrors:        counters.scanErrors.Load(),
		DiscoveryComplete: counters.discoveryComplete.Load(),
	})
}

func sortReport(report *Report) {
	sort.Slice(report.Certificates, func(i, j int) bool {
		if report.Certificates[i].Path == report.Certificates[j].Path {
			return report.Certificates[i].Index < report.Certificates[j].Index
		}
		return report.Certificates[i].Path < report.Certificates[j].Path
	})
	sort.Slice(report.Errors, func(i, j int) bool {
		return report.Errors[i].Path < report.Errors[j].Path
	})
}

func worker(ctx context.Context, jobs <-chan string, outcomes chan<- outcome, maxBytes int64) {
	for {
		select {
		case path, ok := <-jobs:
			if !ok {
				return
			}
			certificates, capped, err := scanFile(path, maxBytes)
			result := outcome{certificates: certificates, scanned: true, capped: capped}
			if err != nil {
				result.err = &FileError{Path: path, Err: err}
			}
			if !sendOutcome(ctx, outcomes, result) {
				return
			}
		case <-ctx.Done():
			return
		}
	}
}

func sendPath(ctx context.Context, jobs chan<- string, path string) bool {
	select {
	case jobs <- path:
		return true
	case <-ctx.Done():
		return false
	}
}

func sendOutcome(ctx context.Context, outcomes chan<- outcome, result outcome) bool {
	select {
	case outcomes <- result:
		return true
	case <-ctx.Done():
		return false
	}
}

func scanFile(path string, maxBytes int64) ([]Certificate, bool, error) {
	file, err := os.Open(path) //nolint:gosec // Scan paths are explicitly supplied by the user.
	if err != nil {
		return nil, false, err
	}
	defer func() { _ = file.Close() }()

	reader := io.Reader(file)
	if maxBytes > 0 {
		reader = io.LimitReader(file, maxBytes)
	}
	data, err := io.ReadAll(reader)
	if err != nil {
		return nil, false, err
	}

	complete := true
	if maxBytes > 0 && int64(len(data)) == maxBytes {
		var extra [1]byte
		if _, err := file.Read(extra[:]); err == nil {
			complete = false
		} else if !errors.Is(err, io.EOF) {
			return nil, false, err
		}
	}

	parsed := parsePEM(data)
	if len(parsed) > 0 && !complete {
		if _, err := file.Seek(0, io.SeekStart); err != nil {
			return nil, false, err
		}
		data, err = io.ReadAll(file)
		if err != nil {
			return nil, false, err
		}
		parsed = parsePEM(data)
		complete = true
	}
	if len(parsed) == 0 && complete {
		if certificates, derErr := x509.ParseCertificates(data); derErr == nil {
			parsed = certificates
		}
	}

	result := make([]Certificate, 0, len(parsed))
	for index, certificate := range parsed {
		result = append(result, describe(path, index, certificate))
	}
	return result, !complete, nil
}

func parsePEM(data []byte) []*x509.Certificate {
	var certificates []*x509.Certificate
	for {
		start := bytes.Index(data, pemBegin)
		if start < 0 {
			return certificates
		}
		data = data[start:]
		block, rest := pem.Decode(data)
		if block == nil {
			data = data[len(pemBegin):]
			continue
		}
		data = rest
		if block.Type != "CERTIFICATE" {
			continue
		}
		certificate, err := x509.ParseCertificate(block.Bytes)
		if err == nil {
			certificates = append(certificates, certificate)
		}
	}
}

func describe(path string, index int, certificate *x509.Certificate) Certificate {
	usages, unrestricted := formatExtendedKeyUsage(certificate)
	publicKeyAlgorithm, publicKeyBits, publicKeyCurve := describePublicKey(certificate)
	sha1Fingerprint := sha1.Sum(certificate.Raw) //nolint:gosec // SHA-1 is required as an ecosystem-compatible certificate identifier.
	sha256Fingerprint := sha256.Sum256(certificate.Raw)
	spkiSHA256Fingerprint := sha256.Sum256(certificate.RawSubjectPublicKeyInfo)
	return Certificate{
		Path:                         path,
		Index:                        index,
		Subject:                      certificate.Subject.String(),
		Issuer:                       certificate.Issuer.String(),
		SerialNumber:                 formatSerialNumber(certificate),
		IsCA:                         certificate.IsCA,
		SelfSigned:                   isSelfSigned(certificate),
		SANs:                         formatSANs(certificate.DNSNames, certificate.IPAddresses, certificate.EmailAddresses, certificate.URIs),
		KeyUsage:                     formatKeyUsage(certificate.KeyUsage),
		ExtendedKeyUsage:             usages,
		ExtendedKeyUsageUnrestricted: unrestricted,
		PublicKeyAlgorithm:           publicKeyAlgorithm,
		PublicKeyBits:                publicKeyBits,
		PublicKeyCurve:               publicKeyCurve,
		SignatureAlgorithm:           signatureAlgorithmName(certificate.SignatureAlgorithm),
		SHA1Fingerprint:              hex.EncodeToString(sha1Fingerprint[:]),
		SHA256Fingerprint:            hex.EncodeToString(sha256Fingerprint[:]),
		SPKISHA256Fingerprint:        hex.EncodeToString(spkiSHA256Fingerprint[:]),
		NotBefore:                    certificate.NotBefore,
		NotAfter:                     certificate.NotAfter,
	}
}

func formatSerialNumber(certificate *x509.Certificate) string {
	if certificate.SerialNumber == nil {
		return ""
	}
	return certificate.SerialNumber.Text(16)
}

func isSelfSigned(certificate *x509.Certificate) bool {
	if !bytes.Equal(certificate.RawSubject, certificate.RawIssuer) {
		return false
	}
	return certificate.CheckSignature(
		certificate.SignatureAlgorithm,
		certificate.RawTBSCertificate,
		certificate.Signature,
	) == nil
}

func describePublicKey(certificate *x509.Certificate) (algorithm string, bits int, curve string) {
	algorithm = publicKeyAlgorithmName(certificate.PublicKeyAlgorithm)
	switch publicKey := certificate.PublicKey.(type) {
	case *rsa.PublicKey:
		if publicKey != nil && publicKey.N != nil {
			bits = publicKey.N.BitLen()
		}
	case *ecdsa.PublicKey:
		if publicKey != nil && publicKey.Curve != nil && publicKey.Params() != nil {
			curve = publicKey.Params().Name
		}
	}
	return algorithm, bits, curve
}

func publicKeyAlgorithmName(algorithm x509.PublicKeyAlgorithm) string {
	if algorithm == x509.UnknownPublicKeyAlgorithm {
		return "unknown"
	}
	return algorithm.String()
}

func signatureAlgorithmName(algorithm x509.SignatureAlgorithm) string {
	if algorithm == x509.UnknownSignatureAlgorithm {
		return "unknown"
	}
	return algorithm.String()
}

func formatKeyUsage(usage x509.KeyUsage) []string {
	names := []struct {
		value x509.KeyUsage
		name  string
	}{
		{x509.KeyUsageDigitalSignature, "digital-signature"},
		{x509.KeyUsageContentCommitment, "content-commitment"},
		{x509.KeyUsageKeyEncipherment, "key-encipherment"},
		{x509.KeyUsageDataEncipherment, "data-encipherment"},
		{x509.KeyUsageKeyAgreement, "key-agreement"},
		{x509.KeyUsageCertSign, "certificate-signing"},
		{x509.KeyUsageCRLSign, "crl-signing"},
		{x509.KeyUsageEncipherOnly, "encipher-only"},
		{x509.KeyUsageDecipherOnly, "decipher-only"},
	}
	result := make([]string, 0, len(names))
	for _, candidate := range names {
		if usage&candidate.value != 0 {
			result = append(result, candidate.name)
		}
	}
	return result
}

func formatExtendedKeyUsage(certificate *x509.Certificate) ([]string, bool) {
	result := make([]string, 0, len(certificate.ExtKeyUsage)+len(certificate.UnknownExtKeyUsage))
	for _, usage := range certificate.ExtKeyUsage {
		result = append(result, extendedKeyUsageName(usage))
	}
	for _, usage := range certificate.UnknownExtKeyUsage {
		result = append(result, "oid:"+usage.String())
	}
	slices.Sort(result)

	hasExtension := false
	for _, extension := range certificate.Extensions {
		if extension.Id.String() == "2.5.29.37" {
			hasExtension = true
			break
		}
	}
	unrestricted := !hasExtension || slices.Contains(certificate.ExtKeyUsage, x509.ExtKeyUsageAny)
	return result, unrestricted
}

func extendedKeyUsageName(usage x509.ExtKeyUsage) string {
	switch usage {
	case x509.ExtKeyUsageAny:
		return UsageAny
	case x509.ExtKeyUsageServerAuth:
		return UsageServer
	case x509.ExtKeyUsageClientAuth:
		return UsageClient
	case x509.ExtKeyUsageCodeSigning:
		return UsageCodeSigning
	case x509.ExtKeyUsageEmailProtection:
		return UsageEmailProtection
	case x509.ExtKeyUsageIPSECEndSystem:
		return UsageIPSECEndSystem
	case x509.ExtKeyUsageIPSECTunnel:
		return UsageIPSECTunnel
	case x509.ExtKeyUsageIPSECUser:
		return UsageIPSECUser
	case x509.ExtKeyUsageTimeStamping:
		return UsageTimestamping
	case x509.ExtKeyUsageOCSPSigning:
		return UsageOCSPSigning
	case x509.ExtKeyUsageMicrosoftServerGatedCrypto:
		return UsageMicrosoftServerGatedCrypto
	case x509.ExtKeyUsageNetscapeServerGatedCrypto:
		return UsageNetscapeServerGatedCrypto
	case x509.ExtKeyUsageMicrosoftCommercialCodeSigning:
		return UsageMicrosoftCommercialCodeSigning
	case x509.ExtKeyUsageMicrosoftKernelCodeSigning:
		return UsageMicrosoftKernelCodeSigning
	default:
		return fmt.Sprintf("unknown:%d", usage)
	}
}

func formatSANs(dnsNames []string, ipAddresses []net.IP, emailAddresses []string, uris []*url.URL) []string {
	result := make([]string, 0, len(dnsNames)+len(ipAddresses)+len(emailAddresses)+len(uris))
	for _, name := range dnsNames {
		result = append(result, "DNS:"+name)
	}
	for _, address := range ipAddresses {
		result = append(result, "IP:"+address.String())
	}
	for _, address := range emailAddresses {
		result = append(result, "email:"+address)
	}
	for _, uri := range uris {
		result = append(result, "URI:"+uri.String())
	}
	slices.Sort(result)
	return result
}
