// Package scanner finds X.509 certificates in files.
package scanner

import (
	"bytes"
	"context"
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
	"path/filepath"
	"runtime"
	"slices"
	"sort"
	"sync"
	"sync/atomic"
	"time"
)

const (
	// DefaultMaxBytes bounds I/O and memory use for large files. A value of
	// zero in Options disables the limit.
	DefaultMaxBytes int64 = 64 << 10
	maxWorkers            = 8

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
	MaxBytes      int64
	Workers       int
	OnProgress    func(Progress)
	OnCertificate func(Certificate)
}

// Progress is a point-in-time snapshot of a running scan. Callbacks may be
// invoked concurrently and should return quickly.
type Progress struct {
	FilesDiscovered   int64
	FilesScanned      int64
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
	SANs                         []string
	ExtendedKeyUsage             []string
	ExtendedKeyUsageUnrestricted bool
	SHA1Fingerprint              string
	SHA256Fingerprint            string
	SPKISHA256Fingerprint        string
	NotBefore                    time.Time
	NotAfter                     time.Time
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
}

type progressCounters struct {
	filesDiscovered   atomic.Int64
	filesScanned      atomic.Int64
	certificatesFound atomic.Int64
	scanErrors        atomic.Int64
	discoveryComplete atomic.Bool
}

// Scan recursively scans root. It follows root itself when root is a symlink,
// but does not follow symlinks found while traversing a directory.
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
			counters.filesDiscovered.Add(1)
			notifyProgress(options.OnProgress, &counters)
			if !sendPath(ctx, jobs, root) {
				counters.filesDiscovered.Add(-1)
			}
			counters.discoveryComplete.Store(true)
			notifyProgress(options.OnProgress, &counters)
			return
		}

		_ = filepath.WalkDir(walkRoot, func(path string, entry os.DirEntry, walkErr error) error {
			if err := ctx.Err(); err != nil {
				return err
			}
			displayPath := path
			if walkRoot != root {
				relative, relativeErr := filepath.Rel(walkRoot, path)
				if relativeErr == nil {
					displayPath = filepath.Join(root, relative)
				}
			}
			if walkErr != nil {
				if !sendOutcome(ctx, outcomes, outcome{err: &FileError{Path: displayPath, Err: walkErr}}) {
					return ctx.Err()
				}
				if entry != nil && entry.IsDir() {
					return filepath.SkipDir
				}
				return nil
			}
			if entry.Type().IsRegular() {
				discovered := counters.filesDiscovered.Add(1)
				if discovered == 1 || discovered%100 == 0 {
					notifyProgress(options.OnProgress, &counters)
				}
				if !sendPath(ctx, jobs, displayPath) {
					counters.filesDiscovered.Add(-1)
					return ctx.Err()
				}
			}
			return nil
		})
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

func notifyProgress(callback func(Progress), counters *progressCounters) {
	if callback == nil {
		return
	}
	callback(Progress{
		FilesDiscovered:   counters.filesDiscovered.Load(),
		FilesScanned:      counters.filesScanned.Load(),
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
			certificates, err := scanFile(path, maxBytes)
			result := outcome{certificates: certificates, scanned: true}
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

func scanFile(path string, maxBytes int64) ([]Certificate, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	reader := io.Reader(file)
	if maxBytes > 0 {
		reader = io.LimitReader(file, maxBytes)
	}
	data, err := io.ReadAll(reader)
	if err != nil {
		return nil, err
	}

	complete := true
	if maxBytes > 0 && int64(len(data)) == maxBytes {
		var extra [1]byte
		if _, err := file.Read(extra[:]); err == nil {
			complete = false
		} else if !errors.Is(err, io.EOF) {
			return nil, err
		}
	}

	parsed := parsePEM(data)
	if len(parsed) == 0 && complete {
		if certificates, derErr := x509.ParseCertificates(data); derErr == nil {
			parsed = certificates
		}
	}

	result := make([]Certificate, 0, len(parsed))
	for index, certificate := range parsed {
		result = append(result, describe(path, index, certificate))
	}
	return result, nil
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
	sha1Fingerprint := sha1.Sum(certificate.Raw) //nolint:gosec // SHA-1 is required as an ecosystem-compatible certificate identifier.
	sha256Fingerprint := sha256.Sum256(certificate.Raw)
	spkiSHA256Fingerprint := sha256.Sum256(certificate.RawSubjectPublicKeyInfo)
	return Certificate{
		Path:                         path,
		Index:                        index,
		Subject:                      certificate.Subject.String(),
		Issuer:                       certificate.Issuer.String(),
		SANs:                         formatSANs(certificate.DNSNames, certificate.IPAddresses, certificate.EmailAddresses, certificate.URIs),
		ExtendedKeyUsage:             usages,
		ExtendedKeyUsageUnrestricted: unrestricted,
		SHA1Fingerprint:              hex.EncodeToString(sha1Fingerprint[:]),
		SHA256Fingerprint:            hex.EncodeToString(sha256Fingerprint[:]),
		SPKISHA256Fingerprint:        hex.EncodeToString(spkiSHA256Fingerprint[:]),
		NotBefore:                    certificate.NotBefore,
		NotAfter:                     certificate.NotAfter,
	}
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
