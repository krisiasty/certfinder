// Command certfinder finds and reports X.509 certificates in a filesystem tree.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net/netip"
	"os"
	"os/signal"
	"path"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/krisiasty/certfinder/internal/buildinfo"
	"github.com/krisiasty/certfinder/internal/scanner"
)

const (
	exitSuccess = iota
	exitRuntimeError
	exitUsageError
	exitOperationalFinding
)

const (
	outputText  = "text"
	outputJSON  = "json"
	outputJSONL = "jsonl"
)

func main() {
	os.Exit(execute())
}

func execute() int {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	return run(ctx, os.Args[1:], os.Stdout, os.Stderr)
}

func run(ctx context.Context, arguments []string, stdout, stderr io.Writer) int {
	logger := slog.New(slog.NewTextHandler(stderr, nil))
	flags := flag.NewFlagSet("certfinder", flag.ContinueOnError)
	flags.SetOutput(stderr)
	var excludes excludeFlag
	var extensions extensionFlag
	var roots rootFlag
	maxBytes := flags.Int64(
		"max-bytes",
		scanner.DefaultMaxBytes,
		"initial bytes inspected per file; PEM and keystore matches are read fully; 0 reads all files fully",
	)
	workers := flags.Int("workers", min(runtime.GOMAXPROCS(0), 8), "number of files scanned concurrently")
	flags.Var(&excludes, "exclude", "exclude a relative path glob; repeatable; patterns without / match at any depth")
	flags.Var(&extensions, "extensions", "scan only these file extensions; comma-separated or repeatable")
	oneFileSystem := flags.Bool("one-file-system", false, "do not scan files or directories on other filesystems (Linux and macOS)")
	followSymlinks := flags.Bool("follow-symlinks", false, "follow symlinks encountered below PATH while preventing cycles")
	ignoreErrors := flags.Bool("ignore-errors", false, "exclude non-fatal file scan errors from the exit status")
	usageValue := flags.String("usage", "", "filter by extended key usage, such as server or client")
	var hostname hostnameFlag
	flags.Var(&hostname, "hostname", "print only certificates valid for this DNS name or IP address")
	expired := flags.Bool("expired", false, "shortcut for -expiration=0d")
	expirationValue := flags.String("expiration", "", "print certificates expired or expiring within a duration, such as 30d")
	failExpired := flags.Bool("fail-expired", false, "return the operational-finding status when an expired certificate matches")
	failExpiringValue := flags.String("fail-expiring", "", "return the operational-finding status for matches expiring within a duration")
	verify := flags.Bool("verify", false, "verify certificate chains offline against trusted roots")
	flags.Var(&roots, "roots", "add certificates from PATH as private trust anchors; repeatable; requires -verify")
	rootsOnly := flags.Bool("roots-only", false, "trust only -roots certificates instead of augmenting system roots")
	unique := flags.Bool("unique", false, "group identical certificates and print each SHA-256 fingerprint once")
	duplicates := flags.Bool("duplicates", false, "print only SHA-256 groups found in more than one location")
	jsonOutput := flags.Bool("json", false, "print results as JSON")
	jsonLinesOutput := flags.Bool("jsonl", false, "stream one compact JSON object per matching certificate")
	quiet := flags.Bool("quiet", false, "suppress startup, progress, and summary output")
	version := flags.Bool("version", false, "show version and build information")
	flags.Usage = func() {
		_, _ = fmt.Fprintln(stderr, "Usage: certfinder [options] PATH")
		_, _ = fmt.Fprintln(
			stderr,
			"Find X.509 certificates in PEM, DER, JKS, JCEKS, or PKCS#12 files in PATH and its subdirectories.",
		)
		_, _ = fmt.Fprintln(stderr)
		flags.PrintDefaults()
	}

	if err := flags.Parse(arguments); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return exitSuccess
		}
		return exitUsageError
	}
	if *version {
		if _, err := fmt.Fprintln(stdout, buildinfo.String()); err != nil {
			logger.Error("write version", "error", err)
			return exitRuntimeError
		}
		return exitSuccess
	}
	if flags.NArg() != 1 {
		flags.Usage()
		return exitUsageError
	}
	if *maxBytes < 0 {
		logger.Error("invalid option", "option", "max-bytes", "error", "value cannot be negative")
		return exitUsageError
	}
	if *workers < 1 {
		logger.Error("invalid option", "option", "workers", "error", "value must be at least 1")
		return exitUsageError
	}
	usage, err := normalizeUsage(*usageValue)
	if err != nil {
		logger.Error("invalid option", "option", "usage", "error", err)
		return exitUsageError
	}
	expiration, hasExpiration, err := parseExpiration(*expirationValue)
	if err != nil {
		logger.Error("invalid option", "option", "expiration", "error", err)
		return exitUsageError
	}
	if *expired && hasExpiration {
		logger.Error("conflicting options", "options", "expired,expiration")
		return exitUsageError
	}
	if *expired {
		expiration = 0
		hasExpiration = true
	}
	expirationDescription := *expirationValue
	if *expired {
		expirationDescription = "0d"
	}
	failExpiration, hasFailExpiration, err := parseDurationOption("fail-expiring", *failExpiringValue)
	if err != nil {
		logger.Error("invalid option", "option", "fail-expiring", "error", err)
		return exitUsageError
	}
	if *failExpired && hasFailExpiration {
		logger.Error("conflicting options", "options", "fail-expired,fail-expiring")
		return exitUsageError
	}
	if *failExpired {
		failExpiration = 0
		hasFailExpiration = true
	}
	if *jsonOutput && *jsonLinesOutput {
		logger.Error("conflicting options", "options", "json,jsonl")
		return exitUsageError
	}
	if !*verify && (len(roots) > 0 || *rootsOnly) {
		logger.Error("invalid option", "error", "-roots and -roots-only require -verify")
		return exitUsageError
	}
	if *rootsOnly && len(roots) == 0 {
		logger.Error("invalid option", "error", "-roots-only requires at least one -roots path")
		return exitUsageError
	}
	if *unique && *duplicates {
		logger.Error("conflicting options", "options", "unique,duplicates")
		return exitUsageError
	}
	if *jsonLinesOutput && (*unique || *duplicates) {
		identityOption := "unique"
		if *duplicates {
			identityOption = "duplicates"
		}
		logger.Error("conflicting options", "options", "jsonl,"+identityOption)
		return exitUsageError
	}
	failExpirationDescription := *failExpiringValue
	if *failExpired {
		failExpirationDescription = "0d"
	}
	hostnameFilter := hostname.String()
	identityMode := identityModeAll
	if *unique {
		identityMode = identityModeUnique
	} else if *duplicates {
		identityMode = identityModeDuplicates
	}
	groupedOutput := identityMode != identityModeAll
	outputFormat := outputText
	if *jsonOutput {
		outputFormat = outputJSON
	} else if *jsonLinesOutput {
		outputFormat = outputJSONL
	}
	now := time.Now()
	display := newProgressDisplay(stderr, stdout, outputFormat == outputText, *quiet)
	display.Start(scanConfiguration{
		Path:           flags.Arg(0),
		Workers:        *workers,
		MaxBytes:       *maxBytes,
		Exclude:        append([]string{}, excludes...),
		Extensions:     append([]string{}, extensions...),
		OneFileSystem:  *oneFileSystem,
		FollowSymlinks: *followSymlinks,
		IgnoreErrors:   *ignoreErrors,
		Usage:          usage,
		Hostname:       hostnameFilter,
		Expiration:     expirationDescription,
		FailExpiring:   failExpirationDescription,
		Verify:         *verify,
		Roots:          append([]string{}, roots...),
		RootsOnly:      *rootsOnly,
		IdentityMode:   identityMode,
		Output:         outputFormat,
		Quiet:          *quiet,
	})
	var verificationRoots []scanner.Certificate
	if *verify && len(roots) > 0 {
		verificationRoots, err = loadVerificationRoots(ctx, roots, *workers)
		if err != nil {
			display.Stop(false)
			logger.Error("load verification roots", "error", err)
			return exitRuntimeError
		}
	}

	scanContext, cancelScan := context.WithCancel(ctx)
	defer cancelScan()
	var jsonLinesEncoder *json.Encoder
	if *jsonLinesOutput {
		jsonLinesEncoder = json.NewEncoder(stdout)
	}
	var outputErr error
	operationalFinding := false
	identityCounts := make(map[string]int64)
	var onProgress func(scanner.Progress)
	if !*quiet {
		onProgress = display.Update
	}
	report, err := scanner.Scan(scanContext, flags.Arg(0), scanner.Options{
		MaxBytes:               *maxBytes,
		Workers:                *workers,
		Exclude:                append([]string{}, excludes...),
		Extensions:             append([]string{}, extensions...),
		OneFileSystem:          *oneFileSystem,
		FollowSymlinks:         *followSymlinks,
		DiscardCertificates:    !*jsonOutput && !groupedOutput && !*verify,
		DiscardPKCS12Encrypted: !*jsonOutput,
		OnProgress:             onProgress,
		OnCertificate: func(certificate scanner.Certificate) {
			if *verify {
				return
			}
			if outputErr != nil || !certificateMatches(certificate, usage, hostnameFilter, expiration, hasExpiration, now) {
				return
			}
			identityCounts[certificate.SHA256Fingerprint]++
			if hasFailExpiration && certificateExpiresWithin(certificate, failExpiration, now) {
				operationalFinding = true
			}
			if groupedOutput {
				return
			}
			switch outputFormat {
			case outputText:
				display.Certificate(certificate)
			case outputJSONL:
				outputErr = jsonLinesEncoder.Encode(newJSONCertificate(certificate, time.Now()))
				if outputErr != nil {
					cancelScan()
				}
			}
		},
		OnPKCS12Encrypted: func(finding scanner.PKCS12EncryptedContent) {
			if outputErr != nil {
				return
			}
			switch outputFormat {
			case outputText:
				display.PKCS12Encrypted(finding)
			case outputJSONL:
				outputErr = jsonLinesEncoder.Encode(newJSONPKCS12EncryptedContent(finding))
				if outputErr != nil {
					cancelScan()
				}
			}
		},
	})
	if outputErr != nil {
		display.Stop(false)
		logger.Error("write JSON Lines", "error", outputErr)
		return exitRuntimeError
	}
	if err != nil {
		display.Stop(false)
		logger.Error("scan failed", "path", flags.Arg(0), "error", err)
		return exitRuntimeError
	}
	if *verify {
		report.Certificates, err = scanner.VerifyCertificates(report.Certificates, scanner.VerificationOptions{
			CurrentTime:        now,
			DNSName:            hostnameFilter,
			IncludeSystemRoots: !*rootsOnly,
			Roots:              verificationRoots,
		})
		if err != nil {
			display.Stop(false)
			logger.Error("verify certificates", "error", err)
			return exitRuntimeError
		}
		for _, certificate := range report.Certificates {
			if !certificateMatches(certificate, usage, hostnameFilter, expiration, hasExpiration, now) {
				continue
			}
			identityCounts[certificate.SHA256Fingerprint]++
			if hasFailExpiration && certificateExpiresWithin(certificate, failExpiration, now) {
				operationalFinding = true
			}
			if groupedOutput {
				continue
			}
			switch outputFormat {
			case outputText:
				display.Certificate(certificate)
			case outputJSONL:
				outputErr = jsonLinesEncoder.Encode(newJSONCertificate(certificate, time.Now()))
			}
			if outputErr != nil {
				break
			}
		}
		if outputErr != nil {
			display.Stop(false)
			logger.Error("write JSON Lines", "error", outputErr)
			return exitRuntimeError
		}
	}
	var filtered []scanner.Certificate
	var groups []certificateGroup
	if *jsonOutput || groupedOutput {
		filtered = make([]scanner.Certificate, 0, len(report.Certificates))
		for _, certificate := range report.Certificates {
			if certificateMatches(certificate, usage, hostnameFilter, expiration, hasExpiration, now) {
				filtered = append(filtered, certificate)
			}
		}
	}
	if groupedOutput {
		groups = groupCertificates(filtered)
		if *duplicates {
			groups = duplicateCertificateGroups(groups)
		}
		if outputFormat == outputText {
			for _, group := range groups {
				display.CertificateGroup(group)
			}
		}
	}
	display.SetIdentitySummary(summarizeCertificateIdentities(identityCounts))
	display.Stop(true)
	if err := display.Err(); err != nil {
		logger.Error("write output", "error", err)
		return exitRuntimeError
	}

	if *jsonOutput {
		var err error
		if groupedOutput {
			err = printJSONCertificateGroupsAndPKCS12At(stdout, groups, report.PKCS12Encrypted, time.Now())
		} else {
			err = printJSONResultsAt(stdout, filtered, report.PKCS12Encrypted, time.Now())
		}
		if err != nil {
			logger.Error("write JSON", "error", err)
			return exitRuntimeError
		}
	}

	for _, scanErr := range report.Errors {
		logger.Warn("path scan failed", "path", scanErr.Path, "error", scanErr.Err, "ignored", *ignoreErrors)
	}
	if len(report.Errors) > 0 && !*ignoreErrors {
		return exitRuntimeError
	}
	if operationalFinding {
		return exitOperationalFinding
	}
	return exitSuccess
}

type excludeFlag []string

type rootFlag []string

type hostnameFlag string

func (values *rootFlag) String() string {
	return strings.Join(*values, ",")
}

func (values *rootFlag) Set(value string) error {
	value = strings.TrimSpace(value)
	if value == "" {
		return errors.New("root path cannot be empty")
	}
	value = filepath.Clean(value)
	if !contains(*values, value) {
		*values = append(*values, value)
	}
	return nil
}

func loadVerificationRoots(ctx context.Context, paths []string, workers int) ([]scanner.Certificate, error) {
	var certificates []scanner.Certificate
	seen := make(map[string]struct{})
	for _, rootPath := range paths {
		report, err := scanner.Scan(ctx, rootPath, scanner.Options{MaxBytes: scanner.DefaultMaxBytes, Workers: workers})
		if err != nil {
			return nil, fmt.Errorf("scan %q: %w", rootPath, err)
		}
		if len(report.Errors) > 0 {
			errorsAtPath := make([]error, 0, len(report.Errors))
			for _, scanErr := range report.Errors {
				errorsAtPath = append(errorsAtPath, scanErr)
			}
			return nil, fmt.Errorf("scan %q: %w", rootPath, errors.Join(errorsAtPath...))
		}
		if len(report.PKCS12Encrypted) > 0 {
			return nil, fmt.Errorf("scan %q: contains encrypted PKCS#12 content", rootPath)
		}
		if len(report.Certificates) == 0 {
			return nil, fmt.Errorf("scan %q: no certificates found", rootPath)
		}
		for _, certificate := range report.Certificates {
			if _, exists := seen[certificate.SHA256Fingerprint]; exists {
				continue
			}
			seen[certificate.SHA256Fingerprint] = struct{}{}
			certificates = append(certificates, certificate)
		}
	}
	return certificates, nil
}

func (hostname *hostnameFlag) String() string {
	return string(*hostname)
}

func (hostname *hostnameFlag) Set(value string) error {
	normalized, err := normalizeHostname(value)
	if err != nil {
		return err
	}
	*hostname = hostnameFlag(normalized)
	return nil
}

func normalizeHostname(value string) (string, error) {
	if value == "" {
		return "", errors.New("hostname cannot be empty")
	}
	if value != strings.TrimSpace(value) {
		return "", fmt.Errorf("invalid hostname or IP address %q", value)
	}

	addressValue := value
	if strings.HasPrefix(value, "[") && strings.HasSuffix(value, "]") {
		addressValue = value[1 : len(value)-1]
	} else if strings.ContainsAny(value, "[]") {
		return "", fmt.Errorf("invalid hostname or IP address %q", value)
	}
	if address, err := netip.ParseAddr(addressValue); err == nil {
		return address.String(), nil
	}
	if err := validateDNSName(value); err != nil {
		return "", fmt.Errorf("invalid hostname or IP address %q: %w", value, err)
	}
	return value, nil
}

func validateDNSName(value string) error {
	value = strings.TrimSuffix(value, ".")
	if value == "" || len(value) > 253 {
		return errors.New("DNS name must contain between 1 and 253 characters")
	}
	for _, label := range strings.Split(value, ".") {
		if len(label) == 0 || len(label) > 63 {
			return errors.New("DNS labels must contain between 1 and 63 characters")
		}
		if label[0] == '-' || label[len(label)-1] == '-' {
			return errors.New("DNS labels cannot start or end with a hyphen")
		}
		for _, character := range label {
			if character >= 'a' && character <= 'z' || character >= 'A' && character <= 'Z' ||
				character >= '0' && character <= '9' || character == '-' || character == '_' {
				continue
			}
			return fmt.Errorf("DNS label contains unsupported character %q", character)
		}
	}
	return nil
}

func (values *excludeFlag) String() string {
	return strings.Join(*values, ",")
}

func (values *excludeFlag) Set(value string) error {
	value = strings.TrimSpace(value)
	value = strings.TrimPrefix(value, "./")
	value = strings.TrimRight(value, "/")
	if value == "" || path.IsAbs(value) || filepath.IsAbs(value) {
		return errors.New("use a non-empty relative glob")
	}
	if _, err := path.Match(value, ""); err != nil {
		return fmt.Errorf("invalid glob %q: %w", value, err)
	}
	if !contains(*values, value) {
		*values = append(*values, value)
	}
	return nil
}

type extensionFlag []string

func (values *extensionFlag) String() string {
	return strings.Join(*values, ",")
}

func (values *extensionFlag) Set(value string) error {
	for _, extension := range strings.Split(value, ",") {
		extension = strings.ToLower(strings.TrimSpace(extension))
		if extension == "" || extension == "." || strings.ContainsAny(extension, `/*?[]\\`) {
			return fmt.Errorf("invalid extension %q", extension)
		}
		if !strings.HasPrefix(extension, ".") {
			extension = "." + extension
		}
		if !contains(*values, extension) {
			*values = append(*values, extension)
		}
	}
	return nil
}

func printCertificate(output io.Writer, certificate scanner.Certificate) error {
	return printCertificateAt(output, certificate, time.Now())
}

func printCertificateAt(output io.Writer, certificate scanner.Certificate, now time.Time) error {
	if _, err := fmt.Fprintf(output, "%s [index %d]\n", certificate.Path, certificate.Index); err != nil {
		return err
	}
	return printCertificateDetailsAt(output, certificate, now)
}

func printCertificateDetailsAt(output io.Writer, certificate scanner.Certificate, now time.Time) error {
	subject := certificate.Subject
	if subject == "" {
		subject = "(empty)"
	}
	issuer := certificate.Issuer
	if issuer == "" {
		issuer = "(empty)"
	}
	sans := "(none)"
	if len(certificate.SANs) > 0 {
		sans = strings.Join(certificate.SANs, ", ")
	}
	usages := "(none)"
	if certificate.ExtendedKeyUsageUnrestricted && len(certificate.ExtendedKeyUsage) == 0 {
		usages = "(not specified; unrestricted)"
	} else if len(certificate.ExtendedKeyUsage) > 0 {
		usages = strings.Join(certificate.ExtendedKeyUsage, ", ")
	}
	keyUsage := "(none)"
	if len(certificate.KeyUsage) > 0 {
		keyUsage = strings.Join(certificate.KeyUsage, ", ")
	}
	serialNumber := certificate.SerialNumber
	if serialNumber == "" {
		serialNumber = "(none)"
	}
	certificateType := "leaf"
	if certificate.IsCA {
		certificateType = "CA"
	}
	publicKey := certificate.PublicKeyAlgorithm
	if publicKey == "" {
		publicKey = "unknown"
	}
	if certificate.PublicKeyBits > 0 {
		publicKey += fmt.Sprintf(" (%d bits)", certificate.PublicKeyBits)
	} else if certificate.PublicKeyCurve != "" {
		publicKey += " (" + certificate.PublicKeyCurve + ")"
	}
	signatureAlgorithm := certificate.SignatureAlgorithm
	if signatureAlgorithm == "" {
		signatureAlgorithm = "unknown"
	}

	lines := make([]string, 0, 20)
	if certificate.Keystore != nil {
		lines = append(lines, "  Keystore format: "+certificate.Keystore.Format)
		if certificate.Keystore.Alias != "" {
			lines = append(lines, "  Keystore alias: "+strconv.Quote(certificate.Keystore.Alias))
		}
		if certificate.Keystore.FriendlyName != "" {
			lines = append(lines, "  Keystore friendly name: "+strconv.Quote(certificate.Keystore.FriendlyName))
		}
		lines = append(lines,
			"  Keystore entry type: "+certificate.Keystore.EntryType,
			fmt.Sprintf("  Keystore chain index: %d", certificate.Keystore.ChainIndex),
			"  Truststore: "+formatBoolean(certificate.Keystore.Truststore),
		)
	}
	lines = append(lines,
		"  Subject: "+subject,
		"  Issuer: "+issuer,
		"  Serial number: "+serialNumber,
		"  Certificate type: "+certificateType,
		"  Self-signed: "+formatBoolean(certificate.SelfSigned),
		"  SANs: "+sans,
		"  Key usage: "+keyUsage,
		"  Extended key usage: "+usages,
		"  Public key: "+publicKey,
		"  Signature algorithm: "+signatureAlgorithm,
		"  SHA-1 fingerprint: "+certificate.SHA1Fingerprint,
		"  SHA-256 fingerprint: "+certificate.SHA256Fingerprint,
		"  SPKI SHA-256 fingerprint: "+certificate.SPKISHA256Fingerprint,
		"  Valid from: "+certificate.NotBefore.UTC().Format(time.RFC3339),
		"  Valid to: "+certificate.NotAfter.UTC().Format(time.RFC3339),
		"  Validity status: "+certificate.ValidityStatus(now),
	)
	for _, line := range lines {
		if _, err := fmt.Fprintln(output, line); err != nil {
			return err
		}
	}
	if certificate.Verification != nil {
		if _, err := fmt.Fprintln(output, "  Verification status: "+certificate.Verification.Status); err != nil {
			return err
		}
		if certificate.Verification.Error != "" {
			if _, err := fmt.Fprintln(output, "  Verification error: "+certificate.Verification.Error); err != nil {
				return err
			}
		}
		if len(certificate.Verification.Chains) > 0 {
			if _, err := fmt.Fprintf(output, "  Verified chains: %d\n", len(certificate.Verification.Chains)); err != nil {
				return err
			}
			for chainIndex, chain := range certificate.Verification.Chains {
				if _, err := fmt.Fprintf(output, "    Chain %d:\n", chainIndex); err != nil {
					return err
				}
				for certificateIndex, chainCertificate := range chain {
					anchor := ""
					if chainCertificate.TrustAnchor {
						anchor = " (trust anchor)"
					}
					if _, err := fmt.Fprintf(
						output,
						"      %d: %s [sha256 %s]%s\n",
						certificateIndex,
						chainCertificate.Subject,
						chainCertificate.SHA256Fingerprint,
						anchor,
					); err != nil {
						return err
					}
				}
			}
		}
	}
	return nil
}

func formatBoolean(value bool) string {
	if value {
		return "yes"
	}
	return "no"
}

func normalizeUsage(value string) (string, error) {
	value = strings.ToLower(strings.TrimSpace(value))
	aliases := map[string]string{
		"":                                  "",
		"any":                               scanner.UsageAny,
		"server":                            scanner.UsageServer,
		"server-auth":                       scanner.UsageServer,
		"client":                            scanner.UsageClient,
		"client-auth":                       scanner.UsageClient,
		"code-signing":                      scanner.UsageCodeSigning,
		"email":                             scanner.UsageEmailProtection,
		"email-protection":                  scanner.UsageEmailProtection,
		"ipsec-end-system":                  scanner.UsageIPSECEndSystem,
		"ipsec-tunnel":                      scanner.UsageIPSECTunnel,
		"ipsec-user":                        scanner.UsageIPSECUser,
		"timestamping":                      scanner.UsageTimestamping,
		"ocsp-signing":                      scanner.UsageOCSPSigning,
		"microsoft-server-gated-crypto":     scanner.UsageMicrosoftServerGatedCrypto,
		"netscape-server-gated-crypto":      scanner.UsageNetscapeServerGatedCrypto,
		"microsoft-commercial-code-signing": scanner.UsageMicrosoftCommercialCodeSigning,
		"microsoft-kernel-code-signing":     scanner.UsageMicrosoftKernelCodeSigning,
	}
	usage, ok := aliases[value]
	if !ok {
		return "", fmt.Errorf("unsupported -usage %q", value)
	}
	return usage, nil
}

func parseExpiration(value string) (time.Duration, bool, error) {
	return parseDurationOption("expiration", value)
}

func parseDurationOption(option, value string) (time.Duration, bool, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return 0, false, nil
	}

	var duration time.Duration
	var err error
	if strings.HasSuffix(value, "d") {
		days, parseErr := strconv.ParseUint(strings.TrimSuffix(value, "d"), 10, 64)
		if parseErr != nil || days > uint64((1<<63-1)/int64(24*time.Hour)) {
			return 0, false, fmt.Errorf("invalid -%s %q", option, value)
		}
		duration = time.Duration(days) * 24 * time.Hour
	} else {
		duration, err = time.ParseDuration(value)
		if err != nil {
			return 0, false, fmt.Errorf("invalid -%s %q: use a duration such as 30d or 48h", option, value)
		}
	}
	if duration < 0 {
		return 0, false, fmt.Errorf("-%s cannot be negative", option)
	}
	return duration, true, nil
}

func certificateExpiresWithin(certificate scanner.Certificate, duration time.Duration, now time.Time) bool {
	return !certificate.NotAfter.After(now.Add(duration))
}

func certificateMatches(
	certificate scanner.Certificate,
	usage string,
	hostname string,
	expiration time.Duration,
	hasExpiration bool,
	now time.Time,
) bool {
	if usage != "" && !certificate.ExtendedKeyUsageUnrestricted && !contains(certificate.ExtendedKeyUsage, usage) {
		return false
	}
	if hostname != "" && certificate.VerifyHostname(hostname) != nil {
		return false
	}
	if hasExpiration {
		return !certificate.NotAfter.After(now.Add(expiration))
	}
	return true
}

func contains(values []string, wanted string) bool {
	for _, value := range values {
		if value == wanted {
			return true
		}
	}
	return false
}

type jsonCertificate struct {
	Path                         string            `json:"path,omitempty"`
	Index                        *int              `json:"index,omitempty"`
	Subject                      string            `json:"subject"`
	Issuer                       string            `json:"issuer"`
	SerialNumber                 string            `json:"serial_number"`
	IsCA                         bool              `json:"is_ca"`
	SelfSigned                   bool              `json:"self_signed"`
	SANs                         []string          `json:"sans"`
	KeyUsage                     []string          `json:"key_usage"`
	ExtendedKeyUsage             []string          `json:"extended_key_usage"`
	ExtendedKeyUsageUnrestricted bool              `json:"extended_key_usage_unrestricted"`
	PublicKey                    jsonPublicKey     `json:"public_key"`
	SignatureAlgorithm           string            `json:"signature_algorithm"`
	Fingerprints                 jsonFingerprints  `json:"fingerprints"`
	ValidFrom                    string            `json:"valid_from"`
	ValidTo                      string            `json:"valid_to"`
	ValidityStatus               string            `json:"validity_status"`
	Keystore                     *jsonKeystoreInfo `json:"keystore,omitempty"`
	Verification                 *jsonVerification `json:"verification,omitempty"`
}

type jsonVerification struct {
	Status string                               `json:"status"`
	Error  string                               `json:"error,omitempty"`
	Chains [][]jsonVerificationChainCertificate `json:"chains,omitempty"`
}

type jsonVerificationChainCertificate struct {
	Subject           string `json:"subject"`
	Issuer            string `json:"issuer"`
	SHA256Fingerprint string `json:"sha256_fingerprint"`
	TrustAnchor       bool   `json:"trust_anchor"`
}

type jsonKeystoreInfo struct {
	Format       string `json:"format"`
	Alias        string `json:"alias,omitempty"`
	FriendlyName string `json:"friendly_name,omitempty"`
	EntryType    string `json:"entry_type"`
	ChainIndex   int    `json:"chain_index"`
	Truststore   bool   `json:"truststore"`
}

type jsonPKCS12EncryptedContent struct {
	RecordType string                    `json:"record_type"`
	Path       string                    `json:"path"`
	PKCS12     jsonPKCS12EncryptedDetail `json:"pkcs12"`
}

type jsonPKCS12EncryptedDetail struct {
	Status       string `json:"status"`
	ContentIndex int    `json:"content_index"`
	Algorithm    string `json:"algorithm"`
	AlgorithmOID string `json:"algorithm_oid"`
	BagCount     *int   `json:"bag_count"`
}

type jsonPublicKey struct {
	Algorithm string `json:"algorithm"`
	Bits      int    `json:"bits,omitempty"`
	Curve     string `json:"curve,omitempty"`
}

type jsonFingerprints struct {
	SHA1       string `json:"sha1"`
	SHA256     string `json:"sha256"`
	SPKISHA256 string `json:"spki_sha256"`
}

func printJSONAt(output io.Writer, certificates []scanner.Certificate, now time.Time) error {
	return printJSONResultsAt(output, certificates, nil, now)
}

func printJSONResultsAt(
	output io.Writer,
	certificates []scanner.Certificate,
	encrypted []scanner.PKCS12EncryptedContent,
	now time.Time,
) error {
	result := make([]any, 0, len(certificates)+len(encrypted))
	for _, certificate := range certificates {
		result = append(result, newJSONCertificate(certificate, now))
	}
	for _, finding := range encrypted {
		result = append(result, newJSONPKCS12EncryptedContent(finding))
	}
	encoder := json.NewEncoder(output)
	encoder.SetIndent("", "  ")
	return encoder.Encode(result)
}

func newJSONCertificate(certificate scanner.Certificate, now time.Time) jsonCertificate {
	index := certificate.Index
	return jsonCertificate{
		Path:                         certificate.Path,
		Index:                        &index,
		Subject:                      certificate.Subject,
		Issuer:                       certificate.Issuer,
		SerialNumber:                 certificate.SerialNumber,
		IsCA:                         certificate.IsCA,
		SelfSigned:                   certificate.SelfSigned,
		SANs:                         append([]string{}, certificate.SANs...),
		KeyUsage:                     append([]string{}, certificate.KeyUsage...),
		ExtendedKeyUsage:             append([]string{}, certificate.ExtendedKeyUsage...),
		ExtendedKeyUsageUnrestricted: certificate.ExtendedKeyUsageUnrestricted,
		PublicKey: jsonPublicKey{
			Algorithm: certificate.PublicKeyAlgorithm,
			Bits:      certificate.PublicKeyBits,
			Curve:     certificate.PublicKeyCurve,
		},
		SignatureAlgorithm: certificate.SignatureAlgorithm,
		Fingerprints: jsonFingerprints{
			SHA1:       certificate.SHA1Fingerprint,
			SHA256:     certificate.SHA256Fingerprint,
			SPKISHA256: certificate.SPKISHA256Fingerprint,
		},
		ValidFrom:      certificate.NotBefore.UTC().Format(time.RFC3339),
		ValidTo:        certificate.NotAfter.UTC().Format(time.RFC3339),
		ValidityStatus: certificate.ValidityStatus(now),
		Keystore:       newJSONKeystoreInfo(certificate.Keystore),
		Verification:   newJSONVerification(certificate.Verification),
	}
}

func newJSONVerification(verification *scanner.VerificationResult) *jsonVerification {
	if verification == nil {
		return nil
	}
	result := &jsonVerification{
		Status: verification.Status,
		Error:  verification.Error,
		Chains: make([][]jsonVerificationChainCertificate, 0, len(verification.Chains)),
	}
	for _, chain := range verification.Chains {
		jsonChain := make([]jsonVerificationChainCertificate, 0, len(chain))
		for _, certificate := range chain {
			jsonChain = append(jsonChain, jsonVerificationChainCertificate{
				Subject:           certificate.Subject,
				Issuer:            certificate.Issuer,
				SHA256Fingerprint: certificate.SHA256Fingerprint,
				TrustAnchor:       certificate.TrustAnchor,
			})
		}
		result.Chains = append(result.Chains, jsonChain)
	}
	return result
}

func newJSONKeystoreInfo(keystore *scanner.KeystoreInfo) *jsonKeystoreInfo {
	if keystore == nil {
		return nil
	}
	return &jsonKeystoreInfo{
		Format:       keystore.Format,
		Alias:        keystore.Alias,
		FriendlyName: keystore.FriendlyName,
		EntryType:    keystore.EntryType,
		ChainIndex:   keystore.ChainIndex,
		Truststore:   keystore.Truststore,
	}
}

func newJSONPKCS12EncryptedContent(finding scanner.PKCS12EncryptedContent) jsonPKCS12EncryptedContent {
	return jsonPKCS12EncryptedContent{
		RecordType: "pkcs12_encrypted_content",
		Path:       finding.Path,
		PKCS12: jsonPKCS12EncryptedDetail{
			Status:       "encrypted",
			ContentIndex: finding.ContentIndex,
			Algorithm:    finding.Algorithm,
			AlgorithmOID: finding.AlgorithmOID,
			BagCount:     finding.BagCount,
		},
	}
}

func printPKCS12EncryptedContent(output io.Writer, finding scanner.PKCS12EncryptedContent) error {
	if _, err := fmt.Fprintf(output, "%s [PKCS#12 content %d]\n", finding.Path, finding.ContentIndex); err != nil {
		return err
	}
	bagCount := "unknown"
	if finding.BagCount != nil {
		bagCount = strconv.Itoa(*finding.BagCount)
	}
	for _, line := range []string{
		"  Status: encrypted; certificates are unreadable without a password",
		fmt.Sprintf("  PBE algorithm: %s (%s)", finding.Algorithm, finding.AlgorithmOID),
		"  Bag count: " + bagCount,
	} {
		if _, err := fmt.Fprintln(output, line); err != nil {
			return err
		}
	}
	return nil
}
