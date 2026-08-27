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
	maxBytes := flags.Int64("max-bytes", scanner.DefaultMaxBytes, "initial bytes inspected per file; PEM matches are read fully; 0 reads all files fully")
	workers := flags.Int("workers", min(runtime.GOMAXPROCS(0), 8), "number of files scanned concurrently")
	flags.Var(&excludes, "exclude", "exclude a relative path glob; repeatable; patterns without / match at any depth")
	flags.Var(&extensions, "extensions", "scan only these file extensions; comma-separated or repeatable")
	oneFileSystem := flags.Bool("one-file-system", false, "do not scan files or directories on other filesystems (Linux and macOS)")
	followSymlinks := flags.Bool("follow-symlinks", false, "follow symlinks encountered below PATH while preventing cycles")
	ignoreErrors := flags.Bool("ignore-errors", false, "return success despite non-fatal file scan errors")
	usageValue := flags.String("usage", "", "filter by extended key usage, such as server or client")
	expired := flags.Bool("expired", false, "shortcut for -expiration=0d")
	expirationValue := flags.String("expiration", "", "print certificates expired or expiring within a duration, such as 30d")
	jsonOutput := flags.Bool("json", false, "print results as JSON")
	version := flags.Bool("version", false, "show version and build information")
	flags.Usage = func() {
		_, _ = fmt.Fprintln(stderr, "Usage: certfinder [options] PATH")
		_, _ = fmt.Fprintln(stderr, "Find PEM or DER encoded X.509 certificates in PATH and its subdirectories.")
		_, _ = fmt.Fprintln(stderr)
		flags.PrintDefaults()
	}

	if err := flags.Parse(arguments); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 2
	}
	if *version {
		if _, err := fmt.Fprintln(stdout, buildinfo.String()); err != nil {
			logger.Error("write version", "error", err)
			return 1
		}
		return 0
	}
	if flags.NArg() != 1 {
		flags.Usage()
		return 2
	}
	if *maxBytes < 0 {
		logger.Error("invalid option", "option", "max-bytes", "error", "value cannot be negative")
		return 2
	}
	if *workers < 1 {
		logger.Error("invalid option", "option", "workers", "error", "value must be at least 1")
		return 2
	}
	usage, err := normalizeUsage(*usageValue)
	if err != nil {
		logger.Error("invalid option", "option", "usage", "error", err)
		return 2
	}
	expiration, hasExpiration, err := parseExpiration(*expirationValue)
	if err != nil {
		logger.Error("invalid option", "option", "expiration", "error", err)
		return 2
	}
	if *expired && hasExpiration {
		logger.Error("conflicting options", "options", "expired,expiration")
		return 2
	}
	if *expired {
		expiration = 0
		hasExpiration = true
	}
	expirationDescription := *expirationValue
	if *expired {
		expirationDescription = "0d"
	}
	now := time.Now()
	display := newProgressDisplay(stderr, stdout, !*jsonOutput)
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
		Expiration:     expirationDescription,
		JSON:           *jsonOutput,
	})

	report, err := scanner.Scan(ctx, flags.Arg(0), scanner.Options{
		MaxBytes:       *maxBytes,
		Workers:        *workers,
		Exclude:        append([]string{}, excludes...),
		Extensions:     append([]string{}, extensions...),
		OneFileSystem:  *oneFileSystem,
		FollowSymlinks: *followSymlinks,
		OnProgress:     display.Update,
		OnCertificate: func(certificate scanner.Certificate) {
			if certificateMatches(certificate, usage, expiration, hasExpiration, now) {
				display.Certificate(certificate)
			}
		},
	})
	if err != nil {
		display.Stop(false)
		logger.Error("scan failed", "path", flags.Arg(0), "error", err)
		return 1
	}
	display.Stop(true)
	if err := display.Err(); err != nil {
		logger.Error("write output", "error", err)
		return 1
	}

	filtered := make([]scanner.Certificate, 0, len(report.Certificates))
	for _, certificate := range report.Certificates {
		if certificateMatches(certificate, usage, expiration, hasExpiration, now) {
			filtered = append(filtered, certificate)
		}
	}
	if *jsonOutput {
		if err := printJSON(stdout, filtered); err != nil {
			logger.Error("write JSON", "error", err)
			return 1
		}
	}

	for _, scanErr := range report.Errors {
		logger.Warn("path scan failed", "path", scanErr.Path, "error", scanErr.Err, "ignored", *ignoreErrors)
	}
	if len(report.Errors) > 0 && !*ignoreErrors {
		return 1
	}
	return 0
}

type excludeFlag []string

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

	lines := []string{
		certificate.Path,
		"  Subject: " + subject,
		"  Issuer: " + issuer,
		"  Serial number: " + serialNumber,
		"  Certificate type: " + certificateType,
		"  Self-signed: " + formatBoolean(certificate.SelfSigned),
		"  SANs: " + sans,
		"  Key usage: " + keyUsage,
		"  Extended key usage: " + usages,
		"  Public key: " + publicKey,
		"  Signature algorithm: " + signatureAlgorithm,
		"  SHA-1 fingerprint: " + certificate.SHA1Fingerprint,
		"  SHA-256 fingerprint: " + certificate.SHA256Fingerprint,
		"  SPKI SHA-256 fingerprint: " + certificate.SPKISHA256Fingerprint,
		"  Valid from: " + certificate.NotBefore.UTC().Format(time.RFC3339),
		"  Valid to: " + certificate.NotAfter.UTC().Format(time.RFC3339),
		"  Validity status: " + certificate.ValidityStatus(now),
	}
	for _, line := range lines {
		if _, err := fmt.Fprintln(output, line); err != nil {
			return err
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
	value = strings.TrimSpace(value)
	if value == "" {
		return 0, false, nil
	}

	var duration time.Duration
	var err error
	if strings.HasSuffix(value, "d") {
		days, parseErr := strconv.ParseUint(strings.TrimSuffix(value, "d"), 10, 64)
		if parseErr != nil || days > uint64((1<<63-1)/int64(24*time.Hour)) {
			return 0, false, fmt.Errorf("invalid -expiration %q", value)
		}
		duration = time.Duration(days) * 24 * time.Hour
	} else {
		duration, err = time.ParseDuration(value)
		if err != nil {
			return 0, false, fmt.Errorf("invalid -expiration %q: use a duration such as 30d or 48h", value)
		}
	}
	if duration < 0 {
		return 0, false, errors.New("-expiration cannot be negative")
	}
	return duration, true, nil
}

func certificateMatches(
	certificate scanner.Certificate,
	usage string,
	expiration time.Duration,
	hasExpiration bool,
	now time.Time,
) bool {
	if usage != "" && !certificate.ExtendedKeyUsageUnrestricted && !contains(certificate.ExtendedKeyUsage, usage) {
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
	Path                         string           `json:"path"`
	Subject                      string           `json:"subject"`
	Issuer                       string           `json:"issuer"`
	SerialNumber                 string           `json:"serial_number"`
	IsCA                         bool             `json:"is_ca"`
	SelfSigned                   bool             `json:"self_signed"`
	SANs                         []string         `json:"sans"`
	KeyUsage                     []string         `json:"key_usage"`
	ExtendedKeyUsage             []string         `json:"extended_key_usage"`
	ExtendedKeyUsageUnrestricted bool             `json:"extended_key_usage_unrestricted"`
	PublicKey                    jsonPublicKey    `json:"public_key"`
	SignatureAlgorithm           string           `json:"signature_algorithm"`
	Fingerprints                 jsonFingerprints `json:"fingerprints"`
	ValidFrom                    string           `json:"valid_from"`
	ValidTo                      string           `json:"valid_to"`
	ValidityStatus               string           `json:"validity_status"`
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

func printJSON(output io.Writer, certificates []scanner.Certificate) error {
	return printJSONAt(output, certificates, time.Now())
}

func printJSONAt(output io.Writer, certificates []scanner.Certificate, now time.Time) error {
	result := make([]jsonCertificate, 0, len(certificates))
	for _, certificate := range certificates {
		result = append(result, jsonCertificate{
			Path:                         certificate.Path,
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
		})
	}
	encoder := json.NewEncoder(output)
	encoder.SetIndent("", "  ")
	return encoder.Encode(result)
}
