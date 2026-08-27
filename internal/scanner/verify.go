package scanner

import (
	"bytes"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"time"
)

// Verification status values.
const (
	VerificationTrusted             = "trusted"
	VerificationUntrusted           = "untrusted"
	VerificationExpired             = "expired"
	VerificationNotYetValid         = "not-yet-valid"
	VerificationMissingIntermediate = "missing-intermediate"
)

// VerificationOptions controls offline certificate-chain verification.
type VerificationOptions struct {
	CurrentTime        time.Time
	DNSName            string
	IncludeSystemRoots bool
	Roots              []Certificate
}

// VerificationResult describes one certificate's chain-verification outcome.
type VerificationResult struct {
	Status string
	Error  string
	Chains [][]VerificationChainCertificate
}

// VerificationChainCertificate identifies one certificate in a verified chain.
type VerificationChainCertificate struct {
	Subject           string
	Issuer            string
	SHA256Fingerprint string
	TrustAnchor       bool
}

// VerifyCertificates verifies certificates without performing network access.
// All supplied certificates are eligible intermediates; Roots are additional
// trust anchors and system roots are optional.
func VerifyCertificates(certificates []Certificate, options VerificationOptions) ([]Certificate, error) {
	roots, err := verificationRootPool(options)
	if err != nil {
		return nil, err
	}
	intermediates := x509.NewCertPool()
	for index, certificate := range certificates {
		if certificate.parsed == nil {
			return nil, fmt.Errorf("certificate %d at %q has no parsed X.509 data", index, certificate.Path)
		}
		intermediates.AddCert(certificate.parsed)
	}

	currentTime := options.CurrentTime
	if currentTime.IsZero() {
		currentTime = time.Now()
	}
	verified := append([]Certificate{}, certificates...)
	for index := range verified {
		certificate := verified[index].parsed
		chains, verifyErr := certificate.Verify(x509.VerifyOptions{
			Roots:         roots,
			Intermediates: intermediates,
			CurrentTime:   currentTime,
			DNSName:       options.DNSName,
			KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
		})
		verified[index].Verification = describeVerification(certificate, chains, verifyErr, currentTime)
	}
	return verified, nil
}

func verificationRootPool(options VerificationOptions) (*x509.CertPool, error) {
	var roots *x509.CertPool
	if options.IncludeSystemRoots {
		var err error
		roots, err = x509.SystemCertPool()
		if err != nil {
			return nil, fmt.Errorf("load system roots: %w", err)
		}
	}
	if roots == nil {
		roots = x509.NewCertPool()
	}
	for index, certificate := range options.Roots {
		if certificate.parsed == nil {
			return nil, fmt.Errorf("root certificate %d at %q has no parsed X.509 data", index, certificate.Path)
		}
		roots.AddCert(certificate.parsed)
	}
	return roots, nil
}

func describeVerification(
	certificate *x509.Certificate,
	chains [][]*x509.Certificate,
	verifyErr error,
	currentTime time.Time,
) *VerificationResult {
	result := &VerificationResult{Status: VerificationTrusted}
	if verifyErr == nil {
		result.Chains = describeVerifiedChains(chains)
		return result
	}
	result.Status = classifyVerificationError(certificate, verifyErr, currentTime)
	result.Error = verifyErr.Error()
	return result
}

func classifyVerificationError(certificate *x509.Certificate, verifyErr error, currentTime time.Time) string {
	if currentTime.Before(certificate.NotBefore) {
		return VerificationNotYetValid
	}
	if currentTime.After(certificate.NotAfter) {
		return VerificationExpired
	}
	var invalid x509.CertificateInvalidError
	if errors.As(verifyErr, &invalid) && invalid.Reason == x509.Expired && invalid.Cert != nil {
		if currentTime.Before(invalid.Cert.NotBefore) {
			return VerificationNotYetValid
		}
		return VerificationExpired
	}
	var unknownAuthority x509.UnknownAuthorityError
	if errors.As(verifyErr, &unknownAuthority) && unknownAuthority.Cert != nil {
		if bytes.Equal(unknownAuthority.Cert.RawSubject, unknownAuthority.Cert.RawIssuer) {
			return VerificationUntrusted
		}
		return VerificationMissingIntermediate
	}
	return VerificationUntrusted
}

func describeVerifiedChains(chains [][]*x509.Certificate) [][]VerificationChainCertificate {
	result := make([][]VerificationChainCertificate, 0, len(chains))
	for _, chain := range chains {
		described := make([]VerificationChainCertificate, 0, len(chain))
		for index, certificate := range chain {
			fingerprint := sha256.Sum256(certificate.Raw)
			described = append(described, VerificationChainCertificate{
				Subject:           certificate.Subject.String(),
				Issuer:            certificate.Issuer.String(),
				SHA256Fingerprint: hex.EncodeToString(fingerprint[:]),
				TrustAnchor:       index == len(chain)-1,
			})
		}
		result = append(result, described)
	}
	return result
}
