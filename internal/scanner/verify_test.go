package scanner

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"
)

func TestVerifyCertificatesBuildsChainFromDiscoveredIntermediate(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, time.June, 1, 0, 0, 0, 0, time.UTC)
	root, intermediate, leaf := makeVerificationChain(t, now.Add(-time.Hour), now.Add(time.Hour))
	verified, err := VerifyCertificates([]Certificate{leaf, intermediate}, VerificationOptions{
		CurrentTime: now,
		Roots:       []Certificate{root},
	})
	if err != nil {
		t.Fatal(err)
	}
	result := verified[0].Verification
	if result == nil || result.Status != VerificationTrusted || result.Error != "" || len(result.Chains) != 1 {
		t.Fatalf("leaf verification = %+v", result)
	}
	chain := result.Chains[0]
	if len(chain) != 3 || chain[0].Subject != "CN=leaf.example.test" ||
		chain[1].Subject != "CN=Intermediate Test CA" || chain[2].Subject != "CN=Root Test CA" ||
		!chain[2].TrustAnchor || chain[0].TrustAnchor {
		t.Fatalf("verified chain = %+v", chain)
	}
}

func TestVerifyCertificatesPrivateRootsAugmentSystemPool(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, time.June, 1, 0, 0, 0, 0, time.UTC)
	root, intermediate, leaf := makeVerificationChain(t, now.Add(-time.Hour), now.Add(time.Hour))
	verified, err := VerifyCertificates([]Certificate{leaf, intermediate}, VerificationOptions{
		CurrentTime:        now,
		IncludeSystemRoots: true,
		Roots:              []Certificate{root},
	})
	if err != nil {
		t.Fatal(err)
	}
	if result := verified[0].Verification; result == nil || result.Status != VerificationTrusted {
		t.Fatalf("leaf verification = %+v", result)
	}
}

func TestVerifyCertificatesClassifiesFailures(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, time.June, 1, 0, 0, 0, 0, time.UTC)
	root, _, validLeaf := makeVerificationChain(t, now.Add(-time.Hour), now.Add(time.Hour))
	_, _, expiredLeaf := makeVerificationChain(t, now.Add(-2*time.Hour), now.Add(-time.Hour))
	_, _, futureLeaf := makeVerificationChain(t, now.Add(time.Hour), now.Add(2*time.Hour))

	for _, test := range []struct {
		name         string
		certificates []Certificate
		roots        []Certificate
		want         string
	}{
		{name: "missing intermediate", certificates: []Certificate{validLeaf}, roots: []Certificate{root}, want: VerificationMissingIntermediate},
		{name: "untrusted self-signed", certificates: []Certificate{root}, want: VerificationUntrusted},
		{name: "expired", certificates: []Certificate{expiredLeaf}, want: VerificationExpired},
		{name: "not yet valid", certificates: []Certificate{futureLeaf}, want: VerificationNotYetValid},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			verified, err := VerifyCertificates(test.certificates, VerificationOptions{
				CurrentTime: now,
				Roots:       test.roots,
			})
			if err != nil {
				t.Fatal(err)
			}
			result := verified[0].Verification
			if result == nil || result.Status != test.want || result.Error == "" || len(result.Chains) != 0 {
				t.Fatalf("verification = %+v, want status %q with an error", result, test.want)
			}
		})
	}
}

func TestVerifyCertificatesRespectsDNSName(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, time.June, 1, 0, 0, 0, 0, time.UTC)
	root, intermediate, leaf := makeVerificationChain(t, now.Add(-time.Hour), now.Add(time.Hour))
	for _, test := range []struct {
		hostname string
		want     string
	}{
		{hostname: "service.example.test", want: VerificationTrusted},
		{hostname: "other.example.test", want: VerificationUntrusted},
	} {
		verified, err := VerifyCertificates([]Certificate{leaf, intermediate}, VerificationOptions{
			CurrentTime: now,
			DNSName:     test.hostname,
			Roots:       []Certificate{root},
		})
		if err != nil {
			t.Fatal(err)
		}
		if got := verified[0].Verification.Status; got != test.want {
			t.Errorf("hostname %q status = %q, want %q", test.hostname, got, test.want)
		}
	}
}

func makeVerificationChain(t *testing.T, leafNotBefore, leafNotAfter time.Time) (
	Certificate,
	Certificate,
	Certificate,
) {
	t.Helper()
	rootKey := makeVerificationKey(t)
	intermediateKey := makeVerificationKey(t)
	leafKey := makeVerificationKey(t)
	rootTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(100),
		Subject:               pkix.Name{CommonName: "Root Test CA"},
		NotBefore:             time.Date(2020, time.January, 1, 0, 0, 0, 0, time.UTC),
		NotAfter:              time.Date(2035, time.January, 1, 0, 0, 0, 0, time.UTC),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	root := createVerificationCertificate(t, rootTemplate, rootTemplate, &rootKey.PublicKey, rootKey)
	intermediateTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(101),
		Subject:               pkix.Name{CommonName: "Intermediate Test CA"},
		NotBefore:             rootTemplate.NotBefore,
		NotAfter:              rootTemplate.NotAfter,
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	intermediate := createVerificationCertificate(
		t,
		intermediateTemplate,
		root.parsed,
		&intermediateKey.PublicKey,
		rootKey,
	)
	leafTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(102),
		Subject:      pkix.Name{CommonName: "leaf.example.test"},
		NotBefore:    leafNotBefore,
		NotAfter:     leafNotAfter,
		DNSNames:     []string{"service.example.test"},
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	leaf := createVerificationCertificate(
		t,
		leafTemplate,
		intermediate.parsed,
		&leafKey.PublicKey,
		intermediateKey,
	)
	root.Path = "/roots/root.pem"
	intermediate.Path = "/scan/intermediate.pem"
	leaf.Path = "/scan/leaf.pem"
	return root, intermediate, leaf
}

func makeVerificationKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

func createVerificationCertificate(
	t *testing.T,
	template *x509.Certificate,
	parent *x509.Certificate,
	publicKey any,
	signer any,
) Certificate {
	t.Helper()
	der, err := x509.CreateCertificate(rand.Reader, template, parent, publicKey, signer)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return describe("", 0, parsed)
}
