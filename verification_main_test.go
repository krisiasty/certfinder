package main

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/krisiasty/certfinder/internal/scanner"
)

func TestRunVerifiesDiscoveredChainAgainstPrivateRoot(t *testing.T) {
	t.Parallel()
	scanPath, rootPath := writeVerificationChain(t, true)
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	status := run(context.Background(), []string{
		"-verify",
		"-roots=" + rootPath,
		"-roots-only",
		"-hostname=service.example.test",
		"-json",
		"-quiet",
		scanPath,
	}, &stdout, &stderr)
	if status != exitSuccess {
		t.Fatalf("status = %d, want %d; stderr = %q", status, exitSuccess, stderr.String())
	}
	var certificates []jsonCertificate
	if err := json.Unmarshal(stdout.Bytes(), &certificates); err != nil {
		t.Fatal(err)
	}
	leaf := findJSONCertificateBySubject(t, certificates, "CN=leaf.example.test")
	if leaf.Verification == nil || leaf.Verification.Status != scanner.VerificationTrusted ||
		leaf.Verification.Error != "" || len(leaf.Verification.Chains) != 1 {
		t.Fatalf("leaf verification = %+v", leaf.Verification)
	}
	chain := leaf.Verification.Chains[0]
	if len(chain) != 3 || chain[0].Subject != "CN=leaf.example.test" ||
		chain[1].Subject != "CN=Intermediate Test CA" || chain[2].Subject != "CN=Root Test CA" ||
		!chain[2].TrustAnchor {
		t.Fatalf("verified chain = %+v", chain)
	}
}

func TestRunReportsMissingIntermediate(t *testing.T) {
	t.Parallel()
	scanPath, rootPath := writeVerificationChain(t, false)
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	status := run(context.Background(), []string{
		"-verify",
		"-roots=" + rootPath,
		"-roots-only",
		"-jsonl",
		"-quiet",
		scanPath,
	}, &stdout, &stderr)
	if status != exitSuccess {
		t.Fatalf("status = %d, want %d; stderr = %q", status, exitSuccess, stderr.String())
	}
	var certificate jsonCertificate
	if err := json.Unmarshal(stdout.Bytes(), &certificate); err != nil {
		t.Fatal(err)
	}
	if certificate.Verification == nil || certificate.Verification.Status != scanner.VerificationMissingIntermediate ||
		certificate.Verification.Error == "" || len(certificate.Verification.Chains) != 0 {
		t.Fatalf("verification = %+v", certificate.Verification)
	}
}

func TestRunRejectsInvalidVerificationFlags(t *testing.T) {
	t.Parallel()
	for _, arguments := range [][]string{
		{"-roots=/tmp/root.pem", "."},
		{"-verify", "-roots-only", "."},
		{"-verify", "-roots=", "."},
	} {
		var stdout bytes.Buffer
		var stderr bytes.Buffer
		if status := run(context.Background(), arguments, &stdout, &stderr); status != exitUsageError {
			t.Errorf("run(%v) status = %d, want %d", arguments, status, exitUsageError)
		}
	}
}

func TestRunRejectsPrivateRootPathWithoutCertificates(t *testing.T) {
	t.Parallel()
	directory := t.TempDir()
	rootPath := filepath.Join(directory, "not-a-root.txt")
	if err := os.WriteFile(rootPath, []byte("not a certificate\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	status := run(context.Background(), []string{
		"-verify",
		"-roots=" + rootPath,
		"-roots-only",
		"-quiet",
		directory,
	}, &stdout, &stderr)
	if status != exitRuntimeError || !strings.Contains(stderr.String(), "no certificates found") {
		t.Fatalf("status = %d, stderr = %q", status, stderr.String())
	}
}

func TestJSONOmitsVerificationWhenDisabled(t *testing.T) {
	t.Parallel()
	certificate := scanner.Certificate{
		Path:      "/certificates/leaf.pem",
		NotBefore: time.Now().Add(-time.Hour),
		NotAfter:  time.Now().Add(time.Hour),
	}
	encoded, err := json.Marshal(newJSONCertificate(certificate, time.Now()))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(encoded), "verification") {
		t.Fatalf("default JSON unexpectedly contains verification: %s", encoded)
	}
}

func TestPrintCertificateIncludesVerification(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, time.June, 1, 0, 0, 0, 0, time.UTC)
	certificate := scanner.Certificate{
		Path:      "/certificates/leaf.pem",
		Subject:   "CN=leaf.example.test",
		NotBefore: now.Add(-time.Hour),
		NotAfter:  now.Add(time.Hour),
		Verification: &scanner.VerificationResult{
			Status: scanner.VerificationTrusted,
			Chains: [][]scanner.VerificationChainCertificate{{
				{Subject: "CN=leaf.example.test", SHA256Fingerprint: "aabb"},
				{Subject: "CN=Root Test CA", SHA256Fingerprint: "ccdd", TrustAnchor: true},
			}},
		},
	}
	var output bytes.Buffer
	if err := printCertificateAt(&output, certificate, now); err != nil {
		t.Fatal(err)
	}
	for _, wanted := range []string{
		"  Verification status: trusted\n",
		"  Verified chains: 1\n",
		"    Chain 0:\n",
		"      0: CN=leaf.example.test [sha256 aabb]\n",
		"      1: CN=Root Test CA [sha256 ccdd] (trust anchor)\n",
	} {
		if !strings.Contains(output.String(), wanted) {
			t.Errorf("output %q does not contain %q", output.String(), wanted)
		}
	}
}

func findJSONCertificateBySubject(t *testing.T, certificates []jsonCertificate, subject string) jsonCertificate {
	t.Helper()
	for _, certificate := range certificates {
		if certificate.Subject == subject {
			return certificate
		}
	}
	t.Fatalf("certificate %q not found in %+v", subject, certificates)
	return jsonCertificate{}
}

func writeVerificationChain(t *testing.T, includeIntermediate bool) (string, string) {
	t.Helper()
	directory := t.TempDir()
	scanPath := filepath.Join(directory, "scan")
	if err := os.Mkdir(scanPath, 0o700); err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	rootKey := makeMainVerificationKey(t)
	intermediateKey := makeMainVerificationKey(t)
	leafKey := makeMainVerificationKey(t)
	rootTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(100),
		Subject:               pkix.Name{CommonName: "Root Test CA"},
		NotBefore:             now.Add(-24 * time.Hour),
		NotAfter:              now.Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	rootDER := createMainVerificationCertificate(t, rootTemplate, rootTemplate, &rootKey.PublicKey, rootKey)
	root, err := x509.ParseCertificate(rootDER)
	if err != nil {
		t.Fatal(err)
	}
	intermediateTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(101),
		Subject:               pkix.Name{CommonName: "Intermediate Test CA"},
		NotBefore:             rootTemplate.NotBefore,
		NotAfter:              rootTemplate.NotAfter,
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	intermediateDER := createMainVerificationCertificate(
		t,
		intermediateTemplate,
		root,
		&intermediateKey.PublicKey,
		rootKey,
	)
	intermediate, err := x509.ParseCertificate(intermediateDER)
	if err != nil {
		t.Fatal(err)
	}
	leafTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(102),
		Subject:      pkix.Name{CommonName: "leaf.example.test"},
		NotBefore:    now.Add(-time.Hour),
		NotAfter:     now.Add(time.Hour),
		DNSNames:     []string{"service.example.test"},
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	leafDER := createMainVerificationCertificate(
		t,
		leafTemplate,
		intermediate,
		&leafKey.PublicKey,
		intermediateKey,
	)
	writePEMCertificate(t, filepath.Join(directory, "root.pem"), rootDER)
	writePEMCertificate(t, filepath.Join(scanPath, "leaf.pem"), leafDER)
	if includeIntermediate {
		writePEMCertificate(t, filepath.Join(scanPath, "intermediate.pem"), intermediateDER)
	}
	return scanPath, filepath.Join(directory, "root.pem")
}

func makeMainVerificationKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

func createMainVerificationCertificate(
	t *testing.T,
	template *x509.Certificate,
	parent *x509.Certificate,
	publicKey any,
	signer any,
) []byte {
	t.Helper()
	der, err := x509.CreateCertificate(rand.Reader, template, parent, publicKey, signer)
	if err != nil {
		t.Fatal(err)
	}
	return der
}

func writePEMCertificate(t *testing.T, path string, der []byte) {
	t.Helper()
	encoded := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	if err := os.WriteFile(path, encoded, 0o600); err != nil {
		t.Fatal(err)
	}
}
