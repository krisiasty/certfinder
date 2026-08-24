package scanner

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestScanFindsPEMBundleAndDERCertificate(t *testing.T) {
	t.Parallel()
	directory := t.TempDir()
	nested := filepath.Join(directory, "nested")
	if err := os.Mkdir(nested, 0o755); err != nil {
		t.Fatal(err)
	}

	serverDER, serverPEM, serverExpiry := makeCertificate(t, certificateSpec{
		serial:       1,
		common:       "server.example",
		issuerCommon: "Example Test CA",
		dnsNames:     []string{"server.example", "www.server.example"},
		ips:          []net.IP{net.ParseIP("192.0.2.10")},
		emails:       []string{"admin@example.test"},
		uris:         []*url.URL{mustURL(t, "spiffe://example.test/server")},
		usage:        x509.ExtKeyUsageServerAuth,
	})
	_, clientPEM, _ := makeCertificate(t, certificateSpec{
		serial: 2,
		common: "client.example",
		usage:  x509.ExtKeyUsageClientAuth,
	})

	bundlePath := filepath.Join(nested, "bundle.data")
	bundle := append([]byte("application config\n"), serverPEM...)
	bundle = append(bundle, clientPEM...)
	writeFile(t, bundlePath, bundle)
	derPath := filepath.Join(directory, "certificate.bin")
	writeFile(t, derPath, serverDER)
	writeFile(t, filepath.Join(directory, "unrelated.txt"), []byte("nothing to see here"))

	var callbackMu sync.Mutex
	var observedProgress Progress
	observedCertificates := 0
	report, err := Scan(context.Background(), directory, Options{
		MaxBytes: DefaultMaxBytes,
		Workers:  3,
		OnProgress: func(progress Progress) {
			callbackMu.Lock()
			defer callbackMu.Unlock()
			observedProgress.FilesDiscovered = max(observedProgress.FilesDiscovered, progress.FilesDiscovered)
			observedProgress.FilesScanned = max(observedProgress.FilesScanned, progress.FilesScanned)
			observedProgress.CertificatesFound = max(observedProgress.CertificatesFound, progress.CertificatesFound)
			observedProgress.DiscoveryComplete = observedProgress.DiscoveryComplete || progress.DiscoveryComplete
		},
		OnCertificate: func(Certificate) {
			callbackMu.Lock()
			defer callbackMu.Unlock()
			observedCertificates++
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(report.Errors) != 0 {
		t.Fatalf("unexpected scan errors: %v", report.Errors)
	}
	if len(report.Certificates) != 3 {
		t.Fatalf("got %d certificates, want 3", len(report.Certificates))
	}
	callbackMu.Lock()
	if observedProgress.FilesDiscovered != 3 || observedProgress.FilesScanned != 3 || observedProgress.CertificatesFound != 3 {
		t.Fatalf("progress = %+v, want 3 discovered, scanned, and found", observedProgress)
	}
	if !observedProgress.DiscoveryComplete || observedCertificates != 3 {
		t.Fatalf("callbacks observed progress %+v and %d certificates", observedProgress, observedCertificates)
	}
	callbackMu.Unlock()

	var server *Certificate
	for index := range report.Certificates {
		candidate := &report.Certificates[index]
		if candidate.Path == bundlePath && candidate.Subject == "CN=server.example" {
			server = candidate
			break
		}
	}
	if server == nil {
		t.Fatal("server certificate from PEM bundle was not found")
	}
	wantSANs := []string{
		"DNS:server.example",
		"DNS:www.server.example",
		"IP:192.0.2.10",
		"URI:spiffe://example.test/server",
		"email:admin@example.test",
	}
	if !reflect.DeepEqual(server.SANs, wantSANs) {
		t.Fatalf("SANs = %v, want %v", server.SANs, wantSANs)
	}
	if !server.NotAfter.Equal(serverExpiry) {
		t.Fatalf("expiration = %v, want %v", server.NotAfter, serverExpiry)
	}
	if server.Issuer != "CN=Example Test CA" {
		t.Fatalf("issuer = %q, want %q", server.Issuer, "CN=Example Test CA")
	}
	wantValidFrom := time.Date(2025, time.January, 2, 3, 4, 5, 0, time.UTC)
	if !server.NotBefore.Equal(wantValidFrom) {
		t.Fatalf("valid from = %v, want %v", server.NotBefore, wantValidFrom)
	}
	if !reflect.DeepEqual(server.ExtendedKeyUsage, []string{UsageServer}) {
		t.Fatalf("extended key usage = %v, want [%s]", server.ExtendedKeyUsage, UsageServer)
	}
	if server.ExtendedKeyUsageUnrestricted {
		t.Fatal("server certificate was marked as unrestricted")
	}
}

func TestScanHonorsByteLimit(t *testing.T) {
	t.Parallel()
	directory := t.TempDir()
	_, certificatePEM, _ := makeCertificate(t, certificateSpec{serial: 3, common: "limited.example"})

	latePath := filepath.Join(directory, "late.pem")
	writeFile(t, latePath, append([]byte(strings.Repeat("x", 128)), certificatePEM...))
	earlyPath := filepath.Join(directory, "early.pem")
	early := append([]byte("prefix\n"), certificatePEM...)
	early = append(early, []byte(strings.Repeat("x", 128))...)
	writeFile(t, earlyPath, early)

	limit := int64(len(early) - 128)
	report, err := Scan(context.Background(), directory, Options{MaxBytes: limit, Workers: 2})
	if err != nil {
		t.Fatal(err)
	}
	if len(report.Certificates) != 1 || report.Certificates[0].Path != earlyPath {
		t.Fatalf("bounded scan found %+v, want only %s", report.Certificates, earlyPath)
	}

	report, err = Scan(context.Background(), directory, Options{MaxBytes: 0, Workers: 2})
	if err != nil {
		t.Fatal(err)
	}
	if len(report.Certificates) != 2 {
		t.Fatalf("unlimited scan found %d certificates, want 2", len(report.Certificates))
	}
}

func TestScanSingleFileAndInvalidOptions(t *testing.T) {
	t.Parallel()
	_, certificatePEM, _ := makeCertificate(t, certificateSpec{serial: 4, common: "single.example"})
	path := filepath.Join(t.TempDir(), "single.pem")
	writeFile(t, path, certificatePEM)

	report, err := Scan(context.Background(), path, Options{MaxBytes: DefaultMaxBytes, Workers: 1})
	if err != nil {
		t.Fatal(err)
	}
	if len(report.Certificates) != 1 || report.Certificates[0].Path != path {
		t.Fatalf("single-file scan = %+v", report.Certificates)
	}
	if !report.Certificates[0].ExtendedKeyUsageUnrestricted {
		t.Fatal("certificate without an extended key usage extension was not marked as unrestricted")
	}
	if _, err := Scan(context.Background(), path, Options{MaxBytes: -1}); err == nil {
		t.Fatal("negative byte limit did not return an error")
	}
	if _, err := Scan(context.Background(), path, Options{Workers: -1}); err == nil {
		t.Fatal("negative worker count did not return an error")
	}
}

func TestScanFollowsRootDirectorySymlinkOnce(t *testing.T) {
	t.Parallel()
	target := t.TempDir()
	_, certificatePEM, _ := makeCertificate(t, certificateSpec{serial: 5, common: "linked.example"})
	writeFile(t, filepath.Join(target, "linked.pem"), certificatePEM)

	link := filepath.Join(t.TempDir(), "certificate-directory")
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("cannot create directory symlink: %v", err)
	}
	report, err := Scan(context.Background(), link, Options{MaxBytes: DefaultMaxBytes, Workers: 1})
	if err != nil {
		t.Fatal(err)
	}
	wantPath := filepath.Join(link, "linked.pem")
	if len(report.Certificates) != 1 || report.Certificates[0].Path != wantPath {
		t.Fatalf("symlink scan = %+v, want one certificate at %s", report.Certificates, wantPath)
	}
}

type certificateSpec struct {
	serial       int64
	common       string
	issuerCommon string
	dnsNames     []string
	ips          []net.IP
	emails       []string
	uris         []*url.URL
	usage        x509.ExtKeyUsage
}

func makeCertificate(t *testing.T, spec certificateSpec) ([]byte, []byte, time.Time) {
	t.Helper()
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	expires := time.Date(2030, time.January, 2, 3, 4, 5, 0, time.UTC)
	template := &x509.Certificate{
		SerialNumber:   big.NewInt(spec.serial),
		Subject:        pkix.Name{CommonName: spec.common},
		NotBefore:      time.Date(2025, time.January, 2, 3, 4, 5, 0, time.UTC),
		NotAfter:       expires,
		DNSNames:       spec.dnsNames,
		IPAddresses:    spec.ips,
		EmailAddresses: spec.emails,
		URIs:           spec.uris,
		KeyUsage:       x509.KeyUsageDigitalSignature,
	}
	if spec.usage != 0 {
		template.ExtKeyUsage = []x509.ExtKeyUsage{spec.usage}
	}
	parent := *template
	if spec.issuerCommon != "" {
		parent.Subject = pkix.Name{CommonName: spec.issuerCommon}
	}
	der, err := x509.CreateCertificate(rand.Reader, template, &parent, &privateKey.PublicKey, privateKey)
	if err != nil {
		t.Fatal(err)
	}
	return der, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), expires
}

func mustURL(t *testing.T, value string) *url.URL {
	t.Helper()
	parsed, err := url.Parse(value)
	if err != nil {
		t.Fatal(err)
	}
	return parsed
}

func writeFile(t *testing.T, path string, data []byte) {
	t.Helper()
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
}
