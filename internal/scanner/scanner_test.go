package scanner

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1" //nolint:gosec // The production compatibility fingerprint must be verified against SHA-1.
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
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
	if err := os.Mkdir(nested, 0o750); err != nil {
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
	sha1Digest := sha1.Sum(serverDER) //nolint:gosec // This verifies the required compatibility fingerprint.
	wantSHA1Fingerprint := hex.EncodeToString(sha1Digest[:])
	if server.SHA1Fingerprint != wantSHA1Fingerprint {
		t.Fatalf("SHA-1 fingerprint = %q, want %q", server.SHA1Fingerprint, wantSHA1Fingerprint)
	}
	sha256Digest := sha256.Sum256(serverDER)
	wantSHA256Fingerprint := hex.EncodeToString(sha256Digest[:])
	if server.SHA256Fingerprint != wantSHA256Fingerprint {
		t.Fatalf("SHA-256 fingerprint = %q, want %q", server.SHA256Fingerprint, wantSHA256Fingerprint)
	}
	parsedServer, err := x509.ParseCertificate(serverDER)
	if err != nil {
		t.Fatal(err)
	}
	spkiDigest := sha256.Sum256(parsedServer.RawSubjectPublicKeyInfo)
	wantSPKIFingerprint := hex.EncodeToString(spkiDigest[:])
	if server.SPKISHA256Fingerprint != wantSPKIFingerprint {
		t.Fatalf("SPKI SHA-256 fingerprint = %q, want %q", server.SPKISHA256Fingerprint, wantSPKIFingerprint)
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
	var progressMu sync.Mutex
	var boundedProgress Progress
	report, err := Scan(context.Background(), directory, Options{
		MaxBytes: limit,
		Workers:  2,
		OnProgress: func(progress Progress) {
			progressMu.Lock()
			defer progressMu.Unlock()
			boundedProgress.FilesCapped = max(boundedProgress.FilesCapped, progress.FilesCapped)
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(report.Certificates) != 1 || report.Certificates[0].Path != earlyPath {
		t.Fatalf("bounded scan found %+v, want only %s", report.Certificates, earlyPath)
	}
	progressMu.Lock()
	if boundedProgress.FilesCapped != 1 {
		t.Fatalf("bounded scan capped %d files, want 1", boundedProgress.FilesCapped)
	}
	progressMu.Unlock()

	report, err = Scan(context.Background(), directory, Options{MaxBytes: 0, Workers: 2})
	if err != nil {
		t.Fatal(err)
	}
	if len(report.Certificates) != 2 {
		t.Fatalf("unlimited scan found %d certificates, want 2", len(report.Certificates))
	}
}

func TestScanReadsCompletePEMBundleAfterPrefixMatch(t *testing.T) {
	t.Parallel()
	directory := t.TempDir()
	_, firstPEM, _ := makeCertificate(t, certificateSpec{serial: 6, common: "first.example"})
	_, secondPEM, _ := makeCertificate(t, certificateSpec{serial: 7, common: "second.example"})

	path := filepath.Join(directory, "large-bundle.pem")
	padding := []byte(strings.Repeat("#", 256))
	bundle := append(append(append([]byte{}, firstPEM...), padding...), secondPEM...)
	writeFile(t, path, bundle)

	report, err := Scan(context.Background(), path, Options{MaxBytes: int64(len(firstPEM)), Workers: 1})
	if err != nil {
		t.Fatal(err)
	}
	if len(report.Certificates) != 2 {
		t.Fatalf("bundle scan found %d certificates, want 2", len(report.Certificates))
	}
	if report.Certificates[0].Subject != "CN=first.example" || report.Certificates[1].Subject != "CN=second.example" {
		t.Fatalf("bundle subjects = %q, %q", report.Certificates[0].Subject, report.Certificates[1].Subject)
	}
}

func TestScanCanDiscardCertificatesAfterCallbacks(t *testing.T) {
	t.Parallel()
	directory := t.TempDir()
	_, certificatePEM, _ := makeCertificate(t, certificateSpec{serial: 8, common: "streamed.example"})
	writeFile(t, filepath.Join(directory, "streamed.pem"), certificatePEM)

	var observed []Certificate
	report, err := Scan(context.Background(), directory, Options{
		MaxBytes:            DefaultMaxBytes,
		Workers:             1,
		DiscardCertificates: true,
		OnCertificate: func(certificate Certificate) {
			observed = append(observed, certificate)
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(report.Certificates) != 0 {
		t.Fatalf("report retained %d certificates, want 0", len(report.Certificates))
	}
	if len(observed) != 1 || observed[0].Subject != "CN=streamed.example" {
		t.Fatalf("callback certificates = %+v, want streamed.example", observed)
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

func TestScanAppliesExclusionsBeforeDescending(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	_, certificatePEM, _ := makeCertificate(t, certificateSpec{serial: 30, common: "included.example"})
	includedPath := filepath.Join(root, "services", "included.pem")
	if err := os.MkdirAll(filepath.Dir(includedPath), 0o750); err != nil {
		t.Fatal(err)
	}
	writeFile(t, includedPath, certificatePEM)

	excludedDirectory := filepath.Join(root, "nested", "cache")
	if err := os.MkdirAll(excludedDirectory, 0o750); err != nil {
		t.Fatal(err)
	}
	writeFile(t, filepath.Join(excludedDirectory, "excluded.pem"), certificatePEM)
	if err := os.Symlink(filepath.Join(root, "missing-target"), filepath.Join(excludedDirectory, "broken")); err != nil {
		t.Skipf("cannot create symlink: %v", err)
	}
	writeFile(t, filepath.Join(root, "services", "ignored.skip"), certificatePEM)

	report, err := Scan(context.Background(), root, Options{
		MaxBytes:       DefaultMaxBytes,
		Workers:        2,
		Exclude:        []string{"cache", "services/*.skip"},
		FollowSymlinks: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(report.Errors) != 0 {
		t.Fatalf("excluded directory was traversed: %v", report.Errors)
	}
	if len(report.Certificates) != 1 || report.Certificates[0].Path != includedPath {
		t.Fatalf("excluded scan = %+v, want only %s", report.Certificates, includedPath)
	}
}

func TestScanFiltersExtensionsCaseInsensitively(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	_, certificatePEM, _ := makeCertificate(t, certificateSpec{serial: 31, common: "extension.example"})
	pemPath := filepath.Join(root, "server.PEM")
	crtPath := filepath.Join(root, "client.crt")
	writeFile(t, pemPath, certificatePEM)
	writeFile(t, crtPath, certificatePEM)
	writeFile(t, filepath.Join(root, "ignored.data"), certificatePEM)

	report, err := Scan(context.Background(), root, Options{
		MaxBytes:   DefaultMaxBytes,
		Workers:    2,
		Extensions: []string{"pem", ".CRT", ".pem"},
	})
	if err != nil {
		t.Fatal(err)
	}
	wantPaths := []string{crtPath, pemPath}
	if len(report.Certificates) != len(wantPaths) {
		t.Fatalf("extension-filtered scan found %+v, want paths %v", report.Certificates, wantPaths)
	}
	for index, wantPath := range wantPaths {
		if report.Certificates[index].Path != wantPath {
			t.Errorf("certificate %d path = %s, want %s", index, report.Certificates[index].Path, wantPath)
		}
	}
}

func TestScanStaysOnInjectedRootFilesystem(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	_, certificatePEM, _ := makeCertificate(t, certificateSpec{serial: 32, common: "filesystem.example"})
	localPath := filepath.Join(root, "local.pem")
	writeFile(t, localPath, certificatePEM)
	otherDirectory := filepath.Join(root, "other-filesystem")
	if err := os.Mkdir(otherDirectory, 0o750); err != nil {
		t.Fatal(err)
	}
	writeFile(t, filepath.Join(otherDirectory, "excluded.pem"), certificatePEM)

	report, err := Scan(context.Background(), root, Options{
		MaxBytes:      DefaultMaxBytes,
		Workers:       2,
		OneFileSystem: true,
		filesystemID: func(info os.FileInfo) (uint64, bool) {
			if info.Name() == "other-filesystem" {
				return 2, true
			}
			return 1, true
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(report.Certificates) != 1 || report.Certificates[0].Path != localPath {
		t.Fatalf("one-filesystem scan = %+v, want only %s", report.Certificates, localPath)
	}
}

func TestScanRejectsOneFilesystemWhenIdentityIsUnavailable(t *testing.T) {
	t.Parallel()
	_, err := Scan(context.Background(), t.TempDir(), Options{
		OneFileSystem: true,
		filesystemID: func(os.FileInfo) (uint64, bool) {
			return 0, false
		},
	})
	if err == nil || !strings.Contains(err.Error(), "one-file-system is not supported") {
		t.Fatalf("unsupported one-filesystem error = %v", err)
	}
}

func TestScanFollowsDirectorySymlinksWithoutCycles(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	external := t.TempDir()
	_, certificatePEM, _ := makeCertificate(t, certificateSpec{serial: 33, common: "linked-directory.example"})
	writeFile(t, filepath.Join(external, "linked.pem"), certificatePEM)
	if err := os.Symlink(external, filepath.Join(root, "external")); err != nil {
		t.Skipf("cannot create directory symlink: %v", err)
	}
	if err := os.Symlink(root, filepath.Join(external, "back-to-root")); err != nil {
		t.Skipf("cannot create cycle symlink: %v", err)
	}

	withoutFollowing, err := Scan(context.Background(), root, Options{MaxBytes: DefaultMaxBytes, Workers: 1})
	if err != nil {
		t.Fatal(err)
	}
	if len(withoutFollowing.Certificates) != 0 || len(withoutFollowing.Errors) != 0 {
		t.Fatalf("default scan followed a symlink: %+v", withoutFollowing)
	}

	report, err := Scan(context.Background(), root, Options{
		MaxBytes:       DefaultMaxBytes,
		Workers:        2,
		FollowSymlinks: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	wantPath := filepath.Join(root, "external", "linked.pem")
	if len(report.Errors) != 0 {
		t.Fatalf("symlink scan errors = %v", report.Errors)
	}
	if len(report.Certificates) != 1 || report.Certificates[0].Path != wantPath {
		t.Fatalf("symlink scan = %+v, want one certificate at %s", report.Certificates, wantPath)
	}
}

func TestScanReportsBrokenFollowedSymlink(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	brokenPath := filepath.Join(root, "broken.pem")
	if err := os.Symlink(filepath.Join(root, "missing.pem"), brokenPath); err != nil {
		t.Skipf("cannot create symlink: %v", err)
	}

	report, err := Scan(context.Background(), root, Options{FollowSymlinks: true, Workers: 1})
	if err != nil {
		t.Fatal(err)
	}
	if len(report.Errors) != 1 || report.Errors[0].Path != brokenPath {
		t.Fatalf("broken-symlink errors = %+v, want one error for %s", report.Errors, brokenPath)
	}
}

func TestScanRejectsInvalidTraversalOptions(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	if _, err := Scan(context.Background(), root, Options{Exclude: []string{"["}}); err == nil {
		t.Fatal("invalid exclude pattern did not return an error")
	}
	if _, err := Scan(context.Background(), root, Options{Extensions: []string{"path/cert"}}); err == nil {
		t.Fatal("invalid extension did not return an error")
	}
	if _, err := Scan(context.Background(), root, Options{Extensions: []string{"*.pem"}}); err == nil {
		t.Fatal("glob extension did not return an error")
	}
}

func TestScanReportsCertificateHealth(t *testing.T) {
	t.Parallel()
	_, certificatePEM, _ := makeCertificate(t, certificateSpec{
		serial:   0xabc123,
		common:   "root.example",
		isCA:     true,
		keyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	})
	path := filepath.Join(t.TempDir(), "root.pem")
	writeFile(t, path, certificatePEM)

	report, err := Scan(context.Background(), path, Options{MaxBytes: DefaultMaxBytes, Workers: 1})
	if err != nil {
		t.Fatal(err)
	}
	if len(report.Certificates) != 1 {
		t.Fatalf("scan found %d certificates, want 1", len(report.Certificates))
	}
	certificate := report.Certificates[0]
	if certificate.SerialNumber != "abc123" {
		t.Errorf("serial number = %q, want abc123", certificate.SerialNumber)
	}
	if !certificate.IsCA {
		t.Error("CA certificate was reported as a leaf")
	}
	if !certificate.SelfSigned {
		t.Error("self-signed certificate was not detected")
	}
	if !reflect.DeepEqual(certificate.KeyUsage, []string{"certificate-signing", "crl-signing"}) {
		t.Errorf("key usage = %v, want certificate-signing and crl-signing", certificate.KeyUsage)
	}
	if certificate.PublicKeyAlgorithm != "ECDSA" || certificate.PublicKeyCurve != "P-256" || certificate.PublicKeyBits != 0 {
		t.Errorf(
			"public key = %s, bits %d, curve %q; want ECDSA, bits 0, curve P-256",
			certificate.PublicKeyAlgorithm,
			certificate.PublicKeyBits,
			certificate.PublicKeyCurve,
		)
	}
	if certificate.SignatureAlgorithm != "ECDSA-SHA256" {
		t.Errorf("signature algorithm = %q, want ECDSA-SHA256", certificate.SignatureAlgorithm)
	}
}

func TestSelfSignedRequiresMatchingNameAndValidSelfSignature(t *testing.T) {
	t.Parallel()
	selfDER, _, _ := makeCertificate(t, certificateSpec{serial: 20, common: "same-name.example"})
	selfCertificate, err := x509.ParseCertificate(selfDER)
	if err != nil {
		t.Fatal(err)
	}
	if !isSelfSigned(selfCertificate) {
		t.Fatal("valid self-signed certificate was not detected")
	}

	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	issuerKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	name := pkix.Name{CommonName: "same-name.example"}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(21),
		Subject:      name,
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	parent := &x509.Certificate{Subject: name}
	issuedDER, err := x509.CreateCertificate(rand.Reader, template, parent, &leafKey.PublicKey, issuerKey)
	if err != nil {
		t.Fatal(err)
	}
	issuedCertificate, err := x509.ParseCertificate(issuedDER)
	if err != nil {
		t.Fatal(err)
	}
	if isSelfSigned(issuedCertificate) {
		t.Fatal("certificate with equal subject and issuer names but a different signer was reported as self-signed")
	}
}

func TestDescribePublicKeyAlgorithms(t *testing.T) {
	t.Parallel()
	rsaModulus := new(big.Int).Lsh(big.NewInt(1), 2047)
	tests := []struct {
		name          string
		certificate   *x509.Certificate
		wantAlgorithm string
		wantBits      int
		wantCurve     string
	}{
		{
			name: "RSA",
			certificate: &x509.Certificate{
				PublicKeyAlgorithm: x509.RSA,
				PublicKey:          &rsa.PublicKey{N: rsaModulus, E: 65537},
			},
			wantAlgorithm: "RSA",
			wantBits:      2048,
		},
		{
			name: "ECDSA",
			certificate: &x509.Certificate{
				PublicKeyAlgorithm: x509.ECDSA,
				PublicKey:          &ecdsa.PublicKey{Curve: elliptic.P384()},
			},
			wantAlgorithm: "ECDSA",
			wantCurve:     "P-384",
		},
		{
			name: "Ed25519",
			certificate: &x509.Certificate{
				PublicKeyAlgorithm: x509.Ed25519,
				PublicKey:          make(ed25519.PublicKey, ed25519.PublicKeySize),
			},
			wantAlgorithm: "Ed25519",
		},
		{
			name: "unknown",
			certificate: &x509.Certificate{
				PublicKeyAlgorithm: x509.UnknownPublicKeyAlgorithm,
				PublicKey:          struct{}{},
			},
			wantAlgorithm: "unknown",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			algorithm, bits, curve := describePublicKey(test.certificate)
			if algorithm != test.wantAlgorithm || bits != test.wantBits || curve != test.wantCurve {
				t.Fatalf(
					"describePublicKey() = %q, %d, %q; want %q, %d, %q",
					algorithm,
					bits,
					curve,
					test.wantAlgorithm,
					test.wantBits,
					test.wantCurve,
				)
			}
		})
	}
}

func TestCertificateValidityStatus(t *testing.T) {
	t.Parallel()
	start := time.Date(2026, time.January, 1, 0, 0, 0, 0, time.UTC)
	end := start.Add(time.Hour)
	certificate := Certificate{NotBefore: start, NotAfter: end}
	tests := []struct {
		name string
		at   time.Time
		want string
	}{
		{name: "not yet valid", at: start.Add(-time.Nanosecond), want: ValidityNotYetValid},
		{name: "valid at start", at: start, want: ValidityValid},
		{name: "valid at end", at: end, want: ValidityValid},
		{name: "expired", at: end.Add(time.Nanosecond), want: ValidityExpired},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			if got := certificate.ValidityStatus(test.at); got != test.want {
				t.Fatalf("ValidityStatus(%s) = %q, want %q", test.at, got, test.want)
			}
		})
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
	isCA         bool
	keyUsage     x509.KeyUsage
}

func makeCertificate(t *testing.T, spec certificateSpec) ([]byte, []byte, time.Time) {
	t.Helper()
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	expires := time.Date(2030, time.January, 2, 3, 4, 5, 0, time.UTC)
	keyUsage := spec.keyUsage
	if keyUsage == 0 {
		keyUsage = x509.KeyUsageDigitalSignature
	}
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(spec.serial),
		Subject:               pkix.Name{CommonName: spec.common},
		NotBefore:             time.Date(2025, time.January, 2, 3, 4, 5, 0, time.UTC),
		NotAfter:              expires,
		DNSNames:              spec.dnsNames,
		IPAddresses:           spec.ips,
		EmailAddresses:        spec.emails,
		URIs:                  spec.uris,
		KeyUsage:              keyUsage,
		IsCA:                  spec.isCA,
		BasicConstraintsValid: spec.isCA,
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
