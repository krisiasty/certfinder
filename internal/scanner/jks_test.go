package scanner

import (
	"bytes"
	"context"
	"encoding/binary"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"unicode/utf16"
)

type testKeystoreEntry struct {
	tag          uint32
	alias        string
	privateKey   []byte
	certificates [][]byte
}

func TestParseJavaKeystoreVersionsAndEntryMetadata(t *testing.T) {
	t.Parallel()
	leafDER, _, _ := makeCertificate(t, certificateSpec{serial: 40, common: "leaf.example.test"})
	issuerDER, _, _ := makeCertificate(t, certificateSpec{serial: 41, common: "issuer.example.test"})
	trustedDER, _, _ := makeCertificate(t, certificateSpec{serial: 42, common: "trusted.example.test"})

	for _, test := range []struct {
		name    string
		magic   uint32
		version uint32
		format  string
	}{
		{name: "JKS version 1", magic: jksMagic, version: 1, format: KeystoreFormatJKS},
		{name: "JCEKS version 2", magic: jceksMagic, version: 2, format: KeystoreFormatJCEKS},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			store := makeTestJavaKeystore(t, test.magic, test.version, []testKeystoreEntry{
				{
					tag:          keystoreTagPrivateKey,
					alias:        "clé\x00😀",
					privateKey:   []byte("not parsed or decrypted"),
					certificates: [][]byte{leafDER, issuerDER},
				},
				{tag: keystoreTagTrusted, alias: "ca-é", certificates: [][]byte{trustedDER}},
			})
			certificates, err := parseJavaKeystore(store)
			if err != nil {
				t.Fatal(err)
			}
			if len(certificates) != 3 {
				t.Fatalf("certificate count = %d, want 3", len(certificates))
			}
			want := []KeystoreInfo{
				{
					Format: test.format, Alias: "clé\x00😀", EntryType: KeystoreEntryPrivateKey, ChainIndex: 0,
				},
				{
					Format: test.format, Alias: "clé\x00😀", EntryType: KeystoreEntryPrivateKey, ChainIndex: 1,
				},
				{
					Format: test.format, Alias: "ca-é", EntryType: KeystoreEntryTrustedCert, ChainIndex: 0,
				},
			}
			for index, certificate := range certificates {
				if certificate.certificate == nil {
					t.Fatalf("certificate %d is nil", index)
				}
				if certificate.keystore != want[index] {
					t.Errorf("certificate %d metadata = %+v, want %+v", index, certificate.keystore, want[index])
				}
			}
		})
	}
}

func TestParseJavaKeystoreTruststoreIgnoresIntegrityMAC(t *testing.T) {
	t.Parallel()
	certificateDER, _, _ := makeCertificate(t, certificateSpec{serial: 43, common: "trusted.example.test"})
	store := makeTestJavaKeystore(t, jksMagic, 2, []testKeystoreEntry{
		{tag: keystoreTagTrusted, alias: "trusted", certificates: [][]byte{certificateDER}},
	})
	for index := len(store) - javaKeystoreMACSize; index < len(store); index++ {
		store[index] ^= 0xff
	}
	certificates, err := parseJavaKeystore(store)
	if err != nil {
		t.Fatal(err)
	}
	if len(certificates) != 1 || !certificates[0].keystore.Truststore {
		t.Fatalf("trusted-only certificates = %+v, want one truststore certificate", certificates)
	}
}

func TestParseJavaKeystoreReturnsPartialCertificatesOnTruncation(t *testing.T) {
	t.Parallel()
	firstDER, _, _ := makeCertificate(t, certificateSpec{serial: 44, common: "first.example.test"})
	secondDER, _, _ := makeCertificate(t, certificateSpec{serial: 45, common: "second.example.test"})
	store := makeTestJavaKeystore(t, jksMagic, 2, []testKeystoreEntry{
		{
			tag:          keystoreTagPrivateKey,
			alias:        "server",
			privateKey:   []byte{0xde, 0xad, 0xbe, 0xef},
			certificates: [][]byte{firstDER, secondDER},
		},
	})
	body := append([]byte{}, store[:len(store)-javaKeystoreMACSize]...)
	body = body[:len(body)-10]
	truncated := make([]byte, 0, len(body)+javaKeystoreMACSize)
	truncated = append(truncated, body...)
	truncated = append(truncated, bytes.Repeat([]byte{0}, javaKeystoreMACSize)...)
	certificates, err := parseJavaKeystore(truncated)
	if err == nil || !strings.Contains(err.Error(), "unexpected EOF") {
		t.Fatalf("truncated error = %v, want unexpected EOF", err)
	}
	if len(certificates) != 1 || certificates[0].certificate.Subject.CommonName != "first.example.test" {
		t.Fatalf("partial certificates = %+v, want the first chain certificate", certificates)
	}
}

func TestParseJavaKeystoreRejectsControlledMalformedInputs(t *testing.T) {
	t.Parallel()
	zeroEntries := makeTestJavaKeystore(t, jksMagic, 2, nil)
	secretKeyEntry := makeTestJavaKeystoreHeader(t, jceksMagic, 2, 1)
	writeTestUint32(t, &secretKeyEntry, keystoreTagSecretKey)
	writeTestJavaUTF(t, &secretKeyEntry, "secret")
	if err := binary.Write(&secretKeyEntry, binary.BigEndian, uint64(0)); err != nil {
		t.Fatal(err)
	}
	_, _ = secretKeyEntry.Write(bytes.Repeat([]byte{0x5a}, javaKeystoreMACSize))
	for _, test := range []struct {
		name string
		data []byte
		want string
	}{
		{name: "zero entries", data: zeroEntries, want: "zero entries"},
		{name: "truncated header", data: []byte{0xfe, 0xed, 0xfe, 0xed}, want: "truncated JKS"},
		{name: "unknown magic", data: bytes.Repeat([]byte{0}, minimumJavaKeystoreFileBytes), want: "unrecognized"},
		{name: "JCEKS secret key", data: secretKeyEntry.Bytes(), want: "unsupported JCEKS secret-key entry"},
	} {
		if _, err := parseJavaKeystore(test.data); err == nil || !strings.Contains(err.Error(), test.want) {
			t.Errorf("%s error = %v, want text %q", test.name, err, test.want)
		}
	}
}

func TestScanFileDetectsJavaKeystoreMagicAndReadsCompleteFile(t *testing.T) {
	t.Parallel()
	certificateDER, _, _ := makeCertificate(t, certificateSpec{serial: 46, common: "service.example.test"})
	store := makeTestJavaKeystore(t, jceksMagic, 2, []testKeystoreEntry{
		{
			tag:          keystoreTagPrivateKey,
			alias:        "service",
			privateKey:   bytes.Repeat([]byte{0xa5}, 256),
			certificates: [][]byte{certificateDER},
		},
	})
	path := filepath.Join(t.TempDir(), "misleading.p12")
	if err := os.WriteFile(path, store, 0o600); err != nil {
		t.Fatal(err)
	}
	certificates, capped, err := scanFile(path, 4)
	if err != nil {
		t.Fatal(err)
	}
	if capped {
		t.Fatal("recognized JCEKS was reported as capped after its full reread")
	}
	if len(certificates) != 1 || certificates[0].Keystore == nil {
		t.Fatalf("certificates = %+v, want one JCEKS certificate", certificates)
	}
	if certificates[0].Path != path || certificates[0].Keystore.Format != KeystoreFormatJCEKS {
		t.Errorf("certificate location = %+v, want path %q and JCEKS", certificates[0], path)
	}
}

func TestScanReportsMalformedJavaKeystoreAsFileError(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "empty.keystore")
	if err := os.WriteFile(path, makeTestJavaKeystore(t, jksMagic, 2, nil), 0o600); err != nil {
		t.Fatal(err)
	}
	report, err := Scan(context.Background(), path, Options{Workers: 1})
	if err != nil {
		t.Fatalf("scan returned a root error: %v", err)
	}
	if len(report.Certificates) != 0 || len(report.Errors) != 1 {
		t.Fatalf("report = %+v, want one controlled file error and no certificates", report)
	}
	if !strings.Contains(report.Errors[0].Error(), "zero entries") {
		t.Errorf("file error = %v, want zero-entry detail", report.Errors[0])
	}
}

func TestDecodeJavaModifiedUTF8(t *testing.T) {
	t.Parallel()
	want := "ascii\x00café😀"
	encoded := encodeTestJavaModifiedUTF8(t, want)
	decoded, err := decodeJavaModifiedUTF8(encoded)
	if err != nil {
		t.Fatal(err)
	}
	if decoded != want {
		t.Fatalf("decoded alias = %q, want %q", decoded, want)
	}
	for _, invalid := range [][]byte{{0}, {0xc2}, {0xe0, 0x80, 0x80}, {0xed, 0xa0, 0x80}} {
		if _, err := decodeJavaModifiedUTF8(invalid); err == nil {
			t.Errorf("invalid modified UTF-8 %x was accepted", invalid)
		}
	}
}

func makeTestJavaKeystore(t *testing.T, magic, version uint32, entries []testKeystoreEntry) []byte {
	t.Helper()
	output := makeTestJavaKeystoreHeader(t, magic, version, uint32(len(entries))) //nolint:gosec // Test input is bounded.
	for _, entry := range entries {
		writeTestUint32(t, &output, entry.tag)
		writeTestJavaUTF(t, &output, entry.alias)
		if err := binary.Write(&output, binary.BigEndian, uint64(0)); err != nil {
			t.Fatal(err)
		}
		switch entry.tag {
		case keystoreTagPrivateKey:
			writeTestUint32(t, &output, uint32(len(entry.privateKey))) //nolint:gosec // Fixture data is bounded by the test.
			_, _ = output.Write(entry.privateKey)
			writeTestUint32(t, &output, uint32(len(entry.certificates))) //nolint:gosec // Generated fixture counts are bounded.
			for _, certificate := range entry.certificates {
				writeTestKeystoreCertificate(t, &output, version, certificate)
			}
		case keystoreTagTrusted:
			if len(entry.certificates) != 1 {
				t.Fatalf("trusted test entry has %d certificates, want 1", len(entry.certificates))
			}
			writeTestKeystoreCertificate(t, &output, version, entry.certificates[0])
		default:
			t.Fatalf("unsupported test entry tag %d", entry.tag)
		}
	}
	_, _ = output.Write(bytes.Repeat([]byte{0x5a}, javaKeystoreMACSize))
	return output.Bytes()
}

func makeTestJavaKeystoreHeader(t *testing.T, magic, version, entryCount uint32) bytes.Buffer {
	t.Helper()
	var output bytes.Buffer
	writeTestUint32(t, &output, magic)
	writeTestUint32(t, &output, version)
	writeTestUint32(t, &output, entryCount)
	return output
}

func writeTestKeystoreCertificate(t *testing.T, output *bytes.Buffer, version uint32, der []byte) {
	t.Helper()
	if version == 2 {
		writeTestJavaUTF(t, output, javaKeystoreCertificateType)
	}
	writeTestUint32(t, output, uint32(len(der))) //nolint:gosec // Generated test certificates are bounded.
	_, _ = output.Write(der)
}

func writeTestJavaUTF(t *testing.T, output *bytes.Buffer, value string) {
	t.Helper()
	encoded := encodeTestJavaModifiedUTF8(t, value)
	if len(encoded) > 1<<16-1 {
		t.Fatalf("test modified UTF-8 string is too long: %d", len(encoded))
	}
	if err := binary.Write(output, binary.BigEndian, uint16(len(encoded))); err != nil { //nolint:gosec // Length is checked above.
		t.Fatal(err)
	}
	_, _ = output.Write(encoded)
}

func encodeTestJavaModifiedUTF8(t *testing.T, value string) []byte {
	t.Helper()
	var encoded []byte
	for _, unit := range utf16.Encode([]rune(value)) {
		switch {
		case unit >= 0x01 && unit <= 0x7f:
			encoded = append(encoded, byte(unit))
		case unit <= 0x7ff:
			encoded = append(encoded, 0xc0|byte(unit>>6), 0x80|byte(unit&0x3f))
		default:
			encoded = append(
				encoded,
				0xe0|byte(unit>>12),
				0x80|byte(unit>>6&0x3f),
				0x80|byte(unit&0x3f),
			)
		}
	}
	return encoded
}

func writeTestUint32(t *testing.T, output *bytes.Buffer, value uint32) {
	t.Helper()
	if err := binary.Write(output, binary.BigEndian, value); err != nil {
		t.Fatal(err)
	}
}
