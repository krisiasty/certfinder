package scanner

import (
	"bytes"
	"context"
	"encoding/asn1"
	"encoding/binary"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"unicode/utf16"
)

func TestParsePKCS12PlaintextCertificatesAndMetadata(t *testing.T) {
	t.Parallel()
	leafDER, _, _ := makeCertificate(t, certificateSpec{serial: 50, common: "leaf.example.test"})
	issuerDER, _, _ := makeCertificate(t, certificateSpec{serial: 51, common: "issuer.example.test"})
	safeContents := testPKCS12SafeContents(
		t,
		testPKCS12KeyBag(t, "service"),
		testPKCS12CertBag(t, leafDER, "service"),
		testPKCS12CertBag(t, issuerDER, "issuer-é😀"),
	)
	store := testPKCS12PFX(t, []byte(testPKCS12DataContentInfo(t, safeContents)), true)

	certificates, encrypted, err := parsePKCS12(store)
	if err != nil {
		t.Fatal(err)
	}
	if len(encrypted) != 0 || len(certificates) != 2 {
		t.Fatalf("certificates=%d encrypted=%d, want 2 and 0", len(certificates), len(encrypted))
	}
	for index, wantName := range []string{"service", "issuer-é😀"} {
		metadata := certificates[index].keystore
		if metadata.Format != KeystoreFormatPKCS12 || metadata.EntryType != KeystoreEntryPKCS12CertBag ||
			metadata.FriendlyName != wantName || metadata.ChainIndex != index || metadata.Truststore {
			t.Errorf("certificate %d metadata = %+v", index, metadata)
		}
	}
}

func TestParsePKCS12CertificateOnlyStoreIsTruststore(t *testing.T) {
	t.Parallel()
	certificateDER, _, _ := makeCertificate(t, certificateSpec{serial: 52, common: "trusted.example.test"})
	store := testPKCS12PFX(
		t,
		[]byte(testPKCS12DataContentInfo(t, testPKCS12SafeContents(t, testPKCS12CertBag(t, certificateDER, "ca")))),
		false,
	)
	certificates, encrypted, err := parsePKCS12(store)
	if err != nil {
		t.Fatal(err)
	}
	if len(encrypted) != 0 || len(certificates) != 1 || !certificates[0].keystore.Truststore {
		t.Fatalf("certificates=%+v encrypted=%+v, want one truststore certificate", certificates, encrypted)
	}
}

func TestParsePKCS12DoesNotRequireOrVerifyIntegrityMAC(t *testing.T) {
	t.Parallel()
	certificateDER, _, _ := makeCertificate(t, certificateSpec{serial: 56, common: "mac.example.test"})
	store := testPKCS12PFX(
		t,
		testPKCS12DataContentInfo(t, testPKCS12SafeContents(t, testPKCS12CertBag(t, certificateDER, "cert"))),
		true,
	)
	store[len(store)-1] ^= 0xff
	certificates, encrypted, err := parsePKCS12(store)
	if err != nil {
		t.Fatal(err)
	}
	if len(certificates) != 1 || len(encrypted) != 0 {
		t.Fatalf("certificates=%+v encrypted=%+v", certificates, encrypted)
	}
}

func TestParsePKCS12ReportsEncryptedDataWithoutError(t *testing.T) {
	t.Parallel()
	algorithm := asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 5, 13}
	authenticatedSafe := append(
		[]byte{},
		testPKCS12EncryptedContentInfo(t, algorithm)...,
	)
	authenticatedSafe = append(
		authenticatedSafe,
		testPKCS12DataContentInfo(t, testPKCS12SafeContents(t, testPKCS12ShroudedKeyBag(t, "service")))...,
	)
	store := testPKCS12PFX(t, authenticatedSafe, true)

	certificates, encrypted, err := parsePKCS12(store)
	if err != nil {
		t.Fatal(err)
	}
	if len(certificates) != 0 || len(encrypted) != 1 {
		t.Fatalf("certificates=%d encrypted=%d, want 0 and 1", len(certificates), len(encrypted))
	}
	finding := encrypted[0]
	if finding.ContentIndex != 0 || finding.Algorithm != "PBES2" || finding.AlgorithmOID != algorithm.String() ||
		finding.BagCount != nil {
		t.Fatalf("encrypted finding = %+v", finding)
	}
}

func TestScanPKCS12MagicIndependentFullReadAndDERNonRegression(t *testing.T) {
	t.Parallel()
	directory := t.TempDir()
	certificateDER, _, _ := makeCertificate(t, certificateSpec{serial: 53, common: "service.example.test"})
	store := testPKCS12PFX(
		t,
		[]byte(testPKCS12DataContentInfo(t, testPKCS12SafeContents(
			t,
			testPKCS12KeyBagWithValue(t, "service", bytes.Repeat([]byte{0xa5}, 512)),
			testPKCS12CertBag(t, certificateDER, "service"),
		))),
		false,
	)
	storePath := filepath.Join(directory, "misleading.jks")
	if err := os.WriteFile(storePath, store, 0o600); err != nil {
		t.Fatal(err)
	}
	result := scanFileContents(storePath, 32)
	if result.err != nil {
		t.Fatal(result.err)
	}
	if result.capped || len(result.certificates) != 1 || len(result.pkcs12Encrypted) != 0 {
		t.Fatalf("scan result = %+v, want one fully read certificate", result)
	}
	if result.certificates[0].Keystore == nil || result.certificates[0].Keystore.Format != KeystoreFormatPKCS12 {
		t.Fatalf("certificate metadata = %+v, want PKCS#12", result.certificates[0].Keystore)
	}
	if detectPKCS12(certificateDER) {
		t.Fatal("bare DER certificate was misclassified as PKCS#12")
	}
	derPath := filepath.Join(directory, "certificate.p12")
	if err := os.WriteFile(derPath, certificateDER, 0o600); err != nil {
		t.Fatal(err)
	}
	certificates, capped, err := scanFile(derPath, int64(len(certificateDER)+1))
	if err != nil || capped || len(certificates) != 1 || certificates[0].Keystore != nil {
		t.Fatalf("bare DER scan certificates=%+v capped=%t err=%v", certificates, capped, err)
	}
}

func TestScanReportsEncryptedPKCS12AsFindingNotError(t *testing.T) {
	t.Parallel()
	directory := t.TempDir()
	path := filepath.Join(directory, "encrypted.p12")
	store := testPKCS12PFX(
		t,
		testPKCS12EncryptedContentInfo(t, oidPBEWithSHAAnd40BitRC2),
		true,
	)
	if err := os.WriteFile(path, store, 0o600); err != nil {
		t.Fatal(err)
	}
	var callback []PKCS12EncryptedContent
	report, err := Scan(context.Background(), directory, Options{
		Workers: 1,
		OnPKCS12Encrypted: func(finding PKCS12EncryptedContent) {
			callback = append(callback, finding)
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(report.Errors) != 0 || len(report.Certificates) != 0 || len(report.PKCS12Encrypted) != 1 ||
		len(callback) != 1 {
		t.Fatalf("report=%+v callback=%+v", report, callback)
	}
	if report.PKCS12Encrypted[0].Path != path || report.PKCS12Encrypted[0].Algorithm != "pbeWithSHAAnd40BitRC2-CBC" {
		t.Fatalf("finding = %+v", report.PKCS12Encrypted[0])
	}
}

func TestScanCanDiscardEncryptedPKCS12AfterCallback(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "encrypted.p12")
	store := testPKCS12PFX(t, testPKCS12EncryptedContentInfo(t, oidPBES2), false)
	if err := os.WriteFile(path, store, 0o600); err != nil {
		t.Fatal(err)
	}
	callbackCount := 0
	report, err := Scan(context.Background(), path, Options{
		Workers:                1,
		DiscardPKCS12Encrypted: true,
		OnPKCS12Encrypted: func(PKCS12EncryptedContent) {
			callbackCount++
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(report.PKCS12Encrypted) != 0 || callbackCount != 1 {
		t.Fatalf("retained=%+v callback count=%d", report.PKCS12Encrypted, callbackCount)
	}
}

func TestParsePKCS12ReturnsPartialCertificatesForMalformedBags(t *testing.T) {
	t.Parallel()
	certificateDER, _, _ := makeCertificate(t, certificateSpec{serial: 54, common: "valid.example.test"})
	invalidCertificate := testPKCS12CertBag(t, []byte("not DER"), "broken")
	validCertificate := testPKCS12CertBag(t, certificateDER, "valid")
	store := testPKCS12PFX(
		t,
		testPKCS12DataContentInfo(t, testPKCS12SafeContents(t, invalidCertificate, validCertificate)),
		false,
	)
	certificates, _, err := parsePKCS12(store)
	if err == nil || !strings.Contains(err.Error(), "X.509 DER") {
		t.Fatalf("parse error = %v, want controlled X.509 error", err)
	}
	if len(certificates) != 1 || certificates[0].certificate.Subject.CommonName != "valid.example.test" ||
		certificates[0].keystore.ChainIndex != 1 {
		t.Fatalf("partial certificates = %+v", certificates)
	}
}

func TestParsePKCS12RejectsTruncationDepthAndBagCount(t *testing.T) {
	t.Parallel()
	certificateDER, _, _ := makeCertificate(t, certificateSpec{serial: 55, common: "truncated.example.test"})
	store := testPKCS12PFX(
		t,
		testPKCS12DataContentInfo(t, testPKCS12SafeContents(t, testPKCS12CertBag(t, certificateDER, "cert"))),
		false,
	)
	if _, _, err := parsePKCS12(store[:len(store)-3]); err == nil {
		t.Fatal("truncated PFX was accepted")
	}

	nested := testPKCS12SafeContents(t)
	for range maxPKCS12SafeContentsDepth + 2 {
		nested = testPKCS12SafeContents(t, testPKCS12SafeContentsBag(t, nested))
	}
	deepStore := testPKCS12PFX(t, testPKCS12DataContentInfo(t, nested), false)
	if _, _, err := parsePKCS12(deepStore); err == nil || !strings.Contains(err.Error(), "nesting depth") {
		t.Fatalf("deep nesting error = %v", err)
	}

	keyBag := testPKCS12KeyBag(t, "key")
	bags := make([][]byte, maxPKCS12Bags+1)
	for index := range bags {
		bags[index] = keyBag
	}
	largeStore := testPKCS12PFX(t, testPKCS12DataContentInfo(t, testPKCS12SafeContents(t, bags...)), false)
	if _, _, err := parsePKCS12(largeStore); err == nil || !strings.Contains(err.Error(), "bag count") {
		t.Fatalf("bag limit error = %v", err)
	}
}

func testPKCS12PFX(t *testing.T, authenticatedSafeContents []byte, withMAC bool) []byte {
	t.Helper()
	authenticatedSafe := testDERWrap(0x30, authenticatedSafeContents)
	authSafeContentInfo := testPKCS12ContentInfo(t, oidPKCS7Data, testDEROctets(t, authenticatedSafe))
	fields := append(testDERInteger(t, pkcs12Version), authSafeContentInfo...)
	if withMAC {
		fields = append(fields, testPKCS12MACData(t)...)
	}
	return testDERWrap(0x30, fields)
}

func testPKCS12DataContentInfo(t *testing.T, safeContents []byte) []byte {
	t.Helper()
	return testPKCS12ContentInfo(t, oidPKCS7Data, testDEROctets(t, safeContents))
}

func testPKCS12EncryptedContentInfo(t *testing.T, algorithm asn1.ObjectIdentifier) []byte {
	t.Helper()
	algorithmIdentifier := testDERWrap(
		0x30,
		append(testDER(t, algorithm), testDER(t, asn1.RawValue{Tag: asn1.TagNull})...),
	)
	encryptedContentInfo := testDERWrap(
		0x30,
		bytes.Join([][]byte{
			testDER(t, oidPKCS7Data),
			algorithmIdentifier,
			testDERWrap(0x80, []byte{0xde, 0xad, 0xbe, 0xef}),
		}, nil),
	)
	encryptedData := testDERWrap(0x30, append(testDERInteger(t, 0), encryptedContentInfo...))
	return testPKCS12ContentInfo(t, oidPKCS7EncryptedData, encryptedData)
}

func testPKCS12ContentInfo(t *testing.T, contentType asn1.ObjectIdentifier, content []byte) []byte {
	t.Helper()
	fields := append(testDER(t, contentType), testDERWrap(0xa0, content)...)
	return testDERWrap(0x30, fields)
}

func testPKCS12SafeContents(t *testing.T, bags ...[]byte) []byte {
	t.Helper()
	return testDERWrap(0x30, bytes.Join(bags, nil))
}

func testPKCS12CertBag(t *testing.T, certificateDER []byte, friendlyName string) []byte {
	t.Helper()
	certificateBag := testDERWrap(
		0x30,
		append(testDER(t, oidPKCS12X509Certificate), testDERWrap(0xa0, testDEROctets(t, certificateDER))...),
	)
	return testPKCS12SafeBag(t, oidPKCS12CertBag, certificateBag, friendlyName)
}

func testPKCS12KeyBag(t *testing.T, friendlyName string) []byte {
	t.Helper()
	return testPKCS12KeyBagWithValue(t, friendlyName, []byte("key material is never parsed"))
}

func testPKCS12KeyBagWithValue(t *testing.T, friendlyName string, value []byte) []byte {
	t.Helper()
	return testPKCS12SafeBag(t, oidPKCS12KeyBag, testDEROctets(t, value), friendlyName)
}

func testPKCS12ShroudedKeyBag(t *testing.T, friendlyName string) []byte {
	t.Helper()
	return testPKCS12SafeBag(t, oidPKCS12ShroudedKeyBag, testDEROctets(t, []byte("encrypted key")), friendlyName)
}

func testPKCS12SafeContentsBag(t *testing.T, safeContents []byte) []byte {
	t.Helper()
	return testPKCS12SafeBag(t, oidPKCS12SafeContentsBag, safeContents, "")
}

func testPKCS12SafeBag(
	t *testing.T,
	bagID asn1.ObjectIdentifier,
	bagValue []byte,
	friendlyName string,
) []byte {
	t.Helper()
	fields := append(testDER(t, bagID), testDERWrap(0xa0, bagValue)...)
	if friendlyName != "" {
		bmpString := testDERWrap(0x1e, testBMPString(t, friendlyName))
		values := testDERWrap(0x31, bmpString)
		attribute := testDERWrap(0x30, append(testDER(t, oidPKCS12FriendlyName), values...))
		fields = append(fields, testDERWrap(0x31, attribute)...)
	}
	return testDERWrap(0x30, fields)
}

func testPKCS12MACData(t *testing.T) []byte {
	t.Helper()
	sha256OID := asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 1}
	algorithm := testDERWrap(0x30, append(testDER(t, sha256OID), testDER(t, asn1.RawValue{Tag: asn1.TagNull})...))
	digestInfo := testDERWrap(0x30, append(algorithm, testDEROctets(t, bytes.Repeat([]byte{0x5a}, 32))...))
	fields := append([]byte{}, digestInfo...)
	fields = append(fields, testDEROctets(t, []byte("salt"))...)
	fields = append(fields, testDERInteger(t, 1)...)
	return testDERWrap(0x30, fields)
}

func testBMPString(t *testing.T, value string) []byte {
	t.Helper()
	units := utf16.Encode([]rune(value))
	result := make([]byte, len(units)*2)
	for index, unit := range units {
		binary.BigEndian.PutUint16(result[index*2:], unit)
	}
	return result
}

func testDERInteger(t *testing.T, value int) []byte {
	t.Helper()
	return testDER(t, value)
}

func testDEROctets(t *testing.T, value []byte) []byte {
	t.Helper()
	return testDER(t, value)
}

func testDER(t *testing.T, value any) []byte {
	t.Helper()
	encoded, err := asn1.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}

func testDERWrap(tag byte, content []byte) []byte {
	result := []byte{tag}
	length := len(content)
	if length < 128 {
		result = append(result, byte(length))
	} else {
		var encoded [8]byte
		index := len(encoded)
		for length > 0 {
			index--
			encoded[index] = byte(length)
			length >>= 8
		}
		result = append(result, 0x80|byte(len(encoded)-index))
		result = append(result, encoded[index:]...)
	}
	return append(result, content...)
}
