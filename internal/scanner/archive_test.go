package scanner

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"context"
	"encoding/binary"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"sync"
	"testing"
)

func TestScanArchivesSupportsZIPTARGZIPAndPEMBundles(t *testing.T) {
	t.Parallel()
	_, firstPEM, _ := makeCertificate(t, certificateSpec{serial: 201, common: "first.archive.example"})
	_, secondPEM, _ := makeCertificate(t, certificateSpec{serial: 202, common: "second.archive.example"})
	bundle := append(append([]byte{}, firstPEM...), secondPEM...)

	for _, test := range []struct {
		name      string
		data      []byte
		wantEntry string
		extension string
	}{
		{name: "ZIP", data: makeTestZIP(t, map[string][]byte{"etc/certs/bundle.pem": bundle}), wantEntry: "etc/certs/bundle.pem", extension: ".zip"},
		{name: "TAR", data: makeTestTAR(t, map[string][]byte{"etc/certs/bundle.pem": bundle}), wantEntry: "etc/certs/bundle.pem", extension: ".tar"},
		{name: "gzip", data: makeTestGZIP(t, "bundle.pem", bundle), wantEntry: "bundle.pem", extension: ".gz"},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			archivePath := filepath.Join(t.TempDir(), "certificates"+test.extension)
			writeFile(t, archivePath, test.data)
			var progressMu sync.Mutex
			var observed Progress
			report, err := Scan(context.Background(), archivePath, Options{
				MaxBytes:     DefaultMaxBytes,
				Workers:      1,
				ScanArchives: true,
				OnProgress: func(progress Progress) {
					progressMu.Lock()
					defer progressMu.Unlock()
					observed.ArchiveEntriesDiscovered = max(
						observed.ArchiveEntriesDiscovered,
						progress.ArchiveEntriesDiscovered,
					)
					observed.ArchiveEntriesScanned = max(
						observed.ArchiveEntriesScanned,
						progress.ArchiveEntriesScanned,
					)
				},
			})
			if err != nil {
				t.Fatal(err)
			}
			if len(report.Errors) != 0 || len(report.Certificates) != 2 {
				t.Fatalf("report certificates=%d errors=%v", len(report.Certificates), report.Errors)
			}
			for index, certificate := range report.Certificates {
				if certificate.Path != archivePath ||
					!reflect.DeepEqual(certificate.ArchiveEntries, []string{test.wantEntry}) ||
					certificate.Index != index {
					t.Errorf("certificate %d location = %+v", index, certificate)
				}
			}
			progressMu.Lock()
			defer progressMu.Unlock()
			if observed.ArchiveEntriesDiscovered != 1 || observed.ArchiveEntriesScanned != 1 {
				t.Errorf("archive progress = %+v", observed)
			}
		})
	}
}

func TestScanArchivesIsOptIn(t *testing.T) {
	t.Parallel()
	_, certificatePEM, _ := makeCertificate(t, certificateSpec{serial: 203, common: "disabled.archive.example"})
	archivePath := filepath.Join(t.TempDir(), "certificates.zip")
	writeFile(t, archivePath, makeTestZIP(t, map[string][]byte{"certificate.pem": certificatePEM}))
	report, err := Scan(context.Background(), archivePath, Options{MaxBytes: DefaultMaxBytes, Workers: 1})
	if err != nil {
		t.Fatal(err)
	}
	if len(report.Certificates) != 0 || len(report.Errors) != 0 {
		t.Fatalf("disabled archive scan report = %+v", report)
	}
}

func TestScanArchivesSupportsNestedArchivesAndDepthLimit(t *testing.T) {
	t.Parallel()
	_, certificatePEM, _ := makeCertificate(t, certificateSpec{serial: 204, common: "nested.archive.example"})
	inner := makeTestTAR(t, map[string][]byte{"etc/service/cert.pem": certificatePEM})
	outerPath := filepath.Join(t.TempDir(), "backup.zip")
	writeFile(t, outerPath, makeTestZIP(t, map[string][]byte{"nested/backup.tar": inner}))

	report, err := Scan(context.Background(), outerPath, Options{
		MaxBytes:        DefaultMaxBytes,
		Workers:         1,
		ScanArchives:    true,
		ArchiveMaxDepth: 2,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(report.Errors) != 0 || len(report.Certificates) != 1 {
		t.Fatalf("nested report certificates=%d errors=%v", len(report.Certificates), report.Errors)
	}
	wantEntries := []string{"nested/backup.tar", "etc/service/cert.pem"}
	if !reflect.DeepEqual(report.Certificates[0].ArchiveEntries, wantEntries) {
		t.Fatalf("archive entries = %v, want %v", report.Certificates[0].ArchiveEntries, wantEntries)
	}

	limited, err := Scan(context.Background(), outerPath, Options{
		MaxBytes:        DefaultMaxBytes,
		Workers:         1,
		ScanArchives:    true,
		ArchiveMaxDepth: 1,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(limited.Certificates) != 0 || len(limited.Errors) != 1 ||
		!strings.Contains(limited.Errors[0].Error(), "archive nesting depth exceeds 1") {
		t.Fatalf("depth-limited report = %+v", limited)
	}
}

func TestScanArchivesEnforcesEntryAndDecompressedByteLimits(t *testing.T) {
	t.Parallel()
	_, certificatePEM, _ := makeCertificate(t, certificateSpec{serial: 205, common: "limited.archive.example"})
	archivePath := filepath.Join(t.TempDir(), "limited.zip")
	writeFile(t, archivePath, makeTestZIP(t, map[string][]byte{
		"a.pem": certificatePEM,
		"b.pem": certificatePEM,
	}))

	entryLimited, err := Scan(context.Background(), archivePath, Options{
		MaxBytes:          DefaultMaxBytes,
		Workers:           1,
		ScanArchives:      true,
		ArchiveMaxEntries: 1,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(entryLimited.Certificates) != 0 || len(entryLimited.Errors) != 1 ||
		!strings.Contains(entryLimited.Errors[0].Error(), "ZIP entry count 2 exceeds remaining archive entry limit 1") {
		t.Fatalf("entry-limited report = %+v", entryLimited)
	}

	byteLimited, err := Scan(context.Background(), archivePath, Options{
		MaxBytes:        DefaultMaxBytes,
		Workers:         1,
		ScanArchives:    true,
		ArchiveMaxBytes: 32,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(byteLimited.Certificates) != 0 || len(byteLimited.Errors) != 1 ||
		!strings.Contains(byteLimited.Errors[0].Error(), "archive decompressed byte limit exceeded") {
		t.Fatalf("byte-limited report = %+v", byteLimited)
	}
}

func TestScanArchivesAppliesMaxBytesPerEntryAndRereadsMatches(t *testing.T) {
	t.Parallel()
	_, certificatePEM, _ := makeCertificate(t, certificateSpec{serial: 206, common: "prefix.archive.example"})
	archivePath := filepath.Join(t.TempDir(), "max-bytes.zip")
	writeFile(t, archivePath, makeTestZIP(t, map[string][]byte{
		"early.pem": append(append([]byte{}, certificatePEM...), bytes.Repeat([]byte("x"), 256)...),
		"late.pem":  append(bytes.Repeat([]byte("x"), len(certificatePEM)+32), certificatePEM...),
	}))
	var progressMu sync.Mutex
	var observed Progress
	report, err := Scan(context.Background(), archivePath, Options{
		MaxBytes:     int64(len(certificatePEM) + 16),
		Workers:      1,
		ScanArchives: true,
		OnProgress: func(progress Progress) {
			progressMu.Lock()
			defer progressMu.Unlock()
			observed.ArchiveEntriesCapped = max(observed.ArchiveEntriesCapped, progress.ArchiveEntriesCapped)
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(report.Errors) != 0 || len(report.Certificates) != 1 ||
		!reflect.DeepEqual(report.Certificates[0].ArchiveEntries, []string{"early.pem"}) {
		t.Fatalf("max-bytes report = %+v", report)
	}
	progressMu.Lock()
	defer progressMu.Unlock()
	if observed.ArchiveEntriesCapped != 1 {
		t.Fatalf("archive capped progress = %+v", observed)
	}
}

func TestScanArchivesReportsMalformedAndEncryptedArchives(t *testing.T) {
	t.Parallel()
	truncatedTAR := makeTestTAR(t, map[string][]byte{"large.pem": bytes.Repeat([]byte("x"), 128)})
	truncatedTAR = truncatedTAR[:512+16]
	for _, test := range []struct {
		name string
		data []byte
	}{
		{name: "ZIP", data: []byte{'P', 'K', 3, 4, 0, 0, 0, 0}},
		{name: "TAR", data: truncatedTAR},
		{name: "gzip", data: []byte{0x1f, 0x8b, 0x08}},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			malformedPath := filepath.Join(t.TempDir(), "malformed.archive")
			writeFile(t, malformedPath, test.data)
			report, err := Scan(context.Background(), malformedPath, Options{
				MaxBytes: DefaultMaxBytes, Workers: 1, ScanArchives: true,
			})
			if err != nil {
				t.Fatal(err)
			}
			if len(report.Errors) != 1 {
				t.Fatalf("malformed report = %+v", report)
			}
		})
	}

	_, certificatePEM, _ := makeCertificate(t, certificateSpec{serial: 207, common: "encrypted.archive.example"})
	encryptedPath := filepath.Join(t.TempDir(), "encrypted.zip")
	writeFile(t, encryptedPath, markTestZIPEncrypted(t, makeTestZIP(t, map[string][]byte{"cert.pem": certificatePEM})))
	encrypted, err := Scan(context.Background(), encryptedPath, Options{
		MaxBytes: DefaultMaxBytes, Workers: 1, ScanArchives: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(encrypted.Certificates) != 0 || len(encrypted.Errors) != 1 ||
		!strings.Contains(encrypted.Errors[0].Error(), "encrypted ZIP entry is unsupported") {
		t.Fatalf("encrypted report = %+v", encrypted)
	}
}

func TestScanRejectsInvalidArchiveLimits(t *testing.T) {
	t.Parallel()
	for _, options := range []Options{
		{ScanArchives: true, ArchiveMaxBytes: -1},
		{ScanArchives: true, ArchiveMaxEntries: -1},
		{ScanArchives: true, ArchiveMaxDepth: -1},
	} {
		if _, err := Scan(context.Background(), t.TempDir(), options); err == nil {
			t.Errorf("Scan accepted invalid options %+v", options)
		}
	}
}

func makeTestZIP(t *testing.T, entries map[string][]byte) []byte {
	t.Helper()
	var output bytes.Buffer
	writer := zip.NewWriter(&output)
	for _, name := range sortedTestEntryNames(entries) {
		entry, err := writer.Create(name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := entry.Write(entries[name]); err != nil {
			t.Fatal(err)
		}
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	return output.Bytes()
}

func makeTestTAR(t *testing.T, entries map[string][]byte) []byte {
	t.Helper()
	var output bytes.Buffer
	writer := tar.NewWriter(&output)
	for _, name := range sortedTestEntryNames(entries) {
		data := entries[name]
		if err := writer.WriteHeader(&tar.Header{Name: name, Mode: 0o600, Size: int64(len(data))}); err != nil {
			t.Fatal(err)
		}
		if _, err := writer.Write(data); err != nil {
			t.Fatal(err)
		}
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	return output.Bytes()
}

func makeTestGZIP(t *testing.T, name string, data []byte) []byte {
	t.Helper()
	var output bytes.Buffer
	writer := gzip.NewWriter(&output)
	writer.Name = name
	if _, err := writer.Write(data); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	return output.Bytes()
}

func sortedTestEntryNames(entries map[string][]byte) []string {
	names := make([]string, 0, len(entries))
	for name := range entries {
		names = append(names, name)
	}
	slices.Sort(names)
	return names
}

func markTestZIPEncrypted(t *testing.T, data []byte) []byte {
	t.Helper()
	result := append([]byte{}, data...)
	local := bytes.Index(result, []byte{'P', 'K', 3, 4})
	central := bytes.Index(result, []byte{'P', 'K', 1, 2})
	if local < 0 || central < 0 {
		t.Fatal("ZIP headers not found")
	}
	binary.LittleEndian.PutUint16(result[local+6:local+8], binary.LittleEndian.Uint16(result[local+6:local+8])|1)
	binary.LittleEndian.PutUint16(result[central+8:central+10], binary.LittleEndian.Uint16(result[central+8:central+10])|1)
	return result
}
