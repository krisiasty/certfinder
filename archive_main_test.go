package main

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/x509"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestRunArchiveOutputIdentifiesOuterPathAndEntry(t *testing.T) {
	t.Parallel()
	directory := t.TempDir()
	certificatePath := writeTestCertificate(
		t,
		directory,
		"archived.example",
		time.Now().Add(-time.Hour),
		time.Now().Add(time.Hour),
		x509.ExtKeyUsageServerAuth,
	)
	certificatePEM, err := os.ReadFile(certificatePath) //nolint:gosec // The path is a test fixture in t.TempDir.
	if err != nil {
		t.Fatal(err)
	}
	archivePath := filepath.Join(directory, "backup.zip")
	writeMainTestZIP(t, archivePath, "etc/service/cert.pem", certificatePEM)
	if err := os.Remove(certificatePath); err != nil {
		t.Fatal(err)
	}

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	status := run(context.Background(), []string{"-archives", "-json", "-quiet", archivePath}, &stdout, &stderr)
	if status != exitSuccess {
		t.Fatalf("status = %d; stderr = %q", status, stderr.String())
	}
	var certificates []jsonCertificate
	if err := json.Unmarshal(stdout.Bytes(), &certificates); err != nil {
		t.Fatal(err)
	}
	if len(certificates) != 1 || certificates[0].Path != archivePath ||
		!reflect.DeepEqual(certificates[0].ArchiveEntries, []string{"etc/service/cert.pem"}) {
		t.Fatalf("JSON certificates = %+v", certificates)
	}

	stdout.Reset()
	stderr.Reset()
	status = run(context.Background(), []string{"-archives", "-quiet", archivePath}, &stdout, &stderr)
	if status != exitSuccess {
		t.Fatalf("text status = %d; stderr = %q", status, stderr.String())
	}
	if !strings.Contains(stdout.String(), archivePath+":etc/service/cert.pem [index 0]") {
		t.Fatalf("text output = %q", stdout.String())
	}
}

func TestRunArchiveScanningIsDisabledByDefault(t *testing.T) {
	t.Parallel()
	directory := t.TempDir()
	certificatePath := writeTestCertificate(
		t,
		directory,
		"disabled-archive.example",
		time.Now().Add(-time.Hour),
		time.Now().Add(time.Hour),
		x509.ExtKeyUsageServerAuth,
	)
	certificatePEM, err := os.ReadFile(certificatePath) //nolint:gosec // The path is a test fixture in t.TempDir.
	if err != nil {
		t.Fatal(err)
	}
	archivePath := filepath.Join(directory, "backup.zip")
	writeMainTestZIP(t, archivePath, "certificate.pem", certificatePEM)
	if err := os.Remove(certificatePath); err != nil {
		t.Fatal(err)
	}
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	status := run(context.Background(), []string{"-json", "-quiet", archivePath}, &stdout, &stderr)
	if status != exitSuccess || strings.TrimSpace(stdout.String()) != "[]" {
		t.Fatalf("status = %d, stdout = %q, stderr = %q", status, stdout.String(), stderr.String())
	}
}

func TestRunRejectsInvalidArchiveOptions(t *testing.T) {
	t.Parallel()
	for _, arguments := range [][]string{
		{"-archive-max-bytes=1024", "."},
		{"-archive-max-entries=10", "."},
		{"-archive-max-depth=2", "."},
		{"-archives", "-archive-max-bytes=0", "."},
		{"-archives", "-archive-max-entries=0", "."},
		{"-archives", "-archive-max-depth=0", "."},
	} {
		var stdout bytes.Buffer
		var stderr bytes.Buffer
		if status := run(context.Background(), arguments, &stdout, &stderr); status != exitUsageError {
			t.Errorf("run(%v) status = %d, want %d", arguments, status, exitUsageError)
		}
	}
}

func writeMainTestZIP(t *testing.T, archivePath, entryName string, data []byte) {
	t.Helper()
	file, err := os.Create(archivePath) //nolint:gosec // The path is inside a test temporary directory.
	if err != nil {
		t.Fatal(err)
	}
	writer := zip.NewWriter(file)
	entry, err := writer.Create(entryName)
	if err != nil {
		_ = file.Close()
		t.Fatal(err)
	}
	if _, err := entry.Write(data); err != nil {
		_ = writer.Close()
		_ = file.Close()
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		_ = file.Close()
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
}
