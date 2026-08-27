package main

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/krisiasty/certfinder/internal/scanner"
)

func TestGroupCertificatesSortsGroupsAndLocations(t *testing.T) {
	t.Parallel()
	certificates := []scanner.Certificate{
		{Path: "/z.pem", Index: 1, SHA256Fingerprint: "duplicate"},
		{Path: "/a.pem", Index: 2, SHA256Fingerprint: "duplicate"},
		{Path: "/a.pem", Index: 0, SHA256Fingerprint: "single"},
	}

	groups := groupCertificates(certificates)
	if len(groups) != 2 {
		t.Fatalf("group count = %d, want 2", len(groups))
	}
	if groups[0].Certificate.SHA256Fingerprint != "single" {
		t.Errorf("first group fingerprint = %q, want single", groups[0].Certificate.SHA256Fingerprint)
	}
	wantLocations := []certificateLocation{{Path: "/a.pem", Index: 2}, {Path: "/z.pem", Index: 1}}
	if len(groups[1].Locations) != len(wantLocations) {
		t.Fatalf("duplicate locations = %+v, want %+v", groups[1].Locations, wantLocations)
	}
	for index, location := range groups[1].Locations {
		if location != wantLocations[index] {
			t.Errorf("duplicate location %d = %+v, want %+v", index, location, wantLocations[index])
		}
	}
}

func TestDuplicateCertificateGroups(t *testing.T) {
	t.Parallel()
	groups := []certificateGroup{
		{Locations: []certificateLocation{{Path: "/single.pem"}}},
		{Locations: []certificateLocation{{Path: "/a.pem"}, {Path: "/b.pem"}}},
	}
	duplicates := duplicateCertificateGroups(groups)
	if len(duplicates) != 1 || len(duplicates[0].Locations) != 2 {
		t.Fatalf("duplicate groups = %+v, want only the two-location group", duplicates)
	}
}

func TestGroupCertificatesPreservesKeystoreLocations(t *testing.T) {
	t.Parallel()
	certificates := []scanner.Certificate{
		{
			Path: "/store.jks", Index: 0, SHA256Fingerprint: "same",
			Keystore: &scanner.KeystoreInfo{
				Format: scanner.KeystoreFormatJKS, Alias: "first", EntryType: scanner.KeystoreEntryPrivateKey,
			},
		},
		{
			Path: "/store.jks", Index: 1, SHA256Fingerprint: "same",
			Keystore: &scanner.KeystoreInfo{
				Format: scanner.KeystoreFormatJKS, Alias: "second", EntryType: scanner.KeystoreEntryTrustedCert,
				Truststore: true,
			},
		},
	}
	groups := groupCertificates(certificates)
	if len(groups) != 1 || len(groups[0].Locations) != 2 {
		t.Fatalf("groups = %+v, want one fingerprint at two keystore locations", groups)
	}
	if groups[0].Locations[0].Keystore == nil || groups[0].Locations[0].Keystore.Alias != "first" {
		t.Errorf("first location = %+v, want alias first", groups[0].Locations[0])
	}
	if groups[0].Locations[1].Keystore == nil || groups[0].Locations[1].Keystore.Alias != "second" ||
		!groups[0].Locations[1].Keystore.Truststore {
		t.Errorf("second location = %+v, want trusted alias second", groups[0].Locations[1])
	}
}

func TestGroupCertificatesPreservesPKCS12FriendlyName(t *testing.T) {
	t.Parallel()
	groups := groupCertificates([]scanner.Certificate{{
		Path: "/store.p12", SHA256Fingerprint: "same",
		Keystore: &scanner.KeystoreInfo{
			Format:       scanner.KeystoreFormatPKCS12,
			FriendlyName: "service",
			EntryType:    scanner.KeystoreEntryPKCS12CertBag,
			ChainIndex:   1,
		},
	}})
	if len(groups) != 1 || groups[0].Locations[0].Keystore == nil ||
		groups[0].Locations[0].Keystore.FriendlyName != "service" {
		t.Fatalf("groups = %+v", groups)
	}
	want := `/store.p12 [index 0] [keystore PKCS#12; friendly name "service"; entry type certBag; chain index 1; truststore false]`
	if got := formatCertificateLocation(groups[0].Locations[0]); got != want {
		t.Fatalf("formatted location = %q, want %q", got, want)
	}
}

func TestSummarizeCertificateIdentities(t *testing.T) {
	t.Parallel()
	summary := summarizeCertificateIdentities(map[string]int64{"a": 3, "b": 1})
	want := certificateIdentitySummary{Matched: 4, Unique: 2, DuplicateOccurrences: 2}
	if summary != want {
		t.Fatalf("summary = %+v, want %+v", summary, want)
	}
}

func TestGroupedOutputIncludesAllLocations(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, time.January, 1, 0, 0, 0, 0, time.UTC)
	group := certificateGroup{
		Certificate: scanner.Certificate{
			Path:              "/a.pem",
			Subject:           "CN=service.example.test",
			SHA256Fingerprint: "aabbcc",
			NotBefore:         now.Add(-time.Hour),
			NotAfter:          now.Add(time.Hour),
			Keystore: &scanner.KeystoreInfo{
				Format: scanner.KeystoreFormatJKS, Alias: "service", EntryType: scanner.KeystoreEntryPrivateKey,
			},
		},
		Locations: []certificateLocation{
			{
				Path: "/a.pem", Index: 0,
				Keystore: &jsonKeystoreInfo{
					Format: scanner.KeystoreFormatJKS, Alias: "service", EntryType: scanner.KeystoreEntryPrivateKey,
				},
			},
			{Path: "/bundle.pem", Index: 2},
		},
	}

	var textOutput bytes.Buffer
	if err := printCertificateGroupAt(&textOutput, group, now); err != nil {
		t.Fatal(err)
	}
	for _, wanted := range []string{
		"Locations (2):",
		`/a.pem [index 0] [keystore JKS; alias "service"; entry type PrivateKeyEntry; chain index 0; truststore false]`,
		"/bundle.pem [index 2]",
	} {
		if !strings.Contains(textOutput.String(), wanted) {
			t.Errorf("text output %q does not contain %q", textOutput.String(), wanted)
		}
	}

	var jsonOutput bytes.Buffer
	if err := printJSONCertificateGroupsAt(&jsonOutput, []certificateGroup{group}, now); err != nil {
		t.Fatal(err)
	}
	var decoded []jsonCertificateGroup
	if err := json.Unmarshal(jsonOutput.Bytes(), &decoded); err != nil {
		t.Fatal(err)
	}
	if len(decoded) != 1 || len(decoded[0].Locations) != 2 {
		t.Fatalf("JSON groups = %+v, want one group with two locations", decoded)
	}
	if decoded[0].Certificate.Path != "" || decoded[0].Certificate.Index != nil || decoded[0].Certificate.Keystore != nil {
		t.Errorf("grouped JSON contains an ambiguous representative location: %s", jsonOutput.String())
	}
	if decoded[0].Locations[0].Keystore == nil || decoded[0].Locations[0].Keystore.Alias != "service" {
		t.Errorf("grouped JSON location lost keystore metadata: %s", jsonOutput.String())
	}
}
