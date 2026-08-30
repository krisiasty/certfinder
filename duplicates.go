package main

import (
	"encoding/json"
	"fmt"
	"io"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/krisiasty/certfinder/internal/scanner"
)

const (
	identityModeAll        = "all"
	identityModeUnique     = "unique"
	identityModeDuplicates = "duplicates"
)

type certificateLocation struct {
	Path           string            `json:"path"`
	ArchiveEntries []string          `json:"archive_entries,omitempty"`
	Index          int               `json:"index"`
	Keystore       *jsonKeystoreInfo `json:"keystore,omitempty"`
}

type certificateGroup struct {
	Certificate scanner.Certificate
	Locations   []certificateLocation
}

type certificateIdentitySummary struct {
	Matched              int64
	Unique               int64
	DuplicateOccurrences int64
}

type jsonCertificateGroup struct {
	Certificate jsonCertificate       `json:"certificate"`
	Locations   []certificateLocation `json:"locations"`
}

func summarizeCertificateIdentities(counts map[string]int64) certificateIdentitySummary {
	summary := certificateIdentitySummary{Unique: int64(len(counts))}
	for _, count := range counts {
		summary.Matched += count
		if count > 1 {
			summary.DuplicateOccurrences += count - 1
		}
	}
	return summary
}

func groupCertificates(certificates []scanner.Certificate) []certificateGroup {
	sort.Slice(certificates, func(left, right int) bool {
		if certificates[left].Path == certificates[right].Path {
			if compared := slices.Compare(
				certificates[left].ArchiveEntries,
				certificates[right].ArchiveEntries,
			); compared != 0 {
				return compared < 0
			}
			return certificates[left].Index < certificates[right].Index
		}
		return certificates[left].Path < certificates[right].Path
	})

	groups := make([]certificateGroup, 0, len(certificates))
	groupByFingerprint := make(map[string]int, len(certificates))
	for _, certificate := range certificates {
		groupIndex, exists := groupByFingerprint[certificate.SHA256Fingerprint]
		if !exists {
			groupIndex = len(groups)
			groupByFingerprint[certificate.SHA256Fingerprint] = groupIndex
			groups = append(groups, certificateGroup{Certificate: certificate})
		}
		groups[groupIndex].Locations = append(groups[groupIndex].Locations, certificateLocation{
			Path:           certificate.Path,
			ArchiveEntries: slices.Clone(certificate.ArchiveEntries),
			Index:          certificate.Index,
			Keystore:       newJSONKeystoreInfo(certificate.Keystore),
		})
	}
	return groups
}

func duplicateCertificateGroups(groups []certificateGroup) []certificateGroup {
	duplicates := make([]certificateGroup, 0, len(groups))
	for _, group := range groups {
		if len(group.Locations) > 1 {
			duplicates = append(duplicates, group)
		}
	}
	return duplicates
}

func printCertificateGroupAt(output io.Writer, group certificateGroup, now time.Time) error {
	if _, err := fmt.Fprintln(output, "Certificate"); err != nil {
		return err
	}
	if _, err := fmt.Fprintf(output, "  Locations (%d):\n", len(group.Locations)); err != nil {
		return err
	}
	for _, location := range group.Locations {
		if _, err := fmt.Fprintln(output, "    "+formatCertificateLocation(location)); err != nil {
			return err
		}
	}
	certificate := group.Certificate
	certificate.Keystore = nil
	return printCertificateDetailsAt(output, certificate, now)
}

func formatCertificateLocation(location certificateLocation) string {
	result := fmt.Sprintf(
		"%s [index %d]",
		formatLogicalLocation(location.Path, location.ArchiveEntries),
		location.Index,
	)
	if location.Keystore == nil {
		return result
	}
	details := []string{"keystore " + location.Keystore.Format}
	if location.Keystore.Alias != "" {
		details = append(details, fmt.Sprintf("alias %q", location.Keystore.Alias))
	}
	if location.Keystore.FriendlyName != "" {
		details = append(details, fmt.Sprintf("friendly name %q", location.Keystore.FriendlyName))
	}
	details = append(
		details,
		"entry type "+location.Keystore.EntryType,
		fmt.Sprintf("chain index %d", location.Keystore.ChainIndex),
		fmt.Sprintf("truststore %t", location.Keystore.Truststore),
	)
	return result + " [" + strings.Join(details, "; ") + "]"
}

func printJSONCertificateGroupsAt(output io.Writer, groups []certificateGroup, now time.Time) error {
	return printJSONCertificateGroupsAndPKCS12At(output, groups, nil, now)
}

func printJSONCertificateGroupsAndPKCS12At(
	output io.Writer,
	groups []certificateGroup,
	encrypted []scanner.PKCS12EncryptedContent,
	now time.Time,
) error {
	result := make([]any, 0, len(groups)+len(encrypted))
	for _, group := range groups {
		certificate := newJSONCertificate(group.Certificate, now)
		certificate.Path = ""
		certificate.Index = nil
		certificate.Keystore = nil
		result = append(result, jsonCertificateGroup{
			Certificate: certificate,
			Locations:   append([]certificateLocation{}, group.Locations...),
		})
	}
	for _, finding := range encrypted {
		result = append(result, newJSONPKCS12EncryptedContent(finding))
	}
	encoder := json.NewEncoder(output)
	encoder.SetIndent("", "  ")
	return encoder.Encode(result)
}
