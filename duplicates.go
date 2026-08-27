package main

import (
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"time"

	"github.com/krisiasty/certfinder/internal/scanner"
)

const (
	identityModeAll        = "all"
	identityModeUnique     = "unique"
	identityModeDuplicates = "duplicates"
)

type certificateLocation struct {
	Path  string `json:"path"`
	Index int    `json:"index"`
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
			Path:  certificate.Path,
			Index: certificate.Index,
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
		if _, err := fmt.Fprintf(output, "    %s [index %d]\n", location.Path, location.Index); err != nil {
			return err
		}
	}
	return printCertificateDetailsAt(output, group.Certificate, now)
}

func printJSONCertificateGroupsAt(output io.Writer, groups []certificateGroup, now time.Time) error {
	result := make([]jsonCertificateGroup, 0, len(groups))
	for _, group := range groups {
		certificate := newJSONCertificate(group.Certificate, now)
		certificate.Path = ""
		certificate.Index = nil
		result = append(result, jsonCertificateGroup{
			Certificate: certificate,
			Locations:   append([]certificateLocation{}, group.Locations...),
		})
	}
	encoder := json.NewEncoder(output)
	encoder.SetIndent("", "  ")
	return encoder.Encode(result)
}
