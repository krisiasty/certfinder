package main

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/krisiasty/certfinder/internal/buildinfo"
	"github.com/krisiasty/certfinder/internal/scanner"
)

const (
	programName      = "certfinder"
	progressInterval = 5 * time.Second
)

type scanConfiguration struct {
	Path           string
	Workers        int
	MaxBytes       int64
	Exclude        []string
	Extensions     []string
	OneFileSystem  bool
	FollowSymlinks bool
	IgnoreErrors   bool
	Usage          string
	Hostname       string
	Expiration     string
	FailExpiring   string
	Verify         bool
	Roots          []string
	RootsOnly      bool
	IdentityMode   string
	Output         string
	Quiet          bool
}

type progressDisplay struct {
	progressOutput    io.Writer
	certificateOutput io.Writer
	showResults       bool
	quiet             bool
	terminal          bool
	started           time.Time

	mu                 sync.Mutex
	progress           scanner.Progress
	identitySummary    certificateIdentitySummary
	identitySummarySet bool
	stopped            bool
	writeErr           error
	done               chan struct{}
	wait               sync.WaitGroup
}

func newProgressDisplay(progressOutput, certificateOutput io.Writer, showResults, quiet bool) *progressDisplay {
	return &progressDisplay{
		progressOutput:    progressOutput,
		certificateOutput: certificateOutput,
		showResults:       showResults,
		quiet:             quiet,
		terminal:          isTerminal(progressOutput),
		done:              make(chan struct{}),
	}
}

func (display *progressDisplay) Start(configuration scanConfiguration) {
	display.mu.Lock()
	display.started = time.Now()
	if display.quiet {
		display.mu.Unlock()
		return
	}
	path := configuration.Path
	if absolute, err := filepath.Abs(path); err == nil {
		path = absolute
	}
	usage := configuration.Usage
	if usage == "" {
		usage = "all"
	}
	hostname := configuration.Hostname
	if hostname == "" {
		hostname = "none"
	}
	expiration := configuration.Expiration
	if expiration == "" {
		expiration = "none"
	}
	failExpiring := configuration.FailExpiring
	if failExpiring == "" {
		failExpiring = "none"
	}
	maxBytes := strconv.FormatInt(configuration.MaxBytes, 10)
	if configuration.MaxBytes == 0 {
		maxBytes = "unlimited"
	}
	output := configuration.Output
	if output == "" {
		output = outputText
	}
	identityMode := configuration.IdentityMode
	if identityMode == "" {
		identityMode = identityModeAll
	}

	display.writeProgress("%s %s\n", programName, buildinfo.Version())
	display.writeProgress("Scan path: %s\n", path)
	display.writeProgress("Workers: %d\n", configuration.Workers)
	display.writeProgress(
		"Options: max-bytes=%s usage=%s hostname=%s expiration=%s fail-expiring=%s identity=%s output=%s quiet=%t\n",
		maxBytes,
		usage,
		hostname,
		expiration,
		failExpiring,
		identityMode,
		output,
		configuration.Quiet,
	)
	display.writeProgress(
		"Traversal: exclude=%s extensions=%s one-file-system=%t follow-symlinks=%t ignore-errors=%t\n",
		formatOptionList(configuration.Exclude, "none"),
		formatOptionList(configuration.Extensions, "all"),
		configuration.OneFileSystem,
		configuration.FollowSymlinks,
		configuration.IgnoreErrors,
	)
	display.writeProgress(
		"Verification: enabled=%t roots=%s roots-only=%t\n",
		configuration.Verify,
		formatOptionList(configuration.Roots, "none"),
		configuration.RootsOnly,
	)
	display.writeProgress("\n")
	display.drawStatusLocked()
	display.mu.Unlock()

	display.wait.Add(1)
	go display.refreshLoop()
}

func formatOptionList(values []string, empty string) string {
	if len(values) == 0 {
		return empty
	}
	return strings.Join(values, ",")
}

func (display *progressDisplay) Update(progress scanner.Progress) {
	display.mu.Lock()
	defer display.mu.Unlock()
	if display.stopped {
		return
	}
	display.progress.FilesDiscovered = max(display.progress.FilesDiscovered, progress.FilesDiscovered)
	display.progress.FilesScanned = max(display.progress.FilesScanned, progress.FilesScanned)
	display.progress.FilesCapped = max(display.progress.FilesCapped, progress.FilesCapped)
	display.progress.CertificatesFound = max(display.progress.CertificatesFound, progress.CertificatesFound)
	display.progress.PKCS12Encrypted = max(display.progress.PKCS12Encrypted, progress.PKCS12Encrypted)
	display.progress.ScanErrors = max(display.progress.ScanErrors, progress.ScanErrors)
	display.progress.DiscoveryComplete = display.progress.DiscoveryComplete || progress.DiscoveryComplete
}

func (display *progressDisplay) Certificate(certificate scanner.Certificate) {
	display.writeResult(func(output io.Writer) error {
		return printCertificate(output, certificate)
	})
}

func (display *progressDisplay) CertificateGroup(group certificateGroup) {
	display.writeResult(func(output io.Writer) error {
		return printCertificateGroupAt(output, group, time.Now())
	})
}

func (display *progressDisplay) PKCS12Encrypted(finding scanner.PKCS12EncryptedContent) {
	display.writeResult(func(output io.Writer) error {
		return printPKCS12EncryptedContent(output, finding)
	})
}

func (display *progressDisplay) writeResult(printResult func(io.Writer) error) {
	display.mu.Lock()
	defer display.mu.Unlock()
	if display.stopped || !display.showResults {
		return
	}
	if !display.quiet && display.terminal {
		display.clearStatusLocked()
	}
	if display.writeErr == nil {
		display.writeErr = printResult(display.certificateOutput)
	}
	if !display.quiet {
		display.writeProgress("\n")
		display.drawStatusLocked()
	}
}

func (display *progressDisplay) SetIdentitySummary(summary certificateIdentitySummary) {
	display.mu.Lock()
	defer display.mu.Unlock()
	display.identitySummary = summary
	display.identitySummarySet = true
}

func (display *progressDisplay) Stop(completed bool) {
	display.mu.Lock()
	if display.stopped {
		display.mu.Unlock()
		return
	}
	display.stopped = true
	close(display.done)
	display.mu.Unlock()
	display.wait.Wait()
	if display.quiet {
		return
	}

	display.mu.Lock()
	defer display.mu.Unlock()
	if display.terminal {
		display.clearStatusLocked()
	}
	elapsed := time.Since(display.started).Round(time.Millisecond)
	state := "Scan stopped"
	if completed {
		state = "Scan complete"
	}
	identitySummary := ""
	if display.identitySummarySet {
		identitySummary = fmt.Sprintf(
			" %d %s matched; %d unique %s; %d duplicate %s;",
			display.identitySummary.Matched,
			plural(display.identitySummary.Matched, "certificate", "certificates"),
			display.identitySummary.Unique,
			plural(display.identitySummary.Unique, "certificate", "certificates"),
			display.identitySummary.DuplicateOccurrences,
			plural(display.identitySummary.DuplicateOccurrences, "occurrence", "occurrences"),
		)
	}
	pkcs12Summary := ""
	if display.progress.PKCS12Encrypted > 0 {
		pkcs12Summary = fmt.Sprintf(
			" %d encrypted PKCS#12 %s;",
			display.progress.PKCS12Encrypted,
			plural(display.progress.PKCS12Encrypted, "content", "contents"),
		)
	}
	display.writeProgress(
		"%s: %d %s scanned, %d stopped at max-bytes; %d %s found;%s%s %d %s; elapsed %s\n",
		state,
		display.progress.FilesScanned,
		plural(display.progress.FilesScanned, "file", "files"),
		display.progress.FilesCapped,
		display.progress.CertificatesFound,
		plural(display.progress.CertificatesFound, "certificate", "certificates"),
		identitySummary,
		pkcs12Summary,
		display.progress.ScanErrors,
		plural(display.progress.ScanErrors, "error", "errors"),
		elapsed,
	)
}

func (display *progressDisplay) Err() error {
	display.mu.Lock()
	defer display.mu.Unlock()
	return display.writeErr
}

func (display *progressDisplay) refreshLoop() {
	defer display.wait.Done()
	ticker := time.NewTicker(progressInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			display.mu.Lock()
			if !display.stopped {
				display.drawStatusLocked()
			}
			display.mu.Unlock()
		case <-display.done:
			return
		}
	}
}

func (display *progressDisplay) drawStatusLocked() {
	if display.terminal {
		display.clearStatusLocked()
	}
	pending := max(display.progress.FilesDiscovered-display.progress.FilesScanned, 0)
	discovery := "discovering files..."
	if display.progress.DiscoveryComplete {
		discovery = "discovery complete"
	}
	status := fmt.Sprintf(
		"Scanning: %d/%d files scanned; %d pending; %d %s found; %s",
		display.progress.FilesScanned,
		display.progress.FilesDiscovered,
		pending,
		display.progress.CertificatesFound,
		plural(display.progress.CertificatesFound, "certificate", "certificates"),
		discovery,
	)
	if display.progress.PKCS12Encrypted > 0 {
		status = fmt.Sprintf(
			"%s; %d encrypted PKCS#12 %s",
			status,
			display.progress.PKCS12Encrypted,
			plural(display.progress.PKCS12Encrypted, "content", "contents"),
		)
	}
	if display.terminal {
		display.writeProgress("%s", status)
		return
	}
	display.writeProgress("%s\n", status)
}

func plural(count int64, singular, multiple string) string {
	if count == 1 {
		return singular
	}
	return multiple
}

func (display *progressDisplay) clearStatusLocked() {
	display.writeProgress("\r\x1b[2K")
}

func (display *progressDisplay) writeProgress(format string, arguments ...any) {
	if display.writeErr != nil {
		return
	}
	_, display.writeErr = fmt.Fprintf(display.progressOutput, format, arguments...)
}

func isTerminal(output io.Writer) bool {
	file, ok := output.(*os.File)
	if !ok {
		return false
	}
	info, err := file.Stat()
	return err == nil && info.Mode()&os.ModeCharDevice != 0
}
