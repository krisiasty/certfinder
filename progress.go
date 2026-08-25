package main

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"time"

	"github.com/krisiasty/certfinder/internal/scanner"
)

const (
	programName      = "certfinder"
	progressInterval = 5 * time.Second
)

var programVersion = "0.1.0"

type scanConfiguration struct {
	Path       string
	Workers    int
	MaxBytes   int64
	Usage      string
	Expiration string
	JSON       bool
}

type progressDisplay struct {
	progressOutput    io.Writer
	certificateOutput io.Writer
	showCertificates  bool
	terminal          bool
	started           time.Time

	mu       sync.Mutex
	progress scanner.Progress
	stopped  bool
	writeErr error
	done     chan struct{}
	wait     sync.WaitGroup
}

func newProgressDisplay(progressOutput, certificateOutput io.Writer, showCertificates bool) *progressDisplay {
	return &progressDisplay{
		progressOutput:    progressOutput,
		certificateOutput: certificateOutput,
		showCertificates:  showCertificates,
		terminal:          isTerminal(progressOutput),
		done:              make(chan struct{}),
	}
}

func (display *progressDisplay) Start(configuration scanConfiguration) {
	display.mu.Lock()
	display.started = time.Now()
	path := configuration.Path
	if absolute, err := filepath.Abs(path); err == nil {
		path = absolute
	}
	usage := configuration.Usage
	if usage == "" {
		usage = "all"
	}
	expiration := configuration.Expiration
	if expiration == "" {
		expiration = "none"
	}
	maxBytes := strconv.FormatInt(configuration.MaxBytes, 10)
	if configuration.MaxBytes == 0 {
		maxBytes = "unlimited"
	}
	output := "text"
	if configuration.JSON {
		output = "json"
	}

	display.writeProgress("%s %s\n", programName, programVersion)
	display.writeProgress("Scan path: %s\n", path)
	display.writeProgress("Workers: %d\n", configuration.Workers)
	display.writeProgress(
		"Options: max-bytes=%s usage=%s expiration=%s output=%s\n",
		maxBytes,
		usage,
		expiration,
		output,
	)
	display.writeProgress("\n")
	display.drawStatusLocked()
	display.mu.Unlock()

	display.wait.Add(1)
	go display.refreshLoop()
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
	display.progress.ScanErrors = max(display.progress.ScanErrors, progress.ScanErrors)
	display.progress.DiscoveryComplete = display.progress.DiscoveryComplete || progress.DiscoveryComplete
}

func (display *progressDisplay) Certificate(certificate scanner.Certificate) {
	display.mu.Lock()
	defer display.mu.Unlock()
	if display.stopped || !display.showCertificates {
		return
	}
	if display.terminal {
		display.clearStatusLocked()
	}
	if display.writeErr == nil {
		display.writeErr = printCertificate(display.certificateOutput, certificate)
	}
	display.writeProgress("\n")
	display.drawStatusLocked()
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
	display.writeProgress(
		"%s: %d %s scanned, %d stopped at max-bytes; %d %s found; %d %s; elapsed %s\n",
		state,
		display.progress.FilesScanned,
		plural(display.progress.FilesScanned, "file", "files"),
		display.progress.FilesCapped,
		display.progress.CertificatesFound,
		plural(display.progress.CertificatesFound, "certificate", "certificates"),
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
