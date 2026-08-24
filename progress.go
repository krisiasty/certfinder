package main

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
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
	maxBytes := fmt.Sprintf("%d", configuration.MaxBytes)
	if configuration.MaxBytes == 0 {
		maxBytes = "unlimited"
	}
	output := "text"
	if configuration.JSON {
		output = "json"
	}

	fmt.Fprintf(display.progressOutput, "%s %s\n", programName, programVersion)
	fmt.Fprintf(display.progressOutput, "Scan path: %s\n", path)
	fmt.Fprintf(display.progressOutput, "Workers: %d\n", configuration.Workers)
	fmt.Fprintf(display.progressOutput, "Options: max-bytes=%s usage=%s expiration=%s output=%s\n", maxBytes, usage, expiration, output)
	fmt.Fprintln(display.progressOutput)
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
	printCertificate(display.certificateOutput, certificate)
	fmt.Fprintln(display.progressOutput)
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
	fmt.Fprintf(
		display.progressOutput,
		"%s: %d/%d files scanned; %d certificates found; %d errors; elapsed %s\n",
		state,
		display.progress.FilesScanned,
		display.progress.FilesDiscovered,
		display.progress.CertificatesFound,
		display.progress.ScanErrors,
		elapsed,
	)
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
		"Scanning: %d/%d files scanned; %d pending; %d certificates found; %s",
		display.progress.FilesScanned,
		display.progress.FilesDiscovered,
		pending,
		display.progress.CertificatesFound,
		discovery,
	)
	if display.terminal {
		fmt.Fprint(display.progressOutput, status)
		return
	}
	fmt.Fprintln(display.progressOutput, status)
}

func (display *progressDisplay) clearStatusLocked() {
	fmt.Fprint(display.progressOutput, "\r\x1b[2K")
}

func isTerminal(output io.Writer) bool {
	file, ok := output.(*os.File)
	if !ok {
		return false
	}
	info, err := file.Stat()
	return err == nil && info.Mode()&os.ModeCharDevice != 0
}
