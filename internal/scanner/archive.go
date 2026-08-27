package scanner

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"slices"
	"strings"
)

type archiveFormat uint8

const (
	archiveFormatNone archiveFormat = iota
	archiveFormatZIP
	archiveFormatTAR
	archiveFormatGZIP
)

var errArchiveDecompressedBytes = errors.New("archive decompressed byte limit exceeded")

type archiveScanner struct {
	outerPath string
	options   Options
	bytesRead int64
	entries   int
	progress  func(discovered, scanned, capped int64)
}

type archiveBudgetReader struct {
	scanner *archiveScanner
	reader  io.Reader
}

func detectArchiveFormat(data []byte) archiveFormat {
	if len(data) >= 4 && bytes.Equal(data[:4], []byte{'P', 'K', 3, 4}) ||
		len(data) >= 4 && bytes.Equal(data[:4], []byte{'P', 'K', 5, 6}) ||
		len(data) >= 4 && bytes.Equal(data[:4], []byte{'P', 'K', 7, 8}) {
		return archiveFormatZIP
	}
	if len(data) >= 2 && data[0] == 0x1f && data[1] == 0x8b {
		return archiveFormatGZIP
	}
	if len(data) >= 263 && (bytes.Equal(data[257:263], []byte("ustar\x00")) ||
		bytes.Equal(data[257:263], []byte("ustar "))) {
		return archiveFormatTAR
	}
	return archiveFormatNone
}

func scanArchiveFile(
	path string,
	file *os.File,
	format archiveFormat,
	options Options,
	progress func(discovered, scanned, capped int64),
) outcome {
	scanner := archiveScanner{outerPath: path, options: options, progress: progress}
	switch format {
	case archiveFormatZIP:
		info, err := file.Stat()
		if err != nil {
			return scanOutcome(nil, nil, false, err)
		}
		if err := scanner.checkZIPEntryCount(file, info.Size()); err != nil {
			return scanOutcome(nil, nil, false, fmt.Errorf("parse ZIP archive: %w", err))
		}
		reader, err := zip.NewReader(file, info.Size())
		if err != nil {
			return scanOutcome(nil, nil, false, fmt.Errorf("parse ZIP archive: %w", err))
		}
		return scanner.scanZIP(reader, nil, 1)
	case archiveFormatTAR:
		return scanner.scanTAR(tar.NewReader(file), nil, 1)
	case archiveFormatGZIP:
		return scanner.scanGZIP(file, nil, 1)
	default:
		return scanOutcome(nil, nil, false, errors.New("unsupported archive format"))
	}
}

func (scanner *archiveScanner) scanZIP(reader *zip.Reader, parents []string, depth int) outcome {
	var result outcome
	for _, entry := range reader.File {
		entries := appendArchiveEntry(parents, entry.Name)
		if err := scanner.beginEntry(); err != nil {
			mergeScanOutcomes(&result, scanner.errorOutcome(entries, err))
			break
		}
		if entry.FileInfo().IsDir() || !entry.Mode().IsRegular() {
			continue
		}
		if entry.Flags&1 != 0 {
			scanner.finishEntry(false)
			mergeScanOutcomes(&result, scanner.errorOutcome(entries, errors.New("encrypted ZIP entry is unsupported")))
			continue
		}
		content, err := entry.Open()
		if err != nil {
			scanner.finishEntry(false)
			mergeScanOutcomes(&result, scanner.errorOutcome(entries, fmt.Errorf("open ZIP entry: %w", err)))
			continue
		}
		entryResult, capped := scanner.scanEntry(content, entries, depth)
		closeErr := content.Close()
		if closeErr != nil {
			mergeScanOutcomes(&entryResult, scanner.errorOutcome(entries, fmt.Errorf("close ZIP entry: %w", closeErr)))
		}
		scanner.finishEntry(capped)
		mergeScanOutcomes(&result, entryResult)
		if entryResult.err != nil && errors.Is(entryResult.err.Err, errArchiveDecompressedBytes) {
			return result
		}
	}
	return result
}

func (scanner *archiveScanner) scanTAR(reader *tar.Reader, parents []string, depth int) outcome {
	var result outcome
	for {
		header, err := reader.Next()
		if errors.Is(err, io.EOF) {
			return result
		}
		if err != nil {
			mergeScanOutcomes(&result, scanner.errorOutcome(parents, fmt.Errorf("parse TAR archive: %w", err)))
			return result
		}
		entries := appendArchiveEntry(parents, header.Name)
		if err := scanner.beginEntry(); err != nil {
			mergeScanOutcomes(&result, scanner.errorOutcome(entries, err))
			return result
		}
		if !header.FileInfo().Mode().IsRegular() {
			continue
		}
		entryResult, capped := scanner.scanEntry(reader, entries, depth)
		scanner.finishEntry(capped)
		mergeScanOutcomes(&result, entryResult)
		if entryResult.err != nil && errors.Is(entryResult.err.Err, errArchiveDecompressedBytes) {
			return result
		}
	}
}

func (scanner *archiveScanner) scanGZIP(reader io.Reader, parents []string, depth int) outcome {
	gzipReader, err := gzip.NewReader(reader)
	if err != nil {
		return scanner.errorOutcome(parents, fmt.Errorf("parse gzip archive: %w", err))
	}
	name := gzipReader.Name
	if name == "" {
		name = defaultGZIPEntryName(scanner.outerPath, parents)
	}
	entries := appendArchiveEntry(parents, name)
	if err := scanner.beginEntry(); err != nil {
		_ = gzipReader.Close()
		return scanner.errorOutcome(entries, err)
	}
	result, capped := scanner.scanEntry(gzipReader, entries, depth)
	if err := gzipReader.Close(); err != nil {
		mergeScanOutcomes(&result, scanner.errorOutcome(entries, fmt.Errorf("close gzip archive: %w", err)))
	}
	scanner.finishEntry(capped)
	return result
}

func (scanner *archiveScanner) scanEntry(reader io.Reader, entries []string, depth int) (outcome, bool) {
	prefix, overflow, complete, err := scanner.readPrefix(reader)
	if err != nil {
		partial, _ := scanContentData(scanner.outerPath, prefix, false)
		attachArchiveEntries(&partial, entries)
		mergeScanOutcomes(&partial, scanner.errorOutcome(entries, err))
		return partial, false
	}

	format := detectArchiveFormat(prefix)
	if format != archiveFormatNone {
		if depth >= scanner.options.ArchiveMaxDepth {
			return scanner.errorOutcome(
				entries,
				fmt.Errorf("archive nesting depth exceeds %d", scanner.options.ArchiveMaxDepth),
			), false
		}
		data := prefix
		if !complete {
			data, err = scanner.readFullEntry(prefix, overflow, reader)
			if err != nil {
				return scanner.errorOutcome(entries, err), false
			}
		}
		return scanner.scanArchiveBytes(data, format, entries, depth+1), false
	}

	result, needsFullRead := scanContentData(scanner.outerPath, prefix, complete)
	if needsFullRead {
		data, readErr := scanner.readFullEntry(prefix, overflow, reader)
		if readErr != nil {
			attachArchiveEntries(&result, entries)
			mergeScanOutcomes(&result, scanner.errorOutcome(entries, readErr))
			return result, false
		}
		result, _ = scanContentData(scanner.outerPath, data, true)
	}
	attachArchiveEntries(&result, entries)
	return result, !complete && !needsFullRead
}

func (scanner *archiveScanner) scanArchiveBytes(
	data []byte,
	format archiveFormat,
	parents []string,
	depth int,
) outcome {
	switch format {
	case archiveFormatZIP:
		dataReader := bytes.NewReader(data)
		if err := scanner.checkZIPEntryCount(dataReader, int64(len(data))); err != nil {
			return scanner.errorOutcome(parents, fmt.Errorf("parse ZIP archive: %w", err))
		}
		reader, err := zip.NewReader(dataReader, int64(len(data)))
		if err != nil {
			return scanner.errorOutcome(parents, fmt.Errorf("parse ZIP archive: %w", err))
		}
		return scanner.scanZIP(reader, parents, depth)
	case archiveFormatTAR:
		return scanner.scanTAR(tar.NewReader(bytes.NewReader(data)), parents, depth)
	case archiveFormatGZIP:
		return scanner.scanGZIP(bytes.NewReader(data), parents, depth)
	default:
		return scanner.errorOutcome(parents, errors.New("unsupported nested archive format"))
	}
}

func (scanner *archiveScanner) checkZIPEntryCount(reader io.ReaderAt, size int64) error {
	const (
		endRecordSize       = 22
		maximumCommentBytes = 1<<16 - 1
	)
	tailSize := min(size, endRecordSize+maximumCommentBytes)
	if tailSize < endRecordSize {
		return errors.New("ZIP end-of-central-directory record is missing")
	}
	tail := make([]byte, tailSize)
	if _, err := reader.ReadAt(tail, size-tailSize); err != nil {
		return fmt.Errorf("read ZIP directory footer: %w", err)
	}
	for offset := len(tail) - endRecordSize; offset >= 0; offset-- {
		if binary.LittleEndian.Uint32(tail[offset:offset+4]) != 0x06054b50 {
			continue
		}
		commentBytes := int(binary.LittleEndian.Uint16(tail[offset+20 : offset+22]))
		if offset+endRecordSize+commentBytes != len(tail) {
			continue
		}
		entryCount := uint64(binary.LittleEndian.Uint16(tail[offset+10 : offset+12]))
		if entryCount == 1<<16-1 {
			zip64Count, err := readZIP64EntryCount(reader, size-tailSize+int64(offset))
			if err == nil {
				entryCount = zip64Count
			}
		}
		remainingEntries := scanner.options.ArchiveMaxEntries - scanner.entries
		remainingEntryLimit := uint64(remainingEntries) //nolint:gosec // Validated positive limits keep this nonnegative.
		if entryCount > remainingEntryLimit {
			return fmt.Errorf(
				"ZIP entry count %d exceeds remaining archive entry limit %d",
				entryCount,
				remainingEntries,
			)
		}
		return nil
	}
	return errors.New("ZIP end-of-central-directory record is missing")
}

func readZIP64EntryCount(reader io.ReaderAt, endRecordOffset int64) (uint64, error) {
	const (
		locatorSize       = 20
		zip64EndFixedSize = 56
	)
	if endRecordOffset < locatorSize {
		return 0, errors.New("ZIP64 locator is missing")
	}
	var locator [locatorSize]byte
	if _, err := reader.ReadAt(locator[:], endRecordOffset-locatorSize); err != nil {
		return 0, err
	}
	if binary.LittleEndian.Uint32(locator[:4]) != 0x07064b50 {
		return 0, errors.New("ZIP64 locator is missing")
	}
	encodedOffset := binary.LittleEndian.Uint64(locator[8:16])
	if encodedOffset > 1<<63-1 {
		return 0, errors.New("ZIP64 directory offset exceeds the supported file size")
	}
	zip64Offset := int64(encodedOffset)
	var endRecord [zip64EndFixedSize]byte
	if _, err := reader.ReadAt(endRecord[:], zip64Offset); err != nil {
		return 0, err
	}
	if binary.LittleEndian.Uint32(endRecord[:4]) != 0x06064b50 {
		return 0, errors.New("ZIP64 end-of-central-directory record is missing")
	}
	return binary.LittleEndian.Uint64(endRecord[32:40]), nil
}

func (scanner *archiveScanner) readPrefix(reader io.Reader) ([]byte, []byte, bool, error) {
	budgeted := &archiveBudgetReader{scanner: scanner, reader: reader}
	if scanner.options.MaxBytes == 0 {
		data, err := io.ReadAll(budgeted)
		return data, nil, err == nil, err
	}
	prefixLimit := scanner.options.MaxBytes
	if prefixLimit < int64(1<<63-1) {
		prefixLimit++
	}
	data, err := io.ReadAll(io.LimitReader(budgeted, prefixLimit))
	if err != nil {
		return data, nil, false, err
	}
	if int64(len(data)) <= scanner.options.MaxBytes {
		return data, nil, true, nil
	}
	return data[:scanner.options.MaxBytes], data[scanner.options.MaxBytes:], false, nil
}

func (scanner *archiveScanner) readFullEntry(prefix, overflow []byte, reader io.Reader) ([]byte, error) {
	result := make([]byte, 0, len(prefix)+len(overflow))
	result = append(result, prefix...)
	result = append(result, overflow...)
	remainder, err := io.ReadAll(&archiveBudgetReader{scanner: scanner, reader: reader})
	result = append(result, remainder...)
	return result, err
}

func (reader *archiveBudgetReader) Read(buffer []byte) (int, error) {
	remaining := reader.scanner.options.ArchiveMaxBytes - reader.scanner.bytesRead
	if remaining <= 0 {
		var probe [1]byte
		count, err := reader.reader.Read(probe[:])
		if count > 0 {
			return 0, fmt.Errorf(
				"%w (maximum %d bytes)",
				errArchiveDecompressedBytes,
				reader.scanner.options.ArchiveMaxBytes,
			)
		}
		return 0, err
	}
	if int64(len(buffer)) > remaining {
		buffer = buffer[:remaining]
	}
	count, err := reader.reader.Read(buffer)
	reader.scanner.bytesRead += int64(count)
	return count, err
}

func (scanner *archiveScanner) beginEntry() error {
	scanner.entries++
	if scanner.progress != nil {
		scanner.progress(1, 0, 0)
	}
	if scanner.entries > scanner.options.ArchiveMaxEntries {
		return fmt.Errorf("archive entry count exceeds %d", scanner.options.ArchiveMaxEntries)
	}
	return nil
}

func (scanner *archiveScanner) finishEntry(capped bool) {
	if scanner.progress == nil {
		return
	}
	var cappedCount int64
	if capped {
		cappedCount = 1
	}
	scanner.progress(0, 1, cappedCount)
}

func (scanner *archiveScanner) errorOutcome(entries []string, err error) outcome {
	if len(entries) > 0 {
		err = fmt.Errorf("archive entry %q: %w", strings.Join(entries, ":"), err)
	}
	return scanOutcome(nil, nil, false, err)
}

func mergeScanOutcomes(target *outcome, source outcome) {
	target.certificates = append(target.certificates, source.certificates...)
	target.pkcs12Encrypted = append(target.pkcs12Encrypted, source.pkcs12Encrypted...)
	if source.err == nil {
		return
	}
	if target.err == nil {
		target.err = &FileError{Err: source.err.Err}
		return
	}
	target.err.Err = errors.Join(target.err.Err, source.err.Err)
}

func attachArchiveEntries(result *outcome, entries []string) {
	for index := range result.certificates {
		result.certificates[index].ArchiveEntries = slices.Clone(entries)
	}
	for index := range result.pkcs12Encrypted {
		result.pkcs12Encrypted[index].ArchiveEntries = slices.Clone(entries)
	}
}

func appendArchiveEntry(parents []string, name string) []string {
	name = path.Clean(filepath.ToSlash(name))
	if name == "." || name == "" {
		name = "(unnamed)"
	}
	return append(slices.Clone(parents), name)
}

func defaultGZIPEntryName(outerPath string, parents []string) string {
	name := filepath.Base(outerPath)
	if len(parents) > 0 {
		name = path.Base(parents[len(parents)-1])
	}
	if strings.HasSuffix(strings.ToLower(name), ".gz") {
		name = name[:len(name)-3]
	}
	if name == "" || name == "." {
		return "content"
	}
	return name
}
