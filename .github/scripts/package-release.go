// SPDX-License-Identifier: MIT
package main

import (
	"archive/zip"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"
)

const pluginID = "privacyfilter"

var archiveEpoch = time.Date(1980, time.January, 1, 0, 0, 0, 0, time.UTC)

func main() {
	libraryPath := flag.String("library", "", "path to the compiled plugin library")
	archivePath := flag.String("archive", "", "path to the output zip archive")
	checksumPath := flag.String("checksum", "", "path to the output checksum file")
	flag.Parse()

	if *libraryPath == "" || *archivePath == "" || *checksumPath == "" {
		fatalf("library, archive, and checksum are required")
	}
	archiveData, err := packageLibrary(*libraryPath, *archivePath)
	if err != nil {
		fatalf("%v", err)
	}
	checksum := sha256.Sum256(archiveData)
	line := fmt.Sprintf("%s  %s\n", hex.EncodeToString(checksum[:]), filepath.Base(*archivePath))
	if err := writeExclusive(*checksumPath, []byte(line), 0o644); err != nil {
		_ = os.Remove(*archivePath)
		fatalf("write checksum: %v", err)
	}
}

func packageLibrary(libraryPath, archivePath string) ([]byte, error) {
	library, err := os.Open(libraryPath)
	if err != nil {
		return nil, fmt.Errorf("open library: %w", err)
	}
	defer library.Close()

	info, err := library.Stat()
	if err != nil {
		return nil, fmt.Errorf("stat library: %w", err)
	}
	if !info.Mode().IsRegular() {
		return nil, errors.New("library is not a regular file")
	}

	entryName, err := archiveEntryName(libraryPath)
	if err != nil {
		return nil, err
	}

	var archive bytes.Buffer
	writer := zip.NewWriter(&archive)
	header := &zip.FileHeader{Name: entryName, Method: zip.Deflate}
	header.SetMode(0o755)
	header.SetModTime(archiveEpoch)
	entry, err := writer.CreateHeader(header)
	if err != nil {
		return nil, fmt.Errorf("create zip entry: %w", err)
	}
	if _, err = io.Copy(entry, library); err != nil {
		return nil, fmt.Errorf("copy library: %w", err)
	}
	if err = writer.Close(); err != nil {
		return nil, fmt.Errorf("close zip writer: %w", err)
	}

	data := archive.Bytes()
	if err = writeExclusive(archivePath, data, 0o644); err != nil {
		return nil, fmt.Errorf("write archive: %w", err)
	}
	return data, nil
}

func archiveEntryName(libraryPath string) (string, error) {
	extension := filepath.Ext(libraryPath)
	switch extension {
	case ".so", ".dylib", ".dll":
		return pluginID + extension, nil
	default:
		return "", fmt.Errorf("unsupported plugin library extension: %q", extension)
	}
}

func writeExclusive(path string, data []byte, mode os.FileMode) error {
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
	if err != nil {
		return err
	}
	if _, err = file.Write(data); err != nil {
		_ = file.Close()
		_ = os.Remove(path)
		return err
	}
	if err = file.Close(); err != nil {
		_ = os.Remove(path)
		return err
	}
	return nil
}

func fatalf(format string, args ...any) {
	fmt.Fprintf(os.Stderr, format+"\n", args...)
	os.Exit(1)
}
