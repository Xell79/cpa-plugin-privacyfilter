// SPDX-License-Identifier: MIT
package main

import (
	"archive/zip"
	"bytes"
	"io"
	"os"
	"path/filepath"
	"testing"
)

func TestPackageLibraryIsDeterministicAndSingleRooted(t *testing.T) {
	dir := t.TempDir()
	libraryPath := filepath.Join(dir, "privacyfilter-v0.3.0.so")
	content := []byte("shared-library-fixture")
	if err := os.WriteFile(libraryPath, content, 0o755); err != nil {
		t.Fatal(err)
	}

	firstPath := filepath.Join(dir, "first.zip")
	secondPath := filepath.Join(dir, "second.zip")
	first, err := packageLibrary(libraryPath, firstPath)
	if err != nil {
		t.Fatal(err)
	}
	second, err := packageLibrary(libraryPath, secondPath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(first, second) {
		t.Fatal("archives differ for identical input")
	}

	reader, err := zip.NewReader(bytes.NewReader(first), int64(len(first)))
	if err != nil {
		t.Fatal(err)
	}
	if len(reader.File) != 1 {
		t.Fatalf("archive entries = %d, want 1", len(reader.File))
	}
	entry := reader.File[0]
	if entry.Name != "privacyfilter.so" {
		t.Fatalf("entry name = %q", entry.Name)
	}
	if entry.Mode().Perm() != 0o755 {
		t.Fatalf("entry mode = %o, want 755", entry.Mode().Perm())
	}
	if !entry.Modified.Equal(archiveEpoch) {
		t.Fatalf("entry timestamp = %s, want %s", entry.Modified, archiveEpoch)
	}
	stream, err := entry.Open()
	if err != nil {
		t.Fatal(err)
	}
	got, err := io.ReadAll(stream)
	if err != nil {
		t.Fatal(err)
	}
	if err = stream.Close(); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, content) {
		t.Fatal("archive entry bytes differ from the input library")
	}
}

func TestArchiveEntryNameUsesCanonicalPlatformNames(t *testing.T) {
	for _, testCase := range []struct {
		path string
		want string
	}{
		{"privacyfilter-v0.3.0.so", "privacyfilter.so"},
		{"privacyfilter-v0.3.0.dylib", "privacyfilter.dylib"},
		{"privacyfilter-v0.3.0.dll", "privacyfilter.dll"},
	} {
		got, err := archiveEntryName(testCase.path)
		if err != nil {
			t.Fatalf("archiveEntryName(%q): %v", testCase.path, err)
		}
		if got != testCase.want {
			t.Fatalf("archiveEntryName(%q) = %q, want %q", testCase.path, got, testCase.want)
		}
	}
	if _, err := archiveEntryName("privacyfilter.a"); err == nil {
		t.Fatal("unsupported library extension was accepted")
	}
}

func TestPackageLibraryRefusesExistingArchive(t *testing.T) {
	dir := t.TempDir()
	libraryPath := filepath.Join(dir, "privacyfilter.so")
	archivePath := filepath.Join(dir, "release.zip")
	if err := os.WriteFile(libraryPath, []byte("library"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(archivePath, []byte("existing"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := packageLibrary(libraryPath, archivePath); err == nil {
		t.Fatal("existing archive was overwritten")
	}
	got, err := os.ReadFile(archivePath)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "existing" {
		t.Fatal("existing archive bytes changed")
	}
}
