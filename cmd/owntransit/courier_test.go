//go:build darwin || linux

package main

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

func TestReadCourierFileRequiresPrivateOwnedSingleLinkRegularFile(t *testing.T) {
	parent := t.TempDir()
	path := filepath.Join(parent, "registration.otreg")
	content := []byte("opaque-registration\n")
	if err := os.WriteFile(path, content, 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := readCourierFile(path, len(content))
	if err != nil || !bytes.Equal(got, content) {
		t.Fatalf("private file read=%q err=%v", got, err)
	}
	if err := os.Chmod(path, 0o640); err != nil {
		t.Fatal(err)
	}
	if _, err := readCourierFile(path, len(content)); err == nil {
		t.Fatal("group-readable courier input accepted")
	}
	if err := os.Chmod(path, 0o600); err != nil {
		t.Fatal(err)
	}
	symlink := filepath.Join(parent, "registration-link.otreg")
	if err := os.Symlink(path, symlink); err != nil {
		t.Fatal(err)
	}
	if _, err := readCourierFile(symlink, len(content)); err == nil {
		t.Fatal("symlinked courier input accepted")
	}
	hardlink := filepath.Join(parent, "registration-hardlink.otreg")
	if err := os.Link(path, hardlink); err != nil {
		t.Fatal(err)
	}
	if _, err := readCourierFile(path, len(content)); err == nil {
		t.Fatal("multiply-linked courier input accepted")
	}
}

func TestCourierOutputRootIsPrivateResumableAndRejectsSymlink(t *testing.T) {
	parent := t.TempDir()
	rootPath := filepath.Join(parent, "courier")
	root, err := createOrOpenCourierRoot(rootPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := root.EnsureFile("opaque", []byte("exact\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := root.Close(); err != nil {
		t.Fatal(err)
	}
	resumed, err := createOrOpenCourierRoot(rootPath)
	if err != nil {
		t.Fatal(err)
	}
	got, err := resumed.ReadFile("opaque", 32)
	if err != nil || string(got) != "exact\n" {
		t.Fatalf("resumed content=%q err=%v", got, err)
	}
	if err := resumed.Close(); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(rootPath)
	if err != nil || info.Mode().Perm() != 0o700 {
		t.Fatalf("root mode=%v err=%v", info.Mode(), err)
	}
	link := filepath.Join(parent, "courier-link")
	if err := os.Symlink(rootPath, link); err != nil {
		t.Fatal(err)
	}
	if opened, err := createOrOpenCourierRoot(link); err == nil {
		_ = opened.Close()
		t.Fatal("symlinked courier output root accepted")
	}
}
