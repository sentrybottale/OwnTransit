//go:build darwin

package development

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// Run under an explicitly supplied private fixture parent, never the real
// user's HOME. The child's HOME environment is not changed. Only the source
// copy's user_home and asset fetch locations are substituted; signature,
// inventory, metadata, install/upgrade and uninstall logic remain real.
func TestMacInstallerIsolatedLifecycle(t *testing.T) {
	parent := os.Getenv("OWNTRANSIT_MAC_INSTALL_TEST_ROOT")
	if parent == "" {
		t.Skip("set OWNTRANSIT_MAC_INSTALL_TEST_ROOT to a private fixture parent")
	}
	root, err := os.MkdirTemp(parent, "mac-install-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(root)
	root, err = filepath.EvalSymlinks(root)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(root, 0700); err != nil {
		t.Fatal(err)
	}
	assets := filepath.Join(root, "assets")
	home := filepath.Join(root, "fixture home")
	for _, p := range []string{assets, home} {
		if err := os.Mkdir(p, 0700); err != nil {
			t.Fatal(err)
		}
	}
	write := func(path string, b []byte, mode os.FileMode) {
		t.Helper()
		if err := os.WriteFile(path, b, mode); err != nil {
			t.Fatal(err)
		}
	}
	key := filepath.Join(root, "fixture-key")
	if out, err := exec.Command("ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", key).CombinedOutput(); err != nil {
		t.Fatalf("key fixture: %v %s", err, out)
	}
	public, err := os.ReadFile(key + ".pub")
	if err != nil {
		t.Fatal(err)
	}
	write(filepath.Join(assets, "distribution-public.key"), public, 0600)
	source, err := os.ReadFile("../../install-preview-macos.sh")
	if err != nil {
		t.Fatal(err)
	}
	top := "owntransit-preview-0.6.1-darwin-arm64"
	files := map[string][]byte{
		"CAPSULE": []byte("schema=owntransit.development-capsule.v1\nversion=0.6.1\nos=darwin\narch=arm64\n"),
		"LICENSE": []byte("fixture license\n"), "NOTICE": []byte("fixture notices\n"),
		"owntransit": []byte("#!/bin/sh\nprintf 'fixture-client\\n'\n"), "install-macos.sh": source,
	}
	var sums strings.Builder
	var names []string
	for name := range files {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		fmt.Fprintf(&sums, "%x  %s\n", sha256.Sum256(files[name]), name)
	}
	files["SHA256SUMS"] = []byte(sums.String())
	names = append(names, "SHA256SUMS")
	sort.Strings(names)
	var archive bytes.Buffer
	gz := gzip.NewWriter(&archive)
	tw := tar.NewWriter(gz)
	if err := tw.WriteHeader(&tar.Header{Name: top + "/", Mode: 0700, Typeflag: tar.TypeDir}); err != nil {
		t.Fatal(err)
	}
	for _, name := range names {
		mode := int64(0644)
		if name == "owntransit" || name == "install-macos.sh" {
			mode = 0755
		}
		if err := tw.WriteHeader(&tar.Header{Name: top + "/" + name, Mode: mode, Size: int64(len(files[name]))}); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write(files[name]); err != nil {
			t.Fatal(err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	write(filepath.Join(assets, top+".tar.gz"), archive.Bytes(), 0600)
	members := []string{"DEVELOPMENT.txt", "install-preview-linux.sh", "install-preview-macos.sh", top + ".tar.gz", "owntransit-preview-0.6.1-linux-amd64.tar.gz", "owntransit-preview-0.6.1-linux-arm64.tar.gz"}
	sort.Strings(members)
	sums.Reset()
	for _, name := range members {
		payload := []byte("unused fixture")
		if name == top+".tar.gz" {
			payload = archive.Bytes()
		}
		fmt.Fprintf(&sums, "%x  %s\n", sha256.Sum256(payload), name)
	}
	inventory := filepath.Join(assets, "DEVELOPMENT-SHA256SUMS")
	write(inventory, []byte(sums.String()), 0600)
	if out, err := exec.Command("ssh-keygen", "-Y", "sign", "-f", key, "-n", "owntransit-development-v1", inventory).CombinedOutput(); err != nil {
		t.Fatalf("signature fixture: %v %s", err, out)
	}
	quote := func(s string) string { return "'" + strings.ReplaceAll(s, "'", "'\"'\"'") + "'" }
	shim := strings.Replace(string(source), "user_home=${HOME:?HOME is required}", "user_home="+quote(home), 1)
	shim = strings.Replace(shim, "55d97d90f4b81628aa534ba28960b63685ea5d1d4eeef489ffb28de632dc0a9e", fmt.Sprintf("%x", sha256.Sum256(public)), 1)
	shim = regexp.MustCompile(`(?s)fetch\(\) \{.*?\n\}`).ReplaceAllStringFunc(shim, func(string) string { return "fetch() { cp " + quote(assets) + "/\"$1\" \"$stage/$1\"; }" })
	script := filepath.Join(root, "installer.sh")
	write(script, []byte(shim), 0700)
	run := func(success bool, args ...string) string {
		t.Helper()
		out, err := exec.Command("sh", append([]string{script}, args...)...).CombinedOutput()
		if (err == nil) != success {
			t.Fatalf("installer success=%t: %v\n%s", success, err, out)
		}
		return string(out)
	}
	// Tampering must fail before any installed command is created.
	write(filepath.Join(assets, top+".tar.gz"), []byte("tampered"), 0600)
	run(false, "client")
	alias := filepath.Join(home, ".local/bin/owntransit-preview")
	if _, err := os.Lstat(alias); !os.IsNotExist(err) {
		t.Fatal("tampered archive installed")
	}
	write(filepath.Join(assets, top+".tar.gz"), archive.Bytes(), 0600)
	out := run(true, "client")
	if !strings.Contains(out, "NEXT — on THIS Mac, without sudo:\n  '") || !strings.Contains(out, "--uninstall") || !strings.Contains(out, "not the public VPS") {
		t.Fatal("missing actionable commands")
	}
	if !strings.Contains(out, "your relay URL and the private receiver code (otpair2.)") || strings.Contains(out, "otrelay1.") {
		t.Fatal("installer did not describe the one-code setup")
	}
	run(true, "client") // exact reinstall
	software := filepath.Join(home, "Library/Application Support/OwnTransitSoftware")
	for _, previousVersion := range []string{"0.2.0", "0.3.0", "0.4.0", "0.5.0", "0.6.0"} {
		previous := filepath.Join(software, previousVersion)
		if err := os.Rename(filepath.Join(software, "0.6.1"), previous); err != nil {
			t.Fatal(err)
		}
		write(filepath.Join(previous, "CAPSULE"), []byte(fmt.Sprintf("schema=owntransit.development-capsule.v1\nversion=%s\nos=darwin\narch=arm64\n", previousVersion)), 0644)
		for _, command := range []string{alias, filepath.Join(home, ".local/bin/owntransit")} {
			if err := os.Remove(command); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(filepath.Join(previous, "owntransit"), command); err != nil {
				t.Fatal(err)
			}
		}
		run(true, "client") // Known prior package upgrades without overwriting other commands.
		for _, command := range []string{alias, filepath.Join(home, ".local/bin/owntransit")} {
			if to, err := os.Readlink(command); err != nil || to != filepath.Join(software, "0.6.1/owntransit") {
				t.Fatal("upgrade failed to select new client")
			}
		}
		if _, err := os.Stat(filepath.Join(previous, "owntransit")); err != nil {
			t.Fatal("upgrade removed previous software")
		}
	}
	state := filepath.Join(home, "Library/Application Support/owntransit-pair")
	if err := os.Mkdir(state, 0700); err != nil {
		t.Fatal(err)
	}
	write(filepath.Join(state, "retained"), []byte("state fixture"), 0600)
	// An unrelated command is never replaced by uninstall/reinstall.
	normal := filepath.Join(home, ".local/bin/owntransit")
	if err := os.Remove(normal); err != nil {
		t.Fatal(err)
	}
	write(normal, []byte("unmanaged"), 0600)
	run(true, "--uninstall")
	if b, err := os.ReadFile(normal); err != nil || string(b) != "unmanaged" {
		t.Fatal("unmanaged command removed")
	}
	if b, err := os.ReadFile(filepath.Join(state, "retained")); err != nil || string(b) != "state fixture" {
		t.Fatal("pairing state removed")
	}
	run(true, "client")
	if _, err := os.Lstat(alias); err != nil {
		t.Fatal("reinstall failed")
	}
	run(true, "--uninstall")
}
