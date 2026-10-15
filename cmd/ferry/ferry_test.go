package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestExcluder(t *testing.T) {
	e := newExcluder([]string{"/proc", "/home/*/.cache", "/etc/ssh/ssh_host_*"})
	cases := map[string]bool{
		"/proc":                     true,
		"/proc/1/status":            true,
		"/processes":                false,
		"/home/bob/.cache/x":        true,
		"/home/bob/docs":            false,
		"/etc/ssh/ssh_host_rsa_key": true,
		"/etc/ssh/sshd_config":      false,
	}
	for p, want := range cases {
		if got := e.match(p); got != want {
			t.Errorf("match(%q) = %v, want %v", p, got, want)
		}
	}
}

func TestParseHexAddr(t *testing.T) {
	addr, port, ok := parseHexAddr("0100007F:1F90", false)
	if !ok || addr != "127.0.0.1" || port != 8080 {
		t.Fatalf("ipv4: %q %d %v", addr, port, ok)
	}
	addr, port, ok = parseHexAddr("00000000000000000000000001000000:0050", true)
	if !ok || addr != "::1" || port != 80 {
		t.Fatalf("ipv6: %q %d %v", addr, port, ok)
	}
	if _, _, ok := parseHexAddr("zz:1", false); ok {
		t.Fatal("мусор должен отвергаться")
	}
}

func TestTarModeToFileMode(t *testing.T) {
	if got := tarModeToFileMode(04755); got != 0755|os.ModeSetuid {
		t.Errorf("suid: %v", got)
	}
	if got := tarModeToFileMode(01777); got != 0777|os.ModeSticky {
		t.Errorf("sticky: %v", got)
	}
	if got := tarModeToFileMode(0644); got != 0644 {
		t.Errorf("plain: %v", got)
	}
}

func TestDetectFamily(t *testing.T) {
	cases := []struct{ id, like, want string }{
		{"debian", "", "debian"},
		{"ubuntu", "debian", "debian"},
		{"rocky", "rhel centos fedora", "rhel"},
		{"opensuse-leap", "suse opensuse", "suse"},
		{"arch", "", "arch"},
		{"manjaro", "arch", "arch"},
		{"alpine", "", "alpine"},
		{"weird", "", "unknown"},
	}
	for _, c := range cases {
		if got := detectFamily(c.id, c.like); got != c.want {
			t.Errorf("detectFamily(%q,%q) = %q, want %q", c.id, c.like, got, c.want)
		}
	}
}

func TestReleaseKey(t *testing.T) {
	cases := []struct {
		h    HostInfo
		want string
	}{
		{HostInfo{OSID: "debian", OSVersion: "12"}, "debian:12"},
		{HostInfo{OSID: "ubuntu", OSVersion: "22.04"}, "ubuntu:22.04"},
		{HostInfo{OSID: "rocky", OSVersion: "9.3"}, "rocky:9"},
		{HostInfo{OSID: "alpine", OSVersion: "3.19.1"}, "alpine:3.19"},
	}
	for _, c := range cases {
		if got := releaseKey(c.h); got != c.want {
			t.Errorf("releaseKey(%+v) = %q, want %q", c.h, got, c.want)
		}
	}
}

func TestCrossLevel(t *testing.T) {
	deb := HostInfo{OSID: "debian", Family: "debian"}
	ubu := HostInfo{OSID: "ubuntu", Family: "debian"}
	roc := HostInfo{OSID: "rocky", Family: "rhel"}
	if crossLevel(deb, deb) != 0 || crossLevel(deb, ubu) != 1 || crossLevel(deb, roc) != 2 {
		t.Fatal("неверные уровни кросс-дистрибутивности")
	}
}

func TestPkgMapTranslate(t *testing.T) {
	m, err := newMapper("")
	if err != nil {
		t.Fatal(err)
	}
	check := func(name, src, dst string, want []string, wantSkip bool) {
		t.Helper()
		got, skip := m.translate(name, src, dst)
		if skip != wantSkip || strings.Join(got, " ") != strings.Join(want, " ") {
			t.Errorf("translate(%q,%s→%s) = %v skip=%v, want %v skip=%v", name, src, dst, got, skip, want, wantSkip)
		}
	}
	check("apache2", "debian", "rhel", []string{"httpd"}, false)
	check("httpd", "rhel", "debian", []string{"apache2"}, false)
	check("build-essential", "debian", "rhel", []string{"gcc", "gcc-c++", "make"}, false)
	check("nginx", "debian", "arch", []string{"nginx"}, false)
	check("nginx", "debian", "debian", []string{"nginx"}, false)
	check("php8.2-fpm", "debian", "rhel", []string{"php-fpm"}, false)
	check("python3-requests", "debian", "arch", []string{"python-requests"}, false)
	check("libfoo-dev", "debian", "rhel", []string{"libfoo-devel"}, false)
	check("ufw", "debian", "rhel", nil, true)
}

func TestPkgMapCustomOverride(t *testing.T) {
	m, err := newMapper("mytool | mytool-rpm | - | - | -")
	if err != nil {
		t.Fatal(err)
	}
	got, _ := m.translate("mytool", "debian", "rhel")
	if len(got) != 1 || got[0] != "mytool-rpm" {
		t.Fatalf("custom row: %v", got)
	}
	if _, err := newMapper("broken | line"); err == nil {
		t.Fatal("ожидалась ошибка разбора")
	}
}

func TestApkSplit(t *testing.T) {
	n, v, ok := apkSplit("nginx-1.24.0-r0")
	if !ok || n != "nginx" || v != "1.24.0-r0" {
		t.Errorf("nginx: %q %q %v", n, v, ok)
	}
	n, _, ok = apkSplit("py3-requests-2.31.0-r1")
	if !ok || n != "py3-requests" {
		t.Errorf("py3-requests: %q %v", n, ok)
	}
	if _, _, ok := apkSplit("nonsense"); ok {
		t.Error("nonsense не должен разбираться")
	}
}

func TestUnitCandidates(t *testing.T) {
	c := unitCandidates("apache2.service")
	if len(c) < 2 || c[0] != "apache2.service" || c[1] != "httpd.service" {
		t.Errorf("apache2: %v", c)
	}
	if normalizeUnit("openrc", "sshd.service") != "sshd" || normalizeUnit("systemd", "sshd") != "sshd.service" {
		t.Error("normalizeUnit")
	}
	if c := unitCandidates("php8.2-fpm.service"); c[len(c)-1] != "php-fpm.service" {
		t.Errorf("php-fpm: %v", c)
	}
}

func TestSafeDst(t *testing.T) {
	dir := t.TempDir()
	if _, err := safeDst(dir, "/a/b"); err != nil {
		t.Fatalf("обычный путь: %v", err)
	}
	if err := os.Symlink("/tmp", filepath.Join(dir, "a")); err != nil {
		t.Skip("симлинки недоступны")
	}
	if _, err := safeDst(dir, "/a/b"); err == nil {
		t.Fatal("симлинк в пути должен отвергаться")
	}
}

func TestVerifyTrailer(t *testing.T) {
	trailer := []byte(`{"/a":"x","/b":"y","/c":"z"}`)
	sums := map[string]string{"/a": "x", "/b": "WRONG"}
	mm, err := verifyTrailer(trailer, sums, map[string]bool{"/c": true})
	if err != nil {
		t.Fatal(err)
	}
	if len(mm) != 1 || !strings.HasPrefix(mm[0], "/b") {
		t.Fatalf("mismatches: %v", mm)
	}
	if _, err := verifyTrailer(nil, sums, nil); err == nil {
		t.Fatal("отсутствие трейлера должно быть ошибкой")
	}
}

func TestFixShellFallback(t *testing.T) {
	if got := fixShell("/definitely/missing/nologin"); got == "" || got == "/definitely/missing/nologin" {
		t.Errorf("fixShell: %q", got)
	}
}
