package main

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

// PkgMgr — всё, что нужно знать о пакетной системе конкретного семейства.
type PkgMgr interface {
	Name() string
	// List возвращает установленные пакеты; Manual=true для поставленных вручную.
	List() ([]Package, error)
	// Candidates делит имена на доступные в репозиториях и отсутствующие.
	Candidates(names []string) (ok, missing []string)
	// Install ставит пакеты (сначала пачкой, при ошибке по одному), возвращает не установившиеся.
	Install(w io.Writer, logf logFn, names []string) []string
	// Refresh обновляет метаданные репозиториев.
	Refresh(w io.Writer) error
	// RepoPrefixes — пути конфигурации репозиториев.
	RepoPrefixes() []string
	// EtcCustom выбирает в /etc то, что не поставляется пакетами или изменено админом.
	EtcCustom(ex, nv *excluder) ([]string, []string)
}

func newPkgMgr(pm string) PkgMgr {
	switch pm {
	case "apt":
		return aptMgr{}
	case "dnf", "yum":
		return rpmMgr{bin: pm}
	case "zypper":
		return rpmMgr{bin: "zypper"}
	case "pacman":
		return pacmanMgr{}
	case "apk":
		return apkMgr{}
	}
	return noMgr{}
}

func installWith(logf logFn, names []string, run func([]string) error) []string {
	err := run(names)
	if err == nil {
		return nil
	}
	logf("   пакетная установка не удалась (%v), пробую по одному", err)
	var bad []string
	for _, n := range names {
		if err := run([]string{n}); err != nil {
			bad = append(bad, n)
		}
	}
	return bad
}

func splitAvail(names []string, avail map[string]bool) (ok, missing []string) {
	for _, n := range names {
		if avail[n] {
			ok = append(ok, n)
		} else {
			missing = append(missing, n)
		}
	}
	return ok, missing
}

// ---------- неизвестная система ----------

type noMgr struct{}

func (noMgr) Name() string { return "none" }
func (noMgr) List() ([]Package, error) {
	return nil, fmt.Errorf("неизвестный пакетный менеджер (семейство дистрибутива не определено)")
}
func (noMgr) Candidates(names []string) ([]string, []string) { return nil, names }
func (noMgr) Install(w io.Writer, logf logFn, names []string) []string {
	return names
}
func (noMgr) Refresh(w io.Writer) error                          { return nil }
func (noMgr) RepoPrefixes() []string                             { return nil }
func (noMgr) EtcCustom(ex, nv *excluder) ([]string, []string) { return nil, nil }

// ---------- apt (Debian, Ubuntu, Mint ...) ----------

type aptMgr struct{}

func (aptMgr) Name() string { return "apt" }

func (aptMgr) List() ([]Package, error) {
	out, err := runStdout(60*time.Second, "dpkg-query", "-W", "-f=${Package}\t${Version}\t${Architecture}\t${db:Status-Abbrev}\n")
	if err != nil {
		return nil, fmt.Errorf("dpkg-query: %w", err)
	}
	manual := map[string]bool{}
	if mo, err := runStdout(60*time.Second, "apt-mark", "showmanual"); err == nil {
		for _, l := range strings.Fields(mo) {
			manual[l] = true
		}
	}
	var pkgs []Package
	for _, line := range strings.Split(out, "\n") {
		f := strings.Split(line, "\t")
		if len(f) < 4 || !strings.HasPrefix(strings.TrimSpace(f[3]), "ii") {
			continue
		}
		pkgs = append(pkgs, Package{Name: f[0], Version: f[1], Arch: f[2], Manual: manual[f[0]]})
	}
	return pkgs, nil
}

func (aptMgr) Candidates(names []string) (ok, missing []string) {
	args := append([]string{"policy"}, names...)
	out, _ := runStdout(3*time.Minute, "apt-cache", args...)
	avail := map[string]bool{}
	cur := ""
	for _, line := range strings.Split(out, "\n") {
		if line == "" {
			continue
		}
		if !strings.HasPrefix(line, " ") && strings.HasSuffix(line, ":") {
			cur = strings.TrimSuffix(line, ":")
			continue
		}
		t := strings.TrimSpace(line)
		if cur != "" && strings.HasPrefix(t, "Candidate:") {
			if c := strings.TrimSpace(strings.TrimPrefix(t, "Candidate:")); c != "" && c != "(none)" {
				avail[cur] = true
			}
		}
	}
	return splitAvail(names, avail)
}

// На время установки запрещаем автозапуск демонов (policy-rc.d), чтобы сервисы
// не стартовали с дефолтными конфигами до того, как приедут наши.
func (aptMgr) Install(w io.Writer, logf logFn, names []string) []string {
	const pol = "/usr/sbin/policy-rc.d"
	if _, err := os.Stat(pol); os.IsNotExist(err) {
		if err := os.WriteFile(pol, []byte("#!/bin/sh\nexit 101\n"), 0755); err == nil {
			defer os.Remove(pol)
		}
	}
	base := []string{"-y", "-o", "Dpkg::Options::=--force-confold", "-o", "Dpkg::Options::=--force-confdef", "install"}
	return installWith(logf, names, func(n []string) error {
		return runStream(w, 3*time.Hour, "apt-get", append(append([]string{}, base...), n...)...)
	})
}

func (aptMgr) Refresh(w io.Writer) error {
	return runStream(w, 15*time.Minute, "apt-get", "update")
}

func (aptMgr) RepoPrefixes() []string { return []string{"/etc/apt"} }

func (aptMgr) EtcCustom(ex, nv *excluder) ([]string, []string) {
	conf := loadConffiles()
	return walkEtc(ex, nv, etcRules{
		owned: loadDpkgEtcOwned(),
		changed: func(p string) (bool, bool) {
			want, ok := conf[p]
			if !ok {
				return false, false
			}
			cur, err := fileMD5(p)
			return true, err == nil && cur != want
		},
	})
}

func loadDpkgEtcOwned() map[string]struct{} {
	owned := map[string]struct{}{}
	files, _ := filepath.Glob("/var/lib/dpkg/info/*.list")
	for _, f := range files {
		fh, err := os.Open(f)
		if err != nil {
			continue
		}
		sc := bufio.NewScanner(fh)
		sc.Buffer(make([]byte, 64*1024), 1<<20)
		for sc.Scan() {
			if l := sc.Text(); strings.HasPrefix(l, "/etc/") {
				owned[l] = struct{}{}
			}
		}
		fh.Close()
	}
	return owned
}

func loadConffiles() map[string]string {
	res := map[string]string{}
	fh, err := os.Open("/var/lib/dpkg/status")
	if err != nil {
		return res
	}
	defer fh.Close()
	sc := bufio.NewScanner(fh)
	sc.Buffer(make([]byte, 64*1024), 1<<20)
	in := false
	for sc.Scan() {
		l := sc.Text()
		switch {
		case strings.HasPrefix(l, "Conffiles:"):
			in = true
		case in && strings.HasPrefix(l, " "):
			f := strings.Fields(l)
			if len(f) >= 2 && !(len(f) >= 3 && f[2] == "obsolete") {
				res[f[0]] = f[1]
			}
		default:
			in = false
		}
	}
	return res
}

// ---------- rpm-семейство: dnf / yum / zypper (RHEL, Rocky, Alma, Fedora, SUSE) ----------

type rpmMgr struct{ bin string }

func (r rpmMgr) Name() string { return r.bin }

func (r rpmMgr) manualSet() map[string]bool {
	set := map[string]bool{}
	if r.bin == "zypper" {
		all, _ := runStdout(2*time.Minute, "rpm", "-qa", "--qf", "%{NAME}\n")
		auto := map[string]bool{}
		if b, err := os.ReadFile("/var/lib/zypp/AutoInstalled"); err == nil {
			for _, l := range strings.Fields(string(b)) {
				auto[l] = true
			}
		}
		for _, n := range strings.Fields(all) {
			if !auto[n] {
				set[n] = true
			}
		}
		return set
	}
	out, _ := runStdout(5*time.Minute, r.bin, "-q", "repoquery", "--userinstalled", "--queryformat", "%{name}\n")
	for _, n := range strings.Fields(out) {
		set[n] = true
	}
	return set
}

func (r rpmMgr) List() ([]Package, error) {
	out, err := runStdout(2*time.Minute, "rpm", "-qa", "--qf", "%{NAME}\t%{VERSION}-%{RELEASE}\t%{ARCH}\n")
	if err != nil {
		return nil, fmt.Errorf("rpm -qa: %w", err)
	}
	manual := r.manualSet()
	var res []Package
	for _, l := range strings.Split(out, "\n") {
		f := strings.Split(l, "\t")
		if len(f) < 3 || f[0] == "gpg-pubkey" {
			continue
		}
		res = append(res, Package{Name: f[0], Version: f[1], Arch: f[2], Manual: manual[f[0]]})
	}
	return res, nil
}

func (r rpmMgr) Candidates(names []string) (ok, missing []string) {
	avail := map[string]bool{}
	if r.bin == "zypper" {
		args := append([]string{"-n", "-q", "search", "-x", "-t", "package"}, names...)
		out, _ := runStdout(5*time.Minute, "zypper", args...)
		for _, l := range strings.Split(out, "\n") {
			f := strings.Split(l, "|")
			if len(f) >= 3 {
				if n := strings.TrimSpace(f[1]); n != "" && n != "Name" {
					avail[n] = true
				}
			}
		}
	} else {
		args := append([]string{"-q", "repoquery", "--queryformat", "%{name}\n"}, names...)
		out, _ := runStdout(5*time.Minute, r.bin, args...)
		for _, n := range strings.Fields(out) {
			avail[n] = true
		}
	}
	return splitAvail(names, avail)
}

func (r rpmMgr) Install(w io.Writer, logf logFn, names []string) []string {
	return installWith(logf, names, func(n []string) error {
		args := []string{"-y", "install"}
		if r.bin == "zypper" {
			args = []string{"-n", "install", "--no-recommends"}
		}
		return runStream(w, 3*time.Hour, r.bin, append(args, n...)...)
	})
}

func (r rpmMgr) Refresh(w io.Writer) error {
	if r.bin == "zypper" {
		return runStream(w, 15*time.Minute, "zypper", "-n", "refresh")
	}
	return runStream(w, 15*time.Minute, r.bin, "-y", "makecache")
}

func (r rpmMgr) RepoPrefixes() []string {
	if r.bin == "zypper" {
		return []string{"/etc/zypp"}
	}
	return []string{"/etc/yum.repos.d", "/etc/yum.conf", "/etc/dnf", "/etc/pki/rpm-gpg"}
}

func (r rpmMgr) EtcCustom(ex, nv *excluder) ([]string, []string) {
	owned := map[string]struct{}{}
	if out, err := runStdout(5*time.Minute, "rpm", "-qla"); err == nil {
		for _, l := range strings.Split(out, "\n") {
			if strings.HasPrefix(l, "/etc/") {
				owned[l] = struct{}{}
			}
		}
	}
	changed := map[string]bool{}
	// rpm -V возвращает ненулевой код при любых отличиях — вывод нам всё равно нужен
	out, _ := runStdout(10*time.Minute, "rpm", "-V", "-a", "-c")
	for _, l := range strings.Split(out, "\n") {
		f := strings.Fields(l)
		if len(f) >= 3 && f[1] == "c" && strings.Contains(f[0], "5") {
			changed[f[2]] = true
		}
	}
	return walkEtc(ex, nv, etcRules{
		owned: owned,
		changed: func(p string) (bool, bool) {
			if changed[p] {
				return true, true
			}
			return false, false
		},
	})
}

// ---------- pacman (Arch, Manjaro) ----------

type pacmanMgr struct{}

func (pacmanMgr) Name() string { return "pacman" }

func (pacmanMgr) List() ([]Package, error) {
	out, err := runStdout(2*time.Minute, "pacman", "-Q")
	if err != nil {
		return nil, fmt.Errorf("pacman -Q: %w", err)
	}
	exp, _ := runStdout(2*time.Minute, "pacman", "-Qeq")
	manual := map[string]bool{}
	for _, n := range strings.Fields(exp) {
		manual[n] = true
	}
	var res []Package
	for _, l := range strings.Split(out, "\n") {
		f := strings.Fields(l)
		if len(f) >= 2 {
			res = append(res, Package{Name: f[0], Version: f[1], Manual: manual[f[0]]})
		}
	}
	return res, nil
}

func (pacmanMgr) Candidates(names []string) (ok, missing []string) {
	out, _ := runStdout(2*time.Minute, "pacman", "-Slq")
	avail := map[string]bool{}
	for _, n := range strings.Fields(out) {
		avail[n] = true
	}
	return splitAvail(names, avail)
}

func (pacmanMgr) Install(w io.Writer, logf logFn, names []string) []string {
	return installWith(logf, names, func(n []string) error {
		return runStream(w, 3*time.Hour, "pacman", append([]string{"-S", "--noconfirm", "--needed"}, n...)...)
	})
}

// Внимание: на Arch частичные обновления официально не поддерживаются,
// держите приёмник полностью обновлённым (pacman -Syu) до переноса.
func (pacmanMgr) Refresh(w io.Writer) error {
	return runStream(w, 15*time.Minute, "pacman", "-Sy", "--noconfirm")
}

func (pacmanMgr) RepoPrefixes() []string { return []string{"/etc/pacman.conf", "/etc/pacman.d"} }

func (pacmanMgr) EtcCustom(ex, nv *excluder) ([]string, []string) {
	owned := map[string]struct{}{}
	if out, err := runStdout(5*time.Minute, "pacman", "-Ql"); err == nil {
		for _, l := range strings.Split(out, "\n") {
			if f := strings.SplitN(l, " ", 2); len(f) == 2 && strings.HasPrefix(f[1], "/etc/") {
				owned[f[1]] = struct{}{}
			}
		}
	}
	changed := map[string]bool{}
	out, _ := runStdout(5*time.Minute, "pacman", "-Qii")
	for _, l := range strings.Split(out, "\n") {
		f := strings.Fields(l)
		for i, tok := range f {
			if tok == "MODIFIED" && i+1 < len(f) {
				changed[f[i+1]] = true
			}
		}
	}
	return walkEtc(ex, nv, etcRules{
		owned: owned,
		changed: func(p string) (bool, bool) {
			if changed[p] {
				return true, true
			}
			return false, false
		},
	})
}

// ---------- apk (Alpine) ----------

type apkMgr struct{}

var apkNameVer = regexp.MustCompile(`^(.+)-([0-9][^-]*-r[0-9]+)$`)

func apkSplit(s string) (name, ver string, ok bool) {
	m := apkNameVer.FindStringSubmatch(strings.TrimSpace(s))
	if m == nil {
		return "", "", false
	}
	return m[1], m[2], true
}

func (apkMgr) Name() string { return "apk" }

func (apkMgr) List() ([]Package, error) {
	out, err := runStdout(2*time.Minute, "apk", "info", "-v")
	if err != nil {
		return nil, fmt.Errorf("apk info: %w", err)
	}
	manual := map[string]bool{}
	if b, err := os.ReadFile("/etc/apk/world"); err == nil {
		for _, tok := range strings.Fields(string(b)) {
			if i := strings.IndexAny(tok, "=<>~@"); i > 0 {
				tok = tok[:i]
			}
			manual[tok] = true
		}
	}
	var res []Package
	for _, l := range strings.Split(out, "\n") {
		if n, v, ok := apkSplit(l); ok {
			res = append(res, Package{Name: n, Version: v, Manual: manual[n]})
		}
	}
	return res, nil
}

func (apkMgr) Candidates(names []string) (ok, missing []string) {
	out, _ := runStdout(3*time.Minute, "apk", "search", "-q")
	avail := map[string]bool{}
	for _, l := range strings.Fields(out) {
		if n, _, okk := apkSplit(l); okk {
			avail[n] = true
		} else {
			avail[l] = true
		}
	}
	return splitAvail(names, avail)
}

func (apkMgr) Install(w io.Writer, logf logFn, names []string) []string {
	return installWith(logf, names, func(n []string) error {
		return runStream(w, 3*time.Hour, "apk", append([]string{"add"}, n...)...)
	})
}

func (apkMgr) Refresh(w io.Writer) error {
	return runStream(w, 15*time.Minute, "apk", "update")
}

func (apkMgr) RepoPrefixes() []string { return []string{"/etc/apk"} }

func (apkMgr) EtcCustom(ex, nv *excluder) ([]string, []string) {
	var files, warns []string
	out, err := runStdout(5*time.Minute, "apk", "audit", "--backup")
	if err != nil && out == "" {
		warns = append(warns, "apk audit: "+err.Error())
	}
	for _, l := range strings.Split(out, "\n") {
		if len(l) < 3 || (l[0] != 'A' && l[0] != 'M') || l[1] != ' ' {
			continue
		}
		p := "/" + strings.TrimSuffix(strings.TrimSpace(l[2:]), "/")
		if !strings.HasPrefix(p, "/etc/") || ex.match(p) || nv.match(p) {
			continue
		}
		if _, err := os.Lstat(p); err == nil {
			files = append(files, p)
		}
	}
	return files, warns
}
