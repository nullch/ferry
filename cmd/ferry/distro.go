package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
)

func hasCmd(name string) bool {
	_, err := exec.LookPath(name)
	return err == nil
}

func parseKV(file string) map[string]string {
	m := map[string]string{}
	b, err := os.ReadFile(file)
	if err != nil {
		return m
	}
	for _, line := range strings.Split(string(b), "\n") {
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		m[strings.TrimSpace(k)] = strings.Trim(strings.TrimSpace(v), `"'`)
	}
	return m
}

// hostInfo описывает ЭТОТ сервер: дистрибутив, семейство, пакетный менеджер, init.
func hostInfo() HostInfo {
	h := HostInfo{Version: protoVersion, Arch: runtime.GOARCH}
	h.Hostname, _ = os.Hostname()
	osr := parseKV("/etc/os-release")
	h.OSID = osr["ID"]
	h.OSVersion = osr["VERSION_ID"]
	h.Codename = osr["VERSION_CODENAME"]
	h.Pretty = osr["PRETTY_NAME"]
	h.Family = detectFamily(osr["ID"], osr["ID_LIKE"])
	h.PM = detectPM(h.Family)
	h.Init = detectInit()
	if b, err := os.ReadFile("/proc/sys/kernel/osrelease"); err == nil {
		h.Kernel = strings.TrimSpace(string(b))
	}
	return h
}

func detectFamily(id, like string) string {
	toks := append([]string{id}, strings.Fields(like)...)
	for _, t := range toks {
		switch strings.ToLower(t) {
		case "debian", "ubuntu":
			return "debian"
		case "rhel", "fedora", "centos":
			return "rhel"
		case "suse", "sles", "opensuse", "opensuse-leap", "opensuse-tumbleweed":
			return "suse"
		case "arch":
			return "arch"
		case "alpine":
			return "alpine"
		}
	}
	return "unknown"
}

func detectPM(family string) string {
	switch family {
	case "debian":
		return "apt"
	case "rhel":
		if hasCmd("dnf") {
			return "dnf"
		}
		return "yum"
	case "suse":
		return "zypper"
	case "arch":
		return "pacman"
	case "alpine":
		return "apk"
	}
	return ""
}

func detectInit() string {
	if fi, err := os.Stat("/run/systemd/system"); err == nil && fi.IsDir() {
		return "systemd"
	}
	if hasCmd("rc-service") {
		return "openrc"
	}
	return "none"
}

// releaseKey — «мажорная» версия дистрибутива для проверки совпадения релизов.
func releaseKey(h HostInfo) string {
	v := h.OSVersion
	parts := strings.Split(v, ".")
	switch h.OSID {
	case "ubuntu":
		// 22.04 и 24.04 — разные релизы
	case "alpine":
		if len(parts) > 2 {
			v = strings.Join(parts[:2], ".")
		}
	default:
		v = parts[0]
	}
	return h.OSID + ":" + v
}

// crossLevel: 0 — тот же дистрибутив, 1 — то же семейство (debian→ubuntu),
// 2 — другое семейство (debian→rocky).
func crossLevel(src, dst HostInfo) int {
	if src.OSID == dst.OSID {
		return 0
	}
	if src.Family == dst.Family && src.Family != "unknown" {
		return 1
	}
	return 2
}

// Конфиги пакетных менеджеров и самой ОС: на чужом дистрибутиве вредны.
var distroSpecific = []string{
	"/etc/apt", "/etc/dpkg", "/etc/yum.repos.d", "/etc/yum.conf", "/etc/dnf", "/etc/zypp",
	"/etc/pacman.conf", "/etc/pacman.d", "/etc/apk", "/etc/pki/rpm-gpg",
	"/etc/os-release", "/etc/lsb-release", "/etc/debian_version", "/etc/redhat-release",
	"/etc/issue", "/etc/issue.net", "/etc/sysconfig", "/etc/selinux", "/etc/audit",
	"/etc/authselect", "/etc/ca-certificates.conf", "/etc/ca-certificates",
}

// Опасно переносить между семействами (PAM, sshd, init-скрипты и т.п.).
var crossFamilyExtra = []string{
	"/etc/pam.d", "/etc/security", "/etc/nsswitch.conf", "/etc/login.defs",
	"/etc/ssh/sshd_config", "/etc/ssh/sshd_config.d",
	"/etc/sudoers", "/etc/default", "/etc/init.d", "/etc/rc.d",
	"/etc/rc0.d", "/etc/rc1.d", "/etc/rc2.d", "/etc/rc3.d", "/etc/rc4.d", "/etc/rc5.d", "/etc/rc6.d", "/etc/rcS.d",
	"/etc/profile", "/etc/bash.bashrc", "/etc/bashrc",
	"/etc/rsyslog.conf", "/etc/logrotate.conf", "/etc/systemd/system.conf",
}

func crossExcludes(level int) []string {
	switch level {
	case 0:
		return nil
	case 1:
		return distroSpecific
	}
	return append(append([]string{}, distroSpecific...), crossFamilyExtra...)
}

var userAliases = map[string][]string{
	"www-data": {"apache", "nginx", "http", "www", "wwwrun"},
	"apache":   {"www-data", "nginx", "http", "www", "wwwrun"},
	"nginx":    {"www-data", "apache", "http", "www", "wwwrun"},
	"http":     {"www-data", "apache", "nginx", "www", "wwwrun"},
	"www":      {"www-data", "apache", "nginx", "http", "wwwrun"},
	"wwwrun":   {"www-data", "apache", "nginx", "http", "www"},
	"mysql":    {"mariadb"},
	"mariadb":  {"mysql"},
}

func aliasesFor(name string, group bool) []string {
	if group {
		switch name {
		case "sudo":
			return []string{"wheel", "admin"}
		case "wheel":
			return []string{"sudo", "admin"}
		}
	}
	return userAliases[name]
}

// fixShell подбирает существующий на этом сервере shell (nologin/bash лежат по-разному).
func fixShell(sh string) string {
	if sh == "" {
		return sh
	}
	if _, err := os.Stat(sh); err == nil {
		return sh
	}
	var cands []string
	switch base := filepath.Base(sh); base {
	case "nologin":
		cands = []string{"/usr/sbin/nologin", "/sbin/nologin", "/bin/false", "/usr/bin/false"}
	case "false":
		cands = []string{"/bin/false", "/usr/bin/false"}
	default:
		cands = []string{"/bin/" + base, "/usr/bin/" + base, "/bin/bash", "/bin/sh"}
	}
	for _, c := range cands {
		if _, err := os.Stat(c); err == nil {
			return c
		}
	}
	return "/bin/sh"
}

// cronSpool — где лежат пользовательские crontab'ы в данном семействе.
func cronSpool(family string) string {
	switch family {
	case "debian":
		return "/var/spool/cron/crontabs"
	case "rhel", "arch":
		return "/var/spool/cron"
	case "suse":
		return "/var/spool/cron/tabs"
	case "alpine":
		return "/etc/crontabs"
	}
	return ""
}

// defaultRootsFor — каталоги для копирования по умолчанию на данном сервере.
func defaultRootsFor(h HostInfo) []string {
	roots := append([]string{}, defaultRoots...)
	if sp := cronSpool(h.Family); sp != "" {
		roots = append(roots, sp)
	}
	return roots
}
