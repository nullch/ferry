package main

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path"
	"strings"
	"time"
)

const (
	protoVersion = 1
	trailerName  = ".ferry-files.json"
	stateDir     = "/var/lib/ferry"
	defaultPKI   = "/etc/ferry/pki"
	defaultPort  = "8443"
)

var version = "0.1.0"

// Что копируем по умолчанию (кроме /etc, у него свой режим, и спула cron — см. defaultRootsFor).
var defaultRoots = []string{
	"/var/www",
	"/root",
	"/home",
	"/opt",
	"/srv",
	"/usr/local",
}

// Никогда не копируем и не обходим.
var defaultExcludes = []string{
	"/proc", "/sys", "/dev", "/run", "/tmp",
	"/var/lib/ferry",
	"/etc/ferry",
	"/usr/local/bin/ferry",
	"/root/.cache",
	"/home/*/.cache",
}

// Файлы, которые нельзя переносить "как есть" (машинно-специфичные или
// обрабатываются отдельно). Применяется и при упаковке на источнике, и при
// размещении на приёмнике.
var neverApply = []string{
	"/etc/passwd", "/etc/passwd-", "/etc/group", "/etc/group-",
	"/etc/shadow", "/etc/shadow-", "/etc/gshadow", "/etc/gshadow-",
	"/etc/subuid", "/etc/subuid-", "/etc/subgid", "/etc/subgid-",
	"/etc/fstab", "/etc/crypttab", "/etc/hostname", "/etc/hosts",
	"/etc/machine-id", "/etc/mtab", "/etc/resolv.conf", "/etc/adjtime",
	"/etc/network", "/etc/netplan", "/etc/NetworkManager/system-connections",
	"/etc/systemd/network",
	"/etc/ssh/ssh_host_*",
	"/etc/initramfs-tools", "/etc/default/grub", "/etc/grub.d", "/etc/kernel",
	"/etc/udev/rules.d/70-persistent-net.rules",
	"/etc/alternatives", "/etc/ssl/certs", "/etc/ld.so.cache",
	"/etc/.pwd.lock", "/etc/lvm", "/etc/mdadm", "/etc/cloud",
}

// Пакеты, которые не имеет смысла ставить на другую машину.
var defaultSkipPkgs = []string{
	"linux-image-*", "linux-headers-*", "linux-kbuild-*", "linux-base",
	"grub*", "shim*", "efibootmgr", "os-prober", "initramfs-tools*",
	"cloud-init", "cloud-guest-utils", "open-vm-tools*", "qemu-guest-agent",
	"netplan.io", "firmware-*", "installation-report",
	"console-setup*", "keyboard-configuration",
	"ifupdown", "network-manager*",
	// rpm / arch / alpine: ядро, загрузчик, базовые мета-пакеты
	"kernel", "kernel-*", "linux", "linux-lts", "linux-firmware*", "grub2*", "dracut*",
	"syslinux", "intel-ucode", "amd-ucode", "microcode_ctl", "NetworkManager*",
	"base", "filesystem", "alpine-base", "alpine-baselayout*", "openrc", "busybox*",
}

// Юниты, которые не включаем/не стартуем автоматически.
var skipUnits = []string{
	"systemd-*", "getty@*", "serial-getty@*", "networking.service",
	"NetworkManager*", "wpa_supplicant*", "ModemManager*", "cloud-*",
	"open-vm-tools*", "qemu-guest-agent*", "console-setup*", "keyboard-setup*",
	"lvm2*", "mdadm*", "multipathd*", "grub*", "e2scrub*", "fstrim*",
	// openrc
	"networking", "hwclock", "bootmisc", "modules", "mdev", "devfs", "sysfs", "dmesg", "hostname", "urandom",
}

// ---------- типы протокола ----------

type HostInfo struct {
	Hostname  string `json:"hostname"`
	OSID      string `json:"os_id"`
	OSVersion string `json:"os_version"`
	Codename  string `json:"codename"`
	Pretty    string `json:"pretty,omitempty"`
	Family    string `json:"family"` // debian | rhel | suse | arch | alpine | unknown
	PM        string `json:"pm"`     // apt | dnf | yum | zypper | pacman | apk
	Init      string `json:"init"`   // systemd | openrc | none
	Arch      string `json:"arch"`
	Kernel    string `json:"kernel"`
	Version   int    `json:"proto"`
}

type Package struct {
	Name    string `json:"name"`
	Version string `json:"version"`
	Arch    string `json:"arch"`
	Manual  bool   `json:"manual"`
}

type Unit struct {
	Name    string `json:"name"`
	Enabled bool   `json:"enabled"`
	Active  bool   `json:"active"`
}

type Listener struct {
	Proto   string `json:"proto"`
	Addr    string `json:"addr"`
	Port    int    `json:"port"`
	PID     int    `json:"pid,omitempty"`
	Process string `json:"process,omitempty"`
}

type CronEntry struct {
	Source string `json:"source"`
	User   string `json:"user,omitempty"`
	Line   string `json:"line"`
}

type User struct {
	Name   string   `json:"name"`
	UID    int      `json:"uid"`
	GID    int      `json:"gid"`
	Gecos  string   `json:"gecos,omitempty"`
	Home   string   `json:"home"`
	Shell  string   `json:"shell"`
	Hash   string   `json:"hash,omitempty"`
	Groups []string `json:"groups,omitempty"`
}

type Group struct {
	Name    string   `json:"name"`
	GID     int      `json:"gid"`
	Members []string `json:"members,omitempty"`
}

type TransferInfo struct {
	Roots    []string `json:"roots"`
	EtcMode  string   `json:"etc_mode"`
	EtcFiles int      `json:"etc_files"`
	Files    int      `json:"files"`
	Dirs     int      `json:"dirs"`
	Bytes    int64    `json:"bytes"`
}

type Manifest struct {
	Proto     int          `json:"proto"`
	CreatedAt time.Time    `json:"created_at"`
	Host      HostInfo     `json:"host"`
	Packages  []Package    `json:"packages"`
	Units     []Unit       `json:"units"`
	Ports     []Listener   `json:"ports"`
	Cron      []CronEntry  `json:"cron"`
	Users     []User       `json:"users"`
	Groups    []Group      `json:"groups"`
	Transfer  TransferInfo `json:"transfer"`
	Warnings  []string     `json:"warnings,omitempty"`
}

type Options struct {
	SkipPkgs             []string `json:"skip_pkgs,omitempty"`
	NoPackages           bool     `json:"no_packages,omitempty"`
	AllowReleaseMismatch bool     `json:"allow_release_mismatch,omitempty"`
	CrossDistro          bool     `json:"cross_distro,omitempty"`
	PkgMap               string   `json:"pkg_map,omitempty"` // дополнительные строки таблицы соответствия пакетов
	Start                bool     `json:"start,omitempty"`
}

type PlanRequest struct {
	Manifest *Manifest `json:"manifest"`
	Options  Options   `json:"options"`
}

type Plan struct {
	Errors          []string `json:"errors,omitempty"`
	Warnings        []string `json:"warnings,omitempty"`
	Cross           int      `json:"cross"` // 0 тот же дистрибутив, 1 то же семейство, 2 другое семейство
	InstallPackages []string `json:"install_packages,omitempty"`
	PackageMap      []string `json:"package_map,omitempty"`
	UnmappedPackages []string `json:"unmapped_packages,omitempty"`
	SkippedPackages []string `json:"skipped_packages,omitempty"`
	VersionDiffs    []string `json:"version_diffs,omitempty"`
	CreateGroups    []string `json:"create_groups,omitempty"`
	CreateUsers     []string `json:"create_users,omitempty"`
	EnableUnits     []string `json:"enable_units,omitempty"`
	Items           int      `json:"items"`
	Bytes           int64    `json:"bytes"`
	FreeBytes       uint64   `json:"free_bytes"`
}

// Entry — запись об одном объекте, принятом приёмником (entries.jsonl).
type Entry struct {
	P  string `json:"p"`            // абсолютный путь назначения
	T  string `json:"t"`            // d | f | l
	M  int64  `json:"m"`            // tar-mode (с битами suid/sgid/sticky)
	U  int    `json:"u"`            // uid на источнике
	G  int    `json:"g"`            // gid на источнике
	UN string `json:"un,omitempty"` // имя владельца
	GN string `json:"gn,omitempty"` // имя группы
	L  string `json:"l,omitempty"`  // цель симлинка
	MT int64  `json:"mt"`           // mtime (unix)
}

type ArchiveResult struct {
	Path   string `json:"path"`
	Bytes  int64  `json:"bytes"`
	SHA256 string `json:"sha256"`
}

type UploadResult struct {
	Files      int      `json:"files"`
	Dirs       int      `json:"dirs"`
	Bytes      int64    `json:"bytes"`
	Skipped    int      `json:"skipped"`
	Mismatches []string `json:"mismatches,omitempty"`
}

// ---------- исключения ----------

type excluder struct{ pats []string }

func newExcluder(pats []string) *excluder {
	var clean []string
	for _, p := range pats {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		if len(p) > 1 {
			p = strings.TrimRight(p, "/")
		}
		clean = append(clean, p)
	}
	return &excluder{pats: clean}
}

// match: путь попадает под исключение, если он равен шаблону, лежит внутри
// него, либо шаблон с масками (* ? [) совпал с самим путём или его предком.
func (e *excluder) match(p string) bool {
	for _, pat := range e.pats {
		if strings.ContainsAny(pat, "*?[") {
			for cur := p; cur != "/" && cur != "." && cur != ""; cur = path.Dir(cur) {
				if ok, _ := path.Match(pat, cur); ok {
					return true
				}
			}
		} else if p == pat || strings.HasPrefix(p, pat+"/") {
			return true
		}
	}
	return false
}

func globAny(pats []string, s string) bool {
	for _, p := range pats {
		if ok, _ := path.Match(p, s); ok {
			return true
		}
	}
	return false
}

func skipPkg(name string, extra []string) bool {
	return globAny(defaultSkipPkgs, name) || globAny(extra, name)
}

// ---------- запуск команд ----------

func baseEnv() []string {
	return append(os.Environ(),
		"LC_ALL=C", "LANG=C",
		"DEBIAN_FRONTEND=noninteractive",
		"APT_LISTCHANGES_FRONTEND=none",
		"NEEDRESTART_MODE=a",
	)
}

// runStdout возвращает только stdout (stderr отбрасывается).
func runStdout(timeout time.Duration, name string, args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Env = baseEnv()
	var out bytes.Buffer
	cmd.Stdout = &out
	err := cmd.Run()
	return out.String(), err
}

// runCombined возвращает stdout+stderr.
func runCombined(timeout time.Duration, name string, args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Env = baseEnv()
	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &out
	err := cmd.Run()
	return out.String(), err
}

// runStream пишет вывод команды в w по мере появления.
func runStream(w io.Writer, timeout time.Duration, name string, args ...string) error {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Env = baseEnv()
	cmd.Stdout = w
	cmd.Stderr = w
	return cmd.Run()
}

// ---------- мелочи ----------

func requireRoot() error {
	if os.Geteuid() != 0 {
		return fmt.Errorf("нужны права root (запустите через sudo/от root)")
	}
	return nil
}

func splitCSV(s string) []string {
	var res []string
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			res = append(res, p)
		}
	}
	return res
}

func firstLine(s string) string {
	s = strings.TrimSpace(s)
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		return s[:i]
	}
	return s
}

func humanBytes(n int64) string {
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%d B", n)
	}
	div, exp := int64(unit), 0
	for m := n / unit; m >= unit; m /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %ciB", float64(n)/float64(div), "KMGTPE"[exp])
}

func normProto(p string) string { return strings.TrimSuffix(p, "6") }
