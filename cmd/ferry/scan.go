package main

import (
	"crypto/md5"
	"encoding/hex"
	"fmt"
	"io"
	"io/fs"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"
)

type CollectCfg struct {
	Paths    []string
	EtcMode  string // custom | full | none
	Excludes []string
	Hashes   bool
}

// collect собирает манифест и список путей для передачи.
func collect(cfg CollectCfg) (*Manifest, []string, error) {
	m := &Manifest{Proto: protoVersion, CreatedAt: time.Now().UTC(), Host: hostInfo()}
	pm := newPkgMgr(m.Host.PM)

	pk, err := pm.List()
	if err != nil {
		m.Warnings = append(m.Warnings, "пакеты: "+err.Error())
	}
	manual := 0
	for _, p := range pk {
		if p.Manual {
			manual++
		}
	}
	if len(pk) > 0 && manual == 0 {
		m.Warnings = append(m.Warnings, "не удалось определить вручную установленные пакеты — пакеты переноситься не будут")
	}
	m.Packages = pk
	m.Units = scanUnits()
	m.Ports = scanPorts()
	m.Cron = scanCron()
	m.Users, m.Groups = scanUsers(cfg.Hashes)

	list, info, warns := buildTransferList(TransferCfg{Roots: cfg.Paths, EtcMode: cfg.EtcMode, Excludes: cfg.Excludes, PM: pm})
	m.Transfer = info
	m.Warnings = append(m.Warnings, warns...)
	return m, list, nil
}

// ---------- порты ----------

func scanPorts() []Listener {
	owners := socketOwners()
	specs := []struct {
		file, proto string
		v6          bool
	}{
		{"/proc/net/tcp", "tcp", false},
		{"/proc/net/tcp6", "tcp6", true},
		{"/proc/net/udp", "udp", false},
		{"/proc/net/udp6", "udp6", true},
	}
	var res []Listener
	for _, sp := range specs {
		b, err := os.ReadFile(sp.file)
		if err != nil {
			continue
		}
		for i, line := range strings.Split(string(b), "\n") {
			if i == 0 {
				continue
			}
			f := strings.Fields(line)
			if len(f) < 10 {
				continue
			}
			state := f[3]
			if strings.HasPrefix(sp.proto, "tcp") && state != "0A" {
				continue
			}
			if strings.HasPrefix(sp.proto, "udp") && state != "07" {
				continue
			}
			addr, port, ok := parseHexAddr(f[1], sp.v6)
			if !ok {
				continue
			}
			l := Listener{Proto: sp.proto, Addr: addr, Port: port}
			if pid, ok := owners[f[9]]; ok {
				l.PID = pid
				l.Process = procName(pid)
			}
			res = append(res, l)
		}
	}
	sort.Slice(res, func(i, j int) bool {
		if res[i].Port != res[j].Port {
			return res[i].Port < res[j].Port
		}
		return res[i].Proto < res[j].Proto
	})
	return res
}

func parseHexAddr(s string, v6 bool) (string, int, bool) {
	hp := strings.Split(s, ":")
	if len(hp) != 2 {
		return "", 0, false
	}
	port, err := strconv.ParseUint(hp[1], 16, 16)
	if err != nil {
		return "", 0, false
	}
	raw, err := hex.DecodeString(hp[0])
	if err != nil {
		return "", 0, false
	}
	if (!v6 && len(raw) != 4) || (v6 && len(raw) != 16) {
		return "", 0, false
	}
	ip := make(net.IP, len(raw))
	// каждое 32-битное слово в /proc записано в little-endian
	for i := 0; i < len(raw); i += 4 {
		ip[i], ip[i+1], ip[i+2], ip[i+3] = raw[i+3], raw[i+2], raw[i+1], raw[i]
	}
	return ip.String(), int(port), true
}

func socketOwners() map[string]int {
	res := map[string]int{}
	dirs, _ := filepath.Glob("/proc/[0-9]*/fd")
	for _, d := range dirs {
		pid, err := strconv.Atoi(filepath.Base(filepath.Dir(d)))
		if err != nil {
			continue
		}
		ents, err := os.ReadDir(d)
		if err != nil {
			continue
		}
		for _, e := range ents {
			l, err := os.Readlink(filepath.Join(d, e.Name()))
			if err != nil || !strings.HasPrefix(l, "socket:[") {
				continue
			}
			inode := strings.TrimSuffix(strings.TrimPrefix(l, "socket:["), "]")
			if _, ok := res[inode]; !ok {
				res[inode] = pid
			}
		}
	}
	return res
}

func procName(pid int) string {
	b, err := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/comm")
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(b))
}

// ---------- cron ----------

func scanCron() []CronEntry {
	var res []CronEntry
	add := func(src, who string) {
		b, err := os.ReadFile(src)
		if err != nil {
			return
		}
		for _, l := range strings.Split(string(b), "\n") {
			t := strings.TrimSpace(l)
			if t == "" || strings.HasPrefix(t, "#") {
				continue
			}
			res = append(res, CronEntry{Source: src, User: who, Line: t})
		}
	}
	for _, pat := range []string{"/var/spool/cron/crontabs/*", "/var/spool/cron/tabs/*", "/var/spool/cron/*", "/etc/crontabs/*"} {
		matches, _ := filepath.Glob(pat)
		for _, f := range matches {
			if fi, err := os.Stat(f); err == nil && fi.Mode().IsRegular() {
				add(f, filepath.Base(f))
			}
		}
	}
	add("/etc/crontab", "")
	var files []string
	files, _ = filepath.Glob("/etc/cron.d/*")
	for _, f := range files {
		add(f, "")
	}
	return res
}

// ---------- пользователи ----------

func splitNonEmpty(s, sep string) []string {
	var res []string
	for _, p := range strings.Split(s, sep) {
		if p = strings.TrimSpace(p); p != "" {
			res = append(res, p)
		}
	}
	return res
}

func readPasswd(file string) []User {
	b, err := os.ReadFile(file)
	if err != nil {
		return nil
	}
	var res []User
	for _, l := range strings.Split(string(b), "\n") {
		f := strings.SplitN(l, ":", 7)
		if len(f) != 7 {
			continue
		}
		uid, err1 := strconv.Atoi(f[2])
		gid, err2 := strconv.Atoi(f[3])
		if err1 != nil || err2 != nil {
			continue
		}
		res = append(res, User{Name: f[0], UID: uid, GID: gid, Gecos: f[4], Home: f[5], Shell: f[6]})
	}
	return res
}

func readGroups(file string) []Group {
	b, err := os.ReadFile(file)
	if err != nil {
		return nil
	}
	var res []Group
	for _, l := range strings.Split(string(b), "\n") {
		f := strings.SplitN(l, ":", 4)
		if len(f) != 4 {
			continue
		}
		gid, err := strconv.Atoi(f[2])
		if err != nil {
			continue
		}
		res = append(res, Group{Name: f[0], GID: gid, Members: splitNonEmpty(f[3], ",")})
	}
	return res
}

func readShadow() map[string]string {
	m := map[string]string{}
	b, err := os.ReadFile("/etc/shadow")
	if err != nil {
		return m
	}
	for _, l := range strings.Split(string(b), "\n") {
		f := strings.SplitN(l, ":", 3)
		if len(f) >= 2 {
			m[f[0]] = f[1]
		}
	}
	return m
}

func scanUsers(hashes bool) ([]User, []Group) {
	users := readPasswd("/etc/passwd")
	groups := readGroups("/etc/group")
	var sh map[string]string
	if hashes {
		sh = readShadow()
	}
	for i := range users {
		if hashes {
			users[i].Hash = sh[users[i].Name]
		}
		for _, g := range groups {
			for _, mem := range g.Members {
				if mem == users[i].Name {
					users[i].Groups = append(users[i].Groups, g.Name)
					break
				}
			}
		}
	}
	return users, groups
}

// ---------- список файлов для передачи ----------

type TransferCfg struct {
	Roots    []string
	EtcMode  string
	Excludes []string
	PM       PkgMgr
}

func buildTransferList(cfg TransferCfg) ([]string, TransferInfo, []string) {
	ex := newExcluder(append(append([]string{}, defaultExcludes...), cfg.Excludes...))
	nv := newExcluder(neverApply)
	info := TransferInfo{Roots: cfg.Roots, EtcMode: cfg.EtcMode}
	var warns []string
	var list []string
	seen := map[string]bool{}

	account := func(p string, fi fs.FileInfo) bool {
		if seen[p] {
			return false
		}
		m := fi.Mode()
		switch {
		case m.IsDir():
			info.Dirs++
		case m.IsRegular():
			info.Files++
			info.Bytes += fi.Size()
		case m&os.ModeSymlink != 0:
			info.Files++
		default:
			return false // сокеты, устройства, fifo — пропускаем
		}
		seen[p] = true
		list = append(list, p)
		return true
	}

	walk := func(root string) {
		err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
			if err != nil {
				warns = append(warns, fmt.Sprintf("пропуск %s: %v", p, err))
				if d != nil && d.IsDir() {
					return filepath.SkipDir
				}
				return nil
			}
			if ex.match(p) || nv.match(p) {
				if d.IsDir() {
					return filepath.SkipDir
				}
				return nil
			}
			fi, ierr := d.Info()
			if ierr != nil {
				warns = append(warns, fmt.Sprintf("пропуск %s: %v", p, ierr))
				return nil
			}
			account(p, fi)
			return nil
		})
		if err != nil {
			warns = append(warns, fmt.Sprintf("обход %s: %v", root, err))
		}
	}

	for _, root := range cfg.Roots {
		root = filepath.Clean(root)
		if fi, err := os.Lstat(root); err == nil && fi.Mode()&os.ModeSymlink != 0 {
			// корень — симлинк: переносим и сам симлинк, и то, на что он указывает
			if real, err := filepath.EvalSymlinks(root); err == nil {
				warns = append(warns, fmt.Sprintf("%s — симлинк на %s: переношу и цель", root, real))
				account(root, fi)
				walk(real)
				continue
			}
		}
		walk(root)
	}

	switch cfg.EtcMode {
	case "full":
		walk("/etc")
	case "custom":
		files, w := cfg.PM.EtcCustom(ex, nv)
		warns = append(warns, w...)
		for _, p := range files {
			if fi, err := os.Lstat(p); err == nil {
				if account(p, fi) {
					info.EtcFiles++
				}
			}
		}
	}
	return list, info, warns
}

// etcRules описывает, как отличить «своё» от поставляемого пакетами.
type etcRules struct {
	owned   map[string]struct{}                  // пути /etc, принадлежащие пакетам
	changed func(p string) (known, differs bool) // для конфигов пакетов: известен ли и изменён ли
}

// walkEtc выбирает в /etc:
//   - файлы и каталоги, которых нет ни в одном пакете (создано админом/скриптами);
//   - конфиги пакетов, изменённые относительно поставки.
func walkEtc(ex, nv *excluder, r etcRules) ([]string, []string) {
	var files, warns []string
	_ = filepath.WalkDir("/etc", func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			warns = append(warns, fmt.Sprintf("пропуск %s: %v", p, err))
			if d != nil && d.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}
		if ex.match(p) || nv.match(p) {
			if d.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}
		if d.IsDir() {
			if _, ok := r.owned[p]; !ok && p != "/etc" {
				files = append(files, p)
			}
			return nil
		}
		if known, differs := r.changed(p); known {
			if differs {
				files = append(files, p)
			}
			return nil
		}
		if _, ok := r.owned[p]; ok {
			return nil
		}
		files = append(files, p)
		return nil
	})
	return files, warns
}

func fileMD5(p string) (string, error) {
	f, err := os.Open(p)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := md5.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}
