package main

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
)

type logFn func(format string, a ...any)

func loadEntries(file string) ([]Entry, error) {
	f, err := os.Open(file)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var res []Entry
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1<<20), 8<<20)
	for sc.Scan() {
		var e Entry
		if err := json.Unmarshal(sc.Bytes(), &e); err != nil {
			return nil, err
		}
		res = append(res, e)
	}
	return res, sc.Err()
}

// runApply применяет принятую сессию. Порядок:
// 1) репозитории  2) пакеты  3) группы/пользователи  4) остальные файлы
// 5) службы  6) запуск (-start)  7) проверка.
func runApply(w io.Writer, sessDir string) error {
	logf := func(format string, a ...any) { fmt.Fprintf(w, format+"\n", a...) }

	if _, err := os.Stat(filepath.Join(sessDir, "applied")); err == nil {
		return errors.New("эта сессия уже применена")
	}
	b, err := os.ReadFile(filepath.Join(sessDir, "session.json"))
	if err != nil {
		return err
	}
	var req PlanRequest
	if err := json.Unmarshal(b, &req); err != nil {
		return err
	}
	m, o := req.Manifest, req.Options
	if m == nil {
		return errors.New("пустой манифест")
	}
	entries, err := loadEntries(filepath.Join(sessDir, "entries.jsonl"))
	if err != nil {
		return fmt.Errorf("данные не загружены: %w", err)
	}
	plan := buildPlan(m, o, false)
	if len(plan.Errors) > 0 {
		return fmt.Errorf("план содержит ошибки: %s", strings.Join(plan.Errors, "; "))
	}

	me := hostInfo()
	lvl := crossLevel(m.Host, me)
	pm := newPkgMgr(me.PM)
	logf("== %s → %s (%s), пакетный менеджер: %s, init: %s", orDash(m.Host.Pretty), orDash(me.Pretty), levelName(lvl), pm.Name(), me.Init)

	failures, warns := 0, 0
	excl := append(append(append([]string{}, defaultExcludes...), neverApply...), crossExcludes(lvl)...)
	pl := &placer{
		logf:     logf,
		stage:    filepath.Join(sessDir, "stage"),
		backup:   filepath.Join(sessDir, "backup"),
		entries:  entries,
		done:     make([]bool, len(entries)),
		ex:       newExcluder(excl),
		srcSpool: cronSpool(m.Host.Family),
		dstSpool: cronSpool(me.Family),
	}

	// 1. репозитории
	logf("== 1/7 репозитории")
	isRepo := func(p string) bool {
		for _, pre := range pm.RepoPrefixes() {
			if p == pre || strings.HasPrefix(p, pre+"/") {
				return true
			}
		}
		return false
	}
	refreshed := false
	placed, failed := pl.place(isRepo)
	failures += failed
	if placed > 0 {
		if err := pm.Refresh(w); err != nil {
			logf("!! обновление метаданных репозиториев: %v", err)
			warns++
		}
		refreshed = true
	}

	// 2. пакеты
	logf("== 2/7 пакеты")
	switch {
	case o.NoPackages:
		logf("   пропущено (-no-packages)")
	case len(plan.InstallPackages) == 0:
		logf("   нечего устанавливать")
	default:
		for _, n := range plan.UnmappedPackages {
			logf("   - пропущен: %s", n)
		}
		for _, n := range plan.PackageMap {
			logf("   ~ соответствие: %s", n)
		}
		if !refreshed {
			if err := pm.Refresh(w); err != nil {
				logf("!! обновление метаданных репозиториев: %v", err)
				warns++
			}
		}
		ok, missing := pm.Candidates(plan.InstallPackages)
		for _, n := range missing {
			logf("   ! нет в репозиториях приёмника: %s", n)
			warns++
		}
		if len(ok) > 0 {
			logf("   ставлю %d пакетов...", len(ok))
			for _, n := range pm.Install(w, logf, ok) {
				logf("!! не установился: %s", n)
				failures++
			}
		}
	}

	// 3. пользователи
	logf("== 3/7 группы и пользователи")
	failures += syncUsers(logf, m, lvl)

	// 4. файлы
	logf("== 4/7 файлы (%d записей)", len(entries))
	placed, failed = pl.place(func(string) bool { return true })
	failures += failed
	logf("   размещено: %d, пропущено правилами: %d, ошибок: %d", placed, pl.skipped, failed)

	// 5. службы
	logf("== 5/7 службы (%s)", me.Init)
	if err := reloadInit(me.Init); err != nil {
		logf("!! перечитывание конфигурации init: %v", err)
		warns++
	}
	for _, u := range unitsToEnable(m, me) {
		t, ok := resolveUnit(me.Init, u)
		if !ok {
			logf("   ! %s: такой службы на приёмнике нет (пакет не установлен или нет аналога)", u)
			warns++
			continue
		}
		if out, err := enableUnit(me.Init, t); err != nil {
			logf("   ! enable %s: %v %s", t, err, firstLine(out))
			warns++
		} else if t != u {
			logf("   enable %s (на источнике: %s)", t, u)
		} else {
			logf("   enable %s", t)
		}
	}

	// 6. запуск
	var started []string
	if o.Start {
		logf("== 6/7 запуск служб")
		for _, u := range m.Units {
			if !u.Active || !u.Enabled || globAny(skipUnits, u.Name) {
				continue
			}
			t, ok := resolveUnit(me.Init, u.Name)
			if !ok {
				continue
			}
			if out, err := startUnit(me.Init, t); err != nil {
				logf("   ! start %s: %v %s", t, err, firstLine(out))
				warns++
			} else {
				started = append(started, t)
				logf("   start %s", t)
			}
		}
	} else {
		logf("== 6/7 запуск служб: пропущен (нужен -start)")
	}

	// 7. проверка
	logf("== 7/7 проверка")
	if o.Start {
		for _, t := range started {
			if unitActive(me.Init, t) {
				logf("   ok %s", t)
			} else {
				logf("   ! %s не активна", t)
				warns++
			}
		}
		have := map[string]bool{}
		for _, l := range scanPorts() {
			have[fmt.Sprintf("%s:%d", normProto(l.Proto), l.Port)] = true
		}
		seen := map[string]bool{}
		for _, l := range m.Ports {
			k := fmt.Sprintf("%s:%d", normProto(l.Proto), l.Port)
			if seen[k] {
				continue
			}
			seen[k] = true
			if have[k] {
				logf("   ok порт %d/%s слушается", l.Port, normProto(l.Proto))
			} else {
				logf("   ! порт %d/%s (%s) на приёмнике НЕ слушается", l.Port, normProto(l.Proto), orDash(l.Process))
				warns++
			}
		}
	} else {
		logf("   проверка служб и портов делается только с -start; запустите их позже вручную")
	}

	logf("-- итог: ошибок %d, предупреждений %d", failures, warns)
	if failures > 0 {
		logf("staging сохранён: %s (можно повторить: push -resume / restore -session)", pl.stage)
		return fmt.Errorf("ошибок: %d", failures)
	}
	_ = os.RemoveAll(pl.stage)
	_ = os.WriteFile(filepath.Join(sessDir, "applied"), []byte(time.Now().Format(time.RFC3339)), 0600)
	logf("staging удалён. Копии перезаписанных файлов: %s", pl.backup)
	return nil
}

// ---------- размещение файлов ----------

type placer struct {
	logf     logFn
	stage    string
	backup   string
	entries  []Entry
	done     []bool
	ex       *excluder
	skipped  int
	srcSpool string // спул cron на источнике
	dstSpool string // спул cron здесь

	uids map[string]int
	gids map[string]int
}

func (p *placer) spoolMapped() bool {
	return p.srcSpool != "" && p.dstSpool != "" && p.srcSpool != p.dstSpool
}

func (p *placer) isSpool(e *Entry) bool {
	return p.spoolMapped() && (e.P == p.srcSpool || strings.HasPrefix(e.P, p.srcSpool+"/"))
}

// dstPath: куда класть объект. Спул cron у разных семейств лежит в разных местах.
func (p *placer) dstPath(e *Entry) string {
	if p.isSpool(e) {
		return p.dstSpool + strings.TrimPrefix(e.P, p.srcSpool)
	}
	return e.P
}

func (p *placer) place(pred func(string) bool) (placed, failed int) {
	// кэш имён сбрасываем на каждой фазе: пользователи могли появиться
	p.uids = map[string]int{}
	p.gids = map[string]int{}
	for i := range p.entries {
		e := &p.entries[i]
		if p.done[i] || !pred(e.P) {
			continue
		}
		p.done[i] = true
		if p.ex.match(e.P) {
			p.skipped++
			continue
		}
		if err := p.placeOne(e); err != nil {
			failed++
			p.logf("   ! %s: %v", e.P, err)
		} else {
			placed++
		}
	}
	return placed, failed
}

func lookupUID(name string) (int, bool) {
	u, err := user.Lookup(name)
	if err != nil {
		return 0, false
	}
	n, err := strconv.Atoi(u.Uid)
	return n, err == nil
}

func lookupGID(name string) (int, bool) {
	g, err := user.LookupGroup(name)
	if err != nil {
		return 0, false
	}
	n, err := strconv.Atoi(g.Gid)
	return n, err == nil
}

// owner переводит владельца с источника в uid/gid приёмника по ИМЕНИ
// (с учётом синонимов www-data/apache/nginx/http...); если имени нет — числа с источника.
func (p *placer) owner(e *Entry) (int, int) {
	uid, gid := e.U, e.G
	if e.UN != "" {
		if v, ok := p.uids[e.UN]; ok {
			uid = v
		} else {
			if n, ok := lookupUID(e.UN); ok {
				uid = n
			} else {
				for _, a := range aliasesFor(e.UN, false) {
					if n, ok := lookupUID(a); ok {
						uid = n
						break
					}
				}
			}
			p.uids[e.UN] = uid
		}
	}
	if e.GN != "" {
		if v, ok := p.gids[e.GN]; ok {
			gid = v
		} else {
			if n, ok := lookupGID(e.GN); ok {
				gid = n
			} else {
				for _, a := range aliasesFor(e.GN, true) {
					if n, ok := lookupGID(a); ok {
						gid = n
						break
					}
				}
			}
			p.gids[e.GN] = gid
		}
	}
	if e.T == "f" && p.isSpool(e) {
		// crontab'ы: группа — основная группа владельца (у семейств разные группы cron)
		if u, err := user.LookupId(strconv.Itoa(uid)); err == nil {
			if n, err := strconv.Atoi(u.Gid); err == nil {
				gid = n
			}
		}
	}
	return uid, gid
}

func tarModeToFileMode(m int64) os.FileMode {
	fm := os.FileMode(m & 0777)
	if m&04000 != 0 {
		fm |= os.ModeSetuid
	}
	if m&02000 != 0 {
		fm |= os.ModeSetgid
	}
	if m&01000 != 0 {
		fm |= os.ModeSticky
	}
	return fm
}

func (p *placer) placeOne(e *Entry) error {
	src := filepath.Join(p.stage, e.P)
	dst := p.dstPath(e)
	uid, gid := p.owner(e)
	mode := tarModeToFileMode(e.M)

	if e.T == "d" {
		if fi, err := os.Stat(dst); err == nil && fi.IsDir() {
			return nil // каталог уже есть — права не трогаем
		}
		if _, err := os.Lstat(dst); err == nil {
			if err := p.backupExisting(dst); err != nil {
				return err
			}
		}
		if err := os.MkdirAll(filepath.Dir(dst), 0755); err != nil {
			return err
		}
		if err := os.Mkdir(dst, 0700); err != nil {
			return err
		}
		if err := os.Lchown(dst, uid, gid); err != nil {
			return err
		}
		if err := os.Chmod(dst, mode); err != nil {
			return err
		}
		mt := time.Unix(e.MT, 0)
		_ = os.Chtimes(dst, mt, mt)
		return nil
	}

	if _, err := os.Lstat(src); err != nil {
		if os.IsNotExist(err) {
			return nil // уже перенесён предыдущим запуском
		}
		return err
	}
	// порядок важен: chown сбрасывает suid/sgid, поэтому chmod после него
	if err := os.Lchown(src, uid, gid); err != nil {
		return err
	}
	if e.T == "f" {
		if err := os.Chmod(src, mode); err != nil {
			return err
		}
	}
	if fi, err := os.Lstat(dst); err == nil {
		if fi.IsDir() {
			return errors.New("в назначении каталог, а переносится файл")
		}
		if err := p.backupExisting(dst); err != nil {
			return err
		}
	}
	if err := os.MkdirAll(filepath.Dir(dst), 0755); err != nil {
		return err
	}
	return moveRaw(src, dst)
}

func (p *placer) backupExisting(dst string) error {
	target := filepath.Join(p.backup, dst)
	if err := os.MkdirAll(filepath.Dir(target), 0700); err != nil {
		return err
	}
	_ = os.RemoveAll(target)
	return moveRaw(dst, target)
}

// moveRaw перемещает файл/симлинк с сохранением владельца, прав и mtime:
// сначала rename, а при разных ФС — копирование.
func moveRaw(src, dst string) error {
	err := os.Rename(src, dst)
	if err == nil {
		return nil
	}
	if !errors.Is(err, syscall.EXDEV) {
		return err
	}
	fi, err := os.Lstat(src)
	if err != nil {
		return err
	}
	var uid, gid int = -1, -1
	if st, ok := fi.Sys().(*syscall.Stat_t); ok {
		uid, gid = int(st.Uid), int(st.Gid)
	}
	switch {
	case fi.Mode()&os.ModeSymlink != 0:
		l, err := os.Readlink(src)
		if err != nil {
			return err
		}
		if err := os.Symlink(l, dst); err != nil {
			return err
		}
		_ = os.Lchown(dst, uid, gid)
	case fi.Mode().IsRegular():
		in, err := os.Open(src)
		if err != nil {
			return err
		}
		out, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
		if err != nil {
			in.Close()
			return err
		}
		_, cerr := io.Copy(out, in)
		in.Close()
		if clerr := out.Close(); cerr == nil {
			cerr = clerr
		}
		if cerr != nil {
			return cerr
		}
		_ = os.Chown(dst, uid, gid)
		_ = os.Chmod(dst, fi.Mode())
		_ = os.Chtimes(dst, fi.ModTime(), fi.ModTime())
	default:
		return fmt.Errorf("неподдерживаемый тип файла %s", fi.Mode())
	}
	return os.Remove(src)
}

// ---------- пользователи ----------

// usersToCreate: что из учётных записей источника отсутствует на приёмнике.
// При переносе между дистрибутивами (lvl>0) создаются только обычные
// пользователи (uid ≥ 1000): системные у каждого дистрибутива свои.
func usersToCreate(m *Manifest, lvl int) ([]Group, []User) {
	bu := map[string]bool{}
	for _, u := range readPasswd("/etc/passwd") {
		bu[u.Name] = true
	}
	bg := map[string]bool{}
	for _, g := range readGroups("/etc/group") {
		bg[g.Name] = true
	}
	agid := map[int]string{}
	for _, g := range m.Groups {
		agid[g.GID] = g.Name
	}
	var us []User
	need := map[string]bool{}
	for _, u := range m.Users {
		if u.UID == 0 || u.UID >= 65534 || u.Name == "root" || u.Name == "nobody" || bu[u.Name] {
			continue
		}
		if lvl > 0 && u.UID < 1000 {
			continue
		}
		us = append(us, u)
		if gn, ok := agid[u.GID]; ok {
			need[gn] = true
		}
		for _, gn := range u.Groups {
			need[gn] = true
		}
	}
	var gs []Group
	for _, g := range m.Groups {
		if g.Name == "root" || bg[g.Name] {
			continue
		}
		regular := g.GID >= 1000 && g.GID < 65534
		if lvl > 0 {
			if regular {
				gs = append(gs, g)
			}
			continue
		}
		if need[g.Name] || regular {
			gs = append(gs, g)
		}
	}
	return gs, us
}

func syncUsers(logf logFn, m *Manifest, lvl int) int {
	gs, us := usersToCreate(m, lvl)
	if len(gs) == 0 && len(us) == 0 {
		logf("   всё уже есть")
		return 0
	}
	if !hasCmd("useradd") && hasCmd("apk") {
		out, err := runCombined(5*time.Minute, "apk", "add", "shadow")
		logf("   apk add shadow (нужен useradd): %v %s", err, firstLine(out))
	}
	if !hasCmd("useradd") || !hasCmd("groupadd") {
		logf("!! нет useradd/groupadd — создать пользователей нельзя")
		return len(gs) + len(us)
	}
	nfail := 0
	usedGID := map[int]bool{}
	for _, g := range readGroups("/etc/group") {
		usedGID[g.GID] = true
	}
	usedUID := map[int]bool{}
	for _, u := range readPasswd("/etc/passwd") {
		usedUID[u.UID] = true
	}

	for _, g := range gs {
		var args []string
		if g.GID < 1000 {
			args = append(args, "-r")
		}
		if !usedGID[g.GID] {
			args = append(args, "-g", strconv.Itoa(g.GID))
		}
		args = append(args, g.Name)
		if out, err := runCombined(time.Minute, "groupadd", args...); err != nil {
			nfail++
			logf("!! groupadd %s: %v %s", g.Name, err, firstLine(out))
		} else {
			usedGID[g.GID] = true
			logf("   группа %s", g.Name)
		}
	}

	nowGroups := map[string]bool{}
	for _, g := range readGroups("/etc/group") {
		nowGroups[g.Name] = true
	}
	agid := map[int]string{}
	for _, g := range m.Groups {
		agid[g.GID] = g.Name
	}

	for _, u := range us {
		args := []string{"-M"} // домашний каталог приедет вместе с файлами
		if u.UID < 1000 {
			args = append(args, "-r")
		}
		if !usedUID[u.UID] {
			args = append(args, "-u", strconv.Itoa(u.UID))
		}
		primary := agid[u.GID]
		if primary != "" && nowGroups[primary] {
			args = append(args, "-g", primary)
		}
		if u.Home != "" {
			args = append(args, "-d", u.Home)
		}
		if u.Shell != "" {
			args = append(args, "-s", fixShell(u.Shell))
		}
		if u.Gecos != "" {
			args = append(args, "-c", u.Gecos)
		}
		if u.Hash != "" {
			args = append(args, "-p", u.Hash)
		}
		args = append(args, u.Name)
		if out, err := runCombined(time.Minute, "useradd", args...); err != nil {
			nfail++
			logf("!! useradd %s: %v %s", u.Name, err, firstLine(out))
			continue
		}
		usedUID[u.UID] = true
		logf("   пользователь %s", u.Name)

		var sup []string
		seen := map[string]bool{}
		for _, gn := range u.Groups {
			t := gn
			if !nowGroups[t] {
				t = ""
				for _, a := range aliasesFor(gn, true) {
					if nowGroups[a] {
						t = a
						break
					}
				}
			}
			if t != "" && t != primary && !seen[t] {
				seen[t] = true
				sup = append(sup, t)
			}
		}
		if len(sup) > 0 {
			if out, err := runCombined(time.Minute, "usermod", "-aG", strings.Join(sup, ","), u.Name); err != nil {
				logf("   ! usermod -aG %s %s: %v %s", strings.Join(sup, ","), u.Name, err, firstLine(out))
			}
		}
	}
	return nfail
}
