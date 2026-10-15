package main

import (
	"fmt"
	"os"
	"sort"
	"strings"
	"syscall"
)

func freeBytes(dir string) uint64 {
	_ = os.MkdirAll(dir, 0700)
	var st syscall.Statfs_t
	if err := syscall.Statfs(dir, &st); err != nil {
		return 0
	}
	return uint64(st.Bavail) * uint64(st.Bsize)
}

func orDash(s string) string {
	if s == "" {
		return "?"
	}
	return s
}

func levelName(l int) string {
	switch l {
	case 0:
		return "тот же дистрибутив"
	case 1:
		return "то же семейство, другой дистрибутив"
	}
	return "другое семейство дистрибутивов"
}

// buildPlan сравнивает манифест источника с состоянием этого сервера.
// checkDisk=false используется при применении (место под staging уже занято).
func buildPlan(m *Manifest, o Options, checkDisk bool) *Plan {
	p := &Plan{Items: m.Transfer.Files + m.Transfer.Dirs, Bytes: m.Transfer.Bytes}
	me := hostInfo()
	lvl := crossLevel(m.Host, me)
	p.Cross = lvl

	if m.Proto != protoVersion {
		p.Errors = append(p.Errors, fmt.Sprintf("несовместимая версия протокола: источник %d, приёмник %d", m.Proto, protoVersion))
	}
	if me.Arch != m.Host.Arch {
		p.Errors = append(p.Errors, fmt.Sprintf("разные архитектуры: источник %q, приёмник %q (бинарники из /opt и /usr/local не подойдут)", m.Host.Arch, me.Arch))
	}
	if me.PM == "" {
		p.Errors = append(p.Errors, "на приёмнике не определён пакетный менеджер (поддерживаются Debian/Ubuntu, RHEL/Fedora/Alma/Rocky, SUSE, Arch, Alpine)")
	}

	switch {
	case lvl > 0:
		msg := fmt.Sprintf("разные дистрибутивы: источник %s, приёмник %s — %s",
			orDash(m.Host.Pretty), orDash(me.Pretty), levelName(lvl))
		if o.CrossDistro {
			p.Warnings = append(p.Warnings, msg)
		} else {
			p.Errors = append(p.Errors, msg+" (разрешить: -cross-distro)")
		}
		p.Warnings = append(p.Warnings,
			"репозитории и системные конфиги ОС не переносятся; имена пакетов, служб и системных пользователей сопоставляются автоматически")
		if lvl == 2 {
			p.Warnings = append(p.Warnings,
				"другое семейство: не переносятся PAM, sshd_config, sudoers, /etc/default, init-скрипты — проверьте доступ по SSH до выхода из сессии")
		}
	case releaseKey(m.Host) != releaseKey(me):
		msg := fmt.Sprintf("релизы различаются: источник %s, приёмник %s", releaseKey(m.Host), releaseKey(me))
		if o.AllowReleaseMismatch {
			p.Warnings = append(p.Warnings, msg)
		} else {
			p.Errors = append(p.Errors, msg+" (разрешить: -allow-release-mismatch)")
		}
	}

	pm := newPkgMgr(me.PM)

	// пакеты
	if !o.NoPackages {
		mapper, err := newMapper(o.PkgMap)
		if err != nil {
			p.Errors = append(p.Errors, err.Error())
			mapper, _ = newMapper("")
		}
		have := map[string]Package{}
		if pk, err := pm.List(); err == nil {
			for _, x := range pk {
				have[x.Name] = x
			}
		}
		queued := map[string]bool{}
		for _, a := range m.Packages {
			if !a.Manual {
				continue
			}
			if skipPkg(a.Name, o.SkipPkgs) {
				p.SkippedPackages = append(p.SkippedPackages, a.Name)
				continue
			}
			names, skip := mapper.translate(a.Name, m.Host.Family, me.Family)
			if skip {
				p.UnmappedPackages = append(p.UnmappedPackages, a.Name+" (нет аналога)")
				continue
			}
			if len(names) != 1 || names[0] != a.Name {
				p.PackageMap = append(p.PackageMap, a.Name+" → "+strings.Join(names, " "))
			}
			for _, n := range names {
				b, ok := have[n]
				switch {
				case !ok:
					if !queued[n] {
						queued[n] = true
						p.InstallPackages = append(p.InstallPackages, n)
					}
				case lvl == 0 && b.Version != a.Version:
					p.VersionDiffs = append(p.VersionDiffs,
						fmt.Sprintf("%s: источник %s, приёмник %s", a.Name, a.Version, b.Version))
				}
			}
		}
	}

	// пользователи и группы
	gs, us := usersToCreate(m, lvl)
	for _, g := range gs {
		p.CreateGroups = append(p.CreateGroups, fmt.Sprintf("%s (gid %d)", g.Name, g.GID))
	}
	for _, u := range us {
		p.CreateUsers = append(p.CreateUsers, fmt.Sprintf("%s (uid %d)", u.Name, u.UID))
	}

	// службы
	p.EnableUnits = unitsToEnable(m, me)

	// порты: что уже занято на приёмнике
	busy := map[string]Listener{}
	for _, l := range scanPorts() {
		busy[fmt.Sprintf("%s:%d", normProto(l.Proto), l.Port)] = l
	}
	seen := map[string]bool{}
	for _, l := range m.Ports {
		k := fmt.Sprintf("%s:%d", normProto(l.Proto), l.Port)
		if b, ok := busy[k]; ok && !seen[k] {
			seen[k] = true
			p.Warnings = append(p.Warnings,
				fmt.Sprintf("порт %d/%s на приёмнике уже занят (%s) — на источнике его слушает %s",
					l.Port, normProto(l.Proto), orDash(b.Process), orDash(l.Process)))
		}
	}

	// базы данных и контейнеры: файлы не копируем «вживую»
	var dbs []string
	for _, u := range m.Units {
		if !u.Active {
			continue
		}
		n := strings.ToLower(u.Name)
		for _, k := range []string{"mysql", "mariadb", "postgres", "redis", "mongo", "elasticsearch", "influx", "docker", "containerd"} {
			if strings.Contains(n, k) {
				dbs = append(dbs, u.Name)
				break
			}
		}
	}
	if len(dbs) > 0 {
		p.Warnings = append(p.Warnings,
			"на источнике запущено: "+strings.Join(dbs, ", ")+
				" — их данные (/var/lib/...) НЕ копируются; сделайте дамп в /root/ и перенесите отдельно (см. README)")
	}

	if checkDisk {
		p.FreeBytes = freeBytes(stateDir)
		if p.FreeBytes > 0 && uint64(m.Transfer.Bytes)/100*105 > p.FreeBytes {
			p.Errors = append(p.Errors,
				fmt.Sprintf("не хватает места под staging в %s: нужно ~%s, свободно %s",
					stateDir, humanBytes(m.Transfer.Bytes), humanBytes(int64(p.FreeBytes))))
		}
	}

	sort.Strings(p.InstallPackages)
	sort.Strings(p.SkippedPackages)
	sort.Strings(p.PackageMap)
	return p
}
