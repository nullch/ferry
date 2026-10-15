package main

import (
	"fmt"
	"os"
	"regexp"
	"sort"
	"strings"
	"time"
)

// scanUnits возвращает включённые и запущенные службы по init-системе этого сервера.
func scanUnits() []Unit {
	switch detectInit() {
	case "systemd":
		return scanUnitsSystemd()
	case "openrc":
		return scanUnitsOpenRC()
	}
	return nil
}

func scanUnitsSystemd() []Unit {
	enabled := map[string]bool{}
	out, _ := runStdout(30*time.Second, "systemctl", "list-unit-files",
		"--type=service,timer,socket,path", "--state=enabled", "--no-legend", "--no-pager", "--plain")
	for _, l := range strings.Split(out, "\n") {
		f := strings.Fields(l)
		if len(f) >= 2 && f[1] == "enabled" {
			enabled[f[0]] = true
		}
	}
	active := map[string]bool{}
	out, _ = runStdout(30*time.Second, "systemctl", "list-units",
		"--type=service", "--state=running", "--no-legend", "--no-pager", "--plain")
	for _, l := range strings.Split(out, "\n") {
		if f := strings.Fields(l); len(f) >= 1 {
			active[f[0]] = true
		}
	}
	return mergeUnits(enabled, active)
}

func scanUnitsOpenRC() []Unit {
	enabled := map[string]bool{}
	out, _ := runStdout(30*time.Second, "rc-update", "show")
	for _, l := range strings.Split(out, "\n") {
		f := strings.Split(l, "|")
		if len(f) != 2 {
			continue
		}
		for _, lvl := range strings.Fields(f[1]) {
			if lvl == "default" {
				enabled[strings.TrimSpace(f[0])] = true
			}
		}
	}
	active := map[string]bool{}
	out, _ = runStdout(30*time.Second, "rc-status", "-a")
	for _, l := range strings.Split(out, "\n") {
		if strings.Contains(l, "[") && strings.Contains(l, "started") {
			if f := strings.Fields(l); len(f) > 0 {
				active[f[0]] = true
			}
		}
	}
	return mergeUnits(enabled, active)
}

func mergeUnits(enabled, active map[string]bool) []Unit {
	names := map[string]bool{}
	for n := range enabled {
		names[n] = true
	}
	for n := range active {
		names[n] = true
	}
	var res []Unit
	for n := range names {
		res = append(res, Unit{Name: n, Enabled: enabled[n], Active: active[n]})
	}
	sort.Slice(res, func(i, j int) bool { return res[i].Name < res[j].Name })
	return res
}

// Одна и та же служба называется по-разному в разных дистрибутивах.
var unitAliasRows = [][]string{
	{"apache2.service", "httpd.service"},
	{"ssh.service", "sshd.service"},
	{"cron.service", "crond.service"},
	{"redis-server.service", "redis.service"},
	{"mariadb.service", "mysql.service", "mysqld.service"},
	{"bind9.service", "named.service"},
	{"smbd.service", "smb.service"},
	{"nmbd.service", "nmb.service"},
	{"exim4.service", "exim.service"},
	{"isc-dhcp-server.service", "dhcpd.service"},
	{"nfs-kernel-server.service", "nfs-server.service"},
	{"chrony.service", "chronyd.service"},
	{"rsyslog.service", "syslog.service"},
}

var rePHPFPM = regexp.MustCompile(`^php[0-9.]+-fpm(\.service)?$`)

// unitCandidates: имя службы с источника + известные синонимы.
func unitCandidates(name string) []string {
	res := []string{name}
	for _, row := range unitAliasRows {
		for _, n := range row {
			if strings.TrimSuffix(n, ".service") == strings.TrimSuffix(name, ".service") {
				for _, o := range row {
					if o != name {
						res = append(res, o)
					}
				}
				return res
			}
		}
	}
	if rePHPFPM.MatchString(name) {
		res = append(res, "php-fpm.service")
	}
	return res
}

// normalizeUnit приводит имя к форме init-системы: foo.service ↔ foo.
func normalizeUnit(initSys, n string) string {
	switch initSys {
	case "openrc":
		return strings.TrimSuffix(n, ".service")
	case "systemd":
		if !strings.Contains(n, ".") {
			return n + ".service"
		}
	}
	return n
}

func unitExists(initSys, name string) bool {
	switch initSys {
	case "systemd":
		_, err := runStdout(20*time.Second, "systemctl", "cat", name)
		return err == nil
	case "openrc":
		_, err := os.Stat("/etc/init.d/" + name)
		return err == nil
	}
	return false
}

// resolveUnit подбирает существующую на этом сервере службу по имени с источника.
func resolveUnit(initSys, name string) (string, bool) {
	for _, c := range unitCandidates(name) {
		t := normalizeUnit(initSys, c)
		if unitExists(initSys, t) {
			return t, true
		}
	}
	return name, false
}

func reloadInit(initSys string) error {
	if initSys == "systemd" {
		out, err := runCombined(2*time.Minute, "systemctl", "daemon-reload")
		if err != nil {
			return fmt.Errorf("%v %s", err, firstLine(out))
		}
	}
	return nil
}

func enableUnit(initSys, name string) (string, error) {
	switch initSys {
	case "systemd":
		return runCombined(time.Minute, "systemctl", "enable", name)
	case "openrc":
		return runCombined(time.Minute, "rc-update", "add", name, "default")
	}
	return "", fmt.Errorf("init-система не поддерживается")
}

func startUnit(initSys, name string) (string, error) {
	switch initSys {
	case "systemd":
		return runCombined(3*time.Minute, "systemctl", "start", name)
	case "openrc":
		return runCombined(3*time.Minute, "rc-service", name, "start")
	}
	return "", fmt.Errorf("init-система не поддерживается")
}

func unitActive(initSys, name string) bool {
	switch initSys {
	case "systemd":
		out, _ := runStdout(30*time.Second, "systemctl", "is-active", name)
		return strings.TrimSpace(out) == "active"
	case "openrc":
		_, err := runStdout(30*time.Second, "rc-service", name, "status")
		return err == nil
	}
	return false
}

// unitsToEnable: включённые на источнике службы, которых ещё нет среди включённых здесь.
func unitsToEnable(m *Manifest, me HostInfo) []string {
	have := map[string]bool{}
	for _, u := range scanUnits() {
		if u.Enabled {
			have[u.Name] = true
		}
	}
	var res []string
	for _, u := range m.Units {
		if !u.Enabled || globAny(skipUnits, u.Name) {
			continue
		}
		if have[u.Name] || have[normalizeUnit(me.Init, u.Name)] {
			continue
		}
		res = append(res, u.Name)
	}
	return res
}
