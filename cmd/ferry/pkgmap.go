package main

import (
	"fmt"
	"regexp"
	"strings"
)

// Таблица соответствия имён пакетов между семействами.
// Формат строки:  debian | rhel | suse | arch | alpine
//   "-"  — то же имя, что в колонке debian
//   "!"  — аналога нет, пакет пропускается
//   несколько имён через пробел — ставятся все
// Свои строки можно передать файлом: -pkgmap my.map (они перекрывают встроенные).
const defaultPkgMapDSL = `
# сервисы и веб
apache2           | httpd             | apache2            | apache          | apache2
nginx             | -                 | -                  | -               | -
redis-server      | redis             | redis              | redis           | redis
memcached         | -                 | -                  | -               | -
haproxy           | -                 | -                  | -               | -
certbot           | -                 | -                  | -               | -
python3-certbot-nginx  | -            | -                  | certbot-nginx   | certbot-nginx
python3-certbot-apache | -            | -                  | certbot-apache  | certbot-apache
php-fpm           | -                 | -                  | -               | -
# базы данных
mariadb-server    | mariadb-server    | mariadb            | mariadb         | mariadb
mariadb-client    | mariadb           | mariadb-client     | mariadb-clients | mariadb-client
postgresql        | postgresql-server | postgresql-server  | postgresql      | postgresql
postgresql-client | postgresql        | postgresql         | postgresql      | postgresql-client
sqlite3           | sqlite            | sqlite3            | sqlite          | sqlite
# ssh, cron, сеть
openssh-server    | -                 | openssh            | openssh         | -
openssh-client    | openssh-clients   | openssh-clients    | openssh         | openssh-client
cron              | cronie            | cron               | cronie          | dcron
iproute2          | iproute           | -                  | -               | -
iputils-ping      | iputils           | iputils            | iputils         | iputils
netcat-openbsd    | nmap-ncat         | -                  | openbsd-netcat  | -
dnsutils          | bind-utils        | bind-utils         | bind            | bind-tools
bind9             | bind              | bind               | bind            | bind
ufw               | !                 | ufw                | ufw             | ufw
nfs-common        | nfs-utils         | nfs-client         | nfs-utils       | nfs-utils
nfs-kernel-server | nfs-utils         | -                  | nfs-utils       | nfs-utils
isc-dhcp-server   | dhcp-server       | dhcp-server        | dhcp            | dhcp
# разработка
build-essential   | gcc gcc-c++ make  | gcc gcc-c++ make   | base-devel      | build-base
golang-go         | golang            | go                 | go              | go
python3-pip       | -                 | -                  | python-pip      | py3-pip
python3-venv      | python3           | python3            | python          | python3
python3-dev       | python3-devel     | python3-devel      | python          | python3-dev
nodejs            | -                 | nodejs-default     | -               | -
npm               | -                 | npm-default        | -               | -
libssl-dev        | openssl-devel     | libopenssl-devel   | openssl         | openssl-dev
zlib1g-dev        | zlib-devel        | zlib-devel         | zlib            | zlib-dev
libpq-dev         | libpq-devel       | postgresql-devel   | postgresql-libs | libpq-dev
libffi-dev        | libffi-devel      | libffi-devel       | libffi          | libffi-dev
libxml2-dev       | libxml2-devel     | libxml2-devel      | libxml2         | libxml2-dev
libcurl4-openssl-dev | libcurl-devel  | libcurl-devel      | curl            | curl-dev
# утилиты
vim               | vim-enhanced      | -                  | -               | -
vim-tiny          | vim-minimal       | vim                | vim             | vim
p7zip-full        | p7zip p7zip-plugins | 7zip             | p7zip           | 7zip
imagemagick       | ImageMagick       | ImageMagick        | imagemagick     | imagemagick
docker.io         | docker            | docker             | docker          | docker
docker-compose-plugin | docker-compose-plugin | docker-compose | docker-compose | docker-cli-compose
chrony            | -                 | -                  | -               | -
# пакеты Debian/Ubuntu без смысла на других системах
software-properties-common | !        | !                  | !               | !
apt-transport-https | !               | !                  | !               | !
unattended-upgrades | !               | !                  | !               | !
needrestart       | !                 | !                  | !               | !
`

var famCols = []string{"debian", "rhel", "suse", "arch", "alpine"}

type pkgRow struct{ cols map[string][]string }

type pkgMapper struct {
	idx map[string]map[string]*pkgRow // семейство -> одиночное имя -> строка
}

func parsePkgMap(dsl string) (*pkgMapper, error) {
	m := &pkgMapper{idx: map[string]map[string]*pkgRow{}}
	for _, f := range famCols {
		m.idx[f] = map[string]*pkgRow{}
	}
	for n, line := range strings.Split(dsl, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.Split(line, "|")
		if len(parts) != len(famCols) {
			return nil, fmt.Errorf("pkgmap: строка %d: ожидается %d колонок через |", n+1, len(famCols))
		}
		row := &pkgRow{cols: map[string][]string{}}
		base := strings.Fields(parts[0])
		if len(base) == 0 {
			return nil, fmt.Errorf("pkgmap: строка %d: пустая колонка debian", n+1)
		}
		for i, f := range famCols {
			c := strings.TrimSpace(parts[i])
			switch {
			case c == "-":
				row.cols[f] = base
			case c == "!":
				row.cols[f] = []string{"!"}
			default:
				row.cols[f] = strings.Fields(c)
			}
		}
		for _, f := range famCols {
			names := row.cols[f]
			if len(names) == 1 && names[0] != "!" {
				m.idx[f][names[0]] = row
			}
		}
	}
	return m, nil
}

func newMapper(extra string) (*pkgMapper, error) {
	return parsePkgMap(defaultPkgMapDSL + "\n" + extra)
}

var (
	rePHP    = regexp.MustCompile(`^php[0-9.]+-(.+)$`)
	rePy     = regexp.MustCompile(`^python3-(.+)$`)
	reLibDev = regexp.MustCompile(`^lib(.+)-dev$`)
)

// regexTranslate — правила для имён с версиями/шаблонами (только из debian).
func regexTranslate(name, src, dst string) string {
	if src != "debian" {
		return ""
	}
	if m := rePHP.FindStringSubmatch(name); m != nil && (dst == "rhel" || dst == "arch") {
		return "php-" + m[1]
	}
	if m := rePy.FindStringSubmatch(name); m != nil {
		switch dst {
		case "arch":
			return "python-" + m[1]
		case "alpine":
			return "py3-" + m[1]
		}
	}
	if m := reLibDev.FindStringSubmatch(name); m != nil && (dst == "rhel" || dst == "suse") {
		return "lib" + m[1] + "-devel"
	}
	return ""
}

// translate: имя пакета на источнике (семейство src) → имена на приёмнике (семейство dst).
// skip=true означает, что аналога нет и пакет надо пропустить.
func (m *pkgMapper) translate(name, src, dst string) (names []string, skip bool) {
	if src == dst || src == "unknown" || dst == "unknown" {
		return []string{name}, false
	}
	if row, ok := m.idx[src][name]; ok {
		t := row.cols[dst]
		if len(t) == 1 && t[0] == "!" {
			return nil, true
		}
		if len(t) > 0 {
			return t, false
		}
		return []string{name}, false
	}
	if t := regexTranslate(name, src, dst); t != "" {
		return []string{t}, false
	}
	return []string{name}, false
}
