package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

func usage() {
	fmt.Fprintf(os.Stderr, `ferry %s — перенос серверов Linux: пакеты, конфиги, службы и данные

Команды:
  pki      создать CA и сертификаты для взаимного TLS (один раз, на любой машине)
  scan     показать, что найдено на ЭТОМ сервере (пакеты, службы, порты, cron...)
  serve    запустить приёмник (на сервере, КУДА переезжаем)
  push     выполнить перенос (на сервере, ОТКУДА переезжаем)
           -archive: не применять, а сохранить tar.gz на приёмнике
           -cross-distro: перенос между разными дистрибутивами
  archive  собрать tar.gz с данными этого сервера в локальный файл
  restore  развернуть такой архив на этом сервере (или распаковать в каталог)
  version

Примеры:
  ferry pki -dir ./pki -hosts 203.0.113.10
  ferry serve
  ferry push -server 203.0.113.10 -dry-run
  ferry push -server 203.0.113.10 -cross-distro -start
  ferry push -server 203.0.113.10 -archive
  ferry archive -o /backup/server.tar.gz
  ferry restore -archive /backup/server.tar.gz
  ferry restore -archive /backup/server.tar.gz -extract-to /mnt/restore

Подробности: README.md, а также «ferry <команда> -h».
`, version)
}

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	var err error
	switch os.Args[1] {
	case "pki":
		err = cmdPKI(os.Args[2:])
	case "scan":
		err = cmdScan(os.Args[2:])
	case "archive":
		err = cmdArchive(os.Args[2:])
	case "restore":
		err = cmdRestore(os.Args[2:])
	case "serve":
		err = cmdServe(os.Args[2:])
	case "push":
		err = cmdPush(os.Args[2:])
	case "version", "-v", "--version":
		fmt.Println("ferry", version)
		return
	case "help", "-h", "--help":
		usage()
		return
	default:
		usage()
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "ошибка:", err)
		os.Exit(1)
	}
}

func cmdScan(args []string) error {
	fl := flag.NewFlagSet("scan", flag.ExitOnError)
	out := fl.String("o", "", "записать полный манифест (JSON) в файл")
	hashes := fl.Bool("hashes", false, "включить в манифест хэши паролей из /etc/shadow (файл будет 0600)")
	paths := fl.String("paths", strings.Join(defaultRootsFor(hostInfo()), ","), "что копировать (через запятую)")
	etc := fl.String("etc", "custom", "режим /etc: custom | full | none")
	exclude := fl.String("exclude", "", "доп. исключения через запятую")
	_ = fl.Parse(args)

	if os.Geteuid() != 0 {
		fmt.Fprintln(os.Stderr, "внимание: без root часть данных (процессы у портов, shadow, закрытые каталоги) будет недоступна")
	}
	m, _, err := collect(CollectCfg{Paths: splitCSV(*paths), EtcMode: *etc, Excludes: splitCSV(*exclude), Hashes: *hashes})
	if err != nil {
		return err
	}

	h := m.Host
	fmt.Printf("Хост: %s — %s [семейство %s, пакеты: %s, init: %s], %s, ядро %s\n",
		h.Hostname, orDash(h.Pretty), h.Family, orDash(h.PM), h.Init, h.Arch, h.Kernel)

	manual := 0
	for _, p := range m.Packages {
		if p.Manual {
			manual++
		}
	}
	fmt.Printf("Пакеты: всего %d, установлено вручную %d\n", len(m.Packages), manual)

	en, run := 0, 0
	for _, u := range m.Units {
		if u.Enabled {
			en++
		}
		if u.Active {
			run++
		}
	}
	fmt.Printf("Юниты systemd: включено %d, запущено служб %d\n", en, run)

	fmt.Printf("Слушающие порты (%d):\n", len(m.Ports))
	for _, l := range m.Ports {
		fmt.Printf("  %-5s %-39s :%-5d %s\n", l.Proto, l.Addr, l.Port, l.Process)
	}

	fmt.Printf("Cron-записей: %d\n", len(m.Cron))
	nu := 0
	for _, u := range m.Users {
		if u.UID >= 1000 && u.UID < 65534 {
			nu++
		}
	}
	fmt.Printf("Пользователей: %d (обычных: %d), групп: %d\n", len(m.Users), nu, len(m.Groups))
	t := m.Transfer
	fmt.Printf("К передаче: %d файлов, %d каталогов, %s (из /etc отобрано: %d, режим %s)\n",
		t.Files, t.Dirs, humanBytes(t.Bytes), t.EtcFiles, t.EtcMode)
	for _, w := range m.Warnings {
		fmt.Println("  ! " + w)
	}

	if *out != "" {
		b, err := json.MarshalIndent(m, "", "  ")
		if err != nil {
			return err
		}
		if err := os.WriteFile(*out, b, 0600); err != nil {
			return err
		}
		fmt.Println("Манифест записан в", *out)
	}
	return nil
}

// cmdArchive собирает локальный tar.gz (тот же набор файлов, что и push)
// и рядом кладёт <файл>.manifest.json.
func cmdArchive(args []string) error {
	fl := flag.NewFlagSet("archive", flag.ExitOnError)
	out := fl.String("o", "", "путь к выходному архиву, например /backup/srv.tar.gz (обязательно)")
	paths := fl.String("paths", strings.Join(defaultRootsFor(hostInfo()), ","), "что копировать (через запятую)")
	etc := fl.String("etc", "custom", "режим /etc: custom | full | none")
	exclude := fl.String("exclude", "", "доп. исключения через запятую")
	hashes := fl.Bool("hashes", false, "включить хэши паролей в манифест (0600)")
	_ = fl.Parse(args)

	if err := requireRoot(); err != nil {
		return err
	}
	if *out == "" {
		return fmt.Errorf("укажите -o файл.tar.gz")
	}
	abs, err := filepath.Abs(*out)
	if err != nil {
		return err
	}
	excl := append(splitCSV(*exclude), abs, abs+".manifest.json")
	m, list, err := collect(CollectCfg{Paths: splitCSV(*paths), EtcMode: *etc, Excludes: excl, Hashes: *hashes})
	if err != nil {
		return err
	}
	for _, w := range m.Warnings {
		fmt.Println("  ! " + w)
	}
	f, err := os.OpenFile(abs, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return err
	}
	h := sha256.New()
	st := &progress{total: m.Transfer.Bytes}
	done := make(chan struct{})
	go st.run(done)
	perr := packStream(io.MultiWriter(f, h), list, st)
	close(done)
	cerr := f.Close()
	fmt.Println()
	if perr != nil {
		return perr
	}
	if cerr != nil {
		return cerr
	}
	b, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return err
	}
	if err := os.WriteFile(abs+".manifest.json", b, 0600); err != nil {
		return err
	}
	fi, _ := os.Stat(abs)
	size := int64(0)
	if fi != nil {
		size = fi.Size()
	}
	fmt.Printf("Готово: %s (%s), sha256 %s\nМанифест: %s.manifest.json\n", abs, humanBytes(size), hex.EncodeToString(h.Sum(nil)), abs)
	return nil
}
