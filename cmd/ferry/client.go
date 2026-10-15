package main

import (
	"archive/tar"
	"bufio"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"time"
)

type apiClient struct {
	hc   *http.Client
	base string
}

func (c *apiClient) doJSON(method, p string, in, out any) error {
	var body io.Reader
	if in != nil {
		b, err := json.Marshal(in)
		if err != nil {
			return err
		}
		body = bytes.NewReader(b)
	}
	req, err := http.NewRequest(method, c.base+p, body)
	if err != nil {
		return err
	}
	if in != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.hc.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<16))
		return fmt.Errorf("%s %s: %s: %s", method, p, resp.Status, strings.TrimSpace(string(b)))
	}
	if out != nil {
		return json.NewDecoder(resp.Body).Decode(out)
	}
	return nil
}

func cmdPush(args []string) error {
	fl := flag.NewFlagSet("push", flag.ExitOnError)
	server := fl.String("server", "", "адрес приёмника host[:port] (обязательно)")
	pki := fl.String("pki", defaultPKI, "каталог с ca.crt, client.crt, client.key")
	serverName := fl.String("server-name", "", "имя для проверки серверного сертификата (по умолчанию host из -server)")
	paths := fl.String("paths", strings.Join(defaultRootsFor(hostInfo()), ","), "что копировать (через запятую)")
	etc := fl.String("etc", "custom", "режим /etc: custom (только изменённое) | full | none")
	exclude := fl.String("exclude", "", "доп. исключения: пути или маски через запятую")
	skipPkgs := fl.String("skip-pkg", "", "пакеты, которые не ставить на приёмнике (маски через запятую)")
	noPkg := fl.Bool("no-packages", false, "не устанавливать пакеты")
	relOK := fl.Bool("allow-release-mismatch", false, "разрешить другой релиз того же дистрибутива")
	cross := fl.Bool("cross-distro", false, "разрешить перенос между разными дистрибутивами (Debian→Rocky и т.п.)")
	pkgmap := fl.String("pkgmap", "", "файл с доп. соответствиями имён пакетов (формат: debian | rhel | suse | arch | alpine)")
	start := fl.Bool("start", false, "после переноса запустить службы, работавшие на источнике")
	dry := fl.Bool("dry-run", false, "только показать план, ничего не передавать")
	yes := fl.Bool("yes", false, "не спрашивать подтверждение")
	archive := fl.Bool("archive", false, "не применять, а только сохранить tar.gz с данными сервера на приёмнике")
	resume := fl.String("resume", "", "ID сессии: только повторить apply для уже загруженных данных")
	_ = fl.Parse(args)

	if err := requireRoot(); err != nil {
		return err
	}
	if *server == "" {
		return errors.New("укажите -server host:port")
	}
	switch *etc {
	case "custom", "full", "none":
	default:
		return fmt.Errorf("неверный -etc: %q", *etc)
	}
	host, port, err := net.SplitHostPort(*server)
	if err != nil {
		host, port = *server, defaultPort
	}
	name := *serverName
	if name == "" {
		name = host
	}
	tcfg, err := clientTLS(*pki, name)
	if err != nil {
		return err
	}
	c := &apiClient{
		base: "https://" + net.JoinHostPort(host, port),
		hc: &http.Client{Transport: &http.Transport{
			TLSClientConfig:     tcfg,
			DisableCompression:  true,
			MaxIdleConnsPerHost: 1,
			IdleConnTimeout:     90 * time.Second,
		}},
	}

	var hello HostInfo
	if err := c.doJSON("GET", "/v1/hello", nil, &hello); err != nil {
		return fmt.Errorf("связь с приёмником: %w", err)
	}
	if hello.Version != protoVersion {
		return fmt.Errorf("разные версии протокола: у приёмника %d, у источника %d", hello.Version, protoVersion)
	}
	fmt.Printf("Приёмник: %s — %s (%s, %s, init: %s)\n", hello.Hostname, orDash(hello.Pretty), hello.PM, hello.Arch, hello.Init)
	if *resume != "" {
		fmt.Println("Повторное применение сессии", *resume)
		return c.apply(*resume)
	}

	fmt.Println("Сканирую источник...")
	excl := splitCSV(*exclude)
	if !*archive {
		excl = append(excl, crossExcludes(crossLevel(hostInfo(), hello))...)
	}
	if abs, err := filepath.Abs(*pki); err == nil {
		excl = append(excl, abs)
	}
	m, list, err := collect(CollectCfg{Paths: splitCSV(*paths), EtcMode: *etc, Excludes: excl, Hashes: true})
	if err != nil {
		return err
	}
	for _, w := range m.Warnings {
		fmt.Println("  ! " + w)
	}
	if *archive {
		return pushArchive(c, m, list, *dry, *yes)
	}
	req := &PlanRequest{
		Manifest: m,
		Options: Options{
			SkipPkgs:             splitCSV(*skipPkgs),
			NoPackages:           *noPkg,
			AllowReleaseMismatch: *relOK,
			CrossDistro:          *cross,
			Start:                *start,
		},
	}
	if *pkgmap != "" {
		b, err := os.ReadFile(*pkgmap)
		if err != nil {
			return err
		}
		req.Options.PkgMap = string(b)
	}

	var plan Plan
	if err := c.doJSON("POST", "/v1/plan", req, &plan); err != nil {
		return err
	}
	printPlan(&plan)
	if len(plan.Errors) > 0 {
		return errors.New("план содержит ошибки, выполнение невозможно")
	}
	if *dry {
		fmt.Println("dry-run: ничего не передавалось.")
		return nil
	}
	if !*yes && !confirm("Начать перенос?") {
		return errors.New("отменено")
	}

	var sess struct {
		ID string `json:"id"`
	}
	if err := c.doJSON("POST", "/v1/session", req, &sess); err != nil {
		return err
	}
	fmt.Println("Сессия:", sess.ID)

	fmt.Println("Передаю данные...")
	res, err := c.upload(sess.ID, list, m.Transfer.Bytes)
	fmt.Println()
	if err != nil {
		return err
	}
	fmt.Printf("Принято: файлов %d, каталогов %d, %s, пропущено правилами: %d\n",
		res.Files, res.Dirs, humanBytes(res.Bytes), res.Skipped)
	if len(res.Mismatches) > 0 {
		for i, mm := range res.Mismatches {
			if i >= 30 {
				fmt.Printf("  ... и ещё %d\n", len(res.Mismatches)-30)
				break
			}
			fmt.Println("  ✗", mm)
		}
		return errors.New("контрольные суммы не сошлись — применение отменено (данные лежат в staging на приёмнике)")
	}

	fmt.Println("Применяю на приёмнике...")
	return c.apply(sess.ID)
}

func confirm(q string) bool {
	fmt.Printf("%s [y/N]: ", q)
	s, _ := bufio.NewReader(os.Stdin).ReadString('\n')
	s = strings.ToLower(strings.TrimSpace(s))
	return s == "y" || s == "yes" || s == "д" || s == "да"
}

func printPlan(p *Plan) {
	fmt.Println("\n=== ПЛАН ===")
	fmt.Printf("Объектов к передаче: %d, объём: %s", p.Items, humanBytes(p.Bytes))
	if p.FreeBytes > 0 {
		fmt.Printf(" (свободно на приёмнике: %s)", humanBytes(int64(p.FreeBytes)))
	}
	fmt.Println()
	show := func(title string, items []string) {
		if len(items) == 0 {
			return
		}
		fmt.Printf("%s (%d):\n", title, len(items))
		for i, it := range items {
			if i >= 40 {
				fmt.Printf("    ... и ещё %d\n", len(items)-40)
				break
			}
			fmt.Println("    " + it)
		}
	}
	show("Пакеты к установке", p.InstallPackages)
	show("Соответствие имён пакетов", p.PackageMap)
	show("Пакеты без аналога (пропускаются)", p.UnmappedPackages)
	show("Пакеты, пропущенные правилами", p.SkippedPackages)
	show("Расхождения версий (не меняются)", p.VersionDiffs)
	show("Группы к созданию", p.CreateGroups)
	show("Пользователи к созданию", p.CreateUsers)
	show("Юниты к включению", p.EnableUnits)
	show("ПРЕДУПРЕЖДЕНИЯ", p.Warnings)
	show("ОШИБКИ", p.Errors)
	fmt.Println()
}

// ---------- передача ----------

type progress struct {
	files int64 // atomic
	bytes int64 // atomic
	total int64
}

func (p *progress) run(done <-chan struct{}) {
	t := time.NewTicker(2 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-done:
			return
		case <-t.C:
			b := atomic.LoadInt64(&p.bytes)
			pct := 0.0
			if p.total > 0 {
				pct = float64(b) * 100 / float64(p.total)
			}
			fmt.Fprintf(os.Stderr, "\r  прочитано %s из ~%s (%.0f%%), файлов: %d   ",
				humanBytes(b), humanBytes(p.total), pct, atomic.LoadInt64(&p.files))
		}
	}
}

func warnf(format string, a ...any) {
	fmt.Fprintf(os.Stderr, "\n  ! "+format+"\n", a...)
}

func (c *apiClient) upload(id string, list []string, total int64) (*UploadResult, error) {
	pr, pw := io.Pipe()
	defer pr.Close()
	st := &progress{total: total}
	done := make(chan struct{})
	defer close(done)
	go st.run(done)
	go func() { pw.CloseWithError(packStream(pw, list, st)) }()

	req, err := http.NewRequest("PUT", c.base+"/v1/session/"+id+"/data", pr)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/gzip")
	resp, err := c.hc.Do(req)
	if err != nil {
		pr.CloseWithError(err)
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<16))
		return nil, fmt.Errorf("приёмник: %s: %s", resp.Status, strings.TrimSpace(string(b)))
	}
	var res UploadResult
	if err := json.NewDecoder(resp.Body).Decode(&res); err != nil {
		return nil, err
	}
	return &res, nil
}

// packStream пишет tar.gz в w. В конце добавляет трейлер с sha256 всех файлов:
// приёмник пересчитывает суммы при распаковке и сверяет их.
func packStream(w io.Writer, list []string, st *progress) error {
	gz, err := gzip.NewWriterLevel(w, gzip.BestSpeed)
	if err != nil {
		return err
	}
	tw := tar.NewWriter(gz)
	sums := make(map[string]string)
	buf := make([]byte, 256*1024)

	for _, p := range list {
		fi, err := os.Lstat(p)
		if err != nil {
			warnf("пропуск %s: %v", p, err)
			continue
		}
		link := ""
		isLink := fi.Mode()&os.ModeSymlink != 0
		if isLink {
			link, err = os.Readlink(p)
			if err != nil {
				warnf("пропуск %s: %v", p, err)
				continue
			}
		}
		hdr, err := tar.FileInfoHeader(fi, link)
		if err != nil {
			warnf("пропуск %s: %v", p, err)
			continue
		}
		hdr.Name = strings.TrimPrefix(p, "/")
		if fi.IsDir() {
			hdr.Name += "/"
		}
		switch {
		case fi.IsDir() || isLink:
			if err := tw.WriteHeader(hdr); err != nil {
				return err
			}
			atomic.AddInt64(&st.files, 1)
		case fi.Mode().IsRegular():
			f, err := os.Open(p)
			if err != nil {
				warnf("пропуск %s: %v", p, err)
				continue
			}
			sum, err := writeRegular(tw, hdr, f, fi.Size(), buf, st, p)
			f.Close()
			if err != nil {
				return err
			}
			sums[p] = sum
			atomic.AddInt64(&st.files, 1)
		}
	}

	tb, err := json.Marshal(sums)
	if err != nil {
		return err
	}
	if err := tw.WriteHeader(&tar.Header{Name: trailerName, Mode: 0600, Size: int64(len(tb)), Typeflag: tar.TypeReg}); err != nil {
		return err
	}
	if _, err := tw.Write(tb); err != nil {
		return err
	}
	if err := tw.Close(); err != nil {
		return err
	}
	return gz.Close()
}

// writeRegular пишет заголовок и ровно size байт. Если файл «усох» или
// не читается посреди передачи — добиваем нулями (с предупреждением), чтобы
// не оборвать весь поток.
func writeRegular(tw *tar.Writer, hdr *tar.Header, f io.Reader, size int64, buf []byte, st *progress, name string) (string, error) {
	if err := tw.WriteHeader(hdr); err != nil {
		return "", err
	}
	h := sha256.New()
	var done int64
	for done < size {
		want := int64(len(buf))
		if size-done < want {
			want = size - done
		}
		n, rerr := f.Read(buf[:want])
		if n > 0 {
			if _, err := tw.Write(buf[:n]); err != nil {
				return "", err
			}
			h.Write(buf[:n])
			done += int64(n)
			atomic.AddInt64(&st.bytes, int64(n))
		}
		if rerr != nil {
			break
		}
	}
	if done < size {
		warnf("%s изменился/не читается во время копирования, дополнено нулями (%d из %d байт)", name, done, size)
		zero := make([]byte, 32*1024)
		for done < size {
			k := int64(len(zero))
			if size-done < k {
				k = size - done
			}
			if _, err := tw.Write(zero[:k]); err != nil {
				return "", err
			}
			h.Write(zero[:k])
			done += k
		}
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func (c *apiClient) apply(id string) error {
	req, err := http.NewRequest("POST", c.base+"/v1/session/"+id+"/apply", nil)
	if err != nil {
		return err
	}
	resp, err := c.hc.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<16))
		return fmt.Errorf("приёмник: %s: %s", resp.Status, strings.TrimSpace(string(b)))
	}
	sc := bufio.NewScanner(resp.Body)
	sc.Buffer(make([]byte, 1<<20), 8<<20)
	last := ""
	for sc.Scan() {
		last = sc.Text()
		fmt.Println(last)
	}
	if err := sc.Err(); err != nil {
		return fmt.Errorf("соединение оборвано: %w (применение на приёмнике могло продолжиться — смотрите вывод serve)", err)
	}
	if !strings.HasPrefix(last, "RESULT: OK") {
		return errors.New("применение завершилось с ошибками")
	}
	return nil
}

// pushArchive: режим «просто положить tar.gz с данными этого сервера на другой».
// Ничего не распаковывается и не применяется; проверки совместимости ОС нет.
func pushArchive(c *apiClient, m *Manifest, list []string, dry, yes bool) error {
	fmt.Printf("\nРежим архива: %d файлов, %d каталогов, ~%s без сжатия\n",
		m.Transfer.Files, m.Transfer.Dirs, humanBytes(m.Transfer.Bytes))
	if dry {
		fmt.Println("dry-run: ничего не передавалось.")
		return nil
	}
	if !yes && !confirm("Отправить архив на приёмник?") {
		return errors.New("отменено")
	}
	var sess struct {
		ID string `json:"id"`
	}
	if err := c.doJSON("POST", "/v1/session?mode=archive", &PlanRequest{Manifest: m}, &sess); err != nil {
		return err
	}
	fmt.Println("Сессия:", sess.ID)
	res, sum, err := c.uploadArchive(sess.ID, list, m.Transfer.Bytes)
	fmt.Println()
	if err != nil {
		return err
	}
	if res.SHA256 != sum {
		return fmt.Errorf("sha256 архива не совпал: отправлено %s, принято %s", sum, res.SHA256)
	}
	fmt.Printf("Готово: %s (%s), sha256 %s\n", res.Path, humanBytes(res.Bytes), res.SHA256)
	fmt.Println("Манифест (пакеты, порты, cron, пользователи): session.json рядом с архивом.")
	return nil
}

func (c *apiClient) uploadArchive(id string, list []string, total int64) (*ArchiveResult, string, error) {
	pr, pw := io.Pipe()
	defer pr.Close()
	h := sha256.New()
	st := &progress{total: total}
	done := make(chan struct{})
	defer close(done)
	go st.run(done)
	go func() { pw.CloseWithError(packStream(io.MultiWriter(h, pw), list, st)) }()

	req, err := http.NewRequest("PUT", c.base+"/v1/session/"+id+"/archive", pr)
	if err != nil {
		return nil, "", err
	}
	req.Header.Set("Content-Type", "application/gzip")
	resp, err := c.hc.Do(req)
	if err != nil {
		pr.CloseWithError(err)
		return nil, "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<16))
		return nil, "", fmt.Errorf("приёмник: %s: %s", resp.Status, strings.TrimSpace(string(b)))
	}
	var res ArchiveResult
	if err := json.NewDecoder(resp.Body).Decode(&res); err != nil {
		return nil, "", err
	}
	return &res, hex.EncodeToString(h.Sum(nil)), nil
}
