package main

import (
	"archive/tar"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"strings"
	"time"
)

// cmdRestore разворачивает архив, созданный `ferry archive` или `ferry push -archive`:
//   - по умолчанию — как обычный перенос: план → подтверждение → применение на ЭТОМ сервере;
//   - с -extract-to DIR — просто распаковать в каталог (с владельцами и правами), ничего не применяя.
func cmdRestore(args []string) error {
	fl := flag.NewFlagSet("restore", flag.ExitOnError)
	archive := fl.String("archive", "", "путь к tar.gz (из `ferry archive`)")
	session := fl.String("session", "", "ID сессии на этом сервере, где лежит archive.tar.gz (после `push -archive`)")
	manifest := fl.String("manifest", "", "манифест (по умолчанию: session.json или <архив>.manifest.json)")
	extractDir := fl.String("extract-to", "", "только распаковать в каталог, без применения")
	skipPkgs := fl.String("skip-pkg", "", "пакеты, которые не ставить (маски через запятую)")
	noPkg := fl.Bool("no-packages", false, "не ставить пакеты")
	relOK := fl.Bool("allow-release-mismatch", false, "разрешить другой релиз того же дистрибутива")
	cross := fl.Bool("cross-distro", false, "разрешить восстановление на другом дистрибутиве")
	pkgmap := fl.String("pkgmap", "", "файл с доп. соответствиями имён пакетов")
	start := fl.Bool("start", false, "после применения запустить службы, работавшие на источнике")
	dry := fl.Bool("dry-run", false, "только показать план")
	yes := fl.Bool("yes", false, "не спрашивать подтверждение")
	_ = fl.Parse(args)

	if err := requireRoot(); err != nil {
		return err
	}
	var arch, sessDir string
	switch {
	case *session != "":
		if !idRe.MatchString(*session) {
			return fmt.Errorf("неверный ID сессии %q", *session)
		}
		sessDir = filepath.Join(stateDir, "sessions", *session)
		arch = filepath.Join(sessDir, "archive.tar.gz")
	case *archive != "":
		arch = *archive
	default:
		return errors.New("укажите -archive файл.tar.gz или -session ID")
	}

	if *extractDir != "" {
		f, err := os.Open(arch)
		if err != nil {
			return err
		}
		defer f.Close()
		res, err := untarTo(f, *extractDir)
		if err != nil {
			return err
		}
		fmt.Printf("Распаковано в %s: файлов %d, каталогов %d, %s\n", *extractDir, res.Files, res.Dirs, humanBytes(res.Bytes))
		if len(res.Mismatches) > 0 {
			for _, mm := range res.Mismatches {
				fmt.Println("  ✗", mm)
			}
			return errors.New("контрольные суммы не сошлись")
		}
		fmt.Println("Контрольные суммы сошлись.")
		return nil
	}

	m, err := loadManifest(arch, *manifest, sessDir)
	if err != nil {
		return err
	}
	opts := Options{
		SkipPkgs:             splitCSV(*skipPkgs),
		NoPackages:           *noPkg,
		AllowReleaseMismatch: *relOK,
		CrossDistro:          *cross,
		Start:                *start,
	}
	if *pkgmap != "" {
		b, err := os.ReadFile(*pkgmap)
		if err != nil {
			return err
		}
		opts.PkgMap = string(b)
	}

	plan := buildPlan(m, opts, false)
	printPlan(plan)
	if len(plan.Errors) > 0 {
		return errors.New("план содержит ошибки, выполнение невозможно")
	}
	if *dry {
		fmt.Println("dry-run: ничего не распаковывалось.")
		return nil
	}
	if !*yes && !confirm("Распаковать архив и применить на этом сервере?") {
		return errors.New("отменено")
	}

	if sessDir == "" {
		sessDir = filepath.Join(stateDir, "sessions", time.Now().Format("20060102-150405")+"-"+randHex(4))
	}
	if err := os.MkdirAll(sessDir, 0700); err != nil {
		return err
	}
	sj, err := json.Marshal(&PlanRequest{Manifest: m, Options: opts})
	if err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(sessDir, "session.json"), sj, 0600); err != nil {
		return err
	}

	f, err := os.Open(arch)
	if err != nil {
		return err
	}
	defer f.Close()
	fmt.Println("Распаковываю в staging...")
	res, err := extractStream(f, sessDir)
	if err != nil {
		return err
	}
	fmt.Printf("Принято: файлов %d, каталогов %d, %s\n", res.Files, res.Dirs, humanBytes(res.Bytes))
	if len(res.Mismatches) > 0 {
		for _, mm := range res.Mismatches {
			fmt.Println("  ✗", mm)
		}
		return errors.New("контрольные суммы не сошлись — применение отменено")
	}

	fmt.Println("Применяю...")
	if err := runApply(os.Stdout, sessDir); err != nil {
		return err
	}
	fmt.Println("RESULT: OK")
	return nil
}

// loadManifest ищет манифест: явный путь, session.json, <архив>.manifest.json.
func loadManifest(arch, explicit, sessDir string) (*Manifest, error) {
	cands := []string{explicit}
	if sessDir != "" {
		cands = append(cands, filepath.Join(sessDir, "session.json"))
	}
	cands = append(cands, arch+".manifest.json", strings.TrimSuffix(arch, ".tar.gz")+".manifest.json")
	for _, c := range cands {
		if c == "" {
			continue
		}
		b, err := os.ReadFile(c)
		if err != nil {
			continue
		}
		var req PlanRequest
		if json.Unmarshal(b, &req) == nil && req.Manifest != nil {
			return req.Manifest, nil
		}
		var m Manifest
		if json.Unmarshal(b, &m) == nil && m.Proto != 0 {
			return &m, nil
		}
	}
	return nil, errors.New("манифест не найден: укажите -manifest файл.json")
}

// untarTo распаковывает архив в каталог как есть: с владельцами (числовыми uid/gid),
// правами и временем. Защищён от выхода за пределы каталога и симлинков в путях.
func untarTo(r io.Reader, dest string) (*UploadResult, error) {
	dest, err := filepath.Abs(dest)
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(dest, 0755); err != nil {
		return nil, err
	}
	gz, err := gzip.NewReader(r)
	if err != nil {
		return nil, fmt.Errorf("gzip: %w", err)
	}
	tr := tar.NewReader(gz)
	isRoot := os.Geteuid() == 0
	res := &UploadResult{}
	sums := map[string]string{}
	var trailer []byte

	type dirMeta struct {
		path     string
		mode     os.FileMode
		uid, gid int
		mt       time.Time
	}
	var dirs []dirMeta

	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("tar: %w", err)
		}
		if hdr.Name == trailerName {
			trailer, err = io.ReadAll(io.LimitReader(tr, 1<<30))
			if err != nil {
				return nil, err
			}
			continue
		}
		rel := path.Clean("/" + hdr.Name)
		if rel == "/" {
			continue
		}
		dst, err := safeDst(dest, rel)
		if err != nil {
			return nil, err
		}
		mode := tarModeToFileMode(hdr.Mode)

		switch hdr.Typeflag {
		case tar.TypeDir:
			if err := os.MkdirAll(dst, 0755); err != nil {
				return nil, err
			}
			dirs = append(dirs, dirMeta{dst, mode, hdr.Uid, hdr.Gid, hdr.ModTime})
			res.Dirs++
		case tar.TypeReg:
			if err := os.MkdirAll(filepath.Dir(dst), 0755); err != nil {
				return nil, err
			}
			f, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
			if err != nil {
				return nil, err
			}
			h := sha256.New()
			n, cerr := io.Copy(io.MultiWriter(f, h), tr)
			clerr := f.Close()
			if cerr != nil {
				return nil, cerr
			}
			if clerr != nil {
				return nil, clerr
			}
			if isRoot {
				_ = os.Lchown(dst, hdr.Uid, hdr.Gid)
			}
			_ = os.Chmod(dst, mode)
			_ = os.Chtimes(dst, hdr.ModTime, hdr.ModTime)
			sums[rel] = hex.EncodeToString(h.Sum(nil))
			res.Files++
			res.Bytes += n
		case tar.TypeSymlink:
			if err := os.MkdirAll(filepath.Dir(dst), 0755); err != nil {
				return nil, err
			}
			_ = os.Remove(dst)
			if err := os.Symlink(hdr.Linkname, dst); err != nil {
				return nil, err
			}
			if isRoot {
				_ = os.Lchown(dst, hdr.Uid, hdr.Gid)
			}
			res.Files++
		default:
			res.Skipped++
		}
	}
	// права каталогов — в конце и от вложенных к внешним
	for i := len(dirs) - 1; i >= 0; i-- {
		d := dirs[i]
		if isRoot {
			_ = os.Lchown(d.path, d.uid, d.gid)
		}
		_ = os.Chmod(d.path, d.mode)
		_ = os.Chtimes(d.path, d.mt, d.mt)
	}
	mm, err := verifyTrailer(trailer, sums, map[string]bool{})
	if err != nil {
		return nil, err
	}
	res.Mismatches = mm
	return res, nil
}
