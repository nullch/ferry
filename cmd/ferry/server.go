package main

import (
	"archive/tar"
	"bufio"
	"compress/gzip"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"
)

var idRe = regexp.MustCompile(`^[0-9]{8}-[0-9]{6}-[0-9a-f]{8}$`)

type server struct {
	mu sync.Mutex // одна тяжёлая операция (upload/apply) за раз
}

func cmdServe(args []string) error {
	fl := flag.NewFlagSet("serve", flag.ExitOnError)
	listen := fl.String("listen", ":"+defaultPort, "адрес:порт для прослушивания")
	pki := fl.String("pki", defaultPKI, "каталог с ca.crt, server.crt, server.key")
	_ = fl.Parse(args)

	if err := requireRoot(); err != nil {
		return err
	}
	tcfg, err := serverTLS(*pki)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Join(stateDir, "sessions"), 0700); err != nil {
		return err
	}
	s := &server{}
	srv := &http.Server{
		Addr:              *listen,
		Handler:           s.routes(),
		TLSConfig:         tcfg,
		ReadHeaderTimeout: 30 * time.Second,
		IdleTimeout:       5 * time.Minute,
	}
	log.Printf("ferry %s: слушаю %s (mTLS, TLS 1.3), состояние: %s", version, *listen, stateDir)
	return srv.ListenAndServeTLS("", "")
}

func (s *server) routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/hello", s.hello)
	mux.HandleFunc("/v1/plan", s.plan)
	mux.HandleFunc("/v1/session", s.newSession)
	mux.HandleFunc("/v1/session/", s.sessionOps)
	return mux
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func httpErr(w http.ResponseWriter, code int, err error) {
	http.Error(w, err.Error(), code)
}

func randHex(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

func (s *server) hello(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, hostInfo())
}

func readPlanRequest(w http.ResponseWriter, r *http.Request) (*PlanRequest, error) {
	if r.Method != http.MethodPost {
		return nil, errors.New("только POST")
	}
	var req PlanRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 256<<20)).Decode(&req); err != nil {
		return nil, err
	}
	if req.Manifest == nil {
		return nil, errors.New("пустой манифест")
	}
	return &req, nil
}

func (s *server) plan(w http.ResponseWriter, r *http.Request) {
	req, err := readPlanRequest(w, r)
	if err != nil {
		httpErr(w, http.StatusBadRequest, err)
		return
	}
	writeJSON(w, http.StatusOK, buildPlan(req.Manifest, req.Options, true))
}

func (s *server) newSession(w http.ResponseWriter, r *http.Request) {
	req, err := readPlanRequest(w, r)
	if err != nil {
		httpErr(w, http.StatusBadRequest, err)
		return
	}
	archiveMode := r.URL.Query().Get("mode") == "archive"
	if !archiveMode {
		if plan := buildPlan(req.Manifest, req.Options, true); len(plan.Errors) > 0 {
			httpErr(w, http.StatusConflict, errors.New(strings.Join(plan.Errors, "; ")))
			return
		}
	}
	id := time.Now().Format("20060102-150405") + "-" + randHex(4)
	dir := filepath.Join(stateDir, "sessions", id)
	if err := os.MkdirAll(dir, 0700); err != nil {
		httpErr(w, http.StatusInternalServerError, err)
		return
	}
	b, err := json.Marshal(req)
	if err != nil {
		httpErr(w, http.StatusInternalServerError, err)
		return
	}
	if err := os.WriteFile(filepath.Join(dir, "session.json"), b, 0600); err != nil {
		httpErr(w, http.StatusInternalServerError, err)
		return
	}
	log.Printf("новая сессия %s от %s (хост-источник: %s)", id, r.RemoteAddr, req.Manifest.Host.Hostname)
	writeJSON(w, http.StatusOK, map[string]string{"id": id})
}

func (s *server) sessionOps(w http.ResponseWriter, r *http.Request) {
	parts := strings.Split(strings.Trim(strings.TrimPrefix(r.URL.Path, "/v1/session/"), "/"), "/")
	if len(parts) != 2 || !idRe.MatchString(parts[0]) {
		http.NotFound(w, r)
		return
	}
	dir := filepath.Join(stateDir, "sessions", parts[0])
	if _, err := os.Stat(filepath.Join(dir, "session.json")); err != nil {
		http.NotFound(w, r)
		return
	}
	switch {
	case parts[1] == "data" && r.Method == http.MethodPut:
		s.upload(w, r, dir)
	case parts[1] == "archive" && r.Method == http.MethodPut:
		s.uploadArchive(w, r, dir)
	case parts[1] == "apply" && r.Method == http.MethodPost:
		s.apply(w, r, dir)
	default:
		http.NotFound(w, r)
	}
}

func (s *server) upload(w http.ResponseWriter, r *http.Request, dir string) {
	if !s.mu.TryLock() {
		httpErr(w, http.StatusConflict, errors.New("приёмник занят другой операцией"))
		return
	}
	defer s.mu.Unlock()
	log.Printf("приём данных в %s ...", dir)
	res, err := extractStream(r.Body, dir)
	if err != nil {
		log.Printf("приём данных: ошибка: %v", err)
		httpErr(w, http.StatusInternalServerError, err)
		return
	}
	log.Printf("приём данных: файлов %d, каталогов %d, %s, расхождений: %d",
		res.Files, res.Dirs, humanBytes(res.Bytes), len(res.Mismatches))
	writeJSON(w, http.StatusOK, res)
}

// uploadArchive сохраняет присланный tar.gz как есть (без распаковки и применения).
func (s *server) uploadArchive(w http.ResponseWriter, r *http.Request, dir string) {
	if !s.mu.TryLock() {
		httpErr(w, http.StatusConflict, errors.New("приёмник занят другой операцией"))
		return
	}
	defer s.mu.Unlock()
	p := filepath.Join(dir, "archive.tar.gz")
	f, err := os.OpenFile(p, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		httpErr(w, http.StatusInternalServerError, err)
		return
	}
	h := sha256.New()
	n, err := io.Copy(io.MultiWriter(f, h), r.Body)
	cerr := f.Close()
	if err == nil {
		err = cerr
	}
	if err != nil {
		log.Printf("приём архива: ошибка: %v", err)
		httpErr(w, http.StatusInternalServerError, err)
		return
	}
	log.Printf("архив сохранён: %s (%s)", p, humanBytes(n))
	writeJSON(w, http.StatusOK, ArchiveResult{Path: p, Bytes: n, SHA256: hex.EncodeToString(h.Sum(nil))})
}

type flushWriter struct {
	w io.Writer
	f http.Flusher
}

// Write никогда не возвращает ошибку: если клиент отвалился, применение
// всё равно должно дойти до конца, а не оборваться посреди apt.
func (fw *flushWriter) Write(p []byte) (int, error) {
	_, _ = fw.w.Write(p)
	if fw.f != nil {
		fw.f.Flush()
	}
	return len(p), nil
}

func (s *server) apply(w http.ResponseWriter, r *http.Request, dir string) {
	if !s.mu.TryLock() {
		httpErr(w, http.StatusConflict, errors.New("приёмник занят другой операцией"))
		return
	}
	defer s.mu.Unlock()
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	fl, _ := w.(http.Flusher)
	out := io.MultiWriter(&flushWriter{w: w, f: fl}, os.Stdout)
	if err := runApply(out, dir); err != nil {
		fmt.Fprintf(out, "RESULT: FAIL: %v\n", err)
	} else {
		fmt.Fprintf(out, "RESULT: OK\n")
	}
}

// ---------- распаковка в staging ----------

// safeDst возвращает путь внутри stage и проверяет, что ни один каталог
// по дороге не является симлинком (защита от записи за пределы staging).
func safeDst(stage, rel string) (string, error) {
	dst := filepath.Join(stage, rel)
	if !strings.HasPrefix(dst, stage+string(filepath.Separator)) {
		return "", fmt.Errorf("недопустимый путь %q", rel)
	}
	parts := strings.Split(strings.Trim(rel, "/"), "/")
	cur := stage
	for _, part := range parts[:len(parts)-1] {
		cur = filepath.Join(cur, part)
		fi, err := os.Lstat(cur)
		if err != nil {
			break // ещё не создан — это нормально
		}
		if fi.Mode()&os.ModeSymlink != 0 {
			return "", fmt.Errorf("симлинк в пути staging: %s", cur)
		}
	}
	return dst, nil
}

func extractStream(body io.Reader, sessDir string) (*UploadResult, error) {
	stage := filepath.Join(sessDir, "stage")
	if err := os.RemoveAll(stage); err != nil {
		return nil, err
	}
	if err := os.MkdirAll(stage, 0700); err != nil {
		return nil, err
	}
	ef, err := os.Create(filepath.Join(sessDir, "entries.jsonl"))
	if err != nil {
		return nil, err
	}
	defer ef.Close()
	bw := bufio.NewWriterSize(ef, 1<<20)
	enc := json.NewEncoder(bw)

	gz, err := gzip.NewReader(body)
	if err != nil {
		return nil, fmt.Errorf("gzip: %w", err)
	}
	tr := tar.NewReader(gz)
	ex := newExcluder(append(append([]string{}, defaultExcludes...), neverApply...))
	res := &UploadResult{}
	sums := map[string]string{}
	skipped := map[string]bool{}
	var trailer []byte

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
		if ex.match(rel) {
			res.Skipped++
			skipped[rel] = true
			continue
		}
		dst, err := safeDst(stage, rel)
		if err != nil {
			return nil, err
		}
		e := Entry{P: rel, M: hdr.Mode, U: hdr.Uid, G: hdr.Gid, UN: hdr.Uname, GN: hdr.Gname, MT: hdr.ModTime.Unix()}

		switch hdr.Typeflag {
		case tar.TypeDir:
			e.T = "d"
			if err := os.MkdirAll(dst, 0700); err != nil {
				return nil, err
			}
			res.Dirs++
		case tar.TypeReg:
			e.T = "f"
			if err := os.MkdirAll(filepath.Dir(dst), 0700); err != nil {
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
			_ = os.Chtimes(dst, hdr.ModTime, hdr.ModTime)
			sums[rel] = hex.EncodeToString(h.Sum(nil))
			res.Files++
			res.Bytes += n
		case tar.TypeSymlink:
			e.T = "l"
			e.L = hdr.Linkname
			if err := os.MkdirAll(filepath.Dir(dst), 0700); err != nil {
				return nil, err
			}
			_ = os.Remove(dst)
			if err := os.Symlink(hdr.Linkname, dst); err != nil {
				return nil, err
			}
			res.Files++
		default:
			res.Skipped++
			continue
		}
		if err := enc.Encode(&e); err != nil {
			return nil, err
		}
	}
	if err := bw.Flush(); err != nil {
		return nil, err
	}
	mm, err := verifyTrailer(trailer, sums, skipped)
	if err != nil {
		return nil, err
	}
	res.Mismatches = mm
	return res, nil
}

// verifyTrailer сверяет sha256 из трейлера архива с посчитанными при распаковке.
func verifyTrailer(trailer []byte, sums map[string]string, skipped map[string]bool) ([]string, error) {
	if trailer == nil {
		return nil, errors.New("поток неполный: нет контрольного трейлера")
	}
	var want map[string]string
	if err := json.Unmarshal(trailer, &want); err != nil {
		return nil, fmt.Errorf("трейлер: %w", err)
	}
	var mm []string
	for p, sum := range want {
		cp := path.Clean(p)
		if skipped[cp] {
			continue
		}
		got, ok := sums[cp]
		switch {
		case !ok:
			mm = append(mm, p+": файл не принят")
		case got != sum:
			mm = append(mm, p+": контрольная сумма не совпала")
		}
	}
	sort.Strings(mm)
	return mm, nil
}
