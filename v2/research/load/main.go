// C30.02 — воспроизводимая нагрузка «100 активных пользователей» по паспорту decisions/C30-load-passport.md.
// Каждый виртуальный пользователь входит один раз (разогрев) и выполняет смесь реальных запросов Web UI с паузой
// 2–6 с. Ожидаемые 412 (гонка правок с If-Match/expected_version) учитываются отдельно и ошибками не считаются.
// load CONFIG.json → JSON-отчёт в stdout.
package main

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"math/rand/v2"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"sort"
	"strings"
	"sync"
	"time"
)

type Config struct {
	BaseURL  string            `json:"base_url"`
	CAFile   string            `json:"ca_file"`
	Origin   string            `json:"origin"`
	Users    []User            `json:"users"`
	Assets   []string          `json:"assets"`
	Subjects []string          `json:"subjects"`
	Searches []string          `json:"searches"`
	VUs      int               `json:"virtual_users"`
	Warmup   float64           `json:"warmup_seconds"`
	Duration float64           `json:"duration_seconds"`
	ThinkMin float64           `json:"think_min_seconds"`
	ThinkMax float64           `json:"think_max_seconds"`
	Seed     uint64            `json:"seed"`
	Mix      map[string]int    `json:"mix"`
	Extra    map[string]string `json:"extra"`
}

type User struct{ Username, Password, Role string }

type sample struct {
	action string
	ms     float64
	status int
	err    bool
	stale  bool
}

type vu struct {
	c    *http.Client
	cfg  *Config
	csrf string
	role string
	rnd  *rand.Rand
}

func (v *vu) do(method, path string, body any, headers map[string]string) (int, []byte, http.Header, error) {
	var r io.Reader
	if body != nil {
		raw, _ := json.Marshal(body)
		r = bytes.NewReader(raw)
	}
	req, _ := http.NewRequest(method, v.cfg.BaseURL+path, r)
	req.Header.Set("Accept", "application/json")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if method != http.MethodGet {
		req.Header.Set("Origin", v.cfg.Origin)
		req.Header.Set("X-CSRF-Token", v.csrf)
	}
	for k, val := range headers {
		req.Header.Set(k, val)
	}
	resp, err := v.c.Do(req)
	if err != nil {
		return 0, nil, nil, err
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(resp.Body)
	return resp.StatusCode, raw, resp.Header, err
}

func (v *vu) login(u User) error {
	code, raw, _, err := v.do(http.MethodPost, "/api/v1/auth/sessions", map[string]string{"username": u.Username, "password": u.Password}, map[string]string{"Origin": v.cfg.Origin})
	if err != nil || code != 201 {
		return fmt.Errorf("login %s: %d %v", u.Username, code, err)
	}
	var s struct {
		CSRF string `json:"csrf_token"`
	}
	_ = json.Unmarshal(raw, &s)
	v.csrf = s.CSRF
	return nil
}

func (v *vu) pick(list []string) string { return list[v.rnd.IntN(len(list))] }

// action выполняет одно действие смеси; возвращает замеры его запросов.
func (v *vu) action(name string) []sample {
	var out []sample
	call := func(label, method, path string, body any, headers map[string]string, expected ...int) (int, []byte, http.Header) {
		start := time.Now()
		code, raw, h, err := v.do(method, path, body, headers)
		s := sample{action: label, ms: float64(time.Since(start).Microseconds()) / 1000, status: code}
		ok := err == nil && code >= 200 && code < 300
		for _, e := range expected {
			if code == e {
				ok, s.stale = true, true
			}
		}
		s.err = !ok
		out = append(out, s)
		return code, raw, h
	}
	asset := v.pick(v.cfg.Assets)
	switch name {
	case "list":
		_, raw, _ := call("list", "GET", "/api/v1/assets?limit=50", nil, nil)
		if v.rnd.IntN(2) == 0 {
			var p struct {
				Next *string `json:"next_cursor"`
			}
			if json.Unmarshal(raw, &p) == nil && p.Next != nil {
				call("list", "GET", "/api/v1/assets?limit=50&cursor="+url.QueryEscape(*p.Next), nil, nil)
			}
		}
	case "card":
		call("card", "GET", "/api/v1/assets/"+asset+"/inventory", nil, nil)
		call("card", "GET", "/api/v1/assets/"+asset+"/cmdb", nil, nil)
	case "search":
		call("search", "GET", "/api/v1/search?limit=20&q="+url.QueryEscape(v.pick(v.cfg.Searches)), nil, nil)
	case "software":
		call("software", "GET", "/api/v1/assets/"+asset+"/software?limit=100", nil, nil)
	case "section12":
		sections := []string{"software", "services", "network", "hardware", "resources", "users_groups"}
		call("section12", "GET", "/api/v1/assets/"+asset+"/inventory/facts/"+sections[v.rnd.IntN(len(sections))]+"?limit=100", nil, nil)
	case "worklist":
		scopes := []string{"mine", "team", "unassigned", "attention"}
		call("worklist", "GET", "/api/v1/worklist?scope="+scopes[v.rnd.IntN(len(scopes))], nil, nil)
	case "topology":
		call("topology", "GET", "/api/v1/topology", nil, nil)
	case "edit":
		code, _, h := call("edit", "GET", "/api/v1/assets/"+asset, nil, nil)
		if code == 200 {
			purpose := fmt.Sprintf("Назначение %d", v.rnd.IntN(1000))
			call("edit", "PATCH", "/api/v1/assets/"+asset, map[string]string{"purpose": purpose}, map[string]string{"If-Match": h.Get("ETag")}, 412)
		}
	case "assign":
		code, raw, _ := call("assign", "GET", "/api/v1/assets/"+asset+"/assignments", nil, nil)
		if code == 200 && len(v.cfg.Subjects) > 0 {
			var a struct {
				Version string `json:"version"`
			}
			_ = json.Unmarshal(raw, &a)
			call("assign", "POST", "/api/v1/assets/"+asset+"/assignments", map[string]any{"role": "technical", "subject_id": v.pick(v.cfg.Subjects), "expected_version": a.Version}, nil, 412)
		}
	}
	return out
}

func percentile(sorted []float64, p float64) float64 {
	if len(sorted) == 0 {
		return 0
	}
	i := int(float64(len(sorted)-1) * p)
	return sorted[i]
}

func main() {
	raw, err := os.ReadFile(os.Args[1])
	if err != nil {
		panic(err)
	}
	var cfg Config
	if err = json.Unmarshal(raw, &cfg); err != nil {
		panic(err)
	}
	pool := x509.NewCertPool()
	ca, err := os.ReadFile(cfg.CAFile)
	if err != nil || !pool.AppendCertsFromPEM(ca) {
		panic("ca")
	}
	transport := &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool}, MaxIdleConnsPerHost: 4, IdleConnTimeout: 90 * time.Second}
	// поведение мешаем по весам
	var mix []string
	keys := make([]string, 0, len(cfg.Mix))
	for k := range cfg.Mix {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		for range cfg.Mix[k] {
			mix = append(mix, k)
		}
	}
	start := time.Now()
	measureFrom := start.Add(time.Duration(cfg.Warmup * float64(time.Second)))
	end := measureFrom.Add(time.Duration(cfg.Duration * float64(time.Second)))
	var mu sync.Mutex
	var samples []sample
	loginErrors := 0
	var wg sync.WaitGroup
	for i := range cfg.VUs {
		wg.Add(1)
		go func() {
			defer wg.Done()
			jar, _ := cookiejar.New(nil)
			v := &vu{c: &http.Client{Transport: transport, Jar: jar, Timeout: 30 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}, cfg: &cfg, rnd: rand.New(rand.NewPCG(cfg.Seed, uint64(i)))}
			// входы растянуты по разогреву (лимит входов центра — 120 в минуту)
			time.Sleep(time.Duration(float64(i) / float64(cfg.VUs) * cfg.Warmup * 0.8 * float64(time.Second)))
			v.role = cfg.Users[i%len(cfg.Users)].Role
			if err := v.login(cfg.Users[i%len(cfg.Users)]); err != nil {
				mu.Lock()
				loginErrors++
				mu.Unlock()
				fmt.Fprintln(os.Stderr, err)
				return
			}
			for time.Now().Before(end) {
				think := cfg.ThinkMin + v.rnd.Float64()*(cfg.ThinkMax-cfg.ThinkMin)
				time.Sleep(time.Duration(think * float64(time.Second)))
				if !time.Now().Before(end) {
					return
				}
				measuring := time.Now().After(measureFrom)
				name := mix[v.rnd.IntN(len(mix))]
				if v.role == "viewer" && (name == "edit" || name == "assign") {
					name = "card" // наблюдатель не правит: его действие — чтение карточки
				}
				res := v.action(name)
				if measuring {
					mu.Lock()
					samples = append(samples, res...)
					mu.Unlock()
				}
			}
		}()
	}
	wg.Wait()
	byAction := map[string][]sample{}
	all := []float64{}
	for _, s := range samples {
		byAction[s.action] = append(byAction[s.action], s)
		all = append(all, s.ms)
	}
	sort.Float64s(all)
	report := map[string]any{"virtual_users": cfg.VUs, "measure_seconds": cfg.Duration, "login_errors": loginErrors, "requests": len(samples),
		"throughput_rps": float64(len(samples)) / cfg.Duration, "p50_ms": percentile(all, .5), "p95_ms": percentile(all, .95), "p99_ms": percentile(all, .99)}
	actions := map[string]any{}
	errorsTotal := 0
	for name, list := range byAction {
		ms := make([]float64, 0, len(list))
		errs, stale := 0, 0
		codes := map[string]int{}
		for _, s := range list {
			ms = append(ms, s.ms)
			if s.err {
				errs++
				codes[fmt.Sprint(s.status)]++
			}
			if s.stale {
				stale++
			}
		}
		errorsTotal += errs
		sort.Float64s(ms)
		actions[name] = map[string]any{"requests": len(list), "p50_ms": percentile(ms, .5), "p95_ms": percentile(ms, .95), "p99_ms": percentile(ms, .99), "max_ms": ms[len(ms)-1], "errors": errs, "error_codes": codes, "expected_412": stale}
	}
	report["errors"] = errorsTotal
	if len(samples) > 0 {
		report["error_rate"] = float64(errorsTotal) / float64(len(samples))
	}
	report["actions"] = actions
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", " ")
	_ = enc.Encode(report)
	_ = strings.TrimSpace
}
