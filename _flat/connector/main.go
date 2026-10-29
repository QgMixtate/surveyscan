// surveyscan connector — агент сбора на стороне заказчика (этап 4).
//
// Коннектор всегда дозванивается до центра сам (pull-модель, только исходящие
// соединения) — у заказчика не нужно открывать входящие правила на фаерволе.
// Для полностью изолированного контура тот же обмен идёт файлами (офлайн-курьер).
//
// Режимы:
//
//	serve           — цикл: забрать задание у центра → собрать сырьё → выгрузить результат
//	courier-run     — офлайн: по файлу-заданию собрать сырьё и записать файл-результат
//	courier-import  — онлайн: отправить файл-результат в центр
//
// Сбор здесь — чтение каталога уже снятых выгрузок коллекторов (--raw). Сами коллекторы
// (linux_collect.sh / windows_collect.ps1) запускаются на целях отдельно; коннектор их
// оркеструет и передаёт результат. Статическая сборка, без внешних зависимостей —
// один бинарник заносится в закрытый контур.
package main

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"time"
)

type Job struct {
	ID       int    `json:"id"`
	Name     string `json:"name"`
	Customer string `json:"customer"`
	Template string `json:"template"`
}

type resultSubmit struct {
	Files map[string]string `json:"files"`
}

type courierResult struct {
	JobID int               `json:"job_id"`
	Files map[string]string `json:"files"`
}

type Client struct {
	Center string
	Token  string
	HTTP   *http.Client
}

func newClient(center, token, caFile, certFile, keyFile string) (*Client, error) {
	tlsCfg := &tls.Config{MinVersion: tls.VersionTLS12}
	if caFile != "" { // mTLS: доверенный CA центра
		pem, err := os.ReadFile(caFile)
		if err != nil {
			return nil, err
		}
		pool := x509.NewCertPool()
		pool.AppendCertsFromPEM(pem)
		tlsCfg.RootCAs = pool
	}
	if certFile != "" && keyFile != "" { // mTLS: клиентский сертификат коннектора
		cert, err := tls.LoadX509KeyPair(certFile, keyFile)
		if err != nil {
			return nil, err
		}
		tlsCfg.Certificates = []tls.Certificate{cert}
	}
	return &Client{Center: center, Token: token,
		HTTP: &http.Client{Timeout: 60 * time.Second,
			Transport: &http.Transport{TLSClientConfig: tlsCfg}}}, nil
}

func (c *Client) do(method, path string, body any) (*http.Response, error) {
	var r io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		r = bytes.NewReader(b)
	}
	req, err := http.NewRequest(method, c.Center+path, r)
	if err != nil {
		return nil, err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	req.Header.Set("Authorization", "Bearer "+c.Token)
	return c.HTTP.Do(req)
}

// nextJob забирает очередное задание у центра (204 — заданий нет).
func (c *Client) nextJob() (*Job, error) {
	resp, err := c.do("GET", "/connector/jobs/next", nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNoContent {
		return nil, nil
	}
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("центр ответил %d: %s", resp.StatusCode, b)
	}
	var j Job
	if err := json.NewDecoder(resp.Body).Decode(&j); err != nil {
		return nil, err
	}
	return &j, nil
}

func (c *Client) submit(jobID int, files map[string]string) error {
	resp, err := c.do("POST", fmt.Sprintf("/connector/jobs/%d/result", jobID), resultSubmit{Files: files})
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		b, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("выгрузка отклонена (%d): %s", resp.StatusCode, b)
	}
	return nil
}

// collect читает каталог выгрузок коллекторов и возвращает имя→содержимое.
func collect(rawDir string) (map[string]string, error) {
	entries, err := os.ReadDir(rawDir)
	if err != nil {
		return nil, err
	}
	files := map[string]string{}
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		b, err := os.ReadFile(filepath.Join(rawDir, e.Name()))
		if err != nil {
			return nil, err
		}
		files[e.Name()] = string(b)
	}
	if len(files) == 0 {
		return nil, fmt.Errorf("в каталоге %s нет файлов выгрузок", rawDir)
	}
	return files, nil
}

func serve(c *Client, rawDir string, interval time.Duration) {
	log.Printf("коннектор запущен: центр %s, опрос каждые %s", c.Center, interval)
	for {
		job, err := c.nextJob()
		if err != nil {
			log.Printf("опрос заданий: %v", err)
		} else if job == nil {
			// заданий нет
		} else {
			log.Printf("получено задание #%d (%q)", job.ID, job.Name)
			files, err := collect(rawDir)
			if err != nil {
				log.Printf("сбор для задания #%d: %v", job.ID, err)
			} else if err := c.submit(job.ID, files); err != nil {
				log.Printf("выгрузка задания #%d: %v", job.ID, err)
			} else {
				log.Printf("задание #%d выгружено (%d файлов)", job.ID, len(files))
			}
		}
		time.Sleep(interval)
	}
}

func courierRun(jobFile, rawDir, outFile string) error {
	b, err := os.ReadFile(jobFile)
	if err != nil {
		return err
	}
	var bundle struct {
		Job Job `json:"job"`
	}
	if err := json.Unmarshal(b, &bundle); err != nil {
		return err
	}
	files, err := collect(rawDir)
	if err != nil {
		return err
	}
	out, _ := json.MarshalIndent(courierResult{JobID: bundle.Job.ID, Files: files}, "", "  ")
	if err := os.WriteFile(outFile, out, 0o600); err != nil {
		return err
	}
	log.Printf("офлайн-результат для задания #%d записан в %s (%d файлов)", bundle.Job.ID, outFile, len(files))
	return nil
}

func courierImport(c *Client, resultFile string) error {
	b, err := os.ReadFile(resultFile)
	if err != nil {
		return err
	}
	var res courierResult
	if err := json.Unmarshal(b, &res); err != nil {
		return err
	}
	if err := c.submit(res.JobID, res.Files); err != nil {
		return err
	}
	log.Printf("офлайн-результат задания #%d импортирован в центр", res.JobID)
	return nil
}

func main() {
	mode := flag.String("mode", "serve", "serve | courier-run | courier-import")
	center := flag.String("center", envOr("SURVEYSCAN_CENTER", "http://127.0.0.1:8000"), "URL центра")
	token := flag.String("token", os.Getenv("SURVEYSCAN_TOKEN"), "токен коннектора")
	rawDir := flag.String("raw", "", "каталог выгрузок коллекторов")
	interval := flag.Duration("interval", 10*time.Second, "период опроса (serve)")
	jobFile := flag.String("job", "", "файл-задание (courier-run)")
	outFile := flag.String("out", "result.json", "файл-результат (courier-run)")
	resultFile := flag.String("result", "", "файл-результат для импорта (courier-import)")
	caFile := flag.String("ca", "", "CA центра (mTLS)")
	certFile := flag.String("cert", "", "клиентский сертификат (mTLS)")
	keyFile := flag.String("key", "", "клиентский ключ (mTLS)")
	flag.Parse()

	c, err := newClient(*center, *token, *caFile, *certFile, *keyFile)
	if err != nil {
		log.Fatalf("настройка TLS: %v", err)
	}

	switch *mode {
	case "serve":
		if *token == "" || *rawDir == "" {
			log.Fatal("serve требует --token и --raw")
		}
		serve(c, *rawDir, *interval)
	case "courier-run":
		if *jobFile == "" || *rawDir == "" {
			log.Fatal("courier-run требует --job и --raw")
		}
		if err := courierRun(*jobFile, *rawDir, *outFile); err != nil {
			log.Fatal(err)
		}
	case "courier-import":
		if *token == "" || *resultFile == "" {
			log.Fatal("courier-import требует --token и --result")
		}
		if err := courierImport(c, *resultFile); err != nil {
			log.Fatal(err)
		}
	default:
		log.Fatalf("неизвестный режим: %s", *mode)
	}
}

func envOr(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}
