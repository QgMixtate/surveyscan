// C28.02 PoC: Bluge (Go). Изолированный модуль (свой go.mod), не входит в продукт.
// run DIR CORPUS UPDATES DELETES QUERIES REPEAT → JSON-отчёт в stdout.
package main

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode"

	"github.com/blugelabs/bluge"
	"github.com/blugelabs/bluge/analysis"
	"github.com/blugelabs/bluge/analysis/lang/ru"
	"github.com/blugelabs/bluge/analysis/token"
	"github.com/blugelabs/bluge/analysis/tokenizer"
)

type Doc struct {
	ID       string   `json:"id"`
	Tenant   string   `json:"tenant"`
	Site     string   `json:"site"`
	OS       string   `json:"os"`
	Host     string   `json:"host"`
	FQDN     string   `json:"fqdn"`
	IPs      []string `json:"ips"`
	MAC      string   `json:"mac"`
	Serial   string   `json:"serial"`
	Owner    string   `json:"owner"`
	Purpose  string   `json:"purpose"`
	Software []string `json:"software"`
}

type Query struct {
	Phase   string            `json:"phase"`
	QID     string            `json:"qid"`
	Tenant  string            `json:"tenant"`
	Kind    string            `json:"kind"`
	Field   string            `json:"field"`
	Value   string            `json:"value"`
	Filters map[string]string `json:"filters"`
	K       int               `json:"k"`
}

// Анализаторы: text — русский (lowercase + стоп-слова + snowball), fqdn — разбиение на части без стемминга.
var (
	// одинаковый с Tantivy SimpleTokenizer разбор: буквы и цифры, остальное — разделители (UAX#29 склеивает
	// «corp.example.test» и «1С:Предприятие» в одно слово)
	simple       = tokenizer.NewCharacterTokenizer(func(r rune) bool { return unicode.IsLetter(r) || unicode.IsDigit(r) })
	textAnalyzer = &analysis.Analyzer{Tokenizer: simple, TokenFilters: []analysis.TokenFilter{token.NewLowerCaseFilter(), ru.StopWordsFilter(), ru.StemmerFilter()}}
	partAnalyzer = &analysis.Analyzer{Tokenizer: simple, TokenFilters: []analysis.TokenFilter{token.NewLowerCaseFilter()}}
)

func document(d Doc) *bluge.Document {
	doc := bluge.NewDocument(d.ID)
	doc.AddField(bluge.NewKeywordField("tenant", d.Tenant))
	doc.AddField(bluge.NewKeywordField("os", d.OS))
	doc.AddField(bluge.NewKeywordField("host", strings.ToLower(d.Host)))
	doc.AddField(bluge.NewKeywordField("serial", strings.ToLower(d.Serial)))
	for _, ip := range d.IPs {
		doc.AddField(bluge.NewKeywordField("ip", ip))
	}
	doc.AddField(bluge.NewTextField("fqdn", d.FQDN).WithAnalyzer(partAnalyzer).SearchTermPositions())
	text := d.Purpose + " " + d.Owner + " " + strings.Join(d.Software, " ") + " " + d.OS
	doc.AddField(bluge.NewTextField("text", text).WithAnalyzer(textAnalyzer))
	return doc
}

func readDocs(path string) []Doc {
	f, err := os.Open(path)
	check(err)
	defer f.Close()
	var out []Doc
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1<<20), 1<<20)
	for sc.Scan() {
		var d Doc
		check(json.Unmarshal(sc.Bytes(), &d))
		out = append(out, d)
	}
	check(sc.Err())
	return out
}

func check(err error) {
	if err != nil {
		panic(err)
	}
}

func build(dir string, docs []Doc) time.Duration {
	check(os.RemoveAll(dir))
	start := time.Now()
	w, err := bluge.OpenWriter(bluge.DefaultConfig(dir))
	check(err)
	for i := 0; i < len(docs); i += 5000 {
		batch := bluge.NewBatch()
		for _, d := range docs[i:min(i+5000, len(docs))] {
			batch.Update(bluge.Identifier(d.ID), document(d))
		}
		check(w.Batch(batch))
	}
	check(w.Close())
	return time.Since(start)
}

func dirSize(dir string) int64 {
	var n int64
	_ = filepath.Walk(dir, func(_ string, info os.FileInfo, err error) error {
		if err == nil && !info.IsDir() {
			n += info.Size()
		}
		return nil
	})
	return n
}

func compile(q Query) bluge.Query {
	b := bluge.NewBooleanQuery().AddMust(bluge.NewTermQuery(q.Tenant).SetField("tenant"))
	for k, v := range q.Filters {
		b.AddMust(bluge.NewTermQuery(v).SetField(k))
	}
	v := q.Value
	switch q.Kind {
	case "term":
		b.AddMust(bluge.NewTermQuery(strings.ToLower(v)).SetField(q.Field))
	case "prefix":
		b.AddMust(bluge.NewPrefixQuery(strings.ToLower(v)).SetField(q.Field))
	case "phrase":
		b.AddMust(bluge.NewMatchPhraseQuery(v).SetField(q.Field).SetAnalyzer(partAnalyzer))
	case "match":
		b.AddMust(bluge.NewMatchQuery(v).SetField(q.Field).SetAnalyzer(textAnalyzer).SetOperator(bluge.MatchQueryOperatorAnd))
	case "fuzzy":
		b.AddMust(bluge.NewFuzzyQuery(strings.ToLower(v)).SetField(q.Field).SetFuzziness(1))
	default:
		panic("unknown kind " + q.Kind)
	}
	return b
}

func search(r *bluge.Reader, q Query) []string {
	req := bluge.NewTopNSearch(q.K, compile(q))
	it, err := r.Search(context.Background(), req)
	check(err)
	ids := []string{}
	for {
		m, err := it.Next()
		check(err)
		if m == nil {
			break
		}
		check(m.VisitStoredFields(func(field string, value []byte) bool {
			if field == "_id" {
				ids = append(ids, string(value))
			}
			return true
		}))
	}
	return ids
}

type Result struct {
	Phase, QID string
	IDs        []string
	P50, P95   float64 // микросекунды
}

func runQueries(dir, phase string, queries []Query, repeat int) []Result {
	r, err := bluge.OpenReader(bluge.DefaultConfig(dir))
	check(err)
	defer r.Close()
	var out []Result
	for _, q := range queries {
		if q.Phase != phase {
			continue
		}
		res := Result{Phase: phase, QID: q.QID, IDs: search(r, q)}
		lat := make([]float64, repeat)
		for i := range lat {
			start := time.Now()
			search(r, q)
			lat[i] = float64(time.Since(start).Microseconds())
		}
		sort.Float64s(lat)
		res.P50, res.P95 = lat[len(lat)/2], lat[len(lat)*95/100]
		out = append(out, res)
	}
	return out
}

func main() {
	if len(os.Args) != 8 || os.Args[1] != "run" {
		fmt.Fprintln(os.Stderr, "usage: run DIR CORPUS UPDATES DELETES QUERIES REPEAT")
		os.Exit(2)
	}
	dir, repeat := os.Args[2], must(strconv.Atoi(os.Args[7]))
	docs, updates := readDocs(os.Args[3]), readDocs(os.Args[4])
	rawDeletes, err := os.ReadFile(os.Args[5])
	check(err)
	deletes := strings.Fields(string(rawDeletes))
	var qf struct {
		Queries []Query `json:"queries"`
	}
	rawQ, err := os.ReadFile(os.Args[6])
	check(err)
	check(json.Unmarshal(rawQ, &qf))
	report := map[string]any{"engine": "bluge", "docs": len(docs)}
	report["index_seconds"] = build(dir, docs).Seconds()
	report["index_bytes"] = dirSize(dir)
	results := runQueries(dir, "A", qf.Queries, repeat)
	// изменения: обновления и удаления одной фиксацией
	start := time.Now()
	w, err := bluge.OpenWriter(bluge.DefaultConfig(dir))
	check(err)
	batch := bluge.NewBatch()
	for _, u := range updates {
		batch.Update(bluge.Identifier(u.ID), document(u))
	}
	for _, id := range deletes {
		batch.Delete(bluge.Identifier(id))
	}
	check(w.Batch(batch))
	check(w.Close())
	report["update_delete_seconds"] = time.Since(start).Seconds()
	results = append(results, runQueries(dir, "B", qf.Queries, repeat)...)
	// пересборка с нуля из состояния «после»
	byID := map[string]Doc{}
	for _, d := range docs {
		byID[d.ID] = d
	}
	for _, u := range updates {
		byID[u.ID] = u
	}
	for _, id := range deletes {
		delete(byID, id)
	}
	after := make([]Doc, 0, len(byID))
	for _, d := range docs {
		if x, ok := byID[d.ID]; ok {
			after = append(after, x)
		}
	}
	report["rebuild_seconds"] = build(dir+"-rebuild", after).Seconds()
	report["rebuild_bytes"] = dirSize(dir + "-rebuild")
	report["results"] = results
	check(json.NewEncoder(os.Stdout).Encode(report))
}

func must[T any](v T, err error) T {
	check(err)
	return v
}
