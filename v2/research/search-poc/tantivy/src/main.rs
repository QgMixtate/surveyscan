// C28.02 PoC: Tantivy (Rust). Изолированный проект, не входит в продукт.
// run DIR CORPUS UPDATES DELETES QUERIES REPEAT → JSON-отчёт в stdout (те же операции, что у Bluge PoC).
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::io::BufRead;
use std::time::Instant;
use tantivy::collector::TopDocs;
use tantivy::query::{BooleanQuery, FuzzyTermQuery, Occur, PhraseQuery, Query, RegexQuery, TermQuery};
use tantivy::schema::*;
use tantivy::tokenizer::{Language, LowerCaser, SimpleTokenizer, Stemmer, StopWordFilter, TextAnalyzer, TokenStream};
use tantivy::{doc, Index, IndexWriter, TantivyDocument, Term};

#[derive(Deserialize, Clone)]
struct Doc { id: String, tenant: String, os: String, host: String, fqdn: String, ips: Vec<String>, serial: String, owner: String, purpose: String, software: Vec<String> }

#[derive(Deserialize)]
struct Q { phase: String, qid: String, tenant: String, kind: String, field: String, value: String, filters: HashMap<String, String>, k: usize }

#[derive(Deserialize)]
struct QFile { queries: Vec<Q> }

#[derive(Serialize)]
struct R { #[serde(rename = "Phase")] phase: String, #[serde(rename = "QID")] qid: String, #[serde(rename = "IDs")] ids: Vec<String>, #[serde(rename = "P50")] p50: f64, #[serde(rename = "P95")] p95: f64 }

struct F { id: Field, tenant: Field, os: Field, host: Field, serial: Field, ip: Field, fqdn: Field, text: Field }

fn schema() -> (Schema, F) {
    let mut b = Schema::builder();
    let kw = STRING | STORED;
    let id = b.add_text_field("id", kw.clone());
    let tenant = b.add_text_field("tenant", STRING);
    let os = b.add_text_field("os", STRING);
    let host = b.add_text_field("host", STRING);
    let serial = b.add_text_field("serial", STRING);
    let ip = b.add_text_field("ip", STRING);
    let parts = TextOptions::default().set_indexing_options(TextFieldIndexing::default().set_tokenizer("parts").set_index_option(IndexRecordOption::WithFreqsAndPositions));
    let fqdn = b.add_text_field("fqdn", parts);
    let ru = TextOptions::default().set_indexing_options(TextFieldIndexing::default().set_tokenizer("ru").set_index_option(IndexRecordOption::WithFreqs));
    let text = b.add_text_field("text", ru);
    (b.build(), F { id, tenant, os, host, serial, ip, fqdn, text })
}

fn ru() -> TextAnalyzer {
    TextAnalyzer::builder(SimpleTokenizer::default()).filter(LowerCaser).filter(StopWordFilter::new(Language::Russian).unwrap()).filter(Stemmer::new(Language::Russian)).build()
}
fn parts() -> TextAnalyzer { TextAnalyzer::builder(SimpleTokenizer::default()).filter(LowerCaser).build() }

fn tokens(a: &mut TextAnalyzer, text: &str) -> Vec<String> {
    let mut out = vec![];
    let mut s = a.token_stream(text);
    while s.advance() { out.push(s.token().text.clone()); }
    out
}

fn open(dir: &str) -> (Index, F) {
    let (schema, f) = schema();
    let _ = std::fs::create_dir_all(dir);
    let index = Index::open_or_create(tantivy::directory::MmapDirectory::open(dir).unwrap(), schema).unwrap();
    index.tokenizers().register("ru", ru());
    index.tokenizers().register("parts", parts());
    (index, f)
}

fn document(f: &F, d: &Doc) -> TantivyDocument {
    let mut x = doc!(f.id => d.id.clone(), f.tenant => d.tenant.clone(), f.os => d.os.clone(), f.host => d.host.to_lowercase(), f.serial => d.serial.to_lowercase(), f.fqdn => d.fqdn.clone(),
        f.text => format!("{} {} {} {}", d.purpose, d.owner, d.software.join(" "), d.os));
    for ip in &d.ips { x.add_text(f.ip, ip); }
    x
}

fn read_docs(path: &str) -> Vec<Doc> {
    std::io::BufReader::new(std::fs::File::open(path).unwrap()).lines().map(|l| serde_json::from_str(&l.unwrap()).unwrap()).collect()
}

fn dir_size(dir: &str) -> u64 {
    std::fs::read_dir(dir).map(|r| r.filter_map(|e| e.ok()).filter_map(|e| e.metadata().ok()).filter(|m| m.is_file()).map(|m| m.len()).sum()).unwrap_or(0)
}

fn build(dir: &str, docs: &[Doc]) -> f64 {
    let _ = std::fs::remove_dir_all(dir);
    let start = Instant::now();
    let (index, f) = open(dir);
    let mut w: IndexWriter = index.writer(256_000_000).unwrap();
    for d in docs { w.add_document(document(&f, d)).unwrap(); }
    w.commit().unwrap();
    w.wait_merging_threads().unwrap();
    start.elapsed().as_secs_f64()
}

fn field(f: &F, name: &str) -> Field {
    match name { "host" => f.host, "serial" => f.serial, "ip" => f.ip, "fqdn" => f.fqdn, "text" => f.text, "os" => f.os, _ => panic!("field {name}") }
}

fn compile(f: &F, q: &Q, ru_a: &mut TextAnalyzer, parts_a: &mut TextAnalyzer) -> Box<dyn Query> {
    let term = |fl: Field, v: &str| -> Box<dyn Query> { Box::new(TermQuery::new(Term::from_field_text(fl, v), IndexRecordOption::Basic)) };
    let mut must: Vec<(Occur, Box<dyn Query>)> = vec![(Occur::Must, term(f.tenant, &q.tenant))];
    for (k, v) in &q.filters { must.push((Occur::Must, term(field(f, k), v))); }
    let fl = field(f, &q.field);
    let v = q.value.as_str();
    match q.kind.as_str() {
        "term" => must.push((Occur::Must, term(fl, &v.to_lowercase()))),
        "prefix" => must.push((Occur::Must, Box::new(RegexQuery::from_pattern(&format!("{}.*", regex::escape(&v.to_lowercase())), fl).unwrap()))),
        "phrase" => {
            let ts: Vec<Term> = tokens(parts_a, v).iter().map(|t| Term::from_field_text(fl, t)).collect();
            must.push((Occur::Must, Box::new(PhraseQuery::new(ts))));
        }
        "match" => { for t in tokens(ru_a, v) { must.push((Occur::Must, term(fl, &t))); } }
        "fuzzy" => must.push((Occur::Must, Box::new(FuzzyTermQuery::new(Term::from_field_text(fl, &v.to_lowercase()), 1, true)))),
        k => panic!("kind {k}"),
    }
    Box::new(BooleanQuery::new(must))
}

fn run_queries(dir: &str, phase: &str, queries: &[Q], repeat: usize) -> Vec<R> {
    let (index, f) = open(dir);
    let reader = index.reader().unwrap();
    let searcher = reader.searcher();
    let (mut ru_a, mut parts_a) = (ru(), parts());
    let mut out = vec![];
    for q in queries.iter().filter(|q| q.phase == phase) {
        let query = compile(&f, q, &mut ru_a, &mut parts_a);
        let search = || -> Vec<String> {
            searcher.search(&*query, &TopDocs::with_limit(q.k).order_by_score()).unwrap().into_iter().map(|(_, addr)| {
                let d: TantivyDocument = searcher.doc(addr).unwrap();
                d.get_first(f.id).and_then(|v| v.as_str()).unwrap().to_string()
            }).collect()
        };
        let ids = search();
        let mut lat: Vec<f64> = (0..repeat).map(|_| { let s = Instant::now(); search(); s.elapsed().as_micros() as f64 }).collect();
        lat.sort_by(|a, b| a.partial_cmp(b).unwrap());
        out.push(R { phase: phase.into(), qid: q.qid.clone(), ids, p50: lat[lat.len() / 2], p95: lat[lat.len() * 95 / 100] });
    }
    out
}

fn main() {
    let a: Vec<String> = std::env::args().collect();
    assert!(a.len() == 8 && a[1] == "run", "usage: run DIR CORPUS UPDATES DELETES QUERIES REPEAT");
    let (dir, repeat) = (a[2].as_str(), a[7].parse::<usize>().unwrap());
    let (docs, updates) = (read_docs(&a[3]), read_docs(&a[4]));
    let deletes: Vec<String> = std::fs::read_to_string(&a[5]).unwrap().split_whitespace().map(String::from).collect();
    let qf: QFile = serde_json::from_str(&std::fs::read_to_string(&a[6]).unwrap()).unwrap();
    let mut report = serde_json::Map::new();
    report.insert("engine".into(), "tantivy".into());
    report.insert("docs".into(), docs.len().into());
    report.insert("index_seconds".into(), build(dir, &docs).into());
    report.insert("index_bytes".into(), dir_size(dir).into());
    let mut results = run_queries(dir, "A", &qf.queries, repeat);
    let start = Instant::now();
    {
        let (index, f) = open(dir);
        let mut w: IndexWriter = index.writer(256_000_000).unwrap();
        for u in &updates { w.delete_term(Term::from_field_text(f.id, &u.id)); w.add_document(document(&f, u)).unwrap(); }
        for id in &deletes { w.delete_term(Term::from_field_text(f.id, id)); }
        w.commit().unwrap();
        w.wait_merging_threads().unwrap();
    }
    report.insert("update_delete_seconds".into(), start.elapsed().as_secs_f64().into());
    results.extend(run_queries(dir, "B", &qf.queries, repeat));
    let mut by_id: HashMap<String, Doc> = docs.iter().map(|d| (d.id.clone(), d.clone())).collect();
    for u in &updates { by_id.insert(u.id.clone(), u.clone()); }
    for id in &deletes { by_id.remove(id); }
    let after: Vec<Doc> = docs.iter().filter_map(|d| by_id.get(&d.id).cloned()).collect();
    let rebuild = format!("{dir}-rebuild");
    report.insert("rebuild_seconds".into(), build(&rebuild, &after).into());
    report.insert("rebuild_bytes".into(), dir_size(&rebuild).into());
    report.insert("results".into(), serde_json::to_value(results).unwrap());
    println!("{}", serde_json::Value::Object(report));
}
