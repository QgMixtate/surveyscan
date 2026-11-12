// surveyscan-search — сервис полнотекстового поиска (ADR C28: Tantivy отдельным процессом).
// Индекс — производная, пересобираемая проекция; источник истины — PostgreSQL центра. Сервис:
// - принимает документы активов от потребителя outbox центра (POST /v1/apply) — идемпотентно по версии агрегата:
//   документ с версией не новее сохранённой не применяется (повтор/переупорядочивание безопасны);
// - отвечает кандидатами (POST /v1/search): asset_uid, оценка, фрагмент; права и тенант центр перепроверяет по PostgreSQL;
// - пересобирается в новое поколение (POST /v1/rebuild/*) с двойной записью изменений во время пересборки;
// - слушает только loopback и требует токен (X-Search-Token) из приватного файла.
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use tantivy::collector::{Count, TopDocs};
use tantivy::query::{BooleanQuery, Occur, PhraseQuery, Query, RegexQuery, TermQuery};
use tantivy::schema::*;
use tantivy::snippet::SnippetGenerator;
use tantivy::tokenizer::{Language, LowerCaser, SimpleTokenizer, Stemmer, StopWordFilter, TextAnalyzer, TokenStream};
use tantivy::{Index, IndexReader, IndexWriter, ReloadPolicy, TantivyDocument, Term};

// null в необязательном поле — как отсутствие поля (Go сериализует пустые срезы/карты как null)
fn null_default<'de, D: serde::Deserializer<'de>, T: Default + Deserialize<'de>>(d: D) -> Result<T, D::Error> {
    Ok(Option::<T>::deserialize(d)?.unwrap_or_default())
}

const FORMAT: &str = "surveyscan-search-2/tantivy-0.27"; // смена схемы — новый формат: центр пересобирает индекс

#[derive(Deserialize, Clone)]
struct Doc {
    asset_uid: String,
    tenant: String,
    version: u64,
    #[serde(default)]
    os: String,
    #[serde(default)]
    class: String,
    #[serde(default, deserialize_with = "null_default")]
    hosts: Vec<String>,
    #[serde(default, deserialize_with = "null_default")]
    serials: Vec<String>,
    #[serde(default, deserialize_with = "null_default")]
    ips: Vec<String>,
    #[serde(default, deserialize_with = "null_default")]
    fqdns: Vec<String>,
    #[serde(default)]
    text: String,
}

#[derive(Deserialize)]
struct Apply {
    #[serde(default, deserialize_with = "null_default")]
    docs: Vec<Doc>,
    #[serde(default, deserialize_with = "null_default")]
    deletes: Vec<Delete>,
}

#[derive(Deserialize)]
struct Delete {
    asset_uid: String,
    version: u64,
}

#[derive(Deserialize)]
struct SearchRequest {
    tenant: String,
    query: String,
    #[serde(default, deserialize_with = "null_default")]
    filters: HashMap<String, String>,
    limit: usize,
    // фрагменты нужны только показываемой странице: строить их для всех кандидатов дорого (C30.03)
    #[serde(default)]
    snippets: Option<usize>,
}

#[derive(Serialize)]
struct Hit {
    asset_uid: String,
    score: f32,
    os: String,
    class: String,
    fragment: String,
    highlights: Vec<[usize; 2]>, // в символах (не байтах) — для браузера
}

#[derive(Clone, Copy)]
struct Fields {
    id: Field,
    tenant: Field,
    version: Field,
    os: Field,
    class: Field,
    host: Field,
    serial: Field,
    ip: Field,
    fqdn: Field,
    text: Field,
}

fn schema() -> (Schema, Fields) {
    let mut b = Schema::builder();
    let id = b.add_text_field("asset_uid", STRING | STORED);
    let tenant = b.add_text_field("tenant", STRING);
    let version = b.add_u64_field("version", STORED | FAST);
    let os = b.add_text_field("os", STRING | STORED);
    let class = b.add_text_field("class", STRING | STORED);
    let host = b.add_text_field("host", STRING);
    let serial = b.add_text_field("serial", STRING);
    let ip = b.add_text_field("ip", STRING);
    let parts = TextOptions::default().set_indexing_options(TextFieldIndexing::default().set_tokenizer("parts").set_index_option(IndexRecordOption::WithFreqsAndPositions));
    let fqdn = b.add_text_field("fqdn", parts);
    let ru = TextOptions::default().set_indexing_options(TextFieldIndexing::default().set_tokenizer("ru").set_index_option(IndexRecordOption::WithFreqsAndPositions)).set_stored();
    let text = b.add_text_field("text", ru);
    (b.build(), Fields { id, tenant, version, os, class, host, serial, ip, fqdn, text })
}

fn ru() -> TextAnalyzer {
    TextAnalyzer::builder(SimpleTokenizer::default()).filter(LowerCaser).filter(StopWordFilter::new(Language::Russian).unwrap()).filter(Stemmer::new(Language::Russian)).build()
}
fn parts() -> TextAnalyzer {
    TextAnalyzer::builder(SimpleTokenizer::default()).filter(LowerCaser).build()
}
fn tokens(mut a: TextAnalyzer, text: &str) -> Vec<String> {
    let mut out = vec![];
    let mut s = a.token_stream(text);
    while s.advance() {
        out.push(s.token().text.clone());
    }
    out
}

struct Generation {
    _index: Index,
    writer: IndexWriter,
    reader: IndexReader,
    fields: Fields,
    number: u64,
}

fn open_generation(root: &Path, number: u64) -> tantivy::Result<Generation> {
    let dir = root.join(format!("gen-{number}"));
    std::fs::create_dir_all(&dir)?;
    let (schema, fields) = schema();
    let index = Index::open_or_create(tantivy::directory::MmapDirectory::open(&dir)?, schema)?;
    index.tokenizers().register("ru", ru());
    index.tokenizers().register("parts", parts());
    let writer = index.writer(64_000_000)?;
    let reader = index.reader_builder().reload_policy(ReloadPolicy::Manual).try_into()?;
    Ok(Generation { _index: index, writer, reader, fields, number })
}

impl Generation {
    fn stored_version(&self, asset: &str) -> Option<u64> {
        let searcher = self.reader.searcher();
        let q = TermQuery::new(Term::from_field_text(self.fields.id, asset), IndexRecordOption::Basic);
        let top = searcher.search(&q, &TopDocs::with_limit(1).order_by_score()).ok()?;
        let (_, addr) = top.first()?;
        let d: TantivyDocument = searcher.doc(*addr).ok()?;
        d.get_first(self.fields.version).and_then(|v| v.as_u64())
    }

    // применяет пакет: документ/удаление со версией не новее сохранённой пропускается (идемпотентность)
    fn apply(&mut self, req: &Apply) -> tantivy::Result<(usize, usize, usize)> {
        let (mut applied, mut stale, mut deleted) = (0, 0, 0);
        let mut seen: HashMap<String, u64> = HashMap::new();
        let f = &self.fields;
        for d in &req.docs {
            let current = seen.get(&d.asset_uid).copied().or_else(|| self.stored_version(&d.asset_uid));
            if current.is_some_and(|v| v >= d.version) {
                stale += 1;
                continue;
            }
            self.writer.delete_term(Term::from_field_text(f.id, &d.asset_uid));
            let mut doc = TantivyDocument::default();
            doc.add_text(f.id, &d.asset_uid);
            doc.add_text(f.tenant, &d.tenant);
            doc.add_u64(f.version, d.version);
            doc.add_text(f.os, &d.os);
            doc.add_text(f.class, &d.class);
            for h in &d.hosts {
                doc.add_text(f.host, h.to_lowercase());
            }
            for s in &d.serials {
                doc.add_text(f.serial, s.to_lowercase());
            }
            for ip in &d.ips {
                doc.add_text(f.ip, ip);
            }
            for q in &d.fqdns {
                doc.add_text(f.fqdn, q);
            }
            doc.add_text(f.text, &d.text);
            self.writer.add_document(doc)?;
            seen.insert(d.asset_uid.clone(), d.version);
            applied += 1;
        }
        for x in &req.deletes {
            let current = seen.get(&x.asset_uid).copied().or_else(|| self.stored_version(&x.asset_uid));
            if current.is_none() || current.is_some_and(|v| v > x.version) {
                stale += 1; // нечего удалять или документ уже новее удаления
                continue;
            }
            self.writer.delete_term(Term::from_field_text(f.id, &x.asset_uid));
            seen.insert(x.asset_uid.clone(), x.version);
            deleted += 1;
        }
        self.writer.commit()?;
        self.reader.reload()?;
        Ok((applied, stale, deleted))
    }

    fn docs(&self) -> u64 {
        self.reader.searcher().num_docs()
    }

    fn compile(&self, req: &SearchRequest) -> Box<dyn Query> {
        let f = &self.fields;
        let term = |field: Field, v: &str| -> Box<dyn Query> { Box::new(TermQuery::new(Term::from_field_text(field, v), IndexRecordOption::WithFreqs)) };
        let mut must: Vec<(Occur, Box<dyn Query>)> = vec![(Occur::Must, term(f.tenant, &req.tenant))];
        for (k, v) in &req.filters {
            match k.as_str() {
                "os" => must.push((Occur::Must, term(f.os, v))),
                "class" => must.push((Occur::Must, term(f.class, v))),
                _ => {}
            }
        }
        // каждое слово запроса должно совпасть хотя бы с одним полем: текст (морфология), хост/IP (префикс),
        // серийный номер (точно), FQDN (часть с позициями)
        for word in req.query.split_whitespace().take(16) {
            let lower = word.to_lowercase();
            let mut any: Vec<(Occur, Box<dyn Query>)> = vec![];
            let text: Vec<Box<dyn Query>> = tokens(ru(), word).iter().map(|t| term(f.text, t)).collect();
            if !text.is_empty() {
                any.push((Occur::Should, Box::new(BooleanQuery::new(text.into_iter().map(|q| (Occur::Must, q)).collect()))));
            }
            if let Ok(q) = RegexQuery::from_pattern(&format!("{}.*", regex::escape(&lower)), f.host) {
                any.push((Occur::Should, Box::new(q)));
            }
            if let Ok(q) = RegexQuery::from_pattern(&format!("{}.*", regex::escape(&lower)), f.ip) {
                any.push((Occur::Should, Box::new(q)));
            }
            any.push((Occur::Should, term(f.serial, &lower)));
            let p: Vec<Term> = tokens(parts(), word).iter().map(|t| Term::from_field_text(f.fqdn, t)).collect();
            if p.len() > 1 {
                any.push((Occur::Should, Box::new(PhraseQuery::new(p))));
            } else if let Some(t) = p.into_iter().next() {
                any.push((Occur::Should, Box::new(TermQuery::new(t, IndexRecordOption::WithFreqs))));
            }
            must.push((Occur::Must, Box::new(BooleanQuery::new(any))));
        }
        Box::new(BooleanQuery::new(must))
    }

    fn snapshot(&self) -> (tantivy::Searcher, Fields) {
        (self.reader.searcher(), self.fields)
    }
}

// Поиск выполняется вне общей блокировки: снимок читателя берётся под блокировкой, сам запрос — параллельно с записью.
fn search(searcher: &tantivy::Searcher, fields: &Fields, query: &dyn Query, req: &SearchRequest) -> tantivy::Result<(usize, Vec<Hit>)> {
    let (total, top) = searcher.search(query, &(Count, TopDocs::with_limit(req.limit.clamp(1, 1000)).order_by_score()))?;
    let wanted = req.snippets.unwrap_or(req.limit).min(top.len());
    let mut snippets = if wanted > 0 { Some(SnippetGenerator::create(searcher, query, fields.text)?) } else { None };
    if let Some(g) = snippets.as_mut() {
        g.set_max_num_chars(160);
    }
    let mut hits = vec![];
    for (i, (score, addr)) in top.into_iter().enumerate() {
        let d: TantivyDocument = searcher.doc(addr)?;
        let (fragment, highlights) = match snippets.as_ref().filter(|_| i < wanted) {
            Some(g) => {
                let snippet = g.snippet_from_doc(&d);
                let fragment = snippet.fragment().to_string();
                let highlights = snippet.highlighted().iter().map(|r| [fragment[..r.start].chars().count(), fragment[..r.end].chars().count()]).collect();
                (fragment, highlights)
            }
            None => (String::new(), vec![]),
        };
        let text = |f: Field| d.get_first(f).and_then(|v| v.as_str()).unwrap_or_default().to_string();
        hits.push(Hit { asset_uid: text(fields.id), score, os: text(fields.os), class: text(fields.class), fragment, highlights });
    }
    Ok((total, hits))
}

struct State {
    root: PathBuf,
    active: Generation,
    building: Option<Generation>,
}

impl State {
    fn open(root: PathBuf) -> tantivy::Result<State> {
        std::fs::create_dir_all(&root)?;
        let number = std::fs::read_to_string(root.join("ACTIVE")).ok().and_then(|s| s.trim().parse().ok()).unwrap_or(1);
        // незавершённые поколения пересборки после сбоя удаляются: пересборку начинают заново
        for e in std::fs::read_dir(&root)?.flatten() {
            let name = e.file_name().to_string_lossy().to_string();
            if name.starts_with("gen-") && name != format!("gen-{number}") {
                let _ = std::fs::remove_dir_all(e.path());
            }
        }
        let active = open_generation(&root, number)?;
        write_active(&root, number)?;
        Ok(State { root, active, building: None })
    }
}

fn write_active(root: &Path, number: u64) -> std::io::Result<()> {
    let tmp = root.join("ACTIVE.tmp");
    std::fs::write(&tmp, number.to_string())?;
    std::fs::File::open(&tmp)?.sync_all()?;
    std::fs::rename(tmp, root.join("ACTIVE"))
}

fn json<T: Serialize>(status: u16, v: &T) -> tiny_http::Response<std::io::Cursor<Vec<u8>>> {
    tiny_http::Response::from_data(serde_json::to_vec(v).unwrap()).with_status_code(status).with_header("Content-Type: application/json".parse::<tiny_http::Header>().unwrap())
}

fn error(status: u16, code: &str) -> tiny_http::Response<std::io::Cursor<Vec<u8>>> {
    json(status, &serde_json::json!({"code": code}))
}

fn handle(state: &Mutex<State>, method: &str, url: &str, body: &[u8]) -> tiny_http::Response<std::io::Cursor<Vec<u8>>> {
    if (method, url) == ("POST", "/v1/search") {
        let r = (|| -> Result<_, Box<dyn std::error::Error>> {
            let req: SearchRequest = serde_json::from_slice(body)?;
            let (searcher, fields, query) = {
                let s = state.lock().unwrap();
                let (searcher, fields) = s.active.snapshot();
                (searcher, fields, s.active.compile(&req))
            };
            let (total, hits) = search(&searcher, &fields, &*query, &req)?;
            Ok(json(200, &serde_json::json!({"total": total, "hits": hits})))
        })();
        return r.unwrap_or_else(|e| {
            eprintln!("request failed: {e}");
            error(400, "INVALID_REQUEST")
        });
    }
    let mut s = state.lock().unwrap();
    let r = (|| -> Result<tiny_http::Response<std::io::Cursor<Vec<u8>>>, Box<dyn std::error::Error>> {
        Ok(match (method, url) {
            ("GET", "/v1/status") => json(200, &serde_json::json!({"format": FORMAT, "generation": s.active.number, "docs": s.active.docs(), "rebuilding": s.building.is_some()})),
            ("POST", "/v1/apply") => {
                let req: Apply = serde_json::from_slice(body)?;
                let (applied, stale, deleted) = s.active.apply(&req)?;
                if let Some(b) = s.building.as_mut() {
                    b.apply(&req)?; // двойная запись: пересборка не теряет изменений, пришедших во время неё
                }
                json(200, &serde_json::json!({"applied": applied, "stale": stale, "deleted": deleted}))
            }
            ("POST", "/v1/rebuild/begin") => {
                let next = s.active.number + 1;
                let _ = std::fs::remove_dir_all(s.root.join(format!("gen-{next}")));
                s.building = Some(open_generation(&s.root, next)?);
                json(200, &serde_json::json!({"generation": next}))
            }
            ("POST", "/v1/rebuild/load") => {
                let req: Apply = serde_json::from_slice(body)?;
                match s.building.as_mut() {
                    Some(b) => {
                        let (applied, stale, deleted) = b.apply(&req)?;
                        json(200, &serde_json::json!({"applied": applied, "stale": stale, "deleted": deleted}))
                    }
                    None => error(409, "NOT_REBUILDING"),
                }
            }
            ("POST", "/v1/rebuild/commit") => match s.building.take() {
                Some(b) => {
                    let (old, number, docs) = (s.active.number, b.number, b.docs());
                    write_active(&s.root, number)?;
                    s.active = b;
                    let _ = std::fs::remove_dir_all(s.root.join(format!("gen-{old}")));
                    json(200, &serde_json::json!({"generation": number, "docs": docs}))
                }
                None => error(409, "NOT_REBUILDING"),
            },
            ("POST", "/v1/rebuild/abort") => {
                if let Some(b) = s.building.take() {
                    let n = b.number;
                    drop(b);
                    let _ = std::fs::remove_dir_all(s.root.join(format!("gen-{n}")));
                }
                json(200, &serde_json::json!({"aborted": true}))
            }
            _ => error(404, "NOT_FOUND"),
        })
    })();
    r.unwrap_or_else(|e| {
        eprintln!("request failed: {e}");
        error(400, "INVALID_REQUEST")
    })
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() == 2 && args[1] == "version" {
        // C33.02: происхождение для подписанного релиза — версия и ревизия задаются при сборке (release.py)
        println!(
            "{{\"component\":\"search\",\"version\":\"{}\",\"revision\":\"{}\",\"source_dirty\":\"{}\",\"format\":\"{}\"}}",
            option_env!("SURVEYSCAN_VERSION").unwrap_or(env!("CARGO_PKG_VERSION")),
            option_env!("SURVEYSCAN_REVISION").unwrap_or("unknown"),
            option_env!("SURVEYSCAN_DIRTY").unwrap_or("unknown"),
            FORMAT
        );
        return;
    }
    if args.len() != 4 {
        eprintln!("usage: surveyscan-search LISTEN(127.0.0.1:PORT) DATA_DIR TOKEN_FILE");
        std::process::exit(2);
    }
    let addr: std::net::SocketAddr = args[1].parse().expect("listen address");
    assert!(addr.ip().is_loopback(), "search service listens on loopback only");
    let token = std::fs::read_to_string(&args[3]).expect("token file").trim().to_string();
    assert!(token.len() >= 32, "token must be at least 32 characters");
    let state = std::sync::Arc::new(Mutex::new(State::open(PathBuf::from(&args[2])).expect("open index")));
    let server = std::sync::Arc::new(tiny_http::Server::http(addr).expect("listen"));
    let token = std::sync::Arc::new(token);
    eprintln!("surveyscan-search READY {addr} format={FORMAT}");
    // несколько обработчиков: поиск идёт параллельно, запись в индекс — под общей блокировкой (C30.03)
    let workers: Vec<_> = (0..8)
        .map(|_| {
            let (server, state, token) = (server.clone(), state.clone(), token.clone());
            std::thread::spawn(move || {
                while let Ok(mut req) = server.recv() {
                    let authorized = req.headers().iter().any(|h| h.field.equiv("X-Search-Token") && h.value.as_str() == token.as_str());
                    let mut body = vec![];
                    let ok = std::io::Read::read_to_end(&mut std::io::Read::take(req.as_reader(), 64 << 20), &mut body).is_ok();
                    let resp = if !authorized { error(401, "UNAUTHORIZED") } else if !ok { error(400, "INVALID_REQUEST") } else { handle(&state, req.method().as_str(), req.url(), &body) };
                    let _ = req.respond(resp);
                }
            })
        })
        .collect();
    for w in workers {
        let _ = w.join();
    }
}
