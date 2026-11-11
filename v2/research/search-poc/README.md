# C28 — PoC полнотекстового поиска (исследование, не продукт)

Два изолированных прототипа на одном корпусе: `bluge/` (Go, свой go.mod — не входит в сборку v2) и `tantivy/` (Rust).
Критерии — docs/plans/surveyscan-v2/decisions/C28-search-criteria.md, итог — C28-search-adr.md.

```
python3 corpus.py OUT 100000                      # корпус, изменения, запросы с ожиданиями
(cd bluge && go build -o ../bluge-poc .)
(cd tantivy && cargo build --release && cp target/release/tantivy-poc ..)
python3 compare.py WORK 100000 50 ./bluge-poc ./tantivy-poc   # → WORK/report.json
```
`results-100k.json` — отчёт прогона R-027 (песочница 4 vCPU / 15 ГиБ, синтетические данные).
