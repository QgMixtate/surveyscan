# SurveyScan v2: полный отчёт на 08.11.2026

[Word](SurveyScan_v2_Architecture_Specification_Status_2026-11-08.docx) ·
[PDF, 97 страниц](SurveyScan_v2_Architecture_Specification_Status_2026-11-08.pdf) ·
[Манифест и контрольные суммы](manifest.json)

Содержание: обзор, 8 схем, полная спецификация/архитектура 0.5, все 50 пакетов и
200 подзадач, выполненные/оставшиеся работы, evidence и ограничения. Схемы приложены
как DOT/PNG. 57 done / 1 in_progress / 142 planned — счёт задач, не трудозатрат.

Это архивный снимок исходников `5fe78c5f844e6d1768fa343cdb64ed18178c5d1b`.
GitHub проверен 08.11.2026: v2/Web/Boot/Evidence success, Windows failure
([run 42309005102](https://github.com/QgMixtate/surveyscan/actions/runs/42309005102),
`TestAtomicReadersSeeWholeOldOrNewData`, `atomic_rename code=5`). C15.02 не принят;
winstate не подключён к agent runtime. PR5 остаётся draft; main/release/deploy не выполнены.

## Пересборка

Требования: Python 3 с `python-docx`, Pillow; Graphviz (`dot`); для PDF — LibreOffice.
Использовать отдельный checkout указанного SHA и отдельный каталог вывода. Генератор
содержит зафиксированный обзор и статусы GitHub того дня: для нового отчёта их нужно
повторно проверить и актуализировать. Это не автоматический сборщик текущего статуса.

```sh
python3 build_report.py --repo /path/to/pinned-checkout --output /tmp/surveyscan-report-rebuild
soffice --headless --convert-to pdf --outdir /tmp/surveyscan-report-rebuild /tmp/surveyscan-report-rebuild/SurveyScan_v2_Architecture_Specification_Status_2026-11-08.docx
```

Автоматическое оглавление Word пересчитывается по F9. PDF экспортирован и вёрстка
проверена; все 200 ID задач присутствуют. Результат пересборки может различаться
байтово из-за метаданных, версии шрифтов и средств рендеринга. Приватные журналы,
секреты, ключи и raw inventory в комплект не включены.
