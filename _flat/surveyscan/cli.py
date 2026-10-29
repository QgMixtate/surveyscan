"""Командная строка сканера обследования.

  python -m surveyscan bdu-import vulxml.zip
  python -m surveyscan collect-ssh 10.0.0.5 --user audit --sudo --ask-pass
  python -m surveyscan ingest results/*.surv results/*.json nmap.xml openvas.xml core-sw1.cfg
  python -m surveyscan analyze --profile profiles/base.yaml
  python -m surveyscan report --out report.html --csv export/
  python -m surveyscan demo
"""
from __future__ import annotations

import argparse
import getpass
import shutil
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DATA = ROOT / "data"


def _paths(a):
    return Path(a.survey), Path(a.bdu), Path(a.msrc)


def cmd_adv_import(a):
    from .advisories import import_feeds
    counts = import_feeds(Path(a.adv), ubuntu_oval=a.ubuntu_oval or [],
                          debian_json=a.debian_json or [], normalized=a.file or [])
    total = sum(counts.values())
    print(f"Фиды вендоров загружены в {a.adv}: записей {total}")
    for k, v in counts.items():
        print(f"  {k}: {v}")


def cmd_bdu_import(a):
    from .bdu import import_bdu
    _, bdu, _ = _paths(a)
    meta = import_bdu(Path(a.file), bdu, progress=lambda n: print(f"  обработано записей: {n}", end="\r", file=sys.stderr))
    print(f"\nБДУ импортирована в {bdu}: записей {meta['records']}, ПО {meta['soft_entries']}, "
          f"связей с CVE {meta['cve_links']}, неразобранных версий {meta['unparsed_versions']}")


def cmd_msrc_sync(a):
    from .msrc import sync
    _, _, msrc = _paths(a)
    msrc.parent.mkdir(parents=True, exist_ok=True)
    n = sync(msrc, months=a.months or [], files=[Path(f) for f in a.file or []])
    print(f"Загружено записей об исправлениях Microsoft: {n} -> {msrc}")


def cmd_ingest(a):
    from .db import connect
    from .ingest import ingest_file
    survey, _, _ = _paths(a)
    con = connect(survey)
    for f in a.files:
        kind, asset_id = ingest_file(con, Path(f))
        print(f"  {f}: {kind}" + (f" -> актив {asset_id}" if asset_id else ""))


def cmd_collect_ssh(a):
    try:
        import paramiko
    except ImportError:
        sys.exit("Нужен paramiko: pip install paramiko")
    from .db import connect
    from .ingest import ingest_file
    script = (ROOT / "collectors" / "linux_collect.sh").read_text(encoding="utf-8")
    password = getpass.getpass(f"Пароль {a.user}@{a.host}: ") if a.ask_pass else None
    client = paramiko.SSHClient()
    client.load_system_host_keys()
    if a.accept_new_hostkey:
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    else:
        client.set_missing_host_key_policy(paramiko.RejectPolicy())
    try:
        client.connect(a.host, port=a.port, username=a.user, password=password, key_filename=a.key,
                       look_for_keys=a.key is None, timeout=20)
    except paramiko.SSHException as e:
        hint = " (ключ хоста неизвестен: проверьте отпечаток и добавьте в known_hosts или используйте --accept-new-hostkey)" \
            if "known_hosts" in str(e) else ""
        sys.exit(f"{a.host}: не удалось подключиться по SSH: {e}{hint}")
    except OSError as e:
        sys.exit(f"{a.host}: сетевая ошибка: {e}")
    if a.sudo:
        cmd = "sudo -S -p '' sh -s" if password else "sudo -n sh -s"
    else:
        cmd = "sh -s"
    stdin, stdout, stderr = client.exec_command(cmd, timeout=600)
    if a.sudo and password:
        stdin.write(password + "\n")
    stdin.write(script)
    stdin.channel.shutdown_write()
    out = stdout.read().decode("utf-8", "replace")
    err = stderr.read().decode("utf-8", "replace").strip()
    client.close()
    if "@@@SURVEY:end@@@" not in out:
        sys.exit(f"Сбор не завершён на {a.host}: {err[:500]}")
    dest = Path(a.out) / f"{a.host}.surv"
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_text(out, encoding="utf-8")
    survey, _, _ = _paths(a)
    kind, asset_id = ingest_file(connect(survey), dest)
    print(f"{a.host}: собрано -> {dest}, актив {asset_id}")


def cmd_analyze(a):
    from .configcheck import run_checks
    from .db import connect
    from .matcher import analyze
    from .normalize import Catalog
    survey, bdu, msrc = _paths(a)
    adv = Path(a.adv)
    from .pgcompat import schema_exists
    con = connect(survey, bdu if not a.no_vuln else None)
    if not a.no_vuln:
        has_ms, has_adv = schema_exists(con, "ms"), schema_exists(con, "adv")
        st = analyze(con, Catalog(ROOT / "rules" / "products.yaml"),
                     msrc if has_ms else None, adv if has_adv else None)
        from .bdu import bdu_version_label
        con.execute("UPDATE survey SET bdu_version = ?", (bdu_version_label(con),))
        con.commit()
        print("Уязвимости:", ", ".join(f"{k}={v}" for k, v in st.items()))
        if not has_ms:
            print("  (бюллетени Microsoft не загружены — ОС Windows проверяются только по ПО; см. msrc-sync)")
        if not has_adv:
            print("  (фиды вендоров не загружены — находки по пакетам ОС «вероятно», бэкпорты не учтены; см. adv-import)")
    if not a.no_config:
        for prof in a.profile or [str(ROOT / "profiles" / "base.yaml")]:
            st = run_checks(con, ROOT / "checks", ROOT / "catalog", Path(prof))
            print("Конфигурации:", ", ".join(f"{k}={v}" for k, v in st.items()))


def cmd_report(a):
    from .db import connect
    from .report import export_csv, render_html
    survey, bdu, _ = _paths(a)
    con = connect(survey)
    if a.name or a.customer:
        con.execute("UPDATE survey SET name = COALESCE(?, name), customer = COALESCE(?, customer)", (a.name, a.customer))
        con.commit()
    out = render_html(con, ROOT / "catalog", Path(a.out), template=a.template, reports_dir=ROOT / "reports")
    print(f"Отчёт: {out}")
    if a.csv:
        for p in export_csv(con, Path(a.csv)):
            print(f"Выгрузка: {p}")


def cmd_demo(a):
    """Полный прогон на синтетических примерах из samples/."""
    out = Path(a.out)
    if out.exists():
        shutil.rmtree(out)
    out.mkdir(parents=True)
    from .pgcompat import drop_db
    drop_db(out / "survey.sqlite")       # чистый прогон на свежей БД PostgreSQL
    s = ROOT / "samples"
    base = ["--survey", str(out / "survey.sqlite"), "--bdu", str(out / "bdu.sqlite"),
            "--msrc", str(out / "msrc.sqlite"), "--adv", str(out / "advisories.sqlite")]
    main(base + ["bdu-import", str(s / "bdu" / "vulxml_sample.xml")])
    main(base + ["msrc-sync", "--file", str(s / "msrc_cvrf_sample.json")])
    adv = s / "advisories"
    main(base + ["adv-import", "--ubuntu-oval", str(adv / "com.ubuntu.jammy.pkg.oval.xml"),
                 "--debian-json", str(adv / "debian_tracker_sample.json"),
                 "--file", str(adv / "astra_normalized.jsonl")])
    main(base + ["ingest", *map(str, sorted(s.glob("hosts/*")))])
    main(base + ["analyze", "--profile", str(ROOT / "profiles" / "base.yaml"),
                 "--profile", str(ROOT / "profiles" / "customer-example.yaml")])
    main(base + ["report", "--out", str(out / "report.html"), "--csv", str(out / "csv"),
                 "--name", "Демонстрационное обследование", "--customer", "ООО «Пример»"])
    # дополнительно — варианты кастомных отчётов из тех же данных
    for tid in ("executive", "vuln", "config"):
        main(base + ["report", "--template", tid, "--out", str(out / f"report-{tid}.html"),
                     "--name", "Демонстрационное обследование", "--customer", "ООО «Пример»"])


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="surveyscan", description="Сканер обследования: инвентаризация, уязвимости (БДУ ФСТЭК), конфигурации")
    p.add_argument("--survey", default="work/survey.sqlite", help="база обследования (по умолчанию work/survey.sqlite)")
    p.add_argument("--bdu", default=str(DATA / "bdu.sqlite"), help="база БДУ (создаётся bdu-import)")
    p.add_argument("--msrc", default=str(DATA / "msrc.sqlite"), help="база бюллетеней Microsoft (создаётся msrc-sync)")
    p.add_argument("--adv", default=str(DATA / "advisories.sqlite"), help="база фидов вендоров (создаётся adv-import)")
    sub = p.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("bdu-import", help="импорт выгрузки БДУ ФСТЭК (vulxml.zip или .xml)")
    s.add_argument("file"); s.set_defaults(func=cmd_bdu_import)

    s = sub.add_parser("msrc-sync", help="загрузка бюллетеней Microsoft (онлайн или из файлов CVRF JSON)")
    s.add_argument("--months", nargs="*", help="например 2026-Sep 2026-Oct")
    s.add_argument("--file", nargs="*", help="локальные файлы CVRF JSON"); s.set_defaults(func=cmd_msrc_sync)

    s = sub.add_parser("collect-ssh", help="безагентный сбор с Linux по SSH")
    s.add_argument("host"); s.add_argument("--user", required=True); s.add_argument("--port", type=int, default=22)
    s.add_argument("--key", help="закрытый ключ"); s.add_argument("--ask-pass", action="store_true", help="запросить пароль")
    s.add_argument("--sudo", action="store_true", help="выполнить коллектор через sudo (полный набор данных)")
    s.add_argument("--accept-new-hostkey", action="store_true", help="принять неизвестный ключ хоста (по умолчанию — отказ)")
    s.add_argument("--out", default="work/raw"); s.set_defaults(func=cmd_collect_ssh)

    s = sub.add_parser("adv-import", help="загрузка фидов вендоров (Ubuntu OVAL, Debian JSON, нормализованный JSONL)")
    s.add_argument("--ubuntu-oval", nargs="*", help="файлы com.ubuntu.<release>.pkg.oval.xml[.bz2]")
    s.add_argument("--debian-json", nargs="*", help="файлы Debian security-tracker data/json")
    s.add_argument("--file", nargs="*", help="нормализованные JSONL (для Astra/РЕД ОС)")
    s.set_defaults(func=cmd_adv_import)

    s = sub.add_parser("ingest", help="загрузка результатов коллекторов и сканеров")
    s.add_argument("files", nargs="+"); s.set_defaults(func=cmd_ingest)

    s = sub.add_parser("analyze", help="сопоставление с БДУ и проверка конфигураций")
    s.add_argument("--profile", action="append", help="профиль (можно несколько); по умолчанию profiles/base.yaml")
    s.add_argument("--no-vuln", action="store_true"); s.add_argument("--no-config", action="store_true")
    s.set_defaults(func=cmd_analyze)

    s = sub.add_parser("report", help="отчёт HTML и выгрузка CSV")
    s.add_argument("--out", default="work/report.html"); s.add_argument("--csv", help="папка для CSV")
    s.add_argument("--template", help="шаблон отчёта: full|executive|vuln|config или путь к .yaml")
    s.add_argument("--name"); s.add_argument("--customer"); s.set_defaults(func=cmd_report)

    s = sub.add_parser("demo", help="полный прогон на синтетических примерах")
    s.add_argument("--out", default="demo-output"); s.set_defaults(func=cmd_demo)
    return p


def main(argv=None):
    a = build_parser().parse_args(argv)
    a.func(a)


if __name__ == "__main__":
    main()
