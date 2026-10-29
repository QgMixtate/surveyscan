"""Аутентифицированный сбор инвентаря с активов по SSH / WinRM / SNMP.

После сетевого обнаружения (nmap) к каждому активу подбирается подходящая учётная
запись из набора и выполняется сбор его «родным» коллектором:
  • SSH  → collectors/linux_collect.sh  (Astra, РЕД ОС, Debian/RHEL-семейство)
  • WinRM → collectors/windows_collect.ps1 (Windows)
Вывод коллектора скармливается тому же ingest, что и выгрузки с диска, поэтому
обогащает ТОТ ЖЕ актив (матч по IP/имени из nmap): появляются пакеты/ПО, учётки,
параметры ОС, конфиги. SNMP-опрос сетевого оборудования даёт соседей (LLDP/ARP) —
связи L2 для схемы сети.

Подбор УЗ («перебор»): для каждого актива по открытым портам/ОС определяются
кандидатные протоколы, затем по очереди пробуются УЗ нужного типа, пока одна не
пройдёт аутентификацию. В сводке фиксируется, какая УЗ подошла (ТОЛЬКО логин —
секреты не логируются и не сохраняются).

Секреты (пароли, приватные ключи, SNMP community) приходят параметром из памяти
задачи и наружу (БД, логи, отчёт) не попадают.
"""
from __future__ import annotations

import io
import ipaddress
import json
import re
import shutil
import subprocess
import tempfile
from pathlib import Path


def _noop(*_a, **_k):
    pass


# --------------------------------------------------------------------------- выбор цели/протокола
def _first_ipv4(ips) -> str | None:
    for p in ips or []:
        try:
            ip = ipaddress.ip_address(p)
        except ValueError:
            continue
        if ip.version == 4 and not ip.is_loopback and not ip.is_link_local:
            return str(ip)
    return None


def _looks_device(os: str, kind: str, ip: str | None) -> bool:
    k, o = (kind or "").lower(), (os or "").lower()
    if "сетев" in k or k == "netdev":
        return True
    if any(t in o for t in ("cisco", "huawei", "mikrotik", "juniper", "router", "switch", "vrp", "ios")):
        return True
    return bool(ip) and ip.rsplit(".", 1)[-1] == "1"


def _protocols(asset: dict) -> list[str]:
    """Кандидатные протоколы сбора для актива — по открытым портам и ОС."""
    ports, os = asset["ports"], (asset["os"] or "").lower()
    out = []
    if 22 in ports or any(t in os for t in ("linux", "astra", "red os", "debian", "ubuntu", "centos", "rhel", "alt")):
        out.append("ssh")
    if ({3389, 445, 5985, 5986} & ports) or "windows" in os:
        out.append("winrm")
    if 161 in ports or _looks_device(asset["os"], asset["kind"], _first_ipv4(asset["ips"])):
        out.append("snmp")
    return out


def _assets_from_db(con) -> list[dict]:
    rows = con.execute("SELECT id, hostname, ips, os_pretty, os_family, kind FROM asset").fetchall()
    out = []
    for r in rows:
        ports = {int(s["port"]) for s in con.execute("SELECT port FROM service WHERE asset_id=?", (r["id"],))}
        out.append({"id": r["id"], "hostname": r["hostname"], "ips": json.loads(r["ips"] or "[]"),
                    "os": r["os_pretty"] or "", "family": r["os_family"] or "", "kind": r["kind"] or "",
                    "ports": ports})
    return out


# --------------------------------------------------------------------------- SSH (paramiko)
def _load_pkey(key_text: str):
    import paramiko
    for cls in (paramiko.Ed25519Key, paramiko.RSAKey, paramiko.ECDSAKey):
        try:
            return cls.from_private_key(io.StringIO(key_text))
        except Exception:
            continue
    raise ValueError("не удалось разобрать приватный ключ (ожидается OpenSSH/PEM)")


def _ssh_collect(host: str, cred: dict, script: str, timeout: int = 60) -> str:
    """Выполняет linux_collect.sh на хосте по SSH, возвращает вывод (.surv). Исключение — на отказе."""
    import paramiko
    cli = paramiko.SSHClient()
    cli.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    kw = dict(hostname=host, port=int(cred.get("port") or 22), username=cred.get("username"),
              timeout=timeout, banner_timeout=timeout, auth_timeout=timeout,
              allow_agent=False, look_for_keys=False)
    if cred.get("key"):
        kw["pkey"] = _load_pkey(cred["key"])
    else:
        kw["password"] = cred.get("secret")
    cli.connect(**kw)
    try:
        # sudo -n, если не root и задан пароль — иначе собираем тем, что доступно (ядро учитывает неполноту)
        cmd = "sudo -n sh -s 2>/dev/null || sh -s"
        stdin, stdout, stderr = cli.exec_command(cmd, timeout=timeout)
        stdin.write(script)
        stdin.channel.shutdown_write()
        out = stdout.read().decode("utf-8", "replace")
        return out
    finally:
        cli.close()


# --------------------------------------------------------------------------- WinRM (pywinrm)
def _winrm_collect(host: str, cred: dict, script: str, timeout: int = 120) -> str:
    import winrm
    port = int(cred.get("port") or 5985)
    user = cred.get("username")
    if cred.get("domain") and "\\" not in user and "@" not in user:
        user = f"{cred['domain']}\\{user}"
    s = winrm.Session(f"http://{host}:{port}/wsman", auth=(user, cred.get("secret")),
                      transport="ntlm", read_timeout_sec=timeout + 10, operation_timeout_sec=timeout)
    r = s.run_ps(script)
    if r.status_code != 0:
        raise RuntimeError((r.std_err or b"").decode("utf-8", "replace")[:300] or f"winrm rc={r.status_code}")
    return r.std_out.decode("utf-8", "replace")


# --------------------------------------------------------------------------- SNMP (net-snmp CLI)
_OID_SYSNAME = "1.3.6.1.2.1.1.5.0"
_OID_SYSDESCR = "1.3.6.1.2.1.1.1.0"
_OID_LLDP_REMSYSNAME = "1.0.8802.1.1.2.1.4.1.1.9"       # lldpRemSysName
_OID_ARP = "1.3.6.1.2.1.4.22.1.2"                        # ipNetToMediaPhysAddress


def _snmpwalk(host: str, community: str, oid: str, timeout: int = 8) -> list[str]:
    if not shutil.which("snmpwalk"):
        raise RuntimeError("net-snmp (snmpwalk) не установлен")
    r = subprocess.run(["snmpwalk", "-v2c", "-c", community, "-Oqv", "-t", "3", "-r", "1", host, oid],
                       capture_output=True, text=True, timeout=timeout)
    if r.returncode != 0:
        raise RuntimeError((r.stderr or r.stdout).strip()[:200] or "snmp timeout/denied")
    bad = ("No Such Object", "No Such Instance", "No more variables", "End of MIB")
    return [v for l in r.stdout.splitlines()
            if (v := l.strip().strip('"')) and not any(b in v for b in bad)]


def _snmp_collect(host: str, community: str, timeout: int = 10) -> dict:
    name = (_snmpwalk(host, community, _OID_SYSNAME, timeout) or [""])[0]
    descr = " ".join(_snmpwalk(host, community, _OID_SYSDESCR, timeout) or [])
    lldp = []
    try:
        lldp = [n for n in _snmpwalk(host, community, _OID_LLDP_REMSYSNAME, timeout) if n]
    except Exception:
        pass
    return {"sysname": name, "sysdescr": descr, "lldp_neighbors": lldp}


# --------------------------------------------------------------------------- оркестрация
def collect(con, creds: list[dict], root: Path, log=None, should_cancel=None) -> dict:
    """Обогащает активы в con аутентифицированным сбором. Возвращает сводку (без секретов)."""
    log = log or _noop
    should_cancel = should_cancel or (lambda: False)
    by_type: dict[str, list[dict]] = {"ssh": [], "winrm": [], "snmp": []}
    for c in creds or []:
        if c.get("type") in by_type:
            by_type[c["type"]].append(c)

    def _read(p):
        try:
            return p.read_text(encoding="utf-8")
        except Exception:
            return None
    linux_script = _read(root / "collectors" / "linux_collect.sh")
    win_script = _read(root / "collectors" / "windows_collect.ps1")

    from .ingest import ingest_file

    def _merge_into(src_id: int, dst_id: int, scanned_ip: str) -> None:
        """Коллектор сообщил другой hostname/IP и создал новый актив, хотя мы подключались
        к известному src_id по scanned_ip — это ТОТ ЖЕ актив. Переносим сетевые данные и
        сканированный IP на обогащённый актив, старый (nmap-only) удаляем."""
        con.execute("UPDATE service SET asset_id=? WHERE asset_id=?", (dst_id, src_id))
        con.execute("UPDATE raw_artifact SET asset_id=? WHERE asset_id=?", (dst_id, src_id))
        row = con.execute("SELECT ips FROM asset WHERE id=?", (dst_id,)).fetchone()
        ips = set(json.loads((row["ips"] if row else None) or "[]"))
        ips.add(scanned_ip)
        con.execute("UPDATE asset SET ips=? WHERE id=?", (json.dumps(sorted(ips)), dst_id))
        con.execute("DELETE FROM asset WHERE id=?", (src_id,))

    collected, failed, l2_links = [], [], []
    runners = {"ssh": (_ssh_collect, linux_script, ".surv"),
               "winrm": (_winrm_collect, win_script, ".json")}

    for a in _assets_from_db(con):
        if should_cancel():
            log("  сбор прерван (отмена)")
            break
        ip = _first_ipv4(a["ips"])
        label = a["hostname"] or ip or f"asset{a['id']}"
        if not ip:
            continue
        for proto in _protocols(a):
            cand = by_type.get(proto) or []
            if not cand:
                continue
            ok = False
            last_err = ""
            # --- SNMP: отдельная ветка (community вместо collector), пополняет L2
            if proto == "snmp":
                for c in cand:
                    try:
                        log(f"  [snmp] {label} ({ip})…")
                        info = _snmp_collect(ip, c.get("secret") or "public")
                        for nb in info.get("lldp_neighbors", []):
                            l2_links.append({"a": label, "b": nb, "ports": "LLDP"})
                        collected.append({"asset": label, "ip": ip, "proto": "snmp",
                                          "cred": c.get("username") or "community", "info": info.get("sysname") or info.get("sysdescr", "")[:40]})
                        ok = True
                        break
                    except Exception as e:
                        last_err = str(e)[:160]
                if not ok:
                    failed.append({"asset": label, "ip": ip, "proto": "snmp", "error": last_err})
                continue
            # --- SSH / WinRM: прогон коллектора, затем ingest
            fn, script, suffix = runners[proto]
            if not script:                            # коллектор не найден (напр. нет в образе)
                failed.append({"asset": label, "ip": ip, "proto": proto,
                               "error": "коллектор не найден (collectors/ отсутствует)"})
                continue
            for c in cand:
                try:
                    log(f"  [{proto}] {label} ({ip}) под УЗ {c.get('username')!r}…")
                    out = fn(ip, c, script)
                    if not out or ("@@@SURVEY:" not in out and '"collector"' not in out and "collector" not in out):
                        raise RuntimeError("коллектор вернул пустой/неожиданный результат")
                    tmp = Path(tempfile.mkdtemp(prefix="surveyscan-collect-")) / (label + suffix)
                    tmp.write_text(out, encoding="utf-8")
                    kind, new_id = ingest_file(con, tmp)
                    if new_id and new_id != a["id"]:          # коллектор создал отдельный актив — склеиваем
                        _merge_into(a["id"], new_id, ip)
                    collected.append({"asset": label, "ip": ip, "proto": proto, "cred": c.get("username"), "kind": kind})
                    ok = True
                    break
                except Exception as e:
                    last_err = str(e)[:160]
            if not ok:
                failed.append({"asset": label, "ip": ip, "proto": proto, "error": last_err})
            else:
                break        # актив собран — другие протоколы не пробуем

    log(f"  сбор завершён: успешно {len(collected)}, не удалось {len(failed)}")
    return {"collected": collected, "failed": failed, "l2_links": l2_links}
