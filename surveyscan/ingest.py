"""Загрузка результатов коллекторов и сканеров в базу обследования.

Поддерживаемые входы (тип определяется по содержимому):
  *.surv        — вывод collectors/linux_collect.sh
  *.json        — вывод collectors/windows_collect.ps1 или отчёт Trivy (JSON)
  *.xml         — отчёт Nmap (-oX) или отчёт Greenbone/OpenVAS (XML)
  *.cfg / *.txt — конфигурация сетевого устройства (Cisco IOS, Huawei VRP)
"""
from __future__ import annotations

import datetime as dt
import hashlib
import ipaddress
import json
import re
import sqlite3
from pathlib import Path

from lxml import etree

from .db import apply_role_guess, find_or_create_asset
from .versions import upstream_of


def _strip_nul(obj):
    """PostgreSQL text-поля не допускают NUL (0x00) — встречается в повреждённых записях реестра."""
    if isinstance(obj, str):
        return obj.replace("\x00", "") if "\x00" in obj else obj
    if isinstance(obj, list):
        return [_strip_nul(x) for x in obj]
    if isinstance(obj, dict):
        return {k: _strip_nul(v) for k, v in obj.items()}
    return obj


def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def _artifact(con, asset_id, kind, path: Path):
    con.execute("INSERT INTO raw_artifact(asset_id, kind, path, sha256, loaded_at) VALUES (?,?,?,?,?)",
                (asset_id, kind, str(path.resolve()), _sha256(path), dt.datetime.now().isoformat(timespec="seconds")))


def detect(path: Path) -> str:
    head = path.read_bytes()[:4096].decode("utf-8", "replace").lstrip("﻿")
    if "@@@SURVEY:" in head:
        return "linux"
    if head.lstrip().startswith("{"):
        data = json.loads(path.read_text(encoding="utf-8-sig"))
        if data.get("meta", {}).get("collector", "").startswith("windows_collect"):
            return "windows"
        if "Results" in data and "ArtifactName" in data:
            return "trivy"
        raise ValueError(f"{path}: неизвестный JSON")
    if "<nmaprun" in head:
        return "nmap"
    if "<report" in head or "<get_reports_response" in head:
        return "openvas"
    if re.search(r"^(hostname|sysname) ", head, re.M) or "Software Version" in head or re.search(r"^version \d", head, re.M):
        return "netdev"
    raise ValueError(f"{path}: не удалось определить тип файла")


def ingest_file(con: sqlite3.Connection, path: Path) -> tuple[str, int | None]:
    kind = detect(path)
    asset_id = {"linux": ingest_linux, "windows": ingest_windows, "nmap": ingest_nmap,
                "openvas": ingest_openvas, "trivy": ingest_trivy, "netdev": ingest_netdev}[kind](con, path)
    con.commit()
    return kind, asset_id


# ============================================================================ Linux
def parse_sections(text: str) -> dict[str, str]:
    sections, name, buf = {}, None, []
    for line in text.splitlines():
        m = re.match(r"^@@@SURVEY:([a-z0-9_]+)@@@$", line)
        if m:
            if name:
                sections[name] = "\n".join(buf).strip("\n")
            name, buf = m.group(1), []
        elif name:
            buf.append(line)
    if name:
        sections[name] = "\n".join(buf).strip("\n")
    return sections


def _kv(text: str, sep: str = "=", lower_keys=False) -> dict:
    out = {}
    for line in (text or "").splitlines():
        if sep in line:
            k, v = line.split(sep, 1)
            k = k.strip()
            out[k.lower() if lower_keys else k] = v.strip().strip('"')
    return out


def _ws_kv(text: str, lower=True) -> dict:
    out = {}
    for line in (text or "").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split(None, 1)
        k = parts[0].lower() if lower else parts[0]
        if k not in out:              # sshd: действует первое вхождение
            out[k] = parts[1].strip() if len(parts) > 1 else ""
    return out


def _pam_args(pam_text: str, module: str) -> dict:
    args = {}
    for line in (pam_text or "").splitlines():
        if module in line:
            for tok in line.split():
                if "=" in tok:
                    k, v = tok.split("=", 1)
                    args[k] = v
                elif tok in ("enforce_for_root", "even_deny_root", "use_authtok"):
                    args[tok] = "1"
    return args


def linux_facts(sec: dict[str, str]) -> dict:
    facts: dict = {}
    meta = _kv(sec.get("meta"))
    facts["is_root"] = meta.get("uid") == "0" if meta.get("uid") else None
    facts["collection_status"] = _kv(sec.get("collection_status"))
    facts["os_release"] = _kv(sec.get("os_release"))
    facts["sysctl"] = _kv(sec.get("sysctl"), " = ") or _kv(sec.get("sysctl"))
    cmdline = (sec.get("cmdline") or "").strip()
    facts["cmdline"] = cmdline
    facts["cmdline_params"] = {t.split("=", 1)[0]: (t.split("=", 1)[1] if "=" in t else "1") for t in cmdline.split()}
    sshd_eff = _ws_kv(sec.get("sshd_effective"))
    facts["sshd_source"] = "sshd -T" if sshd_eff else "sshd_config"
    sshd = sshd_eff or _ws_kv(sec.get("sshd_config"))
    # файл прочитан, но директив нет -> действуют умолчания OpenSSH ({}); файла нет -> нет данных (None)
    sshd_present = bool(sshd_eff) or bool((sec.get("sshd_config") or "").strip())
    facts["sshd"] = {k: v.lower() for k, v in sshd.items()} if sshd_present else None
    facts["login_defs"] = _ws_kv(sec.get("login_defs"), lower=False)
    pam = sec.get("pam", "")
    facts["pam"] = pam
    pwq = _kv(sec.get("pwquality"))
    pwq.update(_pam_args(pam, "pam_pwquality") or _pam_args(pam, "pam_cracklib"))
    facts["pwquality"] = pwq
    fl = _kv(sec.get("faillock"))
    fl.update(_pam_args(pam, "pam_faillock") or _pam_args(pam, "pam_tally"))
    facts["faillock"] = fl
    facts["su_wheel"] = bool(re.search(r"^auth\s+required\s+pam_wheel\.so", _pam_section(pam, "/etc/pam.d/su"), re.M))
    users = []
    for line in (sec.get("passwd") or "").splitlines():
        p = line.split(":")
        if len(p) >= 3 and p[1].isdigit():
            users.append({"name": p[0], "uid": int(p[1]), "shell": p[2]})
    facts["uid0_users"] = [u["name"] for u in users if u["uid"] == 0]
    facts["login_users"] = [u["name"] for u in users
                            if not re.search(r"(nologin|false|sync|shutdown|halt)$", u["shell"] or "")]
    se = sec.get("shadow_empty", "")
    facts["empty_password_users"] = None if "#noaccess" in se else [x for x in se.split() if x]
    sn = sec.get("sudoers_nopasswd", "")
    facts["sudo_nopasswd"] = None if "#noaccess" in sn else [x for x in sn.splitlines() if x.strip()]
    modes = {}
    for line in (sec.get("file_modes") or "").splitlines():
        p = line.split("|")
        if len(p) == 4:
            modes[p[0]] = {"mode": p[1], "owner": p[2], "group": p[3]}
    facts["file_modes"] = modes
    facts["listening"] = _parse_ss(sec.get("listening", ""))
    facts["connections"] = _parse_ss_conn(sec.get("connections", ""))
    facts["nics"] = _parse_linux_interfaces(sec.get("ip_link", ""), sec.get("ip_addr", ""))
    facts["routes"] = _parse_linux_routes(sec.get("ip_route", ""))
    facts["dns"] = [p[1] for l in (sec.get("resolv_conf") or "").splitlines()
                    if len(p := l.split()) > 1 and p[0] == "nameserver"]
    facts["services_enabled"] = [l.split()[0] for l in (sec.get("services_enabled") or "").splitlines() if l.strip()]
    facts["services_active"] = _kv(sec.get("services_active"))
    facts["audit_rules"] = [l for l in (sec.get("audit_rules") or "").splitlines() if l and l != "No rules"]
    facts["astra"] = _kv(sec.get("astra_security"))
    mounts = {}
    for line in (sec.get("mounts") or "").splitlines():
        p = line.split()
        if len(p) >= 4:
            mounts[p[1]] = {"fs": p[2], "options": p[3].split(",")}
    facts["mounts"] = mounts
    return facts


def _pam_section(pam: str, fname: str) -> str:
    m = re.search(rf"^### {re.escape(fname)}\n(.*?)(?=^### |\Z)", pam or "", re.M | re.S)
    return m.group(1) if m else ""


def _parse_ss(text: str) -> list[dict]:
    out = []
    for line in text.splitlines():
        p = line.split()
        if len(p) < 5 or p[0] not in ("tcp", "udp", "tcp6", "udp6"):
            continue
        # ss: proto state recv send local peer; netstat: proto recv send local peer state pid/name.
        local = p[3] if p[1].isdigit() else p[4]
        addr, _, port = local.rpartition(":")
        if not port:
            continue
        out.append({"proto": p[0].rstrip("6"), "address": addr.strip("[]"), "port": int(port) if port.isdigit() else port,
                    "process": _socket_process(line)})
    return out


def _parse_ss_conn(text: str) -> list[dict]:
    """Установленные соединения из `ss -tnp state established` (локальный+удалённый адрес:порт)."""
    out = []
    for line in text.splitlines():
        p = line.split()
        if not p:
            continue
        if p[0] in ("tcp", "udp", "tcp6", "udp6"):
            offset = 3 if len(p) > 1 and p[1].isdigit() else 4
            if offset == 3 and (len(p) < 6 or p[5] != "ESTABLISHED"):
                continue
        elif p[0].isdigit():  # ss с фильтром state: без Netid и State
            offset = 2
        elif p[0] in ("ESTAB", "ESTABLISHED"):
            offset = 3
        else:
            continue
        if len(p) < offset + 2:
            continue
        laddr, _, lport = p[offset].rpartition(":")
        raddr, _, rport = p[offset + 1].rpartition(":")
        if not lport or not rport:
            continue
        out.append({"local_address": laddr.strip("[]"), "local_port": int(lport) if lport.isdigit() else lport,
                    "remote_address": raddr.strip("[]"), "remote_port": int(rport) if rport.isdigit() else rport,
                    "process": _socket_process(line)})
    return out


def _socket_process(line: str) -> str | None:
    proc = re.search(r'users:\(\("([^"]+)"', line)
    if proc:
        return proc.group(1)
    proc = re.search(r"\b\d+/([^\s]+)", line)
    return proc.group(1) if proc else None


def _parse_linux_links(text: str) -> dict[str, str | None]:
    """ifname -> MAC из `ip -o link show`."""
    macs = {}
    for line in text.splitlines():
        m = re.match(r"^\d+:\s+(\S+?)(@\S+)?:\s+<", line)
        mac = re.search(r"link/\S+\s+([0-9a-fA-F:]{17})", line)
        if m:
            macs[m.group(1)] = mac.group(1) if mac else None
    return macs


def _parse_linux_interfaces(link_text: str, addr_text: str) -> list[dict]:
    """Сетевые интерфейсы из `ip -o link show` + `ip -o addr show`."""
    macs = _parse_linux_links(link_text)
    addrs: dict[str, list[dict]] = {}
    for line in addr_text.splitlines():
        m = re.match(r"^\d+:\s+(\S+?)(@\S+)?\s+inet6?\s+(\S+)/(\d+)", line)
        if m:
            name, _, ip, prefix = m.groups()
            addrs.setdefault(name, []).append({"ip": ip, "prefix": int(prefix)})
    # Запасной путь коллектора: ifconfig (net-tools старого и нового формата).
    current = None
    for line in addr_text.splitlines():
        if line and not line[0].isspace() and not re.match(r"^\d+:", line):
            current = line.split()[0].rstrip(":")
            addrs.setdefault(current, [])
        if current is None:
            continue
        mac = re.search(r"(?:ether|HWaddr)\s+([0-9a-fA-F:]{17})", line)
        if mac:
            macs[current] = mac.group(1)
        addr = re.search(r"\binet6?\s+(?:addr:\s*)?([0-9a-fA-F:.]+)(?:/(\d+))?", line)
        if not addr:
            continue
        ip, prefix = addr.groups()
        mask = re.search(r"(?:netmask\s+|Mask:)([0-9a-fA-F.x]+)", line)
        if prefix is None and ":" not in ip and mask:
            try:
                value = mask.group(1)
                if value.startswith("0x"):
                    value = str(ipaddress.IPv4Address(int(value, 16)))
                prefix = str(ipaddress.IPv4Network(f"0.0.0.0/{value}").prefixlen)
            except ValueError:
                pass
        if prefix is None:
            length = re.search(r"\bprefixlen\s+(\d+)", line)
            prefix = length.group(1) if length else None
        addrs[current].append({"ip": ip, "prefix": int(prefix) if prefix is not None else None})
    names = sorted(set(macs) | set(addrs))
    return [{"name": n, "mac": macs.get(n), "addresses": addrs.get(n, [])} for n in names]


def _parse_linux_routes(text: str) -> list[dict]:
    """Таблица маршрутизации из `ip -o route show`."""
    out = []
    for line in text.splitlines():
        p = line.split()
        if not p or p[0] in ("Kernel", "Destination"):
            continue
        if len(p) >= 8 and re.fullmatch(r"[0-9.]+", p[0]) and re.fullmatch(r"[0-9.]+", p[2]):
            try:
                destination = str(ipaddress.IPv4Network(f"{p[0]}/{p[2]}", strict=False))
            except ValueError:
                continue
            out.append({"destination": destination, "gateway": None if p[1] == "0.0.0.0" else p[1],
                        "interface": p[7], "metric": p[4]})
            continue
        def after(key):
            i = p.index(key) + 1 if key in p else len(p)
            return p[i] if i < len(p) else None
        destination = p[1] if p[0] in ("blackhole", "unreachable", "prohibit", "throw") and len(p) > 1 else p[0]
        if destination != "default":
            try:
                ipaddress.ip_network(destination, strict=False)
            except ValueError:
                continue
        out.append({"destination": destination, "gateway": after("via"), "interface": after("dev"),
                    "metric": after("metric")})
    return out


def ingest_linux(con, path: Path) -> int:
    sec = parse_sections(path.read_text(encoding="utf-8", errors="replace"))
    facts = linux_facts(sec)
    osr = facts["os_release"]
    names = [l.strip() for l in (sec.get("hostname") or "").splitlines() if l.strip()]
    ips = [addr["ip"] for nic in facts["nics"] for addr in nic["addresses"]]
    uname = (sec.get("uname") or "").split()
    kernel = uname[1] if len(uname) > 1 else None
    os_id = osr.get("ID", "linux")
    os_version = osr.get("VERSION_ID")
    astra_ver = (sec.get("astra_version") or "").splitlines()
    if os_id.startswith("astra") and astra_ver:
        os_version = astra_ver[0].strip()
    meta = _kv(sec.get("meta"))
    asset_id = find_or_create_asset(
        con, hostname=names[0] if names else None, ips=ips, kind="host",
        fqdn=names[1] if len(names) > 1 else None, os_family="linux", os_id=os_id, os_version=os_version,
        os_pretty=osr.get("PRETTY_NAME"), kernel=kernel, platform="linux",
        source="linux_collect.sh", collected_at=meta.get("collected_at"),
        facts=json.dumps(facts, ensure_ascii=False))
    con.execute("DELETE FROM software WHERE asset_id=?", (asset_id,))
    rows = []
    for line in (sec.get("packages_dpkg") or "").splitlines():
        p = line.split("\t")
        if len(p) >= 4 and p[3].startswith("ii"):
            rows.append((asset_id, p[0], p[1], upstream_of(p[1], "deb"), "deb", None, p[2]))
    for line in (sec.get("packages_rpm") or "").splitlines():
        p = line.split("\t")
        if len(p) >= 3:
            ver = p[1].replace("(none):", "")
            rows.append((asset_id, p[0], ver, upstream_of(ver, "rpm"), "rpm", p[3] if len(p) > 3 else None, p[2]))
    if kernel:
        rows.append((asset_id, "linux-kernel", kernel, upstream_of(kernel, "kernel"), "kernel", None, None))
    con.executemany("INSERT INTO software(asset_id,name,version,upstream,ecosystem,vendor,arch) VALUES (?,?,?,?,?,?,?)", rows)
    apply_role_guess(con, asset_id)
    _artifact(con, asset_id, "linux_collect", path)
    return asset_id


# ============================================================================ Windows
def ingest_windows(con, path: Path) -> int:
    data = _strip_nul(json.loads(path.read_text(encoding="utf-8-sig")))
    host, os_ = data.get("host", {}), data.get("os", {})
    ips = host.get("ips") or []
    if isinstance(ips, str):
        ips = [ips]
    facts = dict(data.get("facts", {}))
    facts["os"] = os_
    facts["is_admin"] = data.get("meta", {}).get("is_admin")
    build = f"{os_.get('version', '')}.{os_.get('ubr') or 0}"
    asset_id = find_or_create_asset(
        con, hostname=host.get("hostname"), ips=ips, kind="host", fqdn=host.get("fqdn"),
        os_family="windows", os_id="windows", os_version=os_.get("display_version"),
        os_pretty=os_.get("caption"), os_build=build, platform="windows",
        source="windows_collect.ps1", collected_at=data.get("meta", {}).get("collected_at"),
        facts=json.dumps(facts, ensure_ascii=False))
    con.execute("DELETE FROM software WHERE asset_id=?", (asset_id,))
    con.execute("DELETE FROM hotfix WHERE asset_id=?", (asset_id,))
    con.executemany("INSERT INTO software(asset_id,name,version,upstream,ecosystem,vendor,arch) VALUES (?,?,?,?,?,?,?)",
                    [(asset_id, s["name"], s.get("version") or "", upstream_of(s.get("version") or "", "win"), "win",
                      s.get("vendor"), None) for s in data.get("software") or []])
    con.executemany("INSERT INTO hotfix VALUES (?,?)",
                    [(asset_id, (h.get("id") or "").upper().replace("KB", "")) for h in data.get("hotfixes") or []])
    apply_role_guess(con, asset_id)
    _artifact(con, asset_id, "windows_collect", path)
    return asset_id


# ============================================================================ Nmap
def ingest_nmap(con, path: Path) -> None:
    root = etree.parse(str(path)).getroot()
    for h in root.iterfind("host"):
        st = h.find("status")
        if st is not None and st.get("state") != "up":
            continue
        ips = [a.get("addr") for a in h.iterfind("address") if a.get("addrtype") in ("ipv4", "ipv6")]
        hn = h.find("hostnames/hostname")
        osm = h.find("os/osmatch")
        asset_id = find_or_create_asset(con, hostname=hn.get("name") if hn is not None else None, ips=ips,
                                        kind="host", os_pretty=osm.get("name") if osm is not None else None)
        con.execute("DELETE FROM service WHERE asset_id=? AND source='nmap'", (asset_id,))
        for p in h.iterfind("ports/port"):
            state = p.find("state")
            if state is None or state.get("state") != "open":
                continue
            s = p.find("service")
            cpe = s.find("cpe") if s is not None else None
            con.execute("INSERT INTO service(asset_id,proto,port,name,product,version,extrainfo,cpe,source) "
                        "VALUES (?,?,?,?,?,?,?,?, 'nmap')",
                        (asset_id, p.get("protocol"), int(p.get("portid")),
                         s.get("name") if s is not None else None,
                         s.get("product") if s is not None else None,
                         s.get("version") if s is not None else None,
                         s.get("extrainfo") if s is not None else None,
                         cpe.text if cpe is not None else None))
        apply_role_guess(con, asset_id)        # роль-подсказка по открытым портам/баннерам
        _artifact(con, asset_id, "nmap", path)


# ============================================================================ OpenVAS / Greenbone
def ingest_openvas(con, path: Path) -> None:
    root = etree.parse(str(path)).getroot()
    seen_assets = set()
    for r in root.iter("result"):
        host_el = r.find("host")
        if host_el is None:
            continue
        ip = (host_el.text or "").strip()
        hn = host_el.findtext("hostname")
        asset_id = find_or_create_asset(con, hostname=hn or None, ips=[ip], kind="host")
        if asset_id not in seen_assets:
            con.execute("DELETE FROM scanner_finding WHERE asset_id=? AND source='openvas'", (asset_id,))
            seen_assets.add(asset_id)
        nvt = r.find("nvt")
        cves = []
        if nvt is not None:
            cves = [ref.get("id") for ref in nvt.iterfind("refs/ref") if (ref.get("type") or "").lower() == "cve"]
            if not cves and nvt.findtext("cve"):        # старый формат GMP
                cves = [c.strip() for c in nvt.findtext("cve").split(",") if c.strip().startswith("CVE")]
        sev = r.findtext("severity")
        con.execute("INSERT INTO scanner_finding(asset_id,source,port,title,cves,severity,score,details) "
                    "VALUES (?, 'openvas', ?, ?, ?, ?, ?, ?)",
                    (asset_id, r.findtext("port"), (nvt.findtext("name") if nvt is not None else r.findtext("name")),
                     json.dumps(cves), r.findtext("threat"), float(sev) if sev else None,
                     json.dumps({"oid": nvt.get("oid") if nvt is not None else None}, ensure_ascii=False)))
    for a in seen_assets:
        apply_role_guess(con, a)               # роль-подсказка по заголовкам находок сканера
        _artifact(con, a, "openvas", path)


# ============================================================================ Trivy
def ingest_trivy(con, path: Path) -> int:
    data = json.loads(path.read_text(encoding="utf-8"))
    asset_id = find_or_create_asset(con, hostname=data.get("ArtifactName"), kind="image", platform="container",
                                    source="trivy")
    con.execute("DELETE FROM scanner_finding WHERE asset_id=? AND source='trivy'", (asset_id,))
    for res in data.get("Results") or []:
        for v in res.get("Vulnerabilities") or []:
            con.execute("INSERT INTO scanner_finding(asset_id,source,port,title,cves,severity,score,details) "
                        "VALUES (?, 'trivy', ?, ?, ?, ?, NULL, ?)",
                        (asset_id, res.get("Target"), f"{v.get('PkgName')} {v.get('InstalledVersion')}: {v.get('Title') or ''}",
                         json.dumps([v.get("VulnerabilityID")]), v.get("Severity"),
                         json.dumps({"fixed": v.get("FixedVersion")}, ensure_ascii=False)))
    apply_role_guess(con, asset_id)
    _artifact(con, asset_id, "trivy", path)
    return asset_id


# ============================================================================ Сетевое оборудование

_NEIGHBOR_DESC_RE = re.compile(r"\bto\s+([\w.\-/]+)\s*$", re.I)


def _neighbor_from_description(desc: str | None) -> str | None:
    """Эвристика: сосед по L2 из текста description интерфейса (напр. 'Uplink to SW2')."""
    if not desc:
        return None
    m = _NEIGHBOR_DESC_RE.search(desc.strip())
    return m.group(1) if m else None


def _expand_vlans_cisco(s: str) -> list[int]:
    """'10,20,30-40' -> [10,20,30,...,40] (Cisco switchport trunk allowed vlan)."""
    out: list[int] = []
    for tok in s.split(","):
        tok = tok.strip()
        if not tok:
            continue
        if "-" in tok:
            a, b = tok.split("-", 1)
            if a.strip().isdigit() and b.strip().isdigit():
                out.extend(range(int(a), int(b) + 1))
        elif tok.isdigit():
            out.append(int(tok))
    return out


def _expand_vlans_vrp(s: str) -> list[int]:
    """'10 20 to 30' -> [10,20,...,30] (Huawei port trunk allow-pass vlan)."""
    toks = s.split()
    out: list[int] = []
    i = 0
    while i < len(toks):
        if toks[i].lower() == "to" and out and i + 1 < len(toks) and toks[i + 1].isdigit():
            out.extend(range(out[-1] + 1, int(toks[i + 1]) + 1))
            i += 2
            continue
        if toks[i].isdigit():
            out.append(int(toks[i]))
        i += 1
    return out


def _parse_netdev_interfaces(text: str, platform: str) -> tuple[list[dict], list[dict]]:
    """Разобрать конфиг на interfaces (имя/IP/VLAN access-trunk) и L2-соседей из description.

    Возвращает (interfaces, neighbors); neighbors — потенциальные L2-связи вида
    {"local_if": ..., "remote": ..., "source": "description"}, без опроса устройства.
    """
    vrp = platform == "huawei_vrp"
    end_markers = ("#",) if vrp else ("!", "end")
    interfaces: list[dict] = []
    cur: dict | None = None

    def close():
        if cur is not None:
            interfaces.append(cur)

    for raw in text.splitlines():
        if raw.startswith("interface "):
            close()
            cur = {"name": raw.split(None, 1)[1].strip(), "ip": None, "mask": None, "mode": None,
                   "vlan": None, "allowed_vlans": [], "description": None}
            continue
        if cur is None:
            continue
        ls = raw.strip()
        if ls in end_markers:
            close()
            cur = None
            continue
        m = re.match(r"^description (.+)$", ls)
        if m:
            cur["description"] = m.group(1).strip()
            continue
        m = re.match(r"^ip address (\d+\.\d+\.\d+\.\d+) (\d+\.\d+\.\d+\.\d+)", ls)
        if m:
            cur["ip"], cur["mask"] = m.group(1), m.group(2)
            continue
        if vrp:
            if re.match(r"^port link-type trunk", ls):
                cur["mode"] = "trunk"
            elif re.match(r"^port link-type access", ls):
                cur["mode"] = "access"
            elif (m := re.match(r"^port default vlan (\d+)", ls)):
                cur["vlan"] = int(m.group(1))
            elif (m := re.match(r"^port trunk allow-pass vlan (.+)$", ls)):
                cur["allowed_vlans"] = _expand_vlans_vrp(m.group(1))
        else:
            if re.match(r"^switchport mode trunk", ls):
                cur["mode"] = "trunk"
            elif re.match(r"^switchport mode access", ls):
                cur["mode"] = "access"
            elif (m := re.match(r"^switchport access vlan (\d+)", ls)):
                cur["vlan"] = int(m.group(1))
            elif (m := re.match(r"^switchport trunk allowed vlan add (\S+)", ls)):
                cur["allowed_vlans"] += _expand_vlans_cisco(m.group(1))
            elif (m := re.match(r"^switchport trunk allowed vlan (\S+)", ls)):
                cur["allowed_vlans"] = _expand_vlans_cisco(m.group(1))
    close()

    neighbors = []
    for iface in interfaces:
        remote = _neighbor_from_description(iface.get("description"))
        if remote:
            neighbors.append({"local_if": iface["name"], "remote": remote, "source": "description"})
    return interfaces, neighbors


def ingest_netdev(con, path: Path) -> int:
    text = path.read_text(encoding="utf-8", errors="replace")
    if re.search(r"^sysname ", text, re.M) or "Software Version V" in text:
        platform = "huawei_vrp"
        name = re.search(r"^sysname (\S+)", text, re.M)
        ver = re.search(r"Software Version (V\d+R\d+C\d+\S*)", text)
        pkg = "huawei-vrp"
    else:
        platform = "cisco_ios"
        name = re.search(r"^hostname (\S+)", text, re.M)
        ver = re.search(r"^version (\S+)", text, re.M)
        pkg = "cisco-ios"
    ips = re.findall(r"^\s*ip address (\d+\.\d+\.\d+\.\d+) ", text, re.M)
    interfaces, neighbors = _parse_netdev_interfaces(text, platform)
    hostname = name.group(1) if name else path.stem
    asset_id = find_or_create_asset(con, hostname=hostname, ips=ips, kind="netdev", platform=platform,
                                    os_family="netdev", os_id=platform, os_version=ver.group(1) if ver else None,
                                    source=path.name,
                                    facts=json.dumps({"config": text, "interfaces": interfaces,
                                                      "neighbors": neighbors}, ensure_ascii=False))
    con.execute("DELETE FROM software WHERE asset_id=?", (asset_id,))
    if ver:
        con.execute("INSERT INTO software(asset_id,name,version,upstream,ecosystem) VALUES (?,?,?,?, 'firmware')",
                    (asset_id, pkg, ver.group(1), ver.group(1)))
    apply_role_guess(con, asset_id)            # kind=netdev -> роль "netdev"
    _artifact(con, asset_id, "netdev_config", path)
    return asset_id
