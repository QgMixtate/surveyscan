"""Построение схемы сети из результатов инвентаризации.

L3-схема строится прямо из собранных активов (их IP-адресов и сервисов): хосты
группируются по подсетям /24, выделяются шлюзы/сетевые устройства, всё сходится к узлу
«Ядро сети». Формат вывода — узлы/связи (elements) для графа в вебе + статистика.

L2-связи (device↔port↔neighbor) добавляются отдельно из данных SNMP (LLDP/CDP/ARP),
когда они есть, через merge_l2().
"""
from __future__ import annotations

import ipaddress
import re


def _ipv4(ips) -> str | None:
    """Первый непетлевой IPv4 из строки/списка адресов."""
    if isinstance(ips, str):
        parts = re.split(r"[,;\s]+", ips)
    else:
        parts = list(ips or [])
    for p in parts:
        p = (p or "").strip()
        if not p:
            continue
        try:
            ip = ipaddress.ip_address(p)
        except ValueError:
            continue
        if ip.version == 4 and not ip.is_loopback and not ip.is_link_local:
            return str(ip)
    return None


def _subnet(ip: str, prefix: int = 24) -> str:
    return str(ipaddress.ip_network(f"{ip}/{prefix}", strict=False))


def _is_device(a: dict, ip: str | None) -> bool:
    """Похоже на сетевое устройство (роутер/коммутатор): по типу, ОС или адресу-шлюзу."""
    kind = (a.get("kind") or "").lower()
    if "сетев" in kind or kind == "netdev":
        return True
    os = (a.get("os") or "").lower()
    if any(t in os for t in ("cisco", "huawei", "mikrotik", "juniper", "router", "switch", "vrp", "ios")):
        return True
    return bool(ip) and ip.rsplit(".", 1)[-1] == "1"        # .1 — обычно шлюз


def _nid(prefix: str, key: str) -> str:
    return prefix + ":" + re.sub(r"[^A-Za-z0-9_.:/-]", "_", str(key))


def build(assets: list[dict], prefix: int = 24) -> dict:
    """assets — список активов (name, ips, os, kind, services, software...). -> {elements, stats}."""
    nodes: dict[str, dict] = {}
    edges: list[dict] = []
    core = "core"
    nodes[core] = {"data": {"id": core, "label": "Ядро сети", "type": "core"}}

    subnets: dict[str, dict] = {}        # subnet -> {router: node_id|None, members: []}

    def subnet_node(sn: str) -> str:
        sid = _nid("net", sn)
        if sid not in nodes:
            nodes[sid] = {"data": {"id": sid, "label": sn, "type": "subnet"}}
            subnets[sn] = {"router": None, "id": sid}
        return sid

    n_hosts = n_dev = n_services = 0
    for a in assets:
        ip = _ipv4(a.get("ips"))
        sn = _subnet(ip, prefix) if ip else "без IP"
        sid = subnet_node(sn) if ip else subnet_node_noip(nodes, subnets)
        dev = _is_device(a, ip)
        svc = a.get("services") or []
        n_services += len(svc)
        hid = _nid("dev" if dev else "host", a.get("name") or ip or id(a))
        nodes[hid] = {"data": {
            "id": hid, "label": a.get("name") or ip or "актив",
            "type": "device" if dev else "host",
            "ip": ip or "", "os": a.get("os") or "", "kind": a.get("kind") or "",
            "services": len(svc), "ports": ", ".join(str(s).split()[0] for s in svc[:8]),
        }}
        if dev:
            n_dev += 1
            edges.append({"data": {"id": f"e{len(edges)}", "source": hid, "target": sid}})
            if ip and subnets.get(sn) and subnets[sn]["router"] is None:
                subnets[sn]["router"] = hid      # устройство становится шлюзом подсети
        else:
            n_hosts += 1
            edges.append({"data": {"id": f"e{len(edges)}", "source": hid, "target": sid}})

    # связываем подсети с ядром — через шлюз, если он есть
    for sn, info in subnets.items():
        if info["router"]:
            edges.append({"data": {"id": f"e{len(edges)}", "source": info["router"], "target": core, "type": "uplink"}})
        else:
            edges.append({"data": {"id": f"e{len(edges)}", "source": info["id"], "target": core, "type": "uplink"}})

    stats = {"hosts": n_hosts, "devices": n_dev, "subnets": len(subnets), "services": n_services,
             "nodes": len(nodes), "edges": len(edges)}
    return {"elements": {"nodes": list(nodes.values()), "edges": edges}, "stats": stats}


def subnet_node_noip(nodes: dict, subnets: dict) -> str:
    sid = _nid("net", "без IP")
    if sid not in nodes:
        nodes[sid] = {"data": {"id": sid, "label": "Без IP", "type": "subnet"}}
        subnets["без IP"] = {"router": None, "id": sid}
    return sid


def _esc(s) -> str:
    return (str(s).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;"))


_SVG_COL = {"core": ("#3D4EA6", "#ffffff"), "subnet": ("#E8EAEF", "#44506a"),
            "device": ("#11141B", "#ffffff"), "host": ("#ffffff", "#16181D")}


def to_svg(topo: dict) -> str:
    """Статичная схема сети в SVG (слои: ядро → подсети → хосты). Для экспорта/отчётов."""
    nodes = {n["data"]["id"]: n["data"] for n in topo["elements"]["nodes"]}
    edges = topo["elements"]["edges"]
    subnets = [n for n in nodes.values() if n["type"] == "subnet"]
    members: dict[str, list] = {s["id"]: [] for s in subnets}
    for e in edges:
        d = e["data"]
        if d["target"] in members and nodes.get(d["source"], {}).get("type") in ("host", "device"):
            members[d["target"]].append(nodes[d["source"]])

    bw, bh, gapx, gapy = 150, 44, 40, 20
    colw = bw + gapx
    ncol = max(1, len(subnets))
    maxrows = max([len(m) for m in members.values()] + [1])
    W = max(640, ncol * colw + gapx)
    H = 120 + 120 + maxrows * (bh + gapy) + 40
    pos: dict[str, tuple] = {}
    cx = W / 2
    pos["core"] = (cx, 60)
    for i, s in enumerate(subnets):
        x = gapx + colw * i + bw / 2
        pos[s["id"]] = (x, 200)
        for j, m in enumerate(members[s["id"]]):
            pos[m["id"]] = (x, 320 + j * (bh + gapy))

    def box(nd):
        x, y = pos.get(nd["id"], (W / 2, H - 40))
        fill, tx = _SVG_COL.get(nd["type"], ("#fff", "#000"))
        w = bw if nd["type"] != "core" else 120
        s = f'<g><rect x="{x-w/2:.0f}" y="{y-bh/2:.0f}" width="{w}" height="{bh}" rx="7" fill="{fill}" stroke="#D7DBE4"/>'
        s += f'<text x="{x:.0f}" y="{y-2:.0f}" text-anchor="middle" font-size="12" font-weight="600" fill="{tx}" font-family="Inter,sans-serif">{_esc(nd["label"])[:22]}</text>'
        sub = nd.get("ip") or (nd.get("ports") if nd["type"] == "device" else "")
        if sub:
            s += f'<text x="{x:.0f}" y="{y+12:.0f}" text-anchor="middle" font-size="9.5" fill="{tx}" opacity="0.8" font-family="monospace">{_esc(sub)[:24]}</text>'
        return s + "</g>"

    svg = [f'<svg xmlns="http://www.w3.org/2000/svg" width="{W}" height="{H}" viewBox="0 0 {W} {H}" font-family="Inter,sans-serif">']
    svg.append(f'<rect width="{W}" height="{H}" fill="#F7F8FA"/>')
    for e in edges:                                        # связи под узлами
        s, t = pos.get(e["data"]["source"]), pos.get(e["data"]["target"])
        if s and t:
            dash = ' stroke-dasharray="4 3"' if e["data"].get("type") == "l2" else ""
            svg.append(f'<line x1="{s[0]:.0f}" y1="{s[1]:.0f}" x2="{t[0]:.0f}" y2="{t[1]:.0f}" stroke="#C4CAD4" stroke-width="1.4"{dash}/>')
    for nd in nodes.values():
        svg.append(box(nd))
    svg.append("</svg>")
    return "\n".join(svg)


def merge_l2(topo: dict, links: list[dict]) -> dict:
    """Добавить L2-связи из SNMP (LLDP/CDP): links = [{"a": nodeLabel, "b": nodeLabel, "ports": "Gi0/1↔Gi0/2"}]."""
    by_label = {n["data"]["label"]: n["data"]["id"] for n in topo["elements"]["nodes"]}
    e = topo["elements"]["edges"]
    for l in links or []:
        s, t = by_label.get(l.get("a")), by_label.get(l.get("b"))
        if s and t:
            e.append({"data": {"id": f"l2_{len(e)}", "source": s, "target": t,
                               "type": "l2", "label": l.get("ports", "")}})
    return topo
