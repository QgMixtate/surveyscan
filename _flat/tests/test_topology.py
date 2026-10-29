from surveyscan.topology import build, merge_l2


def test_l3_topology_groups_by_subnet_and_gateway():
    assets = [
        {"name": "core-sw1", "ips": "10.0.1.1", "kind": "Сетевое устройство", "os": "Cisco IOS 15.2", "services": ["22/tcp ssh"]},
        {"name": "srv-app", "ips": "10.0.1.11", "kind": "Хост", "os": "Astra 1.7", "services": ["22/tcp ssh", "80/tcp http"]},
        {"name": "srv-db", "ips": "10.0.1.12", "kind": "Хост", "os": "РЕД ОС 7.3", "services": ["5432/tcp postgres"]},
        {"name": "ws-1", "ips": "10.0.2.50", "kind": "Хост", "os": "Windows 10", "services": []},
    ]
    t = build(assets)
    st = t["stats"]
    assert st["subnets"] == 2 and st["hosts"] == 3 and st["devices"] == 1
    nodes = {n["data"]["id"]: n["data"] for n in t["elements"]["nodes"]}
    assert "core" in nodes
    # подсеть 10.0.1.0/24 присутствует
    assert any(n["type"] == "subnet" and n["label"] == "10.0.1.0/24" for n in nodes.values())
    # устройство помечено как device, хост как host
    assert any(n["type"] == "device" and n["label"] == "core-sw1" for n in nodes.values())
    assert any(n["type"] == "host" and n["label"] == "srv-app" for n in nodes.values())
    # есть связи и uplink к ядру
    assert any(e["data"].get("type") == "uplink" for e in t["elements"]["edges"])


def test_merge_l2_adds_links():
    assets = [{"name": "sw1", "ips": "10.0.1.1", "kind": "Сетевое устройство"},
              {"name": "sw2", "ips": "10.0.1.2", "kind": "Сетевое устройство"}]
    t = build(assets)
    merge_l2(t, [{"a": "sw1", "b": "sw2", "ports": "Gi0/1↔Gi0/2"}])
    assert any(e["data"].get("type") == "l2" for e in t["elements"]["edges"])


def test_host_without_ip_bucketed():
    t = build([{"name": "mystery", "ips": "", "kind": "Хост"}])
    assert any(n["data"]["label"] == "Без IP" for n in t["elements"]["nodes"])
