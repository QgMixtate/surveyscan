const {
  useState,
  useEffect,
  useRef,
  useCallback
} = React;
const api = (p, opts) => fetch(p, opts).then(r => r.ok ? r.json() : r.json().then(e => Promise.reject(e)));

/* ----------------------------------------------------------------- Новое сканирование */
const CRED_KIND = {
  ssh: "SSH · Linux",
  winrm: "WinRM · Windows",
  snmp: "SNMP · оборуд."
};
function NewScan({
  onRun,
  busy,
  go,
  savedCreds,
  initTargets,
  initCreds
}) {
  const [targets, setTargets] = useState(initTargets || "");
  const [sel, setSel] = useState(initCreds || []);
  const toggle = id => setSel(s => s.includes(id) ? s.filter(x => x !== id) : [...s, id]);
  return /*#__PURE__*/React.createElement("div", null, /*#__PURE__*/React.createElement("h1", {
    className: "h1"
  }, "Новое сканирование"), /*#__PURE__*/React.createElement("p", {
    className: "sub"
  }, "Укажите подсети и хосты. Сбор — сетевой (nmap): живые хосты, порты, версии сервисов, ОС → схема сети. Выберите учётные записи — сканер подключится к активам (SSH/WinRM/SNMP) и соберёт полный инвентарь; к каждому активу УЗ подбирается автоматически."), /*#__PURE__*/React.createElement("div", {
    className: "card",
    style: {
      maxWidth: 820
    }
  }, /*#__PURE__*/React.createElement("div", {
    className: "cb"
  }, /*#__PURE__*/React.createElement("div", {
    className: "field"
  }, /*#__PURE__*/React.createElement("label", null, "Цели: подсети / хосты"), /*#__PURE__*/React.createElement("textarea", {
    rows: "4",
    value: targets,
    onChange: e => setTargets(e.target.value),
    placeholder: "10.0.0.0/24, 10.0.1.5\nsrv01.corp",
    style: {
      fontFamily: "JetBrains Mono, monospace",
      fontSize: 13
    }
  }), /*#__PURE__*/React.createElement("div", {
    className: "sub2"
  }, "Через запятую, пробел или с новой строки. Примеры: ", /*#__PURE__*/React.createElement("span", {
    className: "mono"
  }, "192.168.1.0/24"), ", ", /*#__PURE__*/React.createElement("span", {
    className: "mono"
  }, "10.0.0.5"))), /*#__PURE__*/React.createElement("div", {
    className: "field",
    style: {
      marginTop: 18
    }
  }, /*#__PURE__*/React.createElement("div", {
    style: {
      display: "flex",
      alignItems: "center"
    }
  }, /*#__PURE__*/React.createElement("label", {
    style: {
      margin: 0
    }
  }, "Учётные записи для сбора ", /*#__PURE__*/React.createElement("span", {
    className: "sub2",
    style: {
      fontWeight: 400
    }
  }, "(опционально — без них только сетевое обнаружение)")), /*#__PURE__*/React.createElement("span", {
    className: "more",
    style: {
      marginLeft: "auto"
    },
    onClick: () => go({
      view: "creds"
    })
  }, "Управление УЗ →")), !savedCreds || savedCreds.length === 0 ? /*#__PURE__*/React.createElement("div", {
    className: "sub2",
    style: {
      margin: "8px 0"
    }
  }, "Сохранённых УЗ нет. ", /*#__PURE__*/React.createElement("span", {
    className: "link",
    onClick: () => go({
      view: "creds"
    })
  }, "Добавьте учётную запись"), " во вкладке «Учётные записи» — затем выбирайте её здесь.") : /*#__PURE__*/React.createElement("div", {
    className: "credpick"
  }, savedCreds.map(c => /*#__PURE__*/React.createElement("label", {
    className: "credopt" + (sel.includes(c.id) ? " on" : ""),
    key: c.id
  }, /*#__PURE__*/React.createElement("input", {
    type: "checkbox",
    checked: sel.includes(c.id),
    onChange: () => toggle(c.id)
  }), /*#__PURE__*/React.createElement("span", {
    className: "cn"
  }, c.name), /*#__PURE__*/React.createElement("span", {
    className: "ct"
  }, CRED_KIND[c.type] || c.type), /*#__PURE__*/React.createElement("span", {
    className: "cu mono"
  }, c.type === "snmp" ? "community" : c.username || "—", c.port ? ":" + c.port : ""))))), /*#__PURE__*/React.createElement("div", {
    style: {
      display: "flex",
      gap: 10,
      marginTop: 18
    }
  }, /*#__PURE__*/React.createElement("button", {
    className: "btn",
    disabled: busy || !targets.trim(),
    onClick: () => onRun(targets, sel)
  }, busy ? "Запуск…" : "Запустить скан"), /*#__PURE__*/React.createElement("button", {
    className: "btn ghost",
    onClick: () => go({
      view: "dash"
    })
  }, "Отмена")))), /*#__PURE__*/React.createElement("div", {
    className: "warn",
    style: {
      maxWidth: 820,
      marginTop: 14
    }
  }, "Секреты хранятся в базе в зашифрованном виде (ключ — в переменной окружения, не в БД) и расшифровываются только на время задачи. К каждому активу применяется подходящая по типу УЗ (перебор до первой успешной); в сводке фиксируется только логин."));
}
function Credentials({
  onChange
}) {
  const [list, setList] = useState([]);
  const [f, setF] = useState({
    name: "",
    type: "ssh",
    username: "",
    secret: "",
    domain: "",
    port: ""
  });
  const [err, setErr] = useState("");
  const refresh = () => api("/credentials").then(setList).catch(() => {});
  useEffect(() => {
    refresh();
  }, []);
  const setFF = (k, v) => setF(p => ({
    ...p,
    [k]: v
  }));
  const add = async () => {
    setErr("");
    const body = {
      name: f.name,
      type: f.type,
      username: f.type === "snmp" ? null : f.username,
      secret: f.secret,
      domain: f.domain || null,
      port: f.port ? parseInt(f.port, 10) : null
    };
    try {
      await api("/credentials", {
        method: "POST",
        headers: {
          "Content-Type": "application/json"
        },
        body: JSON.stringify(body)
      });
      setF({
        name: "",
        type: "ssh",
        username: "",
        secret: "",
        domain: "",
        port: ""
      });
      refresh();
      onChange && onChange();
    } catch (e) {
      setErr(e && e.detail ? e.detail : "не удалось сохранить");
    }
  };
  const del = async id => {
    await fetch("/credentials/" + id, {
      method: "DELETE"
    });
    refresh();
    onChange && onChange();
  };
  return /*#__PURE__*/React.createElement("div", null, /*#__PURE__*/React.createElement("h1", {
    className: "h1"
  }, "Учётные записи"), /*#__PURE__*/React.createElement("p", {
    className: "sub"
  }, "Хранилище УЗ для аутентифицированного сбора. Заводятся один раз — затем выбираются в форме скана. Секреты шифруются в БД (ключ в переменной окружения, не в базе)."), /*#__PURE__*/React.createElement("div", {
    className: "card",
    style: {
      marginBottom: 16,
      maxWidth: 820
    }
  }, /*#__PURE__*/React.createElement("div", {
    className: "cb"
  }, /*#__PURE__*/React.createElement("div", {
    className: "credrow"
  }, /*#__PURE__*/React.createElement("input", {
    placeholder: "Имя: Linux-аудит",
    value: f.name,
    style: {
      flex: 1.4
    },
    onChange: e => setFF("name", e.target.value)
  }), /*#__PURE__*/React.createElement("select", {
    value: f.type,
    onChange: e => setFF("type", e.target.value)
  }, /*#__PURE__*/React.createElement("option", {
    value: "ssh"
  }, "SSH · Linux"), /*#__PURE__*/React.createElement("option", {
    value: "winrm"
  }, "WinRM · Windows"), /*#__PURE__*/React.createElement("option", {
    value: "snmp"
  }, "SNMP · оборуд.")), /*#__PURE__*/React.createElement("input", {
    placeholder: f.type === "snmp" ? "— (не нужно)" : "логин",
    value: f.username,
    disabled: f.type === "snmp",
    onChange: e => setFF("username", e.target.value)
  }), /*#__PURE__*/React.createElement("input", {
    type: "password",
    placeholder: f.type === "snmp" ? "community" : "пароль / ключ",
    value: f.secret,
    autoComplete: "new-password",
    onChange: e => setFF("secret", e.target.value)
  }), f.type === "winrm" ? /*#__PURE__*/React.createElement("input", {
    placeholder: "домен",
    value: f.domain,
    style: {
      width: 90
    },
    onChange: e => setFF("domain", e.target.value)
  }) : null, /*#__PURE__*/React.createElement("input", {
    placeholder: "порт",
    value: f.port,
    style: {
      width: 64
    },
    onChange: e => setFF("port", e.target.value)
  }), /*#__PURE__*/React.createElement("button", {
    className: "btn sm",
    onClick: add
  }, "Сохранить")), err ? /*#__PURE__*/React.createElement("div", {
    className: "sub2",
    style: {
      color: "var(--crit,#b4232a)",
      marginTop: 8
    }
  }, err) : null)), /*#__PURE__*/React.createElement("div", {
    className: "card",
    style: {
      maxWidth: 820
    }
  }, /*#__PURE__*/React.createElement("div", {
    className: "cb"
  }, /*#__PURE__*/React.createElement("table", null, /*#__PURE__*/React.createElement("thead", null, /*#__PURE__*/React.createElement("tr", null, /*#__PURE__*/React.createElement("th", null, "Имя"), /*#__PURE__*/React.createElement("th", null, "Тип"), /*#__PURE__*/React.createElement("th", null, "Логин / порт"), /*#__PURE__*/React.createElement("th", null, "Добавлена"), /*#__PURE__*/React.createElement("th", null))), /*#__PURE__*/React.createElement("tbody", null, list.map(c => /*#__PURE__*/React.createElement("tr", {
    key: c.id
  }, /*#__PURE__*/React.createElement("td", null, /*#__PURE__*/React.createElement("b", null, c.name)), /*#__PURE__*/React.createElement("td", null, CRED_KIND[c.type] || c.type), /*#__PURE__*/React.createElement("td", {
    className: "mono sub2"
  }, c.type === "snmp" ? "community" : c.username || "—", c.port ? ":" + c.port : "", c.domain ? " · " + c.domain : ""), /*#__PURE__*/React.createElement("td", {
    className: "sub2"
  }, c.created_at ? c.created_at.replace("T", " ").slice(0, 16) : ""), /*#__PURE__*/React.createElement("td", {
    style: {
      textAlign: "right"
    }
  }, /*#__PURE__*/React.createElement("button", {
    className: "xbtn",
    title: "Удалить",
    onClick: () => del(c.id)
  }, "✕")))), list.length === 0 && /*#__PURE__*/React.createElement("tr", null, /*#__PURE__*/React.createElement("td", {
    colSpan: "5",
    className: "sub2"
  }, "УЗ не заведены. Добавьте первую выше.")))))), /*#__PURE__*/React.createElement("div", {
    className: "warn",
    style: {
      maxWidth: 820,
      marginTop: 14
    }
  }, "Пароли, ключи и community хранятся зашифрованными (Fernet). Мастер-ключ берётся из ", /*#__PURE__*/React.createElement("span", {
    className: "mono"
  }, "SURVEYSCAN_SECRET_KEY"), " и в базе не лежит — дамп БД сам по себе секреты не раскроет. Задайте эту переменную в своём окружении (иначе ключ генерируется в томе данных и теряется вместе с ним)."));
}

/* ----------------------------------------------------------------- Дашборд */
function Dash({
  D,
  tasks,
  go
}) {
  if (!D) return /*#__PURE__*/React.createElement("div", {
    className: "empty"
  }, "Нет данных. Запустите сканирование: «+ Новое сканирование».");
  const ts = D.topology && D.topology.stats || {};
  const assets = D.assets || [];
  const kpi = (n, l, c) => /*#__PURE__*/React.createElement("div", {
    className: "kpi"
  }, /*#__PURE__*/React.createElement("div", {
    className: "l"
  }, l), /*#__PURE__*/React.createElement("div", {
    className: "n",
    style: c ? {
      color: c
    } : null
  }, n));
  return /*#__PURE__*/React.createElement("div", null, /*#__PURE__*/React.createElement("h1", {
    className: "h1"
  }, D.survey && D.survey.name || "Обследование"), /*#__PURE__*/React.createElement("p", {
    className: "sub"
  }, "Инвентаризация сети · ", D.generated), /*#__PURE__*/React.createElement("div", {
    className: "kpis"
  }, kpi(D.totals ? D.totals.assets : assets.length, "Активов"), kpi(ts.hosts != null ? ts.hosts : "—", "Хостов"), kpi(ts.devices != null ? ts.devices : "—", "Сетевых устройств"), kpi(ts.subnets != null ? ts.subnets : "—", "Подсетей"), kpi(ts.services != null ? ts.services : "—", "Открытых сервисов")), /*#__PURE__*/React.createElement("div", {
    className: "cols dash"
  }, /*#__PURE__*/React.createElement("div", {
    className: "card"
  }, /*#__PURE__*/React.createElement("div", {
    className: "ch"
  }, /*#__PURE__*/React.createElement("h3", null, "Активы"), /*#__PURE__*/React.createElement("span", {
    className: "more",
    onClick: () => go({
      view: "assets"
    })
  }, "Все активы →")), /*#__PURE__*/React.createElement("div", {
    className: "cb"
  }, /*#__PURE__*/React.createElement("table", null, /*#__PURE__*/React.createElement("thead", null, /*#__PURE__*/React.createElement("tr", null, /*#__PURE__*/React.createElement("th", null, "Актив"), /*#__PURE__*/React.createElement("th", null, "IP"), /*#__PURE__*/React.createElement("th", null, "ОС / платформа"), /*#__PURE__*/React.createElement("th", null, "Сервисы"))), /*#__PURE__*/React.createElement("tbody", null, assets.slice(0, 6).map(a => /*#__PURE__*/React.createElement("tr", {
    key: a.name,
    className: "click",
    onClick: () => go({
      view: "asset",
      assetName: a.name
    })
  }, /*#__PURE__*/React.createElement("td", null, /*#__PURE__*/React.createElement("b", null, a.name)), /*#__PURE__*/React.createElement("td", {
    className: "mono"
  }, a.ips), /*#__PURE__*/React.createElement("td", null, a.os || "—"), /*#__PURE__*/React.createElement("td", {
    className: "num"
  }, (a.services || []).length))), assets.length === 0 && /*#__PURE__*/React.createElement("tr", null, /*#__PURE__*/React.createElement("td", {
    colSpan: "4",
    className: "sub2"
  }, "Активы не найдены.")))))), /*#__PURE__*/React.createElement("div", {
    className: "card"
  }, /*#__PURE__*/React.createElement("div", {
    className: "ch"
  }, /*#__PURE__*/React.createElement("h3", null, "Схема сети"), /*#__PURE__*/React.createElement("span", {
    className: "more",
    onClick: () => go({
      view: "netmap"
    })
  }, "Открыть →")), /*#__PURE__*/React.createElement("div", {
    className: "cb"
  }, /*#__PURE__*/React.createElement("div", {
    style: {
      fontSize: 13,
      color: "var(--muted)",
      lineHeight: 1.7
    }
  }, "Узлов: ", /*#__PURE__*/React.createElement("b", {
    style: {
      color: "var(--ink)"
    }
  }, ts.nodes || 0), /*#__PURE__*/React.createElement("br", null), "Подсетей: ", /*#__PURE__*/React.createElement("b", {
    style: {
      color: "var(--ink)"
    }
  }, ts.subnets || 0), /*#__PURE__*/React.createElement("br", null), "Сетевых устройств: ", /*#__PURE__*/React.createElement("b", {
    style: {
      color: "var(--ink)"
    }
  }, ts.devices || 0), /*#__PURE__*/React.createElement("br", null), "Связей: ", /*#__PURE__*/React.createElement("b", {
    style: {
      color: "var(--ink)"
    }
  }, ts.edges || 0)), /*#__PURE__*/React.createElement("button", {
    className: "btn",
    style: {
      marginTop: 12
    },
    onClick: () => go({
      view: "netmap"
    })
  }, "Открыть схему сети"))), /*#__PURE__*/React.createElement("div", {
    className: "card"
  }, /*#__PURE__*/React.createElement("div", {
    className: "ch"
  }, /*#__PURE__*/React.createElement("h3", null, "Сканирования"), /*#__PURE__*/React.createElement("span", {
    className: "more",
    onClick: () => go({
      view: "surveys"
    })
  }, "Все →")), /*#__PURE__*/React.createElement("div", {
    className: "cb"
  }, tasks.slice(0, 6).map(tk => {
    const cls = tk.status === "done" ? "d-ok" : tk.status === "running" ? "d-run" : tk.status === "error" ? "d-err" : "d-wait";
    const st = {
      done: "готово",
      running: "идёт",
      queued: "в очереди",
      error: "ошибка"
    }[tk.status];
    return /*#__PURE__*/React.createElement("div", {
      className: "scan",
      key: tk.id
    }, /*#__PURE__*/React.createElement("span", {
      className: "dotc " + cls
    }), /*#__PURE__*/React.createElement("div", null, /*#__PURE__*/React.createElement("div", {
      className: "nm"
    }, tk.name || "Скан #" + tk.id)), /*#__PURE__*/React.createElement("span", {
      className: "pct"
    }, st));
  }), tasks.length === 0 && /*#__PURE__*/React.createElement("div", {
    className: "sub2"
  }, "Пока нет сканирований.")))));
}

/* ----------------------------------------------------------------- Активы */
function Assets({
  D,
  go
}) {
  if (!D) return /*#__PURE__*/React.createElement("div", {
    className: "empty"
  }, "Нет данных. Запустите сканирование.");
  const assets = D.assets || [];
  return /*#__PURE__*/React.createElement("div", null, /*#__PURE__*/React.createElement("h1", {
    className: "h1"
  }, "Активы"), /*#__PURE__*/React.createElement("p", {
    className: "sub"
  }, "Инвентаризация активов обследования «", D.survey && D.survey.name, "»."), /*#__PURE__*/React.createElement("div", {
    className: "card"
  }, /*#__PURE__*/React.createElement("div", {
    className: "cb"
  }, /*#__PURE__*/React.createElement("table", null, /*#__PURE__*/React.createElement("thead", null, /*#__PURE__*/React.createElement("tr", null, /*#__PURE__*/React.createElement("th", null, "Актив"), /*#__PURE__*/React.createElement("th", null, "IP"), /*#__PURE__*/React.createElement("th", null, "ОС / платформа"), /*#__PURE__*/React.createElement("th", null, "Тип"), /*#__PURE__*/React.createElement("th", {
    className: "num"
  }, "ПО"), /*#__PURE__*/React.createElement("th", {
    className: "num"
  }, "Сервисов"))), /*#__PURE__*/React.createElement("tbody", null, assets.map(a => /*#__PURE__*/React.createElement("tr", {
    key: a.name,
    className: "click",
    onClick: () => go({
      view: "asset",
      assetName: a.name
    })
  }, /*#__PURE__*/React.createElement("td", null, /*#__PURE__*/React.createElement("b", null, a.name), a.partial ? /*#__PURE__*/React.createElement("span", {
    className: "chip c-medium",
    style: {
      marginLeft: 8
    }
  }, "сбор без root") : null), /*#__PURE__*/React.createElement("td", {
    className: "mono"
  }, a.ips || "—"), /*#__PURE__*/React.createElement("td", null, a.os || "—", a.build ? /*#__PURE__*/React.createElement("div", {
    className: "sub2 mono"
  }, a.build) : null), /*#__PURE__*/React.createElement("td", null, a.kind), /*#__PURE__*/React.createElement("td", {
    className: "num"
  }, a.software || 0), /*#__PURE__*/React.createElement("td", {
    className: "num"
  }, (a.services || []).length))), assets.length === 0 && /*#__PURE__*/React.createElement("tr", null, /*#__PURE__*/React.createElement("td", {
    colSpan: "6",
    className: "sub2"
  }, "Активы не найдены.")))))));
}

/* --- вспомогательные блоки карточки актива --- */
function KV({
  k,
  v
}) {
  return /*#__PURE__*/React.createElement("div", {
    className: "kv"
  }, /*#__PURE__*/React.createElement("span", {
    className: "k"
  }, k), /*#__PURE__*/React.createElement("span", {
    className: "v"
  }, v === null || v === undefined || v === "" ? "—" : String(v)));
}
function SimpleTable({
  cols,
  rows,
  empty
}) {
  if (!rows || rows.length === 0) return /*#__PURE__*/React.createElement("div", {
    className: "sub2"
  }, empty);
  return /*#__PURE__*/React.createElement("table", null, /*#__PURE__*/React.createElement("thead", null, /*#__PURE__*/React.createElement("tr", null, cols.map(c => /*#__PURE__*/React.createElement("th", {
    key: c.key,
    className: c.num ? "num" : ""
  }, c.label)))), /*#__PURE__*/React.createElement("tbody", null, rows.map((r, i) => /*#__PURE__*/React.createElement("tr", {
    key: i
  }, cols.map(c => /*#__PURE__*/React.createElement("td", {
    key: c.key,
    className: c.mono ? "mono" : c.num ? "num" : ""
  }, c.render ? c.render(r) : r[c.key] ?? "—"))))));
}
function AssetDetail({
  D,
  name,
  go
}) {
  const a = (D.assets || []).find(x => x.name === name);
  const [tab, setTab] = useState("overview");
  const [swFilter, setSwFilter] = useState("");
  if (!a) return /*#__PURE__*/React.createElement("div", {
    className: "empty"
  }, "Актив не найден.");
  const inv = a.inventory || {};
  const fam = a.os_family || "";
  const software = inv.software || [];
  const swShown = swFilter ? software.filter(s => (s.name || "").toLowerCase().includes(swFilter.toLowerCase())) : software;
  const listening = inv.listening || [];
  const tabs = [{
    id: "overview",
    label: "Обзор"
  }, {
    id: "software",
    label: "ПО",
    count: software.length
  }];
  if (fam === "windows") tabs.push({
    id: "hotfixes",
    label: "Обновления",
    count: (inv.hotfixes || []).length
  });
  if (fam === "windows" || fam === "linux") tabs.push({
    id: "users",
    label: "Пользователи"
  });
  tabs.push({
    id: "network",
    label: "Сеть и службы",
    count: (a.services || []).length + listening.length
  });
  if (fam === "windows" || fam === "linux") tabs.push({
    id: "security",
    label: "Защита"
  });
  if (inv.config) tabs.push({
    id: "config",
    label: "Конфигурация"
  });
  return /*#__PURE__*/React.createElement("div", null, /*#__PURE__*/React.createElement("div", {
    className: "crumb",
    style: {
      marginBottom: 10
    }
  }, /*#__PURE__*/React.createElement("span", {
    className: "link",
    onClick: () => go({
      view: "assets"
    })
  }, "Активы"), /*#__PURE__*/React.createElement("span", {
    className: "sep"
  }, "/"), /*#__PURE__*/React.createElement("b", null, name)), /*#__PURE__*/React.createElement("div", {
    className: "pagehead"
  }, /*#__PURE__*/React.createElement("div", {
    className: "ic"
  }, (a.kind || "").toLowerCase().includes("сетев") ? "🖧" : "🖥"), /*#__PURE__*/React.createElement("div", null, /*#__PURE__*/React.createElement("div", {
    className: "h1",
    style: {
      margin: 0
    }
  }, name), /*#__PURE__*/React.createElement("div", {
    className: "meta mono"
  }, a.ips, a.os ? " · " + a.os : ""))), a.partial ? /*#__PURE__*/React.createElement("div", {
    className: "warn",
    style: {
      margin: "10px 0"
    }
  }, "Сбор выполнен без root/sudo — часть данных (учётки, конфиги) может быть неполной.") : null, /*#__PURE__*/React.createElement("div", {
    className: "tabs"
  }, tabs.map(t => /*#__PURE__*/React.createElement("div", {
    key: t.id,
    className: "tab" + (tab === t.id ? " on" : ""),
    onClick: () => setTab(t.id)
  }, t.label, t.count !== undefined ? /*#__PURE__*/React.createElement("span", {
    className: "cnt"
  }, t.count) : null))), tab === "overview" && /*#__PURE__*/React.createElement("div", {
    className: "detail"
  }, /*#__PURE__*/React.createElement("div", {
    className: "card"
  }, /*#__PURE__*/React.createElement("div", {
    className: "ch"
  }, /*#__PURE__*/React.createElement("h3", null, "Сведения")), /*#__PURE__*/React.createElement("div", {
    className: "cb"
  }, /*#__PURE__*/React.createElement(KV, {
    k: "Тип",
    v: a.kind
  }), /*#__PURE__*/React.createElement(KV, {
    k: "IP",
    v: a.ips
  }), /*#__PURE__*/React.createElement(KV, {
    k: "ОС / платформа",
    v: a.os
  }), /*#__PURE__*/React.createElement(KV, {
    k: "Сборка / версия",
    v: a.build
  }), fam === "windows" ? /*#__PURE__*/React.createElement(React.Fragment, null, /*#__PURE__*/React.createElement(KV, {
    k: "Домен",
    v: inv.part_of_domain ? inv.domain : "рабочая группа"
  }), /*#__PURE__*/React.createElement(KV, {
    k: "Архитектура",
    v: inv.architecture
  }), /*#__PURE__*/React.createElement(KV, {
    k: "Тип установки",
    v: inv.installation_type
  }), /*#__PURE__*/React.createElement(KV, {
    k: "Последняя загрузка",
    v: inv.last_boot
  }), /*#__PURE__*/React.createElement(KV, {
    k: "Сбор от администратора",
    v: inv.is_admin === true ? "да" : inv.is_admin === false ? "нет" : "—"
  })) : null, fam === "linux" ? /*#__PURE__*/React.createElement(KV, {
    k: "Сбор от root",
    v: inv.is_root === true ? "да" : inv.is_root === false ? "нет (sudo/частично)" : "—"
  }) : null, /*#__PURE__*/React.createElement(KV, {
    k: "Источник сбора",
    v: a.source
  }), /*#__PURE__*/React.createElement(KV, {
    k: "Собрано",
    v: a.collected_at
  }))), /*#__PURE__*/React.createElement("div", null, /*#__PURE__*/React.createElement("div", {
    className: "card"
  }, /*#__PURE__*/React.createElement("div", {
    className: "ch"
  }, /*#__PURE__*/React.createElement("h3", null, "Итоги")), /*#__PURE__*/React.createElement("div", {
    className: "cb"
  }, /*#__PURE__*/React.createElement(KV, {
    k: "Пакетов / ПО",
    v: software.length
  }), /*#__PURE__*/React.createElement(KV, {
    k: "Открытых сервисов (сеть)",
    v: (a.services || []).length
  }), /*#__PURE__*/React.createElement(KV, {
    k: "Слушающих портов (ОС)",
    v: listening.length
  }), fam === "windows" ? /*#__PURE__*/React.createElement(KV, {
    k: "Обновлений (KB)",
    v: (inv.hotfixes || []).length
  }) : null)), a.sec_tools && a.sec_tools.length ? /*#__PURE__*/React.createElement("div", {
    className: "card",
    style: {
      marginTop: 16
    }
  }, /*#__PURE__*/React.createElement("div", {
    className: "ch"
  }, /*#__PURE__*/React.createElement("h3", null, "Средства защиты")), /*#__PURE__*/React.createElement("div", {
    className: "cb"
  }, a.sec_tools.map((t, i) => /*#__PURE__*/React.createElement("div", {
    key: i,
    style: {
      padding: "5px 0"
    }
  }, /*#__PURE__*/React.createElement("span", {
    style: {
      color: "var(--ok)"
    }
  }, "✓"), " ", t)))) : null)), tab === "software" && /*#__PURE__*/React.createElement("div", {
    className: "card"
  }, /*#__PURE__*/React.createElement("div", {
    className: "ch"
  }, /*#__PURE__*/React.createElement("h3", null, "Установленное ПО / пакеты"), /*#__PURE__*/React.createElement("input", {
    value: swFilter,
    onChange: e => setSwFilter(e.target.value),
    placeholder: "Фильтр по имени…",
    style: {
      marginLeft: "auto",
      fontSize: 12.5,
      padding: "4px 8px"
    }
  })), /*#__PURE__*/React.createElement("div", {
    className: "cb"
  }, /*#__PURE__*/React.createElement(SimpleTable, {
    empty: "ПО не обнаружено.",
    cols: [{
      key: "name",
      label: "Название"
    }, {
      key: "version",
      label: "Версия",
      mono: true
    }, {
      key: "vendor",
      label: "Производитель"
    }, {
      key: "ecosystem",
      label: "Тип"
    }],
    rows: swShown
  }))), tab === "hotfixes" && /*#__PURE__*/React.createElement("div", {
    className: "card"
  }, /*#__PURE__*/React.createElement("div", {
    className: "ch"
  }, /*#__PURE__*/React.createElement("h3", null, "Установленные обновления")), /*#__PURE__*/React.createElement("div", {
    className: "cb"
  }, (inv.hotfixes || []).length ? /*#__PURE__*/React.createElement("div", {
    style: {
      display: "flex",
      flexWrap: "wrap",
      gap: 8
    }
  }, inv.hotfixes.map(kb => /*#__PURE__*/React.createElement("span", {
    key: kb,
    className: "mono chip c-low"
  }, "KB", kb))) : /*#__PURE__*/React.createElement("div", {
    className: "sub2"
  }, "Обновления не собраны."))), tab === "users" && /*#__PURE__*/React.createElement("div", {
    className: "detail"
  }, /*#__PURE__*/React.createElement("div", {
    className: "card"
  }, /*#__PURE__*/React.createElement("div", {
    className: "ch"
  }, /*#__PURE__*/React.createElement("h3", null, "Учётные записи")), /*#__PURE__*/React.createElement("div", {
    className: "cb"
  }, fam === "windows" ? /*#__PURE__*/React.createElement(SimpleTable, {
    empty: "Локальные учётки не собраны.",
    cols: [{
      key: "name",
      label: "Имя"
    }, {
      key: "disabled",
      label: "Отключена",
      render: r => r.disabled ? "да" : "нет"
    }, {
      key: "password_required",
      label: "Треб. пароль",
      render: r => r.password_required ? "да" : "нет"
    }, {
      key: "password_expires",
      label: "Пароль истекает",
      render: r => r.password_expires ? "да" : "нет"
    }],
    rows: inv.users
  }) : /*#__PURE__*/React.createElement(SimpleTable, {
    empty: "Пользователи не собраны.",
    cols: [{
      key: "name",
      label: "Логин"
    }],
    rows: (inv.login_users || []).map(n => ({
      name: n
    }))
  }))), /*#__PURE__*/React.createElement("div", null, fam === "windows" ? /*#__PURE__*/React.createElement("div", {
    className: "card"
  }, /*#__PURE__*/React.createElement("div", {
    className: "ch"
  }, /*#__PURE__*/React.createElement("h3", null, "Администраторы")), /*#__PURE__*/React.createElement("div", {
    className: "cb"
  }, (inv.admins || []).length ? inv.admins.map((n, i) => /*#__PURE__*/React.createElement("div", {
    key: i,
    className: "mono",
    style: {
      padding: "4px 0",
      fontSize: 12.5
    }
  }, n)) : /*#__PURE__*/React.createElement("div", {
    className: "sub2"
  }, "Группа «Администраторы» пуста или не собрана."))) : /*#__PURE__*/React.createElement(React.Fragment, null, /*#__PURE__*/React.createElement("div", {
    className: "card"
  }, /*#__PURE__*/React.createElement("div", {
    className: "ch"
  }, /*#__PURE__*/React.createElement("h3", null, "UID 0 / sudo без пароля")), /*#__PURE__*/React.createElement("div", {
    className: "cb"
  }, /*#__PURE__*/React.createElement(KV, {
    k: "UID 0 (кроме root)",
    v: (inv.uid0_users || []).join(", ") || "—"
  }), /*#__PURE__*/React.createElement(KV, {
    k: "sudo NOPASSWD",
    v: inv.sudo_nopasswd === null ? "нет доступа к данным" : (inv.sudo_nopasswd || []).join("; ") || "нет"
  }), /*#__PURE__*/React.createElement(KV, {
    k: "Пустой пароль",
    v: inv.empty_password_users === null ? "нет доступа к данным" : (inv.empty_password_users || []).join(", ") || "нет"
  })))))), tab === "network" && /*#__PURE__*/React.createElement("div", {
    className: "detail"
  }, /*#__PURE__*/React.createElement("div", {
    className: "card"
  }, /*#__PURE__*/React.createElement("div", {
    className: "ch"
  }, /*#__PURE__*/React.createElement("h3", null, "Открытые сервисы (сетевой скан)")), /*#__PURE__*/React.createElement("div", {
    className: "cb"
  }, (a.services || []).length ? (a.services || []).map((s, i) => /*#__PURE__*/React.createElement("div", {
    key: i,
    className: "mono",
    style: {
      padding: "5px 0",
      fontSize: 12.5
    }
  }, s)) : /*#__PURE__*/React.createElement("div", {
    className: "sub2"
  }, "Открытых сервисов не обнаружено."))), /*#__PURE__*/React.createElement("div", {
    className: "card"
  }, /*#__PURE__*/React.createElement("div", {
    className: "ch"
  }, /*#__PURE__*/React.createElement("h3", null, "Слушающие порты (на хосте)")), /*#__PURE__*/React.createElement("div", {
    className: "cb"
  }, /*#__PURE__*/React.createElement(SimpleTable, {
    empty: "Не собрано.",
    cols: [{
      key: "proto",
      label: "Протокол"
    }, {
      key: "port",
      label: "Порт",
      num: true
    }, {
      key: "address",
      label: "Адрес",
      mono: true
    }, {
      key: "process",
      label: "Процесс"
    }],
    rows: listening
  }))), fam === "windows" && (inv.services || []).length ? /*#__PURE__*/React.createElement("div", {
    className: "card",
    style: {
      gridColumn: "1 / -1"
    }
  }, /*#__PURE__*/React.createElement("div", {
    className: "ch"
  }, /*#__PURE__*/React.createElement("h3", null, "Службы Windows")), /*#__PURE__*/React.createElement("div", {
    className: "cb"
  }, /*#__PURE__*/React.createElement(SimpleTable, {
    empty: "Не собрано.",
    cols: [{
      key: "display",
      label: "Название"
    }, {
      key: "state",
      label: "Состояние"
    }, {
      key: "start_mode",
      label: "Запуск"
    }, {
      key: "account",
      label: "Учётка",
      mono: true
    }],
    rows: inv.services
  }))) : null), tab === "security" && /*#__PURE__*/React.createElement("div", {
    className: "detail"
  }, fam === "windows" ? /*#__PURE__*/React.createElement(React.Fragment, null, /*#__PURE__*/React.createElement("div", {
    className: "card"
  }, /*#__PURE__*/React.createElement("div", {
    className: "ch"
  }, /*#__PURE__*/React.createElement("h3", null, "Межсетевой экран")), /*#__PURE__*/React.createElement("div", {
    className: "cb"
  }, Object.keys(inv.firewall || {}).length ? Object.entries(inv.firewall).map(([k, v]) => /*#__PURE__*/React.createElement(KV, {
    key: k,
    k: k,
    v: v ? "включён" : "отключён"
  })) : /*#__PURE__*/React.createElement("div", {
    className: "sub2"
  }, "Не собрано."))), /*#__PURE__*/React.createElement("div", {
    className: "card"
  }, /*#__PURE__*/React.createElement("div", {
    className: "ch"
  }, /*#__PURE__*/React.createElement("h3", null, "Антивирус / Defender")), /*#__PURE__*/React.createElement("div", {
    className: "cb"
  }, (inv.antivirus || []).map((av, i) => /*#__PURE__*/React.createElement("div", {
    key: i,
    style: {
      padding: "4px 0"
    }
  }, /*#__PURE__*/React.createElement("span", {
    style: {
      color: "var(--ok)"
    }
  }, "✓"), " ", av.name)), inv.defender ? /*#__PURE__*/React.createElement(React.Fragment, null, /*#__PURE__*/React.createElement(KV, {
    k: "Defender включён",
    v: inv.defender.enabled ? "да" : "нет"
  }), /*#__PURE__*/React.createElement(KV, {
    k: "Защита в реальном времени",
    v: inv.defender.realtime ? "да" : "нет"
  }), /*#__PURE__*/React.createElement(KV, {
    k: "Обновление сигнатур",
    v: inv.defender.signatures
  })) : null, (!inv.antivirus || inv.antivirus.length === 0) && !inv.defender ? /*#__PURE__*/React.createElement("div", {
    className: "sub2"
  }, "Не собрано.") : null))) : /*#__PURE__*/React.createElement(React.Fragment, null, /*#__PURE__*/React.createElement("div", {
    className: "card"
  }, /*#__PURE__*/React.createElement("div", {
    className: "ch"
  }, /*#__PURE__*/React.createElement("h3", null, "SSH")), /*#__PURE__*/React.createElement("div", {
    className: "cb"
  }, inv.sshd ? Object.entries(inv.sshd).map(([k, v]) => /*#__PURE__*/React.createElement(KV, {
    key: k,
    k: k,
    v: v
  })) : /*#__PURE__*/React.createElement("div", {
    className: "sub2"
  }, "sshd не собран."))), /*#__PURE__*/React.createElement("div", {
    className: "card"
  }, /*#__PURE__*/React.createElement("div", {
    className: "ch"
  }, /*#__PURE__*/React.createElement("h3", null, "Активные службы безопасности")), /*#__PURE__*/React.createElement("div", {
    className: "cb"
  }, Object.keys(inv.services_active || {}).length ? Object.entries(inv.services_active).map(([k, v]) => /*#__PURE__*/React.createElement(KV, {
    key: k,
    k: k,
    v: v
  })) : /*#__PURE__*/React.createElement("div", {
    className: "sub2"
  }, "Не собрано."))))), tab === "config" && /*#__PURE__*/React.createElement("div", {
    className: "card"
  }, /*#__PURE__*/React.createElement("div", {
    className: "ch"
  }, /*#__PURE__*/React.createElement("h3", null, "Конфигурация устройства"), /*#__PURE__*/React.createElement("span", {
    className: "sub2"
  }, "секреты замаскированы")), /*#__PURE__*/React.createElement("div", {
    className: "cb"
  }, /*#__PURE__*/React.createElement("pre", {
    className: "mono",
    style: {
      whiteSpace: "pre-wrap",
      fontSize: 12,
      margin: 0
    }
  }, inv.config))));
}

/* ----------------------------------------------------------------- Схема сети */
const CY_STYLE = [{
  selector: "node",
  style: {
    "label": "data(label)",
    "font-size": 11,
    "font-family": "Inter, sans-serif",
    "text-valign": "center",
    "text-halign": "center",
    "width": "label",
    "height": 28,
    "padding": "8px"
  }
}, {
  selector: 'node[type="core"]',
  style: {
    "background-color": "#3D4EA6",
    "shape": "diamond",
    "color": "#fff",
    "width": 60,
    "height": 60,
    "font-weight": 600
  }
}, {
  selector: 'node[type="subnet"]',
  style: {
    "background-color": "#E8EAEF",
    "shape": "round-rectangle",
    "color": "#44506a",
    "font-weight": 600
  }
}, {
  selector: 'node[type="device"]',
  style: {
    "background-color": "#11141B",
    "shape": "round-rectangle",
    "color": "#fff"
  }
}, {
  selector: 'node[type="host"]',
  style: {
    "background-color": "#ffffff",
    "shape": "round-rectangle",
    "color": "#16181D",
    "border-color": "#C4CAD4",
    "border-width": 1
  }
}, {
  selector: "edge",
  style: {
    "line-color": "#C4CAD4",
    "width": 1.5,
    "curve-style": "bezier"
  }
}, {
  selector: 'edge[type="uplink"]',
  style: {
    "line-color": "#AEB4C0",
    "width": 2
  }
}, {
  selector: 'edge[type="l2"]',
  style: {
    "line-color": "#3D4EA6",
    "line-style": "dashed"
  }
}];
function NetMap({
  taskId,
  go
}) {
  const box = useRef(null);
  const cyRef = useRef(null);
  const [err, setErr] = useState(null);
  const [stats, setStats] = useState(null);
  useEffect(() => {
    if (!taskId) return;
    let cy;
    api("/tasks/" + taskId + "/topology").then(topo => {
      setStats(topo.stats);
      cy = window.cytoscape({
        container: box.current,
        elements: topo.elements,
        style: CY_STYLE,
        layout: {
          name: "breadthfirst",
          roots: ["core"],
          directed: false,
          spacingFactor: 1.1,
          padding: 24
        },
        wheelSensitivity: 0.25
      });
      cy.on("tap", "node", ev => {
        const d = ev.target.data();
        if (d.type === "host" || d.type === "device") go({
          view: "asset",
          assetName: d.label
        });
      });
      cyRef.current = cy;
    }).catch(e => setErr(e && e.detail ? e.detail : "схема недоступна"));
    return () => {
      if (cy) cy.destroy();
    };
  }, [taskId]);
  const fit = () => cyRef.current && cyRef.current.fit(undefined, 30);
  const relayout = name => cyRef.current && cyRef.current.layout(name === "cose" ? {
    name: "cose",
    padding: 20,
    animate: false
  } : {
    name: "breadthfirst",
    roots: ["core"],
    directed: false,
    spacingFactor: 1.1,
    padding: 24
  }).run();
  const exportPng = () => {
    if (!cyRef.current) return;
    const png = cyRef.current.png({
      scale: 2,
      full: true,
      bg: "#ffffff"
    });
    const a = document.createElement("a");
    a.href = png;
    a.download = "network-map.png";
    a.click();
  };
  if (err) return /*#__PURE__*/React.createElement("div", null, /*#__PURE__*/React.createElement("h1", {
    className: "h1"
  }, "Схема сети"), /*#__PURE__*/React.createElement("div", {
    className: "empty"
  }, err, ". Запустите сканирование и дождитесь готовности."));
  return /*#__PURE__*/React.createElement("div", null, /*#__PURE__*/React.createElement("div", {
    className: "maptools"
  }, /*#__PURE__*/React.createElement("h1", {
    className: "h1",
    style: {
      margin: 0
    }
  }, "Схема сети"), /*#__PURE__*/React.createElement("span", {
    className: "sp"
  }), /*#__PURE__*/React.createElement("button", {
    className: "btn ghost",
    onClick: fit
  }, "Вписать"), /*#__PURE__*/React.createElement("button", {
    className: "btn ghost",
    onClick: () => relayout("breadthfirst")
  }, "Слои"), /*#__PURE__*/React.createElement("button", {
    className: "btn ghost",
    onClick: () => relayout("cose")
  }, "Свободно"), /*#__PURE__*/React.createElement("button", {
    className: "btn ghost",
    onClick: exportPng
  }, "Экспорт PNG"), /*#__PURE__*/React.createElement("a", {
    className: "btn",
    href: "/tasks/" + taskId + "/topology.svg",
    target: "_blank",
    style: {
      textDecoration: "none"
    }
  }, "Экспорт SVG")), /*#__PURE__*/React.createElement("div", {
    id: "cy",
    ref: box
  }), /*#__PURE__*/React.createElement("div", {
    className: "legend2"
  }, /*#__PURE__*/React.createElement("span", null, /*#__PURE__*/React.createElement("i", {
    style: {
      background: "#3D4EA6",
      transform: "rotate(45deg)"
    }
  }), "Ядро сети"), /*#__PURE__*/React.createElement("span", null, /*#__PURE__*/React.createElement("i", {
    style: {
      background: "#E8EAEF"
    }
  }), "Подсеть"), /*#__PURE__*/React.createElement("span", null, /*#__PURE__*/React.createElement("i", {
    style: {
      background: "#11141B"
    }
  }), "Сетевое устройство"), /*#__PURE__*/React.createElement("span", null, /*#__PURE__*/React.createElement("i", {
    style: {
      background: "#fff",
      border: "1px solid #C4CAD4"
    }
  }), "Хост"), /*#__PURE__*/React.createElement("span", {
    style: {
      marginLeft: "auto"
    }
  }, "клик по узлу — карточка актива", stats ? ` · узлов ${stats.nodes}, связей ${stats.edges}` : "")));
}

/* ----------------------------------------------------------------- Карточка задачи */
const ST_LABEL = {
  done: "готово",
  running: "идёт",
  queued: "в очереди",
  error: "ошибка",
  cancelling: "отмена…",
  cancelled: "отменено"
};
const ST_CHIP = {
  done: "low",
  error: "critical",
  cancelled: "medium",
  running: "medium",
  queued: "medium"
};
function TaskDetail({
  taskId,
  go,
  setActive
}) {
  const [t, setT] = useState(null);
  const [busy, setBusy] = useState(false);
  const logRef = useRef(null);
  const load = useCallback(() => taskId && api("/tasks/" + taskId).then(setT).catch(() => {}), [taskId]);
  useEffect(() => {
    load();
  }, [load]);
  useEffect(() => {
    if (!t || t.status !== "running" && t.status !== "queued") return;
    const h = setInterval(load, 2000);
    return () => clearInterval(h);
  }, [t, load]);
  useEffect(() => {
    if (logRef.current) logRef.current.scrollTop = logRef.current.scrollHeight;
  }, [t]);
  if (!t) return /*#__PURE__*/React.createElement("div", {
    className: "empty"
  }, "Загрузка задачи…");
  const p = t.params || {},
    r = t.result || {},
    coll = r.collect;
  const running = t.status === "running" || t.status === "queued";
  const cancel = async () => {
    setBusy(true);
    try {
      await api("/tasks/" + taskId + "/cancel", {
        method: "POST"
      });
    } catch (e) {}
    setBusy(false);
    load();
  };
  const repeat = () => go({
    view: "newscan",
    initTargets: p.targets || (r.targets || []).join(", "),
    initCreds: (p.creds || []).map(c => c.id).filter(Boolean)
  });
  return /*#__PURE__*/React.createElement("div", null, /*#__PURE__*/React.createElement("div", {
    className: "crumb",
    style: {
      marginBottom: 10
    }
  }, /*#__PURE__*/React.createElement("span", {
    className: "link",
    onClick: () => go({
      view: "surveys"
    })
  }, "Сканирования"), /*#__PURE__*/React.createElement("span", {
    className: "sep"
  }, "/"), /*#__PURE__*/React.createElement("b", null, t.name || "Задача #" + t.id)), /*#__PURE__*/React.createElement("div", {
    style: {
      display: "flex",
      alignItems: "center",
      gap: 12,
      flexWrap: "wrap"
    }
  }, /*#__PURE__*/React.createElement("h1", {
    className: "h1",
    style: {
      margin: 0
    }
  }, t.name || "Задача #" + t.id), /*#__PURE__*/React.createElement("span", {
    className: "chip c-" + (ST_CHIP[t.status] || "medium")
  }, ST_LABEL[t.status] || t.status), /*#__PURE__*/React.createElement("div", {
    style: {
      marginLeft: "auto",
      display: "flex",
      gap: 8
    }
  }, running ? /*#__PURE__*/React.createElement("button", {
    className: "btn ghost",
    disabled: busy,
    onClick: cancel
  }, "Отменить") : null, /*#__PURE__*/React.createElement("button", {
    className: "btn ghost",
    onClick: repeat
  }, "Повторить"), t.status === "done" && t.has_report ? /*#__PURE__*/React.createElement("button", {
    className: "btn ghost",
    onClick: () => {
      setActive(t.id);
      go({
        view: "netmap"
      });
    }
  }, "Схема сети") : null, t.status === "done" ? /*#__PURE__*/React.createElement("button", {
    className: "btn",
    onClick: () => {
      setActive(t.id);
      go({
        view: "dash"
      });
    }
  }, "Открыть результат") : null)), /*#__PURE__*/React.createElement("p", {
    className: "sub"
  }, "Цели: ", /*#__PURE__*/React.createElement("span", {
    className: "mono"
  }, p.targets || (r.targets || []).join(", ") || "—"), running ? " · обновляется каждые 2 c" : ""), /*#__PURE__*/React.createElement("div", {
    className: "cols dash",
    style: {
      marginTop: 4
    }
  }, /*#__PURE__*/React.createElement("div", {
    className: "card",
    style: {
      gridColumn: "span 2"
    }
  }, /*#__PURE__*/React.createElement("div", {
    className: "ch"
  }, /*#__PURE__*/React.createElement("h3", null, "Журнал выполнения")), /*#__PURE__*/React.createElement("div", {
    className: "cb"
  }, /*#__PURE__*/React.createElement("div", {
    className: "tasklog",
    ref: logRef
  }, (t.progress || []).length === 0 ? /*#__PURE__*/React.createElement("div", {
    className: "sub2"
  }, "Пока нет записей. Для демо-задач журнал не ведётся.") : (t.progress || []).map((l, i) => /*#__PURE__*/React.createElement("div", {
    key: i
  }, /*#__PURE__*/React.createElement("span", {
    className: "lt"
  }, l.t), " ", l.m))), t.status === "error" && t.error ? /*#__PURE__*/React.createElement("div", {
    className: "warn",
    style: {
      marginTop: 10,
      whiteSpace: "pre-wrap",
      fontFamily: "JetBrains Mono, monospace",
      fontSize: 12
    }
  }, t.error) : null)), /*#__PURE__*/React.createElement("div", {
    className: "card"
  }, /*#__PURE__*/React.createElement("div", {
    className: "ch"
  }, /*#__PURE__*/React.createElement("h3", null, "Учётные записи")), /*#__PURE__*/React.createElement("div", {
    className: "cb"
  }, (p.creds || []).length === 0 ? /*#__PURE__*/React.createElement("div", {
    className: "sub2"
  }, "Без УЗ — только сетевое обнаружение.") : (p.creds || []).map((c, i) => /*#__PURE__*/React.createElement("div", {
    key: i,
    style: {
      padding: "4px 0",
      fontSize: 13
    }
  }, /*#__PURE__*/React.createElement("b", null, c.name || c.username || c.type), " ", /*#__PURE__*/React.createElement("span", {
    className: "sub2"
  }, "· ", c.type, c.username ? " · " + c.username : "")))))), coll ? /*#__PURE__*/React.createElement("div", {
    className: "card",
    style: {
      marginTop: 16
    }
  }, /*#__PURE__*/React.createElement("div", {
    className: "ch"
  }, /*#__PURE__*/React.createElement("h3", null, "Сбор по активам"), /*#__PURE__*/React.createElement("span", {
    className: "sub2"
  }, "успешно ", coll.collected.length, " · не удалось ", coll.failed.length)), /*#__PURE__*/React.createElement("div", {
    className: "cb"
  }, /*#__PURE__*/React.createElement("table", null, /*#__PURE__*/React.createElement("thead", null, /*#__PURE__*/React.createElement("tr", null, /*#__PURE__*/React.createElement("th", null, "Актив"), /*#__PURE__*/React.createElement("th", null, "IP"), /*#__PURE__*/React.createElement("th", null, "Протокол"), /*#__PURE__*/React.createElement("th", null, "Результат"))), /*#__PURE__*/React.createElement("tbody", null, coll.collected.map((c, i) => /*#__PURE__*/React.createElement("tr", {
    key: "c" + i
  }, /*#__PURE__*/React.createElement("td", null, /*#__PURE__*/React.createElement("b", null, c.asset)), /*#__PURE__*/React.createElement("td", {
    className: "mono"
  }, c.ip), /*#__PURE__*/React.createElement("td", null, c.proto), /*#__PURE__*/React.createElement("td", {
    style: {
      color: "var(--ok,#2e7d32)"
    }
  }, "✓ собрано (УЗ ", c.cred || "—", ")"))), coll.failed.map((c, i) => /*#__PURE__*/React.createElement("tr", {
    key: "f" + i
  }, /*#__PURE__*/React.createElement("td", null, /*#__PURE__*/React.createElement("b", null, c.asset)), /*#__PURE__*/React.createElement("td", {
    className: "mono"
  }, c.ip), /*#__PURE__*/React.createElement("td", null, c.proto), /*#__PURE__*/React.createElement("td", {
    className: "sub2"
  }, "✕ ", c.error))), coll.collected.length === 0 && coll.failed.length === 0 && /*#__PURE__*/React.createElement("tr", null, /*#__PURE__*/React.createElement("td", {
    colSpan: "4",
    className: "sub2"
  }, "Активов для сбора не было.")))))) : null);
}

/* ----------------------------------------------------------------- Обследования */
function Surveys({
  tasks,
  go,
  onNew,
  setActive
}) {
  return /*#__PURE__*/React.createElement("div", null, /*#__PURE__*/React.createElement("div", {
    style: {
      display: "flex",
      alignItems: "center",
      marginBottom: 16
    }
  }, /*#__PURE__*/React.createElement("div", null, /*#__PURE__*/React.createElement("h1", {
    className: "h1",
    style: {
      margin: 0
    }
  }, "Сканирования"), /*#__PURE__*/React.createElement("p", {
    className: "sub",
    style: {
      margin: "2px 0 0"
    }
  }, "Запуск, статус, схема и активы.")), /*#__PURE__*/React.createElement("button", {
    className: "btn",
    style: {
      marginLeft: "auto"
    },
    onClick: onNew
  }, "+ Новое сканирование")), /*#__PURE__*/React.createElement("div", {
    className: "card"
  }, /*#__PURE__*/React.createElement("div", {
    className: "cb"
  }, /*#__PURE__*/React.createElement("table", null, /*#__PURE__*/React.createElement("thead", null, /*#__PURE__*/React.createElement("tr", null, /*#__PURE__*/React.createElement("th", null, "#"), /*#__PURE__*/React.createElement("th", null, "Скан"), /*#__PURE__*/React.createElement("th", null, "Цели"), /*#__PURE__*/React.createElement("th", null, "Статус"), /*#__PURE__*/React.createElement("th", {
    className: "num"
  }, "Собрано по УЗ"), /*#__PURE__*/React.createElement("th", null, "Схема"))), /*#__PURE__*/React.createElement("tbody", null, tasks.map(t => {
    const st = ST_LABEL[t.status] || t.status;
    const p = t.params || {};
    const tg = p.targets || t.result && (t.result.targets || []).join(", ") || (p.kind === "demo" ? "демо" : "—");
    const nc = (p.creds || []).length;
    const coll = t.result && t.result.collect;
    return /*#__PURE__*/React.createElement("tr", {
      key: t.id
    }, /*#__PURE__*/React.createElement("td", {
      className: "mono"
    }, t.id), /*#__PURE__*/React.createElement("td", {
      className: "link",
      onClick: () => go({
        view: "task",
        taskId: t.id
      })
    }, /*#__PURE__*/React.createElement("b", null, t.name || "—"), nc ? /*#__PURE__*/React.createElement("div", {
      className: "sub2"
    }, nc, " УЗ", coll ? ` · собрано ${coll.collected.length}` : "") : null), /*#__PURE__*/React.createElement("td", {
      className: "sub2 mono"
    }, tg), /*#__PURE__*/React.createElement("td", null, /*#__PURE__*/React.createElement("span", {
      className: "chip c-" + (ST_CHIP[t.status] || "medium")
    }, st)), /*#__PURE__*/React.createElement("td", {
      className: "num"
    }, coll ? coll.collected.length : "—"), /*#__PURE__*/React.createElement("td", null, t.has_report ? /*#__PURE__*/React.createElement("span", {
      className: "link",
      onClick: () => {
        setActive(t.id);
        go({
          view: "netmap"
        });
      }
    }, "схема →") : /*#__PURE__*/React.createElement("span", {
      className: "link",
      onClick: () => go({
        view: "task",
        taskId: t.id
      })
    }, "открыть →")));
  }), tasks.length === 0 && /*#__PURE__*/React.createElement("tr", null, /*#__PURE__*/React.createElement("td", {
    colSpan: "6",
    className: "sub2"
  }, "Пока нет сканирований — запустите «+ Новое сканирование».")))))));
}

/* ----------------------------------------------------------------- Коннекторы */
function Connectors() {
  const [list, setList] = useState([]);
  const [name, setName] = useState("");
  const refresh = () => api("/connectors").then(setList).catch(() => {});
  useEffect(() => {
    refresh();
  }, []);
  const add = async () => {
    if (!name) return;
    await api("/connectors", {
      method: "POST",
      headers: {
        "Content-Type": "application/json"
      },
      body: JSON.stringify({
        name
      })
    });
    setName("");
    refresh();
  };
  return /*#__PURE__*/React.createElement("div", null, /*#__PURE__*/React.createElement("h1", {
    className: "h1"
  }, "Коннекторы"), /*#__PURE__*/React.createElement("p", {
    className: "sub"
  }, "Агенты сбора у заказчика (pull-модель, только исходящие соединения; офлайн-курьер для изолированного контура)."), /*#__PURE__*/React.createElement("div", {
    className: "card",
    style: {
      marginBottom: 16
    }
  }, /*#__PURE__*/React.createElement("div", {
    className: "cb row"
  }, /*#__PURE__*/React.createElement("div", {
    className: "field"
  }, /*#__PURE__*/React.createElement("label", null, "Название коннектора"), /*#__PURE__*/React.createElement("input", {
    value: name,
    onChange: e => setName(e.target.value),
    placeholder: "Коннектор-1",
    style: {
      minWidth: 260
    }
  })), /*#__PURE__*/React.createElement("button", {
    className: "btn",
    onClick: add
  }, "Зарегистрировать"))), /*#__PURE__*/React.createElement("div", {
    className: "card"
  }, /*#__PURE__*/React.createElement("div", {
    className: "cb"
  }, /*#__PURE__*/React.createElement("table", null, /*#__PURE__*/React.createElement("thead", null, /*#__PURE__*/React.createElement("tr", null, /*#__PURE__*/React.createElement("th", null, "#"), /*#__PURE__*/React.createElement("th", null, "Коннектор"), /*#__PURE__*/React.createElement("th", null, "Последний дозвон"))), /*#__PURE__*/React.createElement("tbody", null, list.map(c => /*#__PURE__*/React.createElement("tr", {
    key: c.id
  }, /*#__PURE__*/React.createElement("td", {
    className: "mono"
  }, c.id), /*#__PURE__*/React.createElement("td", null, /*#__PURE__*/React.createElement("b", null, c.name)), /*#__PURE__*/React.createElement("td", {
    className: "sub2"
  }, c.last_seen ? c.last_seen.replace("T", " ").slice(0, 16) : "ни разу"))), list.length === 0 && /*#__PURE__*/React.createElement("tr", null, /*#__PURE__*/React.createElement("td", {
    colSpan: "3",
    className: "sub2"
  }, "Коннекторы не зарегистрированы.")))))));
}

/* ----------------------------------------------------------------- приложение */
const NAV = [{
  sec: "Обзор",
  items: [{
    id: "dash",
    ic: "▦",
    l: "Дашборд"
  }, {
    id: "surveys",
    ic: "▤",
    l: "Сканирования"
  }]
}, {
  sec: "Сеть",
  items: [{
    id: "assets",
    ic: "🖥",
    l: "Активы",
    cnt: "assets"
  }, {
    id: "netmap",
    ic: "◈",
    l: "Схема сети"
  }]
}, {
  sec: "Система",
  items: [{
    id: "creds",
    ic: "🔑",
    l: "Учётные записи"
  }, {
    id: "connectors",
    ic: "⇄",
    l: "Коннекторы"
  }]
}];
const TITLES = {
  dash: "Дашборд",
  surveys: "Сканирования",
  task: "Задача",
  assets: "Активы",
  asset: "Актив",
  netmap: "Схема сети",
  newscan: "Новое сканирование",
  creds: "Учётные записи",
  connectors: "Коннекторы"
};
function App() {
  const [tasks, setTasks] = useState([]);
  const [activeId, setActiveId] = useState(null);
  const [D, setD] = useState(null);
  const [nav, setNav] = useState({
    view: "dash"
  });
  const [busy, setBusy] = useState(false);
  const [savedCreds, setSavedCreds] = useState([]);
  const loadCreds = useCallback(() => api("/credentials").then(setSavedCreds).catch(() => {}), []);
  useEffect(() => {
    loadCreds();
  }, [loadCreds]);
  const loadTasks = useCallback(() => api("/tasks?limit=50").then(ts => {
    setTasks(ts);
    setActiveId(id => id || (ts.find(t => t.status === "done") || {}).id || null);
    return ts;
  }).catch(() => []), []);
  useEffect(() => {
    loadTasks();
  }, [loadTasks]);
  const activeStatus = (tasks.find(t => t.id === activeId) || {}).status;
  useEffect(() => {
    if (!activeId) {
      setD(null);
      return;
    }
    api("/tasks/" + activeId).then(t => setD(t.dashboard || null)).catch(() => setD(null));
  }, [activeId, activeStatus]);
  useEffect(() => {
    if (!tasks.some(t => t.status === "running" || t.status === "queued")) return;
    const h = setInterval(() => loadTasks().then(ts => {
      const run = ts.find(t => t.status === "running" || t.status === "queued");
      if (!run) {
        const done = ts.find(t => t.status === "done");
        if (done) setActiveId(done.id);
      }
    }), 2000);
    return () => clearInterval(h);
  }, [tasks, loadTasks]);
  const go = n => {
    setNav(n);
    window.scrollTo(0, 0);
  };
  const setActive = id => {
    setActiveId(id);
    go({
      view: "dash"
    });
  };
  const runScan = async (targets, credIds) => {
    const nm = "Скан — " + (targets.split(/[\s,;]+/)[0] || "");
    const body = {
      kind: "inventory",
      run: "async",
      name: nm,
      customer: null,
      targets
    };
    if (credIds && credIds.length) body.cred_ids = credIds;
    setBusy(true);
    try {
      const t = await api("/tasks", {
        method: "POST",
        headers: {
          "Content-Type": "application/json"
        },
        body: JSON.stringify(body)
      });
      await loadTasks();
      setActiveId(t.id);
      go({
        view: "task",
        taskId: t.id
      });
    } catch (e) {
      alert("Не удалось запустить: " + (e && e.detail ? e.detail : JSON.stringify(e)));
    }
    setBusy(false);
  };
  const counts = D ? D.totals || {} : {};
  let screen;
  if (nav.view === "dash") screen = /*#__PURE__*/React.createElement(Dash, {
    D: D,
    tasks: tasks,
    go: go
  });else if (nav.view === "surveys") screen = /*#__PURE__*/React.createElement(Surveys, {
    tasks: tasks,
    go: go,
    onNew: () => go({
      view: "newscan"
    }),
    setActive: setActive
  });else if (nav.view === "task") screen = /*#__PURE__*/React.createElement(TaskDetail, {
    taskId: nav.taskId,
    go: go,
    setActive: setActive
  });else if (nav.view === "newscan") screen = /*#__PURE__*/React.createElement(NewScan, {
    onRun: runScan,
    busy: busy,
    go: go,
    savedCreds: savedCreds,
    initTargets: nav.initTargets,
    initCreds: nav.initCreds
  });else if (nav.view === "assets") screen = /*#__PURE__*/React.createElement(Assets, {
    D: D,
    go: go
  });else if (nav.view === "asset") screen = /*#__PURE__*/React.createElement(AssetDetail, {
    D: D,
    name: nav.assetName,
    go: go
  });else if (nav.view === "netmap") screen = /*#__PURE__*/React.createElement(NetMap, {
    taskId: activeId,
    go: go
  });else if (nav.view === "creds") screen = /*#__PURE__*/React.createElement(Credentials, {
    onChange: loadCreds
  });else if (nav.view === "connectors") screen = /*#__PURE__*/React.createElement(Connectors, null);else screen = /*#__PURE__*/React.createElement(Dash, {
    D: D,
    tasks: tasks,
    go: go
  });
  const crumb = nav.view === "asset" ? /*#__PURE__*/React.createElement(React.Fragment, null, /*#__PURE__*/React.createElement("span", {
    className: "link",
    onClick: () => go({
      view: "assets"
    })
  }, "Активы"), /*#__PURE__*/React.createElement("span", {
    className: "sep"
  }, "/"), /*#__PURE__*/React.createElement("b", null, nav.assetName)) : /*#__PURE__*/React.createElement("b", null, TITLES[nav.view] || "Дашборд");
  return /*#__PURE__*/React.createElement("div", {
    className: "app"
  }, /*#__PURE__*/React.createElement("aside", {
    className: "nav"
  }, /*#__PURE__*/React.createElement("div", {
    className: "brand"
  }, /*#__PURE__*/React.createElement("span", {
    className: "logo"
  }, "◢"), "surveyscan"), NAV.map(g => /*#__PURE__*/React.createElement(React.Fragment, {
    key: g.sec
  }, /*#__PURE__*/React.createElement("div", {
    className: "navsec"
  }, g.sec), g.items.map(it => {
    const on = nav.view === it.id || it.id === "assets" && nav.view === "asset";
    const cc = it.cnt && counts[it.cnt] != null ? counts[it.cnt] : null;
    return /*#__PURE__*/React.createElement("button", {
      className: "navi" + (on ? " on" : ""),
      key: it.id,
      onClick: () => go({
        view: it.id
      })
    }, /*#__PURE__*/React.createElement("span", {
      className: "ico"
    }, it.ic), it.l, cc ? /*#__PURE__*/React.createElement("span", {
      className: "cnt"
    }, cc) : null);
  }))), /*#__PURE__*/React.createElement("div", {
    className: "foot"
  }, "сканер инвентаризации", /*#__PURE__*/React.createElement("br", null), "и схемы сети")), /*#__PURE__*/React.createElement("div", {
    className: "main"
  }, /*#__PURE__*/React.createElement("div", {
    className: "top"
  }, /*#__PURE__*/React.createElement("div", {
    className: "crumb"
  }, crumb), /*#__PURE__*/React.createElement("div", {
    className: "search"
  }, "⌕ Поиск по активам, IP…"), /*#__PURE__*/React.createElement("div", {
    className: "right"
  }, /*#__PURE__*/React.createElement("button", {
    className: "btn",
    onClick: () => go({
      view: "newscan"
    })
  }, "+ Новое сканирование"), /*#__PURE__*/React.createElement("div", {
    className: "av"
  }, "ИП"))), /*#__PURE__*/React.createElement("div", {
    className: "body"
  }, screen)));
}
ReactDOM.createRoot(document.getElementById("root")).render(/*#__PURE__*/React.createElement(App, null));
