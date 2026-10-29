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
  }, "\u041D\u043E\u0432\u043E\u0435 \u0441\u043A\u0430\u043D\u0438\u0440\u043E\u0432\u0430\u043D\u0438\u0435"), /*#__PURE__*/React.createElement("p", {
    className: "sub"
  }, "\u0423\u043A\u0430\u0436\u0438\u0442\u0435 \u043F\u043E\u0434\u0441\u0435\u0442\u0438 \u0438 \u0445\u043E\u0441\u0442\u044B. \u0421\u0431\u043E\u0440 \u2014 \u0441\u0435\u0442\u0435\u0432\u043E\u0439 (nmap): \u0436\u0438\u0432\u044B\u0435 \u0445\u043E\u0441\u0442\u044B, \u043F\u043E\u0440\u0442\u044B, \u0432\u0435\u0440\u0441\u0438\u0438 \u0441\u0435\u0440\u0432\u0438\u0441\u043E\u0432, \u041E\u0421 \u2192 \u0441\u0445\u0435\u043C\u0430 \u0441\u0435\u0442\u0438. \u0412\u044B\u0431\u0435\u0440\u0438\u0442\u0435 \u0443\u0447\u0451\u0442\u043D\u044B\u0435 \u0437\u0430\u043F\u0438\u0441\u0438 \u2014 \u0441\u043A\u0430\u043D\u0435\u0440 \u043F\u043E\u0434\u043A\u043B\u044E\u0447\u0438\u0442\u0441\u044F \u043A \u0430\u043A\u0442\u0438\u0432\u0430\u043C (SSH/WinRM/SNMP) \u0438 \u0441\u043E\u0431\u0435\u0440\u0451\u0442 \u043F\u043E\u043B\u043D\u044B\u0439 \u0438\u043D\u0432\u0435\u043D\u0442\u0430\u0440\u044C; \u043A \u043A\u0430\u0436\u0434\u043E\u043C\u0443 \u0430\u043A\u0442\u0438\u0432\u0443 \u0423\u0417 \u043F\u043E\u0434\u0431\u0438\u0440\u0430\u0435\u0442\u0441\u044F \u0430\u0432\u0442\u043E\u043C\u0430\u0442\u0438\u0447\u0435\u0441\u043A\u0438."), /*#__PURE__*/React.createElement("div", {
    className: "card",
    style: {
      maxWidth: 820
    }
  }, /*#__PURE__*/React.createElement("div", {
    className: "cb"
  }, /*#__PURE__*/React.createElement("div", {
    className: "field"
  }, /*#__PURE__*/React.createElement("label", null, "\u0426\u0435\u043B\u0438: \u043F\u043E\u0434\u0441\u0435\u0442\u0438 / \u0445\u043E\u0441\u0442\u044B"), /*#__PURE__*/React.createElement("textarea", {
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
  }, "\u0427\u0435\u0440\u0435\u0437 \u0437\u0430\u043F\u044F\u0442\u0443\u044E, \u043F\u0440\u043E\u0431\u0435\u043B \u0438\u043B\u0438 \u0441 \u043D\u043E\u0432\u043E\u0439 \u0441\u0442\u0440\u043E\u043A\u0438. \u041F\u0440\u0438\u043C\u0435\u0440\u044B: ", /*#__PURE__*/React.createElement("span", {
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
  }, "\u0423\u0447\u0451\u0442\u043D\u044B\u0435 \u0437\u0430\u043F\u0438\u0441\u0438 \u0434\u043B\u044F \u0441\u0431\u043E\u0440\u0430 ", /*#__PURE__*/React.createElement("span", {
    className: "sub2",
    style: {
      fontWeight: 400
    }
  }, "(\u043E\u043F\u0446\u0438\u043E\u043D\u0430\u043B\u044C\u043D\u043E \u2014 \u0431\u0435\u0437 \u043D\u0438\u0445 \u0442\u043E\u043B\u044C\u043A\u043E \u0441\u0435\u0442\u0435\u0432\u043E\u0435 \u043E\u0431\u043D\u0430\u0440\u0443\u0436\u0435\u043D\u0438\u0435)")), /*#__PURE__*/React.createElement("span", {
    className: "more",
    style: {
      marginLeft: "auto"
    },
    onClick: () => go({
      view: "creds"
    })
  }, "\u0423\u043F\u0440\u0430\u0432\u043B\u0435\u043D\u0438\u0435 \u0423\u0417 \u2192")), !savedCreds || savedCreds.length === 0 ? /*#__PURE__*/React.createElement("div", {
    className: "sub2",
    style: {
      margin: "8px 0"
    }
  }, "\u0421\u043E\u0445\u0440\u0430\u043D\u0451\u043D\u043D\u044B\u0445 \u0423\u0417 \u043D\u0435\u0442. ", /*#__PURE__*/React.createElement("span", {
    className: "link",
    onClick: () => go({
      view: "creds"
    })
  }, "\u0414\u043E\u0431\u0430\u0432\u044C\u0442\u0435 \u0443\u0447\u0451\u0442\u043D\u0443\u044E \u0437\u0430\u043F\u0438\u0441\u044C"), " \u0432\u043E \u0432\u043A\u043B\u0430\u0434\u043A\u0435 \xAB\u0423\u0447\u0451\u0442\u043D\u044B\u0435 \u0437\u0430\u043F\u0438\u0441\u0438\xBB \u2014 \u0437\u0430\u0442\u0435\u043C \u0432\u044B\u0431\u0438\u0440\u0430\u0439\u0442\u0435 \u0435\u0451 \u0437\u0434\u0435\u0441\u044C.") : /*#__PURE__*/React.createElement("div", {
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
  }, "\u041E\u0442\u043C\u0435\u043D\u0430")))), /*#__PURE__*/React.createElement("div", {
    className: "warn",
    style: {
      maxWidth: 820,
      marginTop: 14
    }
  }, "\u0421\u0435\u043A\u0440\u0435\u0442\u044B \u0445\u0440\u0430\u043D\u044F\u0442\u0441\u044F \u0432 \u0431\u0430\u0437\u0435 \u0432 \u0437\u0430\u0448\u0438\u0444\u0440\u043E\u0432\u0430\u043D\u043D\u043E\u043C \u0432\u0438\u0434\u0435 (\u043A\u043B\u044E\u0447 \u2014 \u0432 \u043F\u0435\u0440\u0435\u043C\u0435\u043D\u043D\u043E\u0439 \u043E\u043A\u0440\u0443\u0436\u0435\u043D\u0438\u044F, \u043D\u0435 \u0432 \u0411\u0414) \u0438 \u0440\u0430\u0441\u0448\u0438\u0444\u0440\u043E\u0432\u044B\u0432\u0430\u044E\u0442\u0441\u044F \u0442\u043E\u043B\u044C\u043A\u043E \u043D\u0430 \u0432\u0440\u0435\u043C\u044F \u0437\u0430\u0434\u0430\u0447\u0438. \u041A \u043A\u0430\u0436\u0434\u043E\u043C\u0443 \u0430\u043A\u0442\u0438\u0432\u0443 \u043F\u0440\u0438\u043C\u0435\u043D\u044F\u0435\u0442\u0441\u044F \u043F\u043E\u0434\u0445\u043E\u0434\u044F\u0449\u0430\u044F \u043F\u043E \u0442\u0438\u043F\u0443 \u0423\u0417 (\u043F\u0435\u0440\u0435\u0431\u043E\u0440 \u0434\u043E \u043F\u0435\u0440\u0432\u043E\u0439 \u0443\u0441\u043F\u0435\u0448\u043D\u043E\u0439); \u0432 \u0441\u0432\u043E\u0434\u043A\u0435 \u0444\u0438\u043A\u0441\u0438\u0440\u0443\u0435\u0442\u0441\u044F \u0442\u043E\u043B\u044C\u043A\u043E \u043B\u043E\u0433\u0438\u043D."));
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
  }, "\u0423\u0447\u0451\u0442\u043D\u044B\u0435 \u0437\u0430\u043F\u0438\u0441\u0438"), /*#__PURE__*/React.createElement("p", {
    className: "sub"
  }, "\u0425\u0440\u0430\u043D\u0438\u043B\u0438\u0449\u0435 \u0423\u0417 \u0434\u043B\u044F \u0430\u0443\u0442\u0435\u043D\u0442\u0438\u0444\u0438\u0446\u0438\u0440\u043E\u0432\u0430\u043D\u043D\u043E\u0433\u043E \u0441\u0431\u043E\u0440\u0430. \u0417\u0430\u0432\u043E\u0434\u044F\u0442\u0441\u044F \u043E\u0434\u0438\u043D \u0440\u0430\u0437 \u2014 \u0437\u0430\u0442\u0435\u043C \u0432\u044B\u0431\u0438\u0440\u0430\u044E\u0442\u0441\u044F \u0432 \u0444\u043E\u0440\u043C\u0435 \u0441\u043A\u0430\u043D\u0430. \u0421\u0435\u043A\u0440\u0435\u0442\u044B \u0448\u0438\u0444\u0440\u0443\u044E\u0442\u0441\u044F \u0432 \u0411\u0414 (\u043A\u043B\u044E\u0447 \u0432 \u043F\u0435\u0440\u0435\u043C\u0435\u043D\u043D\u043E\u0439 \u043E\u043A\u0440\u0443\u0436\u0435\u043D\u0438\u044F, \u043D\u0435 \u0432 \u0431\u0430\u0437\u0435)."), /*#__PURE__*/React.createElement("div", {
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
    placeholder: "\u0418\u043C\u044F: Linux-\u0430\u0443\u0434\u0438\u0442",
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
  }, "SSH \xB7 Linux"), /*#__PURE__*/React.createElement("option", {
    value: "winrm"
  }, "WinRM \xB7 Windows"), /*#__PURE__*/React.createElement("option", {
    value: "snmp"
  }, "SNMP \xB7 \u043E\u0431\u043E\u0440\u0443\u0434.")), /*#__PURE__*/React.createElement("input", {
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
    placeholder: "\u0434\u043E\u043C\u0435\u043D",
    value: f.domain,
    style: {
      width: 90
    },
    onChange: e => setFF("domain", e.target.value)
  }) : null, /*#__PURE__*/React.createElement("input", {
    placeholder: "\u043F\u043E\u0440\u0442",
    value: f.port,
    style: {
      width: 64
    },
    onChange: e => setFF("port", e.target.value)
  }), /*#__PURE__*/React.createElement("button", {
    className: "btn sm",
    onClick: add
  }, "\u0421\u043E\u0445\u0440\u0430\u043D\u0438\u0442\u044C")), err ? /*#__PURE__*/React.createElement("div", {
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
  }, /*#__PURE__*/React.createElement("table", null, /*#__PURE__*/React.createElement("thead", null, /*#__PURE__*/React.createElement("tr", null, /*#__PURE__*/React.createElement("th", null, "\u0418\u043C\u044F"), /*#__PURE__*/React.createElement("th", null, "\u0422\u0438\u043F"), /*#__PURE__*/React.createElement("th", null, "\u041B\u043E\u0433\u0438\u043D / \u043F\u043E\u0440\u0442"), /*#__PURE__*/React.createElement("th", null, "\u0414\u043E\u0431\u0430\u0432\u043B\u0435\u043D\u0430"), /*#__PURE__*/React.createElement("th", null))), /*#__PURE__*/React.createElement("tbody", null, list.map(c => /*#__PURE__*/React.createElement("tr", {
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
    title: "\u0423\u0434\u0430\u043B\u0438\u0442\u044C",
    onClick: () => del(c.id)
  }, "\u2715")))), list.length === 0 && /*#__PURE__*/React.createElement("tr", null, /*#__PURE__*/React.createElement("td", {
    colSpan: "5",
    className: "sub2"
  }, "\u0423\u0417 \u043D\u0435 \u0437\u0430\u0432\u0435\u0434\u0435\u043D\u044B. \u0414\u043E\u0431\u0430\u0432\u044C\u0442\u0435 \u043F\u0435\u0440\u0432\u0443\u044E \u0432\u044B\u0448\u0435.")))))), /*#__PURE__*/React.createElement("div", {
    className: "warn",
    style: {
      maxWidth: 820,
      marginTop: 14
    }
  }, "\u041F\u0430\u0440\u043E\u043B\u0438, \u043A\u043B\u044E\u0447\u0438 \u0438 community \u0445\u0440\u0430\u043D\u044F\u0442\u0441\u044F \u0437\u0430\u0448\u0438\u0444\u0440\u043E\u0432\u0430\u043D\u043D\u044B\u043C\u0438 (Fernet). \u041C\u0430\u0441\u0442\u0435\u0440-\u043A\u043B\u044E\u0447 \u0431\u0435\u0440\u0451\u0442\u0441\u044F \u0438\u0437 ", /*#__PURE__*/React.createElement("span", {
    className: "mono"
  }, "SURVEYSCAN_SECRET_KEY"), " \u0438 \u0432 \u0431\u0430\u0437\u0435 \u043D\u0435 \u043B\u0435\u0436\u0438\u0442 \u2014 \u0434\u0430\u043C\u043F \u0411\u0414 \u0441\u0430\u043C \u043F\u043E \u0441\u0435\u0431\u0435 \u0441\u0435\u043A\u0440\u0435\u0442\u044B \u043D\u0435 \u0440\u0430\u0441\u043A\u0440\u043E\u0435\u0442. \u0417\u0430\u0434\u0430\u0439\u0442\u0435 \u044D\u0442\u0443 \u043F\u0435\u0440\u0435\u043C\u0435\u043D\u043D\u0443\u044E \u0432 \u0441\u0432\u043E\u0451\u043C \u043E\u043A\u0440\u0443\u0436\u0435\u043D\u0438\u0438 (\u0438\u043D\u0430\u0447\u0435 \u043A\u043B\u044E\u0447 \u0433\u0435\u043D\u0435\u0440\u0438\u0440\u0443\u0435\u0442\u0441\u044F \u0432 \u0442\u043E\u043C\u0435 \u0434\u0430\u043D\u043D\u044B\u0445 \u0438 \u0442\u0435\u0440\u044F\u0435\u0442\u0441\u044F \u0432\u043C\u0435\u0441\u0442\u0435 \u0441 \u043D\u0438\u043C)."));
}

/* ----------------------------------------------------------------- Дашборд */
function Dash({
  D,
  tasks,
  go
}) {
  if (!D) return /*#__PURE__*/React.createElement("div", {
    className: "empty"
  }, "\u041D\u0435\u0442 \u0434\u0430\u043D\u043D\u044B\u0445. \u0417\u0430\u043F\u0443\u0441\u0442\u0438\u0442\u0435 \u0441\u043A\u0430\u043D\u0438\u0440\u043E\u0432\u0430\u043D\u0438\u0435: \xAB+ \u041D\u043E\u0432\u043E\u0435 \u0441\u043A\u0430\u043D\u0438\u0440\u043E\u0432\u0430\u043D\u0438\u0435\xBB.");
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
  }, "\u0418\u043D\u0432\u0435\u043D\u0442\u0430\u0440\u0438\u0437\u0430\u0446\u0438\u044F \u0441\u0435\u0442\u0438 \xB7 ", D.generated), /*#__PURE__*/React.createElement("div", {
    className: "kpis"
  }, kpi(D.totals ? D.totals.assets : assets.length, "Активов"), kpi(ts.hosts != null ? ts.hosts : "—", "Хостов"), kpi(ts.devices != null ? ts.devices : "—", "Сетевых устройств"), kpi(ts.subnets != null ? ts.subnets : "—", "Подсетей"), kpi(ts.services != null ? ts.services : "—", "Открытых сервисов")), /*#__PURE__*/React.createElement("div", {
    className: "cols dash"
  }, /*#__PURE__*/React.createElement("div", {
    className: "card"
  }, /*#__PURE__*/React.createElement("div", {
    className: "ch"
  }, /*#__PURE__*/React.createElement("h3", null, "\u0410\u043A\u0442\u0438\u0432\u044B"), /*#__PURE__*/React.createElement("span", {
    className: "more",
    onClick: () => go({
      view: "assets"
    })
  }, "\u0412\u0441\u0435 \u0430\u043A\u0442\u0438\u0432\u044B \u2192")), /*#__PURE__*/React.createElement("div", {
    className: "cb"
  }, /*#__PURE__*/React.createElement("table", null, /*#__PURE__*/React.createElement("thead", null, /*#__PURE__*/React.createElement("tr", null, /*#__PURE__*/React.createElement("th", null, "\u0410\u043A\u0442\u0438\u0432"), /*#__PURE__*/React.createElement("th", null, "IP"), /*#__PURE__*/React.createElement("th", null, "\u041E\u0421 / \u043F\u043B\u0430\u0442\u0444\u043E\u0440\u043C\u0430"), /*#__PURE__*/React.createElement("th", null, "\u0421\u0435\u0440\u0432\u0438\u0441\u044B"))), /*#__PURE__*/React.createElement("tbody", null, assets.slice(0, 6).map(a => /*#__PURE__*/React.createElement("tr", {
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
  }, "\u0410\u043A\u0442\u0438\u0432\u044B \u043D\u0435 \u043D\u0430\u0439\u0434\u0435\u043D\u044B.")))))), /*#__PURE__*/React.createElement("div", {
    className: "card"
  }, /*#__PURE__*/React.createElement("div", {
    className: "ch"
  }, /*#__PURE__*/React.createElement("h3", null, "\u0421\u0445\u0435\u043C\u0430 \u0441\u0435\u0442\u0438"), /*#__PURE__*/React.createElement("span", {
    className: "more",
    onClick: () => go({
      view: "netmap"
    })
  }, "\u041E\u0442\u043A\u0440\u044B\u0442\u044C \u2192")), /*#__PURE__*/React.createElement("div", {
    className: "cb"
  }, /*#__PURE__*/React.createElement("div", {
    style: {
      fontSize: 13,
      color: "var(--muted)",
      lineHeight: 1.7
    }
  }, "\u0423\u0437\u043B\u043E\u0432: ", /*#__PURE__*/React.createElement("b", {
    style: {
      color: "var(--ink)"
    }
  }, ts.nodes || 0), /*#__PURE__*/React.createElement("br", null), "\u041F\u043E\u0434\u0441\u0435\u0442\u0435\u0439: ", /*#__PURE__*/React.createElement("b", {
    style: {
      color: "var(--ink)"
    }
  }, ts.subnets || 0), /*#__PURE__*/React.createElement("br", null), "\u0421\u0435\u0442\u0435\u0432\u044B\u0445 \u0443\u0441\u0442\u0440\u043E\u0439\u0441\u0442\u0432: ", /*#__PURE__*/React.createElement("b", {
    style: {
      color: "var(--ink)"
    }
  }, ts.devices || 0), /*#__PURE__*/React.createElement("br", null), "\u0421\u0432\u044F\u0437\u0435\u0439: ", /*#__PURE__*/React.createElement("b", {
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
  }, "\u041E\u0442\u043A\u0440\u044B\u0442\u044C \u0441\u0445\u0435\u043C\u0443 \u0441\u0435\u0442\u0438"))), /*#__PURE__*/React.createElement("div", {
    className: "card"
  }, /*#__PURE__*/React.createElement("div", {
    className: "ch"
  }, /*#__PURE__*/React.createElement("h3", null, "\u0421\u043A\u0430\u043D\u0438\u0440\u043E\u0432\u0430\u043D\u0438\u044F"), /*#__PURE__*/React.createElement("span", {
    className: "more",
    onClick: () => go({
      view: "surveys"
    })
  }, "\u0412\u0441\u0435 \u2192")), /*#__PURE__*/React.createElement("div", {
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
  }, "\u041F\u043E\u043A\u0430 \u043D\u0435\u0442 \u0441\u043A\u0430\u043D\u0438\u0440\u043E\u0432\u0430\u043D\u0438\u0439.")))));
}

/* ----------------------------------------------------------------- Активы */
function Assets({
  D,
  go
}) {
  if (!D) return /*#__PURE__*/React.createElement("div", {
    className: "empty"
  }, "\u041D\u0435\u0442 \u0434\u0430\u043D\u043D\u044B\u0445. \u0417\u0430\u043F\u0443\u0441\u0442\u0438\u0442\u0435 \u0441\u043A\u0430\u043D\u0438\u0440\u043E\u0432\u0430\u043D\u0438\u0435.");
  const assets = D.assets || [];
  return /*#__PURE__*/React.createElement("div", null, /*#__PURE__*/React.createElement("h1", {
    className: "h1"
  }, "\u0410\u043A\u0442\u0438\u0432\u044B"), /*#__PURE__*/React.createElement("p", {
    className: "sub"
  }, "\u0418\u043D\u0432\u0435\u043D\u0442\u0430\u0440\u0438\u0437\u0430\u0446\u0438\u044F \u0430\u043A\u0442\u0438\u0432\u043E\u0432 \u043E\u0431\u0441\u043B\u0435\u0434\u043E\u0432\u0430\u043D\u0438\u044F \xAB", D.survey && D.survey.name, "\xBB."), /*#__PURE__*/React.createElement("div", {
    className: "card"
  }, /*#__PURE__*/React.createElement("div", {
    className: "cb"
  }, /*#__PURE__*/React.createElement("table", null, /*#__PURE__*/React.createElement("thead", null, /*#__PURE__*/React.createElement("tr", null, /*#__PURE__*/React.createElement("th", null, "\u0410\u043A\u0442\u0438\u0432"), /*#__PURE__*/React.createElement("th", null, "IP"), /*#__PURE__*/React.createElement("th", null, "\u041E\u0421 / \u043F\u043B\u0430\u0442\u0444\u043E\u0440\u043C\u0430"), /*#__PURE__*/React.createElement("th", null, "\u0422\u0438\u043F"), /*#__PURE__*/React.createElement("th", {
    className: "num"
  }, "\u0421\u0435\u0440\u0432\u0438\u0441\u043E\u0432"))), /*#__PURE__*/React.createElement("tbody", null, assets.map(a => /*#__PURE__*/React.createElement("tr", {
    key: a.name,
    className: "click",
    onClick: () => go({
      view: "asset",
      assetName: a.name
    })
  }, /*#__PURE__*/React.createElement("td", null, /*#__PURE__*/React.createElement("b", null, a.name)), /*#__PURE__*/React.createElement("td", {
    className: "mono"
  }, a.ips || "—"), /*#__PURE__*/React.createElement("td", null, a.os || "—", a.build ? /*#__PURE__*/React.createElement("div", {
    className: "sub2 mono"
  }, a.build) : null), /*#__PURE__*/React.createElement("td", null, a.kind), /*#__PURE__*/React.createElement("td", {
    className: "num"
  }, (a.services || []).length))), assets.length === 0 && /*#__PURE__*/React.createElement("tr", null, /*#__PURE__*/React.createElement("td", {
    colSpan: "5",
    className: "sub2"
  }, "\u0410\u043A\u0442\u0438\u0432\u044B \u043D\u0435 \u043D\u0430\u0439\u0434\u0435\u043D\u044B.")))))));
}
function AssetDetail({
  D,
  name,
  go
}) {
  const a = (D.assets || []).find(x => x.name === name);
  if (!a) return /*#__PURE__*/React.createElement("div", {
    className: "empty"
  }, "\u0410\u043A\u0442\u0438\u0432 \u043D\u0435 \u043D\u0430\u0439\u0434\u0435\u043D.");
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
  }, "\u0410\u043A\u0442\u0438\u0432\u044B"), /*#__PURE__*/React.createElement("span", {
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
  }, a.ips, a.os ? " · " + a.os : ""))), /*#__PURE__*/React.createElement("div", {
    className: "detail",
    style: {
      marginTop: 10
    }
  }, /*#__PURE__*/React.createElement("div", {
    className: "card"
  }, /*#__PURE__*/React.createElement("div", {
    className: "ch"
  }, /*#__PURE__*/React.createElement("h3", null, "\u041E\u0442\u043A\u0440\u044B\u0442\u044B\u0435 \u0441\u0435\u0440\u0432\u0438\u0441\u044B")), /*#__PURE__*/React.createElement("div", {
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
  }, "\u041E\u0442\u043A\u0440\u044B\u0442\u044B\u0445 \u0441\u0435\u0440\u0432\u0438\u0441\u043E\u0432 \u043D\u0435 \u043E\u0431\u043D\u0430\u0440\u0443\u0436\u0435\u043D\u043E."))), /*#__PURE__*/React.createElement("div", null, /*#__PURE__*/React.createElement("div", {
    className: "card"
  }, /*#__PURE__*/React.createElement("div", {
    className: "ch"
  }, /*#__PURE__*/React.createElement("h3", null, "\u0421\u0432\u0435\u0434\u0435\u043D\u0438\u044F")), /*#__PURE__*/React.createElement("div", {
    className: "cb"
  }, /*#__PURE__*/React.createElement("div", {
    className: "kv"
  }, /*#__PURE__*/React.createElement("span", {
    className: "k"
  }, "\u0422\u0438\u043F"), /*#__PURE__*/React.createElement("span", {
    className: "v"
  }, a.kind)), /*#__PURE__*/React.createElement("div", {
    className: "kv"
  }, /*#__PURE__*/React.createElement("span", {
    className: "k"
  }, "IP"), /*#__PURE__*/React.createElement("span", {
    className: "v mono"
  }, a.ips || "—")), /*#__PURE__*/React.createElement("div", {
    className: "kv"
  }, /*#__PURE__*/React.createElement("span", {
    className: "k"
  }, "\u041E\u0421 / \u043F\u043B\u0430\u0442\u0444\u043E\u0440\u043C\u0430"), /*#__PURE__*/React.createElement("span", {
    className: "v"
  }, a.os || "—")), /*#__PURE__*/React.createElement("div", {
    className: "kv"
  }, /*#__PURE__*/React.createElement("span", {
    className: "k"
  }, "\u041F\u0430\u043A\u0435\u0442\u043E\u0432 / \u041F\u041E"), /*#__PURE__*/React.createElement("span", {
    className: "v"
  }, a.software || 0)), /*#__PURE__*/React.createElement("div", {
    className: "kv"
  }, /*#__PURE__*/React.createElement("span", {
    className: "k"
  }, "\u041E\u0442\u043A\u0440\u044B\u0442\u044B\u0445 \u0441\u0435\u0440\u0432\u0438\u0441\u043E\u0432"), /*#__PURE__*/React.createElement("span", {
    className: "v"
  }, (a.services || []).length)))), a.sec_tools && a.sec_tools.length ? /*#__PURE__*/React.createElement("div", {
    className: "card",
    style: {
      marginTop: 16
    }
  }, /*#__PURE__*/React.createElement("div", {
    className: "ch"
  }, /*#__PURE__*/React.createElement("h3", null, "\u0421\u0440\u0435\u0434\u0441\u0442\u0432\u0430 \u0437\u0430\u0449\u0438\u0442\u044B")), /*#__PURE__*/React.createElement("div", {
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
  }, "\u2713"), " ", t)))) : null)));
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
  }, "\u0421\u0445\u0435\u043C\u0430 \u0441\u0435\u0442\u0438"), /*#__PURE__*/React.createElement("div", {
    className: "empty"
  }, err, ". \u0417\u0430\u043F\u0443\u0441\u0442\u0438\u0442\u0435 \u0441\u043A\u0430\u043D\u0438\u0440\u043E\u0432\u0430\u043D\u0438\u0435 \u0438 \u0434\u043E\u0436\u0434\u0438\u0442\u0435\u0441\u044C \u0433\u043E\u0442\u043E\u0432\u043D\u043E\u0441\u0442\u0438."));
  return /*#__PURE__*/React.createElement("div", null, /*#__PURE__*/React.createElement("div", {
    className: "maptools"
  }, /*#__PURE__*/React.createElement("h1", {
    className: "h1",
    style: {
      margin: 0
    }
  }, "\u0421\u0445\u0435\u043C\u0430 \u0441\u0435\u0442\u0438"), /*#__PURE__*/React.createElement("span", {
    className: "sp"
  }), /*#__PURE__*/React.createElement("button", {
    className: "btn ghost",
    onClick: fit
  }, "\u0412\u043F\u0438\u0441\u0430\u0442\u044C"), /*#__PURE__*/React.createElement("button", {
    className: "btn ghost",
    onClick: () => relayout("breadthfirst")
  }, "\u0421\u043B\u043E\u0438"), /*#__PURE__*/React.createElement("button", {
    className: "btn ghost",
    onClick: () => relayout("cose")
  }, "\u0421\u0432\u043E\u0431\u043E\u0434\u043D\u043E"), /*#__PURE__*/React.createElement("button", {
    className: "btn ghost",
    onClick: exportPng
  }, "\u042D\u043A\u0441\u043F\u043E\u0440\u0442 PNG"), /*#__PURE__*/React.createElement("a", {
    className: "btn",
    href: "/tasks/" + taskId + "/topology.svg",
    target: "_blank",
    style: {
      textDecoration: "none"
    }
  }, "\u042D\u043A\u0441\u043F\u043E\u0440\u0442 SVG")), /*#__PURE__*/React.createElement("div", {
    id: "cy",
    ref: box
  }), /*#__PURE__*/React.createElement("div", {
    className: "legend2"
  }, /*#__PURE__*/React.createElement("span", null, /*#__PURE__*/React.createElement("i", {
    style: {
      background: "#3D4EA6",
      transform: "rotate(45deg)"
    }
  }), "\u042F\u0434\u0440\u043E \u0441\u0435\u0442\u0438"), /*#__PURE__*/React.createElement("span", null, /*#__PURE__*/React.createElement("i", {
    style: {
      background: "#E8EAEF"
    }
  }), "\u041F\u043E\u0434\u0441\u0435\u0442\u044C"), /*#__PURE__*/React.createElement("span", null, /*#__PURE__*/React.createElement("i", {
    style: {
      background: "#11141B"
    }
  }), "\u0421\u0435\u0442\u0435\u0432\u043E\u0435 \u0443\u0441\u0442\u0440\u043E\u0439\u0441\u0442\u0432\u043E"), /*#__PURE__*/React.createElement("span", null, /*#__PURE__*/React.createElement("i", {
    style: {
      background: "#fff",
      border: "1px solid #C4CAD4"
    }
  }), "\u0425\u043E\u0441\u0442"), /*#__PURE__*/React.createElement("span", {
    style: {
      marginLeft: "auto"
    }
  }, "\u043A\u043B\u0438\u043A \u043F\u043E \u0443\u0437\u043B\u0443 \u2014 \u043A\u0430\u0440\u0442\u043E\u0447\u043A\u0430 \u0430\u043A\u0442\u0438\u0432\u0430", stats ? ` · узлов ${stats.nodes}, связей ${stats.edges}` : "")));
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
  }, "\u0417\u0430\u0433\u0440\u0443\u0437\u043A\u0430 \u0437\u0430\u0434\u0430\u0447\u0438\u2026");
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
  }, "\u0421\u043A\u0430\u043D\u0438\u0440\u043E\u0432\u0430\u043D\u0438\u044F"), /*#__PURE__*/React.createElement("span", {
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
  }, "\u041E\u0442\u043C\u0435\u043D\u0438\u0442\u044C") : null, /*#__PURE__*/React.createElement("button", {
    className: "btn ghost",
    onClick: repeat
  }, "\u041F\u043E\u0432\u0442\u043E\u0440\u0438\u0442\u044C"), t.status === "done" && t.has_report ? /*#__PURE__*/React.createElement("button", {
    className: "btn ghost",
    onClick: () => {
      setActive(t.id);
      go({
        view: "netmap"
      });
    }
  }, "\u0421\u0445\u0435\u043C\u0430 \u0441\u0435\u0442\u0438") : null, t.status === "done" ? /*#__PURE__*/React.createElement("button", {
    className: "btn",
    onClick: () => {
      setActive(t.id);
      go({
        view: "dash"
      });
    }
  }, "\u041E\u0442\u043A\u0440\u044B\u0442\u044C \u0440\u0435\u0437\u0443\u043B\u044C\u0442\u0430\u0442") : null)), /*#__PURE__*/React.createElement("p", {
    className: "sub"
  }, "\u0426\u0435\u043B\u0438: ", /*#__PURE__*/React.createElement("span", {
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
  }, /*#__PURE__*/React.createElement("h3", null, "\u0416\u0443\u0440\u043D\u0430\u043B \u0432\u044B\u043F\u043E\u043B\u043D\u0435\u043D\u0438\u044F")), /*#__PURE__*/React.createElement("div", {
    className: "cb"
  }, /*#__PURE__*/React.createElement("div", {
    className: "tasklog",
    ref: logRef
  }, (t.progress || []).length === 0 ? /*#__PURE__*/React.createElement("div", {
    className: "sub2"
  }, "\u041F\u043E\u043A\u0430 \u043D\u0435\u0442 \u0437\u0430\u043F\u0438\u0441\u0435\u0439. \u0414\u043B\u044F \u0434\u0435\u043C\u043E-\u0437\u0430\u0434\u0430\u0447 \u0436\u0443\u0440\u043D\u0430\u043B \u043D\u0435 \u0432\u0435\u0434\u0451\u0442\u0441\u044F.") : (t.progress || []).map((l, i) => /*#__PURE__*/React.createElement("div", {
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
  }, /*#__PURE__*/React.createElement("h3", null, "\u0423\u0447\u0451\u0442\u043D\u044B\u0435 \u0437\u0430\u043F\u0438\u0441\u0438")), /*#__PURE__*/React.createElement("div", {
    className: "cb"
  }, (p.creds || []).length === 0 ? /*#__PURE__*/React.createElement("div", {
    className: "sub2"
  }, "\u0411\u0435\u0437 \u0423\u0417 \u2014 \u0442\u043E\u043B\u044C\u043A\u043E \u0441\u0435\u0442\u0435\u0432\u043E\u0435 \u043E\u0431\u043D\u0430\u0440\u0443\u0436\u0435\u043D\u0438\u0435.") : (p.creds || []).map((c, i) => /*#__PURE__*/React.createElement("div", {
    key: i,
    style: {
      padding: "4px 0",
      fontSize: 13
    }
  }, /*#__PURE__*/React.createElement("b", null, c.name || c.username || c.type), " ", /*#__PURE__*/React.createElement("span", {
    className: "sub2"
  }, "\xB7 ", c.type, c.username ? " · " + c.username : "")))))), coll ? /*#__PURE__*/React.createElement("div", {
    className: "card",
    style: {
      marginTop: 16
    }
  }, /*#__PURE__*/React.createElement("div", {
    className: "ch"
  }, /*#__PURE__*/React.createElement("h3", null, "\u0421\u0431\u043E\u0440 \u043F\u043E \u0430\u043A\u0442\u0438\u0432\u0430\u043C"), /*#__PURE__*/React.createElement("span", {
    className: "sub2"
  }, "\u0443\u0441\u043F\u0435\u0448\u043D\u043E ", coll.collected.length, " \xB7 \u043D\u0435 \u0443\u0434\u0430\u043B\u043E\u0441\u044C ", coll.failed.length)), /*#__PURE__*/React.createElement("div", {
    className: "cb"
  }, /*#__PURE__*/React.createElement("table", null, /*#__PURE__*/React.createElement("thead", null, /*#__PURE__*/React.createElement("tr", null, /*#__PURE__*/React.createElement("th", null, "\u0410\u043A\u0442\u0438\u0432"), /*#__PURE__*/React.createElement("th", null, "IP"), /*#__PURE__*/React.createElement("th", null, "\u041F\u0440\u043E\u0442\u043E\u043A\u043E\u043B"), /*#__PURE__*/React.createElement("th", null, "\u0420\u0435\u0437\u0443\u043B\u044C\u0442\u0430\u0442"))), /*#__PURE__*/React.createElement("tbody", null, coll.collected.map((c, i) => /*#__PURE__*/React.createElement("tr", {
    key: "c" + i
  }, /*#__PURE__*/React.createElement("td", null, /*#__PURE__*/React.createElement("b", null, c.asset)), /*#__PURE__*/React.createElement("td", {
    className: "mono"
  }, c.ip), /*#__PURE__*/React.createElement("td", null, c.proto), /*#__PURE__*/React.createElement("td", {
    style: {
      color: "var(--ok,#2e7d32)"
    }
  }, "\u2713 \u0441\u043E\u0431\u0440\u0430\u043D\u043E (\u0423\u0417 ", c.cred || "—", ")"))), coll.failed.map((c, i) => /*#__PURE__*/React.createElement("tr", {
    key: "f" + i
  }, /*#__PURE__*/React.createElement("td", null, /*#__PURE__*/React.createElement("b", null, c.asset)), /*#__PURE__*/React.createElement("td", {
    className: "mono"
  }, c.ip), /*#__PURE__*/React.createElement("td", null, c.proto), /*#__PURE__*/React.createElement("td", {
    className: "sub2"
  }, "\u2715 ", c.error))), coll.collected.length === 0 && coll.failed.length === 0 && /*#__PURE__*/React.createElement("tr", null, /*#__PURE__*/React.createElement("td", {
    colSpan: "4",
    className: "sub2"
  }, "\u0410\u043A\u0442\u0438\u0432\u043E\u0432 \u0434\u043B\u044F \u0441\u0431\u043E\u0440\u0430 \u043D\u0435 \u0431\u044B\u043B\u043E.")))))) : null);
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
  }, "\u0421\u043A\u0430\u043D\u0438\u0440\u043E\u0432\u0430\u043D\u0438\u044F"), /*#__PURE__*/React.createElement("p", {
    className: "sub",
    style: {
      margin: "2px 0 0"
    }
  }, "\u0417\u0430\u043F\u0443\u0441\u043A, \u0441\u0442\u0430\u0442\u0443\u0441, \u0441\u0445\u0435\u043C\u0430 \u0438 \u0430\u043A\u0442\u0438\u0432\u044B.")), /*#__PURE__*/React.createElement("button", {
    className: "btn",
    style: {
      marginLeft: "auto"
    },
    onClick: onNew
  }, "+ \u041D\u043E\u0432\u043E\u0435 \u0441\u043A\u0430\u043D\u0438\u0440\u043E\u0432\u0430\u043D\u0438\u0435")), /*#__PURE__*/React.createElement("div", {
    className: "card"
  }, /*#__PURE__*/React.createElement("div", {
    className: "cb"
  }, /*#__PURE__*/React.createElement("table", null, /*#__PURE__*/React.createElement("thead", null, /*#__PURE__*/React.createElement("tr", null, /*#__PURE__*/React.createElement("th", null, "#"), /*#__PURE__*/React.createElement("th", null, "\u0421\u043A\u0430\u043D"), /*#__PURE__*/React.createElement("th", null, "\u0426\u0435\u043B\u0438"), /*#__PURE__*/React.createElement("th", null, "\u0421\u0442\u0430\u0442\u0443\u0441"), /*#__PURE__*/React.createElement("th", {
    className: "num"
  }, "\u0421\u043E\u0431\u0440\u0430\u043D\u043E \u043F\u043E \u0423\u0417"), /*#__PURE__*/React.createElement("th", null, "\u0421\u0445\u0435\u043C\u0430"))), /*#__PURE__*/React.createElement("tbody", null, tasks.map(t => {
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
    }, nc, " \u0423\u0417", coll ? ` · собрано ${coll.collected.length}` : "") : null), /*#__PURE__*/React.createElement("td", {
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
    }, "\u0441\u0445\u0435\u043C\u0430 \u2192") : /*#__PURE__*/React.createElement("span", {
      className: "link",
      onClick: () => go({
        view: "task",
        taskId: t.id
      })
    }, "\u043E\u0442\u043A\u0440\u044B\u0442\u044C \u2192")));
  }), tasks.length === 0 && /*#__PURE__*/React.createElement("tr", null, /*#__PURE__*/React.createElement("td", {
    colSpan: "6",
    className: "sub2"
  }, "\u041F\u043E\u043A\u0430 \u043D\u0435\u0442 \u0441\u043A\u0430\u043D\u0438\u0440\u043E\u0432\u0430\u043D\u0438\u0439 \u2014 \u0437\u0430\u043F\u0443\u0441\u0442\u0438\u0442\u0435 \xAB+ \u041D\u043E\u0432\u043E\u0435 \u0441\u043A\u0430\u043D\u0438\u0440\u043E\u0432\u0430\u043D\u0438\u0435\xBB.")))))));
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
  }, "\u041A\u043E\u043D\u043D\u0435\u043A\u0442\u043E\u0440\u044B"), /*#__PURE__*/React.createElement("p", {
    className: "sub"
  }, "\u0410\u0433\u0435\u043D\u0442\u044B \u0441\u0431\u043E\u0440\u0430 \u0443 \u0437\u0430\u043A\u0430\u0437\u0447\u0438\u043A\u0430 (pull-\u043C\u043E\u0434\u0435\u043B\u044C, \u0442\u043E\u043B\u044C\u043A\u043E \u0438\u0441\u0445\u043E\u0434\u044F\u0449\u0438\u0435 \u0441\u043E\u0435\u0434\u0438\u043D\u0435\u043D\u0438\u044F; \u043E\u0444\u043B\u0430\u0439\u043D-\u043A\u0443\u0440\u044C\u0435\u0440 \u0434\u043B\u044F \u0438\u0437\u043E\u043B\u0438\u0440\u043E\u0432\u0430\u043D\u043D\u043E\u0433\u043E \u043A\u043E\u043D\u0442\u0443\u0440\u0430)."), /*#__PURE__*/React.createElement("div", {
    className: "card",
    style: {
      marginBottom: 16
    }
  }, /*#__PURE__*/React.createElement("div", {
    className: "cb row"
  }, /*#__PURE__*/React.createElement("div", {
    className: "field"
  }, /*#__PURE__*/React.createElement("label", null, "\u041D\u0430\u0437\u0432\u0430\u043D\u0438\u0435 \u043A\u043E\u043D\u043D\u0435\u043A\u0442\u043E\u0440\u0430"), /*#__PURE__*/React.createElement("input", {
    value: name,
    onChange: e => setName(e.target.value),
    placeholder: "\u041A\u043E\u043D\u043D\u0435\u043A\u0442\u043E\u0440-1",
    style: {
      minWidth: 260
    }
  })), /*#__PURE__*/React.createElement("button", {
    className: "btn",
    onClick: add
  }, "\u0417\u0430\u0440\u0435\u0433\u0438\u0441\u0442\u0440\u0438\u0440\u043E\u0432\u0430\u0442\u044C"))), /*#__PURE__*/React.createElement("div", {
    className: "card"
  }, /*#__PURE__*/React.createElement("div", {
    className: "cb"
  }, /*#__PURE__*/React.createElement("table", null, /*#__PURE__*/React.createElement("thead", null, /*#__PURE__*/React.createElement("tr", null, /*#__PURE__*/React.createElement("th", null, "#"), /*#__PURE__*/React.createElement("th", null, "\u041A\u043E\u043D\u043D\u0435\u043A\u0442\u043E\u0440"), /*#__PURE__*/React.createElement("th", null, "\u041F\u043E\u0441\u043B\u0435\u0434\u043D\u0438\u0439 \u0434\u043E\u0437\u0432\u043E\u043D"))), /*#__PURE__*/React.createElement("tbody", null, list.map(c => /*#__PURE__*/React.createElement("tr", {
    key: c.id
  }, /*#__PURE__*/React.createElement("td", {
    className: "mono"
  }, c.id), /*#__PURE__*/React.createElement("td", null, /*#__PURE__*/React.createElement("b", null, c.name)), /*#__PURE__*/React.createElement("td", {
    className: "sub2"
  }, c.last_seen ? c.last_seen.replace("T", " ").slice(0, 16) : "ни разу"))), list.length === 0 && /*#__PURE__*/React.createElement("tr", null, /*#__PURE__*/React.createElement("td", {
    colSpan: "3",
    className: "sub2"
  }, "\u041A\u043E\u043D\u043D\u0435\u043A\u0442\u043E\u0440\u044B \u043D\u0435 \u0437\u0430\u0440\u0435\u0433\u0438\u0441\u0442\u0440\u0438\u0440\u043E\u0432\u0430\u043D\u044B.")))))));
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
  }, "\u0410\u043A\u0442\u0438\u0432\u044B"), /*#__PURE__*/React.createElement("span", {
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
  }, "\u25E2"), "surveyscan"), NAV.map(g => /*#__PURE__*/React.createElement(React.Fragment, {
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
  }, "\u0441\u043A\u0430\u043D\u0435\u0440 \u0438\u043D\u0432\u0435\u043D\u0442\u0430\u0440\u0438\u0437\u0430\u0446\u0438\u0438", /*#__PURE__*/React.createElement("br", null), "\u0438 \u0441\u0445\u0435\u043C\u044B \u0441\u0435\u0442\u0438")), /*#__PURE__*/React.createElement("div", {
    className: "main"
  }, /*#__PURE__*/React.createElement("div", {
    className: "top"
  }, /*#__PURE__*/React.createElement("div", {
    className: "crumb"
  }, crumb), /*#__PURE__*/React.createElement("div", {
    className: "search"
  }, "\u2315 \u041F\u043E\u0438\u0441\u043A \u043F\u043E \u0430\u043A\u0442\u0438\u0432\u0430\u043C, IP\u2026"), /*#__PURE__*/React.createElement("div", {
    className: "right"
  }, /*#__PURE__*/React.createElement("button", {
    className: "btn",
    onClick: () => go({
      view: "newscan"
    })
  }, "+ \u041D\u043E\u0432\u043E\u0435 \u0441\u043A\u0430\u043D\u0438\u0440\u043E\u0432\u0430\u043D\u0438\u0435"), /*#__PURE__*/React.createElement("div", {
    className: "av"
  }, "\u0418\u041F"))), /*#__PURE__*/React.createElement("div", {
    className: "body"
  }, screen)));
}
ReactDOM.createRoot(document.getElementById("root")).render(/*#__PURE__*/React.createElement(App, null));
