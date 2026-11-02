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

/* ----------------------------------------------------------------- Diff между прогонами */
function DiffBanner({
  diff
}) {
  if (!diff) return null;
  const nNew = (diff.new_hosts || []).length,
    nGone = (diff.gone_hosts || []).length,
    nChg = (diff.changed || []).length;
  if (!nNew && !nGone && !nChg) return /*#__PURE__*/React.createElement("div", {
    className: "diffbar"
  }, "\u0411\u0435\u0437 \u0438\u0437\u043C\u0435\u043D\u0435\u043D\u0438\u0439 \u0441 \u043F\u0440\u043E\u0448\u043B\u043E\u0433\u043E \u043F\u0440\u043E\u0433\u043E\u043D\u0430 \u043F\u043E \u044D\u0442\u043E\u0439 \u0446\u0435\u043B\u0438.");
  return /*#__PURE__*/React.createElement("div", {
    className: "diffbar"
  }, /*#__PURE__*/React.createElement("div", null, /*#__PURE__*/React.createElement("b", null, "\u0418\u0437\u043C\u0435\u043D\u0435\u043D\u0438\u044F \u0441 \u043F\u0440\u043E\u0448\u043B\u043E\u0433\u043E \u043F\u0440\u043E\u0433\u043E\u043D\u0430:"), " ", nNew ? /*#__PURE__*/React.createElement("span", {
    className: "chip c-low",
    style: {
      marginRight: 6
    }
  }, "+", nNew, " \u043D\u043E\u0432\u044B\u0445") : null, nGone ? /*#__PURE__*/React.createElement("span", {
    className: "chip c-critical",
    style: {
      marginRight: 6
    }
  }, "\u2212", nGone, " \u0438\u0441\u0447\u0435\u0437\u043B\u043E") : null, nChg ? /*#__PURE__*/React.createElement("span", {
    className: "chip c-medium"
  }, nChg, " \u0438\u0437\u043C\u0435\u043D\u0438\u043B\u0438 \u0441\u0435\u0440\u0432\u0438\u0441\u044B") : null), /*#__PURE__*/React.createElement("details", {
    style: {
      marginTop: 6
    }
  }, /*#__PURE__*/React.createElement("summary", {
    className: "sub2",
    style: {
      cursor: "pointer"
    }
  }, "\u041F\u043E\u0434\u0440\u043E\u0431\u043D\u0435\u0435"), nNew ? /*#__PURE__*/React.createElement("div", {
    className: "sub2",
    style: {
      marginTop: 4
    }
  }, "\u041D\u043E\u0432\u044B\u0435: ", diff.new_hosts.join(", ")) : null, nGone ? /*#__PURE__*/React.createElement("div", {
    className: "sub2",
    style: {
      marginTop: 4
    }
  }, "\u0418\u0441\u0447\u0435\u0437\u043B\u0438: ", diff.gone_hosts.join(", ")) : null, diff.changed.map(c => /*#__PURE__*/React.createElement("div", {
    key: c.name,
    className: "sub2",
    style: {
      marginTop: 4
    }
  }, /*#__PURE__*/React.createElement("b", null, c.name), ": ", c.added_services.length ? "+ " + c.added_services.join("; ") : "", c.added_services.length && c.removed_services.length ? " · " : "", c.removed_services.length ? "− " + c.removed_services.join("; ") : ""))));
}

/* ----------------------------------------------------------------- Дашборд */
function Dash({
  D,
  tasks,
  go,
  diff
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
  }, "\u0418\u043D\u0432\u0435\u043D\u0442\u0430\u0440\u0438\u0437\u0430\u0446\u0438\u044F \u0441\u0435\u0442\u0438 \xB7 ", D.generated), /*#__PURE__*/React.createElement(DiffBanner, {
    diff: diff
  }), /*#__PURE__*/React.createElement("div", {
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

/* ----------------------------------------------------------------- Роль актива (ИТ/сетевое/АСУ ТП/СЗИ) */
const ROLE_LABELS = {
  "": "— не задано —",
  it: "ИТ-хост",
  netdev: "Сетевое устройство",
  ics: "АСУ ТП (ПЛК/SCADA)",
  security: "СЗИ"
};
const ROLE_CHIP = {
  it: "tag-ro",
  netdev: "tagline",
  ics: "c-ics",
  security: "c-security"
};
function RoleBadge({
  role
}) {
  const r = role || "";
  const cls = ROLE_CHIP[r] || "tag-ro";
  return /*#__PURE__*/React.createElement("span", {
    className: cls === "tag-ro" || cls === "tagline" ? "tagline " + cls : "chip " + cls
  }, ROLE_LABELS[r] || r);
}
function RoleSelect({
  value,
  onChange
}) {
  return /*#__PURE__*/React.createElement("select", {
    value: value || "",
    onChange: e => onChange(e.target.value),
    style: {
      fontSize: 12.5,
      padding: "4px 8px"
    }
  }, Object.entries(ROLE_LABELS).map(([k, l]) => /*#__PURE__*/React.createElement("option", {
    key: k,
    value: k
  }, l)));
}
function assetIcon(a) {
  if (a.role === "ics") return "🏭";
  if (a.role === "security") return "🛡";
  return (a.kind || "").toLowerCase().includes("сетев") ? "🖧" : "🖥";
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
  }, /*#__PURE__*/React.createElement("table", null, /*#__PURE__*/React.createElement("thead", null, /*#__PURE__*/React.createElement("tr", null, /*#__PURE__*/React.createElement("th", null, "\u0410\u043A\u0442\u0438\u0432"), /*#__PURE__*/React.createElement("th", null, "IP"), /*#__PURE__*/React.createElement("th", null, "\u041E\u0421 / \u043F\u043B\u0430\u0442\u0444\u043E\u0440\u043C\u0430"), /*#__PURE__*/React.createElement("th", null, "\u0422\u0438\u043F"), /*#__PURE__*/React.createElement("th", null, "\u0420\u043E\u043B\u044C"), /*#__PURE__*/React.createElement("th", {
    className: "num"
  }, "\u041F\u041E"), /*#__PURE__*/React.createElement("th", {
    className: "num"
  }, "\u0421\u0435\u0440\u0432\u0438\u0441\u043E\u0432"))), /*#__PURE__*/React.createElement("tbody", null, assets.map(a => /*#__PURE__*/React.createElement("tr", {
    key: a.name,
    className: "click",
    onClick: () => go({
      view: "asset",
      assetName: a.name
    })
  }, /*#__PURE__*/React.createElement("td", null, /*#__PURE__*/React.createElement("b", null, a.name), assetPartial(a) ? /*#__PURE__*/React.createElement("span", {
    className: "chip c-medium",
    style: {
      marginLeft: 8
    }
  }, a.os_family === "windows" ? "без прав администратора" : "сбор без root") : null), /*#__PURE__*/React.createElement("td", {
    className: "mono"
  }, a.ips || "—"), /*#__PURE__*/React.createElement("td", null, a.os || "—", a.build ? /*#__PURE__*/React.createElement("div", {
    className: "sub2 mono"
  }, a.build) : null), /*#__PURE__*/React.createElement("td", null, a.kind), /*#__PURE__*/React.createElement("td", null, /*#__PURE__*/React.createElement(RoleBadge, {
    role: a.role
  })), /*#__PURE__*/React.createElement("td", {
    className: "num"
  }, a.software || 0), /*#__PURE__*/React.createElement("td", {
    className: "num"
  }, (a.services || []).length))), assets.length === 0 && /*#__PURE__*/React.createElement("tr", null, /*#__PURE__*/React.createElement("td", {
    colSpan: "7",
    className: "sub2"
  }, "\u0410\u043A\u0442\u0438\u0432\u044B \u043D\u0435 \u043D\u0430\u0439\u0434\u0435\u043D\u044B.")))))));
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
function InventoryTable({
  inv,
  section,
  cols,
  rows,
  filtered = false
}) {
  const status = (inv.collection_status || {})[section];
  const message = filtered ? "Нет совпадений по фильтру." : status === "ok" ? "Записей не обнаружено." : status === "unavailable" ? "Данные недоступны: ошибка сбора или нет доступа." : status === "partial" ? "Данные собраны частично." : "Нет данных о сборе.";
  return /*#__PURE__*/React.createElement(React.Fragment, null, status === "partial" && (rows || []).length ? /*#__PURE__*/React.createElement("div", {
    className: "warn",
    style: {
      marginBottom: 8
    }
  }, "\u0414\u0430\u043D\u043D\u044B\u0435 \u0441\u043E\u0431\u0440\u0430\u043D\u044B \u0447\u0430\u0441\u0442\u0438\u0447\u043D\u043E.") : null, /*#__PURE__*/React.createElement(SimpleTable, {
    cols: cols,
    rows: rows,
    empty: message
  }));
}
function inventoryCount(inv, key) {
  const count = (inv[key] || []).length;
  return count || ((inv.collection_status || {})[key] === "ok" ? 0 : "—");
}
function assetPartial(a) {
  return a.partial || a.os_family === "windows" && (a.inventory || {}).is_admin === false;
}
function AssetDetail({
  D,
  name,
  go,
  taskId,
  onRoleChange
}) {
  const a = (D.assets || []).find(x => x.name === name);
  const [tab, setTab] = useState("overview");
  const [swFilter, setSwFilter] = useState("");
  const [svcFilter, setSvcFilter] = useState("");
  const [roleErr, setRoleErr] = useState("");
  if (!a) return /*#__PURE__*/React.createElement("div", {
    className: "empty"
  }, "\u0410\u043A\u0442\u0438\u0432 \u043D\u0435 \u043D\u0430\u0439\u0434\u0435\u043D.");
  const saveRole = async role => {
    setRoleErr("");
    try {
      await api("/tasks/" + taskId + "/assets/" + a.id + "/role", {
        method: "PATCH",
        headers: {
          "Content-Type": "application/json"
        },
        body: JSON.stringify({
          role
        })
      });
      onRoleChange && onRoleChange();
    } catch (e) {
      setRoleErr(e && e.detail ? e.detail : "не удалось сохранить роль");
    }
  };
  const inv = a.inventory || {};
  const fam = a.os_family || "";
  const software = inv.software || [];
  const swShown = swFilter ? software.filter(s => (s.name || "").toLowerCase().includes(swFilter.toLowerCase())) : software;
  const listening = inv.listening || [];
  const connections = inv.connections || [];
  const winServices = inv.services || [];
  const svcShown = svcFilter ? winServices.filter(s => ((s.display || "") + " " + (s.name || "")).toLowerCase().includes(svcFilter.toLowerCase())) : winServices;
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
  if (fam === "windows") tabs.push({
    id: "devices",
    label: "Диски и устройства"
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
  }, "\u0410\u043A\u0442\u0438\u0432\u044B"), /*#__PURE__*/React.createElement("span", {
    className: "sep"
  }, "/"), /*#__PURE__*/React.createElement("b", null, name)), /*#__PURE__*/React.createElement("div", {
    className: "pagehead"
  }, /*#__PURE__*/React.createElement("div", {
    className: "ic"
  }, assetIcon(a)), /*#__PURE__*/React.createElement("div", null, /*#__PURE__*/React.createElement("div", {
    className: "h1",
    style: {
      margin: 0
    }
  }, name), /*#__PURE__*/React.createElement("div", {
    className: "meta mono"
  }, a.ips, a.os ? " · " + a.os : ""))), assetPartial(a) ? /*#__PURE__*/React.createElement("div", {
    className: "warn",
    style: {
      margin: "10px 0"
    }
  }, "\u0421\u0431\u043E\u0440 \u0432\u044B\u043F\u043E\u043B\u043D\u0435\u043D ", fam === "windows" ? "без прав администратора" : "без root/sudo", " \u2014 \u0447\u0430\u0441\u0442\u044C \u0434\u0430\u043D\u043D\u044B\u0445 \u043C\u043E\u0436\u0435\u0442 \u0431\u044B\u0442\u044C \u043D\u0435\u043F\u043E\u043B\u043D\u043E\u0439.") : null, /*#__PURE__*/React.createElement("div", {
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
  }, /*#__PURE__*/React.createElement("h3", null, "\u0421\u0432\u0435\u0434\u0435\u043D\u0438\u044F")), /*#__PURE__*/React.createElement("div", {
    className: "cb"
  }, /*#__PURE__*/React.createElement(KV, {
    k: "\u0422\u0438\u043F",
    v: a.kind
  }), /*#__PURE__*/React.createElement("div", {
    className: "kv"
  }, /*#__PURE__*/React.createElement("span", {
    className: "k"
  }, "\u0420\u043E\u043B\u044C"), /*#__PURE__*/React.createElement("span", {
    className: "v"
  }, /*#__PURE__*/React.createElement(RoleSelect, {
    value: a.role,
    onChange: saveRole
  }))), roleErr ? /*#__PURE__*/React.createElement("div", {
    className: "sub2",
    style: {
      color: "var(--crit,#b4232a)",
      margin: "2px 0 6px"
    }
  }, roleErr) : null, /*#__PURE__*/React.createElement(KV, {
    k: "IP",
    v: a.ips
  }), /*#__PURE__*/React.createElement(KV, {
    k: "\u041E\u0421 / \u043F\u043B\u0430\u0442\u0444\u043E\u0440\u043C\u0430",
    v: a.os
  }), /*#__PURE__*/React.createElement(KV, {
    k: "\u0421\u0431\u043E\u0440\u043A\u0430 / \u0432\u0435\u0440\u0441\u0438\u044F",
    v: a.build
  }), fam === "windows" ? /*#__PURE__*/React.createElement(React.Fragment, null, /*#__PURE__*/React.createElement(KV, {
    k: "\u0414\u043E\u043C\u0435\u043D / \u0440\u0430\u0431\u043E\u0447\u0430\u044F \u0433\u0440\u0443\u043F\u043F\u0430",
    v: inv.part_of_domain === true ? inv.domain : inv.part_of_domain === false ? inv.domain || "рабочая группа" : null
  }), /*#__PURE__*/React.createElement(KV, {
    k: "\u0410\u0440\u0445\u0438\u0442\u0435\u043A\u0442\u0443\u0440\u0430",
    v: inv.architecture
  }), /*#__PURE__*/React.createElement(KV, {
    k: "\u0422\u0438\u043F \u0443\u0441\u0442\u0430\u043D\u043E\u0432\u043A\u0438",
    v: inv.installation_type
  }), /*#__PURE__*/React.createElement(KV, {
    k: "\u041F\u043E\u0441\u043B\u0435\u0434\u043D\u044F\u044F \u0437\u0430\u0433\u0440\u0443\u0437\u043A\u0430",
    v: inv.last_boot
  }), /*#__PURE__*/React.createElement(KV, {
    k: "\u0421\u0431\u043E\u0440 \u043E\u0442 \u0430\u0434\u043C\u0438\u043D\u0438\u0441\u0442\u0440\u0430\u0442\u043E\u0440\u0430",
    v: inv.is_admin === true ? "да" : inv.is_admin === false ? "нет" : "—"
  })) : null, fam === "linux" ? /*#__PURE__*/React.createElement(KV, {
    k: "\u0421\u0431\u043E\u0440 \u043E\u0442 root",
    v: inv.is_root === true ? "да" : inv.is_root === false ? "нет (sudo/частично)" : "—"
  }) : null, /*#__PURE__*/React.createElement(KV, {
    k: "\u0418\u0441\u0442\u043E\u0447\u043D\u0438\u043A \u0441\u0431\u043E\u0440\u0430",
    v: a.source
  }), /*#__PURE__*/React.createElement(KV, {
    k: "\u0421\u043E\u0431\u0440\u0430\u043D\u043E",
    v: a.collected_at
  }))), /*#__PURE__*/React.createElement("div", null, /*#__PURE__*/React.createElement("div", {
    className: "card"
  }, /*#__PURE__*/React.createElement("div", {
    className: "ch"
  }, /*#__PURE__*/React.createElement("h3", null, "\u0418\u0442\u043E\u0433\u0438")), /*#__PURE__*/React.createElement("div", {
    className: "cb"
  }, /*#__PURE__*/React.createElement(KV, {
    k: "\u041F\u0430\u043A\u0435\u0442\u043E\u0432 / \u041F\u041E",
    v: software.length
  }), /*#__PURE__*/React.createElement(KV, {
    k: "\u041E\u0442\u043A\u0440\u044B\u0442\u044B\u0445 \u0441\u0435\u0440\u0432\u0438\u0441\u043E\u0432 (\u0441\u0435\u0442\u044C)",
    v: (a.services || []).length
  }), /*#__PURE__*/React.createElement(KV, {
    k: "\u0421\u043B\u0443\u0448\u0430\u044E\u0449\u0438\u0445 \u043F\u043E\u0440\u0442\u043E\u0432 (\u041E\u0421)",
    v: inventoryCount(inv, "listening")
  }), fam === "windows" ? /*#__PURE__*/React.createElement(KV, {
    k: "\u041E\u0431\u043D\u043E\u0432\u043B\u0435\u043D\u0438\u0439 (KB)",
    v: (inv.hotfixes || []).length
  }) : null)), a.sec_tools && a.sec_tools.length ? /*#__PURE__*/React.createElement("div", {
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
  }, "\u2713"), " ", t)))) : null)), tab === "software" && /*#__PURE__*/React.createElement("div", {
    className: "card"
  }, /*#__PURE__*/React.createElement("div", {
    className: "ch"
  }, /*#__PURE__*/React.createElement("h3", null, "\u0423\u0441\u0442\u0430\u043D\u043E\u0432\u043B\u0435\u043D\u043D\u043E\u0435 \u041F\u041E / \u043F\u0430\u043A\u0435\u0442\u044B"), /*#__PURE__*/React.createElement("input", {
    value: swFilter,
    onChange: e => setSwFilter(e.target.value),
    placeholder: "\u0424\u0438\u043B\u044C\u0442\u0440 \u043F\u043E \u0438\u043C\u0435\u043D\u0438\u2026",
    style: {
      marginLeft: "auto",
      fontSize: 12.5,
      padding: "4px 8px"
    }
  })), /*#__PURE__*/React.createElement("div", {
    className: "cb"
  }, /*#__PURE__*/React.createElement(SimpleTable, {
    empty: swFilter ? "Нет совпадений по фильтру." : "Нет данных об установленном ПО.",
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
  }, /*#__PURE__*/React.createElement("h3", null, "\u0423\u0441\u0442\u0430\u043D\u043E\u0432\u043B\u0435\u043D\u043D\u044B\u0435 \u043E\u0431\u043D\u043E\u0432\u043B\u0435\u043D\u0438\u044F")), /*#__PURE__*/React.createElement("div", {
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
  }, "\u041E\u0431\u043D\u043E\u0432\u043B\u0435\u043D\u0438\u044F \u043D\u0435 \u0441\u043E\u0431\u0440\u0430\u043D\u044B."))), tab === "users" && /*#__PURE__*/React.createElement("div", {
    className: "detail"
  }, /*#__PURE__*/React.createElement("div", {
    className: "card"
  }, /*#__PURE__*/React.createElement("div", {
    className: "ch"
  }, /*#__PURE__*/React.createElement("h3", null, "\u0423\u0447\u0451\u0442\u043D\u044B\u0435 \u0437\u0430\u043F\u0438\u0441\u0438")), /*#__PURE__*/React.createElement("div", {
    className: "cb"
  }, fam === "windows" ? /*#__PURE__*/React.createElement(SimpleTable, {
    empty: "\u041B\u043E\u043A\u0430\u043B\u044C\u043D\u044B\u0435 \u0443\u0447\u0451\u0442\u043A\u0438 \u043D\u0435 \u0441\u043E\u0431\u0440\u0430\u043D\u044B.",
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
    empty: "\u041F\u043E\u043B\u044C\u0437\u043E\u0432\u0430\u0442\u0435\u043B\u0438 \u043D\u0435 \u0441\u043E\u0431\u0440\u0430\u043D\u044B.",
    cols: [{
      key: "name",
      label: "Логин"
    }],
    rows: (inv.login_users || []).map(n => ({
      name: n
    }))
  }))), /*#__PURE__*/React.createElement("div", null, fam === "windows" ? /*#__PURE__*/React.createElement(React.Fragment, null, /*#__PURE__*/React.createElement("div", {
    className: "card"
  }, /*#__PURE__*/React.createElement("div", {
    className: "ch"
  }, /*#__PURE__*/React.createElement("h3", null, "\u0410\u0434\u043C\u0438\u043D\u0438\u0441\u0442\u0440\u0430\u0442\u043E\u0440\u044B")), /*#__PURE__*/React.createElement("div", {
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
  }, "\u0413\u0440\u0443\u043F\u043F\u0430 \xAB\u0410\u0434\u043C\u0438\u043D\u0438\u0441\u0442\u0440\u0430\u0442\u043E\u0440\u044B\xBB \u043F\u0443\u0441\u0442\u0430 \u0438\u043B\u0438 \u043D\u0435 \u0441\u043E\u0431\u0440\u0430\u043D\u0430."))), /*#__PURE__*/React.createElement("div", {
    className: "card",
    style: {
      marginTop: 16
    }
  }, /*#__PURE__*/React.createElement("div", {
    className: "ch"
  }, /*#__PURE__*/React.createElement("h3", null, "\u041B\u043E\u043A\u0430\u043B\u044C\u043D\u044B\u0435 \u0433\u0440\u0443\u043F\u043F\u044B")), /*#__PURE__*/React.createElement("div", {
    className: "cb"
  }, /*#__PURE__*/React.createElement(InventoryTable, {
    inv: inv,
    section: "groups",
    cols: [{
      key: "name",
      label: "Наименование"
    }, {
      key: "sid",
      label: "SID",
      mono: true
    }, {
      key: "description",
      label: "Описание"
    }, {
      key: "members",
      label: "Члены группы",
      render: r => r.members == null ? "Не собрано" : r.members.join(", ") || "нет"
    }],
    rows: inv.groups
  })))) : /*#__PURE__*/React.createElement(React.Fragment, null, /*#__PURE__*/React.createElement("div", {
    className: "card"
  }, /*#__PURE__*/React.createElement("div", {
    className: "ch"
  }, /*#__PURE__*/React.createElement("h3", null, "UID 0 / sudo \u0431\u0435\u0437 \u043F\u0430\u0440\u043E\u043B\u044F")), /*#__PURE__*/React.createElement("div", {
    className: "cb"
  }, /*#__PURE__*/React.createElement(KV, {
    k: "UID 0 (\u043A\u0440\u043E\u043C\u0435 root)",
    v: (inv.uid0_users || []).join(", ") || "—"
  }), /*#__PURE__*/React.createElement(KV, {
    k: "sudo NOPASSWD",
    v: inv.sudo_nopasswd === null ? "нет доступа к данным" : (inv.sudo_nopasswd || []).join("; ") || "нет"
  }), /*#__PURE__*/React.createElement(KV, {
    k: "\u041F\u0443\u0441\u0442\u043E\u0439 \u043F\u0430\u0440\u043E\u043B\u044C",
    v: inv.empty_password_users === null ? "нет доступа к данным" : (inv.empty_password_users || []).join(", ") || "нет"
  })))))), tab === "network" && /*#__PURE__*/React.createElement("div", {
    className: "detail"
  }, fam === "windows" || fam === "linux" ? /*#__PURE__*/React.createElement("div", {
    className: "card",
    style: {
      gridColumn: "1 / -1"
    }
  }, /*#__PURE__*/React.createElement("div", {
    className: "ch"
  }, /*#__PURE__*/React.createElement("h3", null, "\u0421\u0435\u0442\u0435\u0432\u044B\u0435 \u0438\u043D\u0442\u0435\u0440\u0444\u0435\u0439\u0441\u044B")), /*#__PURE__*/React.createElement("div", {
    className: "cb"
  }, fam === "windows" ? /*#__PURE__*/React.createElement(InventoryTable, {
    inv: inv,
    section: "nics",
    cols: [{
      key: "name",
      label: "Наименование"
    }, {
      key: "mac",
      label: "MAC адрес",
      mono: true
    }, {
      key: "status",
      label: "Статус"
    }, {
      key: "ip",
      label: "IP адрес",
      mono: true,
      render: r => (r.ip || []).join(", ") || "—"
    }, {
      key: "mask",
      label: "Маска подсети",
      mono: true,
      render: r => (r.mask || []).join(", ") || "—"
    }, {
      key: "gateway",
      label: "Основной шлюз",
      mono: true,
      render: r => (r.gateway || []).join(", ") || "—"
    }, {
      key: "dns",
      label: "DNS сервер",
      mono: true,
      render: r => (r.dns || []).join(", ") || "—"
    }, {
      key: "dhcp_server",
      label: "DHCP сервер",
      mono: true,
      render: r => r.dhcp_enabled === true ? r.dhcp_server || "включён" : r.dhcp_enabled === false ? "отключён" : "—"
    }],
    rows: inv.nics
  }) : /*#__PURE__*/React.createElement(InventoryTable, {
    inv: inv,
    section: "nics",
    cols: [{
      key: "name",
      label: "Наименование"
    }, {
      key: "mac",
      label: "MAC адрес",
      mono: true
    }, {
      key: "addresses",
      label: "IP адрес / маска",
      mono: true,
      render: r => (r.addresses || []).map(x => x.ip + (x.prefix == null ? "" : "/" + x.prefix)).join(", ") || "—"
    }],
    rows: inv.nics
  }))) : null, fam === "linux" ? /*#__PURE__*/React.createElement("div", {
    className: "card"
  }, /*#__PURE__*/React.createElement("div", {
    className: "ch"
  }, /*#__PURE__*/React.createElement("h3", null, "DNS \u0441\u0435\u0440\u0432\u0435\u0440\u044B")), /*#__PURE__*/React.createElement("div", {
    className: "cb"
  }, /*#__PURE__*/React.createElement(InventoryTable, {
    inv: inv,
    section: "dns",
    cols: [{
      key: "address",
      label: "Адрес",
      mono: true
    }],
    rows: (inv.dns || []).map(address => ({
      address
    }))
  }))) : null, fam === "windows" || fam === "linux" ? /*#__PURE__*/React.createElement("div", {
    className: "card",
    style: {
      gridColumn: "1 / -1"
    }
  }, /*#__PURE__*/React.createElement("div", {
    className: "ch"
  }, /*#__PURE__*/React.createElement("h3", null, "\u0422\u0430\u0431\u043B\u0438\u0446\u0430 \u043C\u0430\u0440\u0448\u0440\u0443\u0442\u0438\u0437\u0430\u0446\u0438\u0438")), /*#__PURE__*/React.createElement("div", {
    className: "cb"
  }, /*#__PURE__*/React.createElement(InventoryTable, {
    inv: inv,
    section: "routes",
    cols: [{
      key: "destination",
      label: "Сеть",
      mono: true
    }, {
      key: "gateway",
      label: "Шлюз",
      mono: true
    }, {
      key: "interface",
      label: "Интерфейс"
    }, {
      key: "metric",
      label: "Метрика",
      num: true
    }],
    rows: inv.routes
  }))) : null, /*#__PURE__*/React.createElement("div", {
    className: "card"
  }, /*#__PURE__*/React.createElement("div", {
    className: "ch"
  }, /*#__PURE__*/React.createElement("h3", null, "\u041E\u0442\u043A\u0440\u044B\u0442\u044B\u0435 \u0441\u0435\u0440\u0432\u0438\u0441\u044B (\u0441\u0435\u0442\u0435\u0432\u043E\u0439 \u0441\u043A\u0430\u043D)")), /*#__PURE__*/React.createElement("div", {
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
  }, "\u041E\u0442\u043A\u0440\u044B\u0442\u044B\u0445 \u0441\u0435\u0440\u0432\u0438\u0441\u043E\u0432 \u043D\u0435 \u043E\u0431\u043D\u0430\u0440\u0443\u0436\u0435\u043D\u043E."))), /*#__PURE__*/React.createElement("div", {
    className: "card"
  }, /*#__PURE__*/React.createElement("div", {
    className: "ch"
  }, /*#__PURE__*/React.createElement("h3", null, "\u0421\u043B\u0443\u0448\u0430\u044E\u0449\u0438\u0435 \u043F\u043E\u0440\u0442\u044B (\u043D\u0430 \u0445\u043E\u0441\u0442\u0435)")), /*#__PURE__*/React.createElement("div", {
    className: "cb"
  }, /*#__PURE__*/React.createElement(InventoryTable, {
    inv: inv,
    section: "listening",
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
  }))), fam === "windows" || fam === "linux" ? /*#__PURE__*/React.createElement("div", {
    className: "card",
    style: {
      gridColumn: "1 / -1"
    }
  }, /*#__PURE__*/React.createElement("div", {
    className: "ch"
  }, /*#__PURE__*/React.createElement("h3", null, "\u0418\u0441\u043F\u043E\u043B\u044C\u0437\u0443\u0435\u043C\u044B\u0435 \u0441\u0435\u0442\u0435\u0432\u044B\u0435 \u0441\u043E\u0435\u0434\u0438\u043D\u0435\u043D\u0438\u044F")), /*#__PURE__*/React.createElement("div", {
    className: "cb"
  }, /*#__PURE__*/React.createElement(InventoryTable, {
    inv: inv,
    section: "connections",
    cols: [{
      key: "local_address",
      label: "Локальный адрес",
      mono: true
    }, {
      key: "local_port",
      label: "Локальный порт",
      num: true
    }, {
      key: "remote_address",
      label: "Удалённый адрес",
      mono: true
    }, {
      key: "remote_port",
      label: "Удалённый порт",
      num: true
    }, {
      key: "process",
      label: "Процесс"
    }],
    rows: connections
  }))) : null, fam === "windows" ? /*#__PURE__*/React.createElement("div", {
    className: "card",
    style: {
      gridColumn: "1 / -1"
    }
  }, /*#__PURE__*/React.createElement("div", {
    className: "ch"
  }, /*#__PURE__*/React.createElement("h3", null, "\u0421\u043B\u0443\u0436\u0431\u044B Windows"), /*#__PURE__*/React.createElement("span", {
    className: "sub2"
  }, winServices.length), /*#__PURE__*/React.createElement("input", {
    value: svcFilter,
    onChange: e => setSvcFilter(e.target.value),
    placeholder: "\u0424\u0438\u043B\u044C\u0442\u0440 \u043F\u043E \u0438\u043C\u0435\u043D\u0438\u2026",
    style: {
      marginLeft: "auto",
      fontSize: 12.5,
      padding: "4px 8px"
    }
  })), /*#__PURE__*/React.createElement("div", {
    className: "cb"
  }, /*#__PURE__*/React.createElement(InventoryTable, {
    inv: inv,
    section: "services",
    filtered: !!svcFilter && winServices.length > 0,
    cols: [{
      key: "display",
      label: "Полное имя"
    }, {
      key: "name",
      label: "Имя службы",
      mono: true
    }, {
      key: "state",
      label: "Статус"
    }, {
      key: "start_mode",
      label: "Тип запуска"
    }, {
      key: "account",
      label: "Учётная запись",
      mono: true
    }, {
      key: "path",
      label: "Путь до файла",
      mono: true
    }],
    rows: svcShown
  }))) : null), tab === "devices" && /*#__PURE__*/React.createElement("div", {
    className: "detail"
  }, /*#__PURE__*/React.createElement("div", {
    className: "card"
  }, /*#__PURE__*/React.createElement("div", {
    className: "ch"
  }, /*#__PURE__*/React.createElement("h3", null, "\u041B\u043E\u043A\u0430\u043B\u044C\u043D\u044B\u0435 \u0442\u043E\u043C\u0430")), /*#__PURE__*/React.createElement("div", {
    className: "cb"
  }, /*#__PURE__*/React.createElement(InventoryTable, {
    inv: inv,
    section: "disks",
    cols: [{
      key: "id",
      label: "ID диска",
      mono: true
    }, {
      key: "name",
      label: "Наименование"
    }, {
      key: "size_gb",
      label: "Объём, ГБ",
      num: true
    }, {
      key: "free_gb",
      label: "Свободно, ГБ",
      num: true
    }],
    rows: inv.disks
  }))), /*#__PURE__*/React.createElement("div", {
    className: "card"
  }, /*#__PURE__*/React.createElement("div", {
    className: "ch"
  }, /*#__PURE__*/React.createElement("h3", null, "\u041E\u0431\u0449\u0438\u0435 \u043F\u0430\u043F\u043A\u0438")), /*#__PURE__*/React.createElement("div", {
    className: "cb"
  }, /*#__PURE__*/React.createElement(InventoryTable, {
    inv: inv,
    section: "shares",
    cols: [{
      key: "name",
      label: "Наименование"
    }, {
      key: "path",
      label: "Путь",
      mono: true
    }, {
      key: "description",
      label: "Описание"
    }],
    rows: inv.shares
  }))), /*#__PURE__*/React.createElement("div", {
    className: "card",
    style: {
      gridColumn: "1 / -1"
    }
  }, /*#__PURE__*/React.createElement("div", {
    className: "ch"
  }, /*#__PURE__*/React.createElement("h3", null, "\u041F\u043E\u0434\u043A\u043B\u044E\u0447\u0451\u043D\u043D\u044B\u0435 USB-\u0443\u0441\u0442\u0440\u043E\u0439\u0441\u0442\u0432\u0430")), /*#__PURE__*/React.createElement("div", {
    className: "cb"
  }, /*#__PURE__*/React.createElement(InventoryTable, {
    inv: inv,
    section: "usb_devices",
    cols: [{
      key: "name",
      label: "Наименование"
    }, {
      key: "device_id",
      label: "ID устройства",
      mono: true
    }, {
      key: "description",
      label: "Описание"
    }],
    rows: inv.usb_devices
  })))), tab === "security" && /*#__PURE__*/React.createElement("div", {
    className: "detail"
  }, fam === "windows" ? /*#__PURE__*/React.createElement(React.Fragment, null, /*#__PURE__*/React.createElement("div", {
    className: "card"
  }, /*#__PURE__*/React.createElement("div", {
    className: "ch"
  }, /*#__PURE__*/React.createElement("h3", null, "\u041C\u0435\u0436\u0441\u0435\u0442\u0435\u0432\u043E\u0439 \u044D\u043A\u0440\u0430\u043D")), /*#__PURE__*/React.createElement("div", {
    className: "cb"
  }, Object.keys(inv.firewall || {}).length ? Object.entries(inv.firewall).map(([k, v]) => /*#__PURE__*/React.createElement(KV, {
    key: k,
    k: k,
    v: v ? "включён" : "отключён"
  })) : /*#__PURE__*/React.createElement("div", {
    className: "sub2"
  }, "\u041D\u0435 \u0441\u043E\u0431\u0440\u0430\u043D\u043E."))), /*#__PURE__*/React.createElement("div", {
    className: "card"
  }, /*#__PURE__*/React.createElement("div", {
    className: "ch"
  }, /*#__PURE__*/React.createElement("h3", null, "\u0410\u043D\u0442\u0438\u0432\u0438\u0440\u0443\u0441 / Defender")), /*#__PURE__*/React.createElement("div", {
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
  }, "\u2713"), " ", av.name)), inv.defender ? /*#__PURE__*/React.createElement(React.Fragment, null, /*#__PURE__*/React.createElement(KV, {
    k: "Defender \u0432\u043A\u043B\u044E\u0447\u0451\u043D",
    v: inv.defender.enabled ? "да" : "нет"
  }), /*#__PURE__*/React.createElement(KV, {
    k: "\u0417\u0430\u0449\u0438\u0442\u0430 \u0432 \u0440\u0435\u0430\u043B\u044C\u043D\u043E\u043C \u0432\u0440\u0435\u043C\u0435\u043D\u0438",
    v: inv.defender.realtime ? "да" : "нет"
  }), /*#__PURE__*/React.createElement(KV, {
    k: "\u041E\u0431\u043D\u043E\u0432\u043B\u0435\u043D\u0438\u0435 \u0441\u0438\u0433\u043D\u0430\u0442\u0443\u0440",
    v: inv.defender.signatures
  })) : null, (!inv.antivirus || inv.antivirus.length === 0) && !inv.defender ? /*#__PURE__*/React.createElement("div", {
    className: "sub2"
  }, "\u041D\u0435 \u0441\u043E\u0431\u0440\u0430\u043D\u043E.") : null))) : /*#__PURE__*/React.createElement(React.Fragment, null, /*#__PURE__*/React.createElement("div", {
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
  }, "sshd \u043D\u0435 \u0441\u043E\u0431\u0440\u0430\u043D."))), /*#__PURE__*/React.createElement("div", {
    className: "card"
  }, /*#__PURE__*/React.createElement("div", {
    className: "ch"
  }, /*#__PURE__*/React.createElement("h3", null, "\u0410\u043A\u0442\u0438\u0432\u043D\u044B\u0435 \u0441\u043B\u0443\u0436\u0431\u044B \u0431\u0435\u0437\u043E\u043F\u0430\u0441\u043D\u043E\u0441\u0442\u0438")), /*#__PURE__*/React.createElement("div", {
    className: "cb"
  }, Object.keys(inv.services_active || {}).length ? Object.entries(inv.services_active).map(([k, v]) => /*#__PURE__*/React.createElement(KV, {
    key: k,
    k: k,
    v: v
  })) : /*#__PURE__*/React.createElement("div", {
    className: "sub2"
  }, "\u041D\u0435 \u0441\u043E\u0431\u0440\u0430\u043D\u043E."))))), tab === "config" && /*#__PURE__*/React.createElement("div", {
    className: "card"
  }, /*#__PURE__*/React.createElement("div", {
    className: "ch"
  }, /*#__PURE__*/React.createElement("h3", null, "\u041A\u043E\u043D\u0444\u0438\u0433\u0443\u0440\u0430\u0446\u0438\u044F \u0443\u0441\u0442\u0440\u043E\u0439\u0441\u0442\u0432\u0430"), /*#__PURE__*/React.createElement("span", {
    className: "sub2"
  }, "\u0441\u0435\u043A\u0440\u0435\u0442\u044B \u0437\u0430\u043C\u0430\u0441\u043A\u0438\u0440\u043E\u0432\u0430\u043D\u044B")), /*#__PURE__*/React.createElement("div", {
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
},
// роль (см. roleguess.py) переопределяет цвет независимо от type — чтобы АСУ ТП/СЗИ были заметны сразу
{
  selector: 'node[role="ics"]',
  style: {
    "background-color": "#8A4B16",
    "color": "#fff"
  }
}, {
  selector: 'node[role="security"]',
  style: {
    "background-color": "#1B6B4A",
    "color": "#fff"
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
  go,
  diff
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
  }, "\u042D\u043A\u0441\u043F\u043E\u0440\u0442 SVG")), /*#__PURE__*/React.createElement(DiffBanner, {
    diff: diff
  }), /*#__PURE__*/React.createElement("div", {
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
  }), "\u0425\u043E\u0441\u0442"), /*#__PURE__*/React.createElement("span", null, /*#__PURE__*/React.createElement("i", {
    style: {
      background: "#8A4B16"
    }
  }), "\u0410\u0421\u0423 \u0422\u041F"), /*#__PURE__*/React.createElement("span", null, /*#__PURE__*/React.createElement("i", {
    style: {
      background: "#1B6B4A"
    }
  }), "\u0421\u0417\u0418"), /*#__PURE__*/React.createElement("span", {
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
  }, p.targets || (r.targets || []).join(", ") || "—"), running ? " · обновляется каждые 2 c" : ""), /*#__PURE__*/React.createElement(DiffBanner, {
    diff: t.diff
  }), /*#__PURE__*/React.createElement("div", {
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

/* ----------------------------------------------------------------- Расписания */
const SCHED_KINDS = {
  demo: "Демо",
  inventory: "Инвентаризация",
  vuln: "Уязвимости",
  config: "Конфигурации"
};
function Schedules({
  savedCreds
}) {
  const [list, setList] = useState([]);
  const [f, setF] = useState({
    name: "",
    kind: "inventory",
    targets: "",
    interval_minutes: 60,
    cred_ids: []
  });
  const [err, setErr] = useState("");
  const refresh = () => api("/schedules").then(setList).catch(() => {});
  useEffect(() => {
    refresh();
    const h = setInterval(refresh, 5000);
    return () => clearInterval(h);
  }, []);
  const setFF = (k, v) => setF(p => ({
    ...p,
    [k]: v
  }));
  const toggleCred = id => setFF("cred_ids", f.cred_ids.includes(id) ? f.cred_ids.filter(x => x !== id) : [...f.cred_ids, id]);
  const add = async () => {
    setErr("");
    try {
      await api("/schedules", {
        method: "POST",
        headers: {
          "Content-Type": "application/json"
        },
        body: JSON.stringify({
          name: f.name || null,
          kind: f.kind,
          targets: f.targets || null,
          interval_minutes: parseInt(f.interval_minutes, 10) || 60,
          cred_ids: f.cred_ids
        })
      });
      setF({
        name: "",
        kind: "inventory",
        targets: "",
        interval_minutes: 60,
        cred_ids: []
      });
      refresh();
    } catch (e) {
      setErr(e && e.detail ? e.detail : "не удалось сохранить");
    }
  };
  const del = async id => {
    await fetch("/schedules/" + id, {
      method: "DELETE"
    });
    refresh();
  };
  const toggleEnabled = async s => {
    await api("/schedules/" + s.id, {
      method: "PATCH",
      headers: {
        "Content-Type": "application/json"
      },
      body: JSON.stringify({
        enabled: !s.enabled
      })
    });
    refresh();
  };
  const runNow = async id => {
    await api("/schedules/" + id + "/run", {
      method: "POST"
    });
    refresh();
  };
  const fmt = s => s ? s.replace("T", " ").slice(0, 16) : "—";
  return /*#__PURE__*/React.createElement("div", null, /*#__PURE__*/React.createElement("h1", {
    className: "h1"
  }, "\u0420\u0430\u0441\u043F\u0438\u0441\u0430\u043D\u0438\u044F"), /*#__PURE__*/React.createElement("p", {
    className: "sub"
  }, "\u041F\u0435\u0440\u0438\u043E\u0434\u0438\u0447\u0435\u0441\u043A\u0438\u0439 \u043F\u0435\u0440\u0435\u0441\u0431\u043E\u0440 \u043F\u043E \u0437\u0430\u0434\u0430\u043D\u043D\u044B\u043C \u0446\u0435\u043B\u044F\u043C \u2014 \u0431\u0435\u0437 \u0440\u0443\u0447\u043D\u043E\u0433\u043E \u0437\u0430\u043F\u0443\u0441\u043A\u0430. \u041F\u0440\u0438 \u0441\u0440\u0430\u0431\u0430\u0442\u044B\u0432\u0430\u043D\u0438\u0438 \u0441\u0442\u0430\u0432\u0438\u0442\u0441\u044F \u043E\u0431\u044B\u0447\u043D\u0430\u044F \u0437\u0430\u0434\u0430\u0447\u0430 \u0441\u043A\u0430\u043D\u0438\u0440\u043E\u0432\u0430\u043D\u0438\u044F; \u0438\u0437\u043C\u0435\u043D\u0435\u043D\u0438\u044F \u0441 \u043F\u0440\u043E\u0448\u043B\u043E\u0433\u043E \u043F\u0440\u043E\u0433\u043E\u043D\u0430 \u0432\u0438\u0434\u043D\u044B \u0432 \u043A\u0430\u0440\u0442\u043E\u0447\u043A\u0435 \u0437\u0430\u0434\u0430\u0447\u0438 \u0438 \u043D\u0430 \u0434\u0430\u0448\u0431\u043E\u0440\u0434\u0435."), /*#__PURE__*/React.createElement("div", {
    className: "card",
    style: {
      marginBottom: 16,
      maxWidth: 820
    }
  }, /*#__PURE__*/React.createElement("div", {
    className: "cb"
  }, /*#__PURE__*/React.createElement("div", {
    className: "field"
  }, /*#__PURE__*/React.createElement("label", null, "\u041D\u0430\u0437\u0432\u0430\u043D\u0438\u0435"), /*#__PURE__*/React.createElement("input", {
    value: f.name,
    onChange: e => setFF("name", e.target.value),
    placeholder: "\u041F\u0435\u0440\u0438\u043C\u0435\u0442\u0440 \u2014 \u0435\u0436\u0435\u0447\u0430\u0441\u043D\u043E"
  })), /*#__PURE__*/React.createElement("div", {
    className: "field",
    style: {
      marginTop: 10
    }
  }, /*#__PURE__*/React.createElement("label", null, "\u0426\u0435\u043B\u0438: \u043F\u043E\u0434\u0441\u0435\u0442\u0438 / \u0445\u043E\u0441\u0442\u044B ", f.kind === "demo" ? /*#__PURE__*/React.createElement("span", {
    className: "sub2",
    style: {
      fontWeight: 400
    }
  }, "(\u043D\u0435 \u043D\u0443\u0436\u043D\u044B \u0434\u043B\u044F \u0434\u0435\u043C\u043E)") : null), /*#__PURE__*/React.createElement("textarea", {
    rows: "2",
    value: f.targets,
    onChange: e => setFF("targets", e.target.value),
    placeholder: "10.0.0.0/24, srv01.corp"
  })), /*#__PURE__*/React.createElement("div", {
    style: {
      display: "flex",
      gap: 10,
      marginTop: 10,
      flexWrap: "wrap"
    }
  }, /*#__PURE__*/React.createElement("div", {
    className: "field"
  }, /*#__PURE__*/React.createElement("label", null, "\u0412\u0438\u0434"), /*#__PURE__*/React.createElement("select", {
    value: f.kind,
    onChange: e => setFF("kind", e.target.value)
  }, Object.entries(SCHED_KINDS).map(([k, l]) => /*#__PURE__*/React.createElement("option", {
    key: k,
    value: k
  }, l)))), /*#__PURE__*/React.createElement("div", {
    className: "field"
  }, /*#__PURE__*/React.createElement("label", null, "\u0418\u043D\u0442\u0435\u0440\u0432\u0430\u043B, \u043C\u0438\u043D"), /*#__PURE__*/React.createElement("input", {
    type: "number",
    min: "1",
    style: {
      width: 100
    },
    value: f.interval_minutes,
    onChange: e => setFF("interval_minutes", e.target.value)
  }))), savedCreds && savedCreds.length ? /*#__PURE__*/React.createElement("div", {
    className: "field",
    style: {
      marginTop: 10
    }
  }, /*#__PURE__*/React.createElement("label", null, "\u0423\u0447\u0451\u0442\u043D\u044B\u0435 \u0437\u0430\u043F\u0438\u0441\u0438 \u0434\u043B\u044F \u0441\u0431\u043E\u0440\u0430 ", /*#__PURE__*/React.createElement("span", {
    className: "sub2",
    style: {
      fontWeight: 400
    }
  }, "(\u043E\u043F\u0446\u0438\u043E\u043D\u0430\u043B\u044C\u043D\u043E)")), /*#__PURE__*/React.createElement("div", {
    className: "credpick"
  }, savedCreds.map(c => /*#__PURE__*/React.createElement("label", {
    className: "credopt" + (f.cred_ids.includes(c.id) ? " on" : ""),
    key: c.id
  }, /*#__PURE__*/React.createElement("input", {
    type: "checkbox",
    checked: f.cred_ids.includes(c.id),
    onChange: () => toggleCred(c.id)
  }), /*#__PURE__*/React.createElement("span", {
    className: "cn"
  }, c.name), /*#__PURE__*/React.createElement("span", {
    className: "ct"
  }, CRED_KIND[c.type] || c.type))))) : null, /*#__PURE__*/React.createElement("button", {
    className: "btn",
    style: {
      marginTop: 14
    },
    onClick: add
  }, "\u0421\u043E\u0437\u0434\u0430\u0442\u044C \u0440\u0430\u0441\u043F\u0438\u0441\u0430\u043D\u0438\u0435"), err ? /*#__PURE__*/React.createElement("div", {
    className: "sub2",
    style: {
      color: "var(--crit,#b4232a)",
      marginTop: 8
    }
  }, err) : null)), /*#__PURE__*/React.createElement("div", {
    className: "card"
  }, /*#__PURE__*/React.createElement("div", {
    className: "cb"
  }, /*#__PURE__*/React.createElement("table", null, /*#__PURE__*/React.createElement("thead", null, /*#__PURE__*/React.createElement("tr", null, /*#__PURE__*/React.createElement("th", null, "\u041D\u0430\u0437\u0432\u0430\u043D\u0438\u0435"), /*#__PURE__*/React.createElement("th", null, "\u0426\u0435\u043B\u0438"), /*#__PURE__*/React.createElement("th", null, "\u0418\u043D\u0442\u0435\u0440\u0432\u0430\u043B"), /*#__PURE__*/React.createElement("th", null, "\u0412\u043A\u043B\u044E\u0447\u0435\u043D\u043E"), /*#__PURE__*/React.createElement("th", null, "\u041F\u043E\u0441\u043B\u0435\u0434\u043D\u0438\u0439 \u0437\u0430\u043F\u0443\u0441\u043A"), /*#__PURE__*/React.createElement("th", null, "\u0421\u043B\u0435\u0434\u0443\u044E\u0449\u0438\u0439"), /*#__PURE__*/React.createElement("th", null))), /*#__PURE__*/React.createElement("tbody", null, list.map(s => /*#__PURE__*/React.createElement("tr", {
    key: s.id
  }, /*#__PURE__*/React.createElement("td", null, /*#__PURE__*/React.createElement("b", null, s.name || "Расписание #" + s.id), /*#__PURE__*/React.createElement("div", {
    className: "sub2"
  }, SCHED_KINDS[s.kind] || s.kind)), /*#__PURE__*/React.createElement("td", {
    className: "sub2 mono"
  }, s.targets || "демо"), /*#__PURE__*/React.createElement("td", null, s.interval_minutes, " \u043C\u0438\u043D"), /*#__PURE__*/React.createElement("td", null, /*#__PURE__*/React.createElement("label", {
    style: {
      display: "inline-flex",
      alignItems: "center",
      gap: 6,
      cursor: "pointer"
    }
  }, /*#__PURE__*/React.createElement("input", {
    type: "checkbox",
    checked: s.enabled,
    onChange: () => toggleEnabled(s)
  }), s.enabled ? "да" : "нет")), /*#__PURE__*/React.createElement("td", {
    className: "sub2"
  }, fmt(s.last_run_at)), /*#__PURE__*/React.createElement("td", {
    className: "sub2"
  }, fmt(s.next_run_at)), /*#__PURE__*/React.createElement("td", {
    style: {
      textAlign: "right",
      whiteSpace: "nowrap"
    }
  }, /*#__PURE__*/React.createElement("button", {
    className: "btn sm ghost",
    onClick: () => runNow(s.id)
  }, "\u0417\u0430\u043F\u0443\u0441\u0442\u0438\u0442\u044C \u0441\u0435\u0439\u0447\u0430\u0441"), " ", /*#__PURE__*/React.createElement("button", {
    className: "xbtn",
    title: "\u0423\u0434\u0430\u043B\u0438\u0442\u044C",
    onClick: () => del(s.id)
  }, "\u2715")))), list.length === 0 && /*#__PURE__*/React.createElement("tr", null, /*#__PURE__*/React.createElement("td", {
    colSpan: "7",
    className: "sub2"
  }, "\u0420\u0430\u0441\u043F\u0438\u0441\u0430\u043D\u0438\u0439 \u043D\u0435\u0442. \u0421\u043E\u0437\u0434\u0430\u0439\u0442\u0435 \u043F\u0435\u0440\u0432\u043E\u0435 \u0432\u044B\u0448\u0435 \u2014 \u043F\u0435\u0440\u0435\u0441\u0431\u043E\u0440 \u0431\u0443\u0434\u0435\u0442 \u0437\u0430\u043F\u0443\u0441\u043A\u0430\u0442\u044C\u0441\u044F \u0430\u0432\u0442\u043E\u043C\u0430\u0442\u0438\u0447\u0435\u0441\u043A\u0438.")))))));
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
    id: "schedules",
    ic: "⏱",
    l: "Расписания"
  }, {
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
  schedules: "Расписания",
  creds: "Учётные записи",
  connectors: "Коннекторы"
};

/* ----------------------------------------------------------------- поиск по активам */
function SearchBox({
  taskId,
  go
}) {
  const [q, setQ] = useState("");
  const [results, setResults] = useState([]);
  const [open, setOpen] = useState(false);
  useEffect(() => {
    if (!taskId || !q.trim()) {
      setResults([]);
      return;
    }
    const h = setTimeout(() => {
      api("/tasks/" + taskId + "/assets/search?q=" + encodeURIComponent(q)).then(r => {
        setResults(r);
        setOpen(true);
      }).catch(() => setResults([]));
    }, 250);
    return () => clearTimeout(h);
  }, [q, taskId]);
  const pick = name => {
    setOpen(false);
    setQ("");
    go({
      view: "asset",
      assetName: name
    });
  };
  return /*#__PURE__*/React.createElement("div", {
    className: "search"
  }, /*#__PURE__*/React.createElement("span", null, "\u2315"), /*#__PURE__*/React.createElement("input", {
    value: q,
    placeholder: "\u041F\u043E\u0438\u0441\u043A \u043F\u043E \u0430\u043A\u0442\u0438\u0432\u0430\u043C, IP\u2026",
    disabled: !taskId,
    onChange: e => setQ(e.target.value),
    onFocus: () => q.trim() && setOpen(true),
    onBlur: () => setTimeout(() => setOpen(false), 150),
    onKeyDown: e => {
      if (e.key === "Escape") {
        setQ("");
        setOpen(false);
      }
    }
  }), open && q.trim() && /*#__PURE__*/React.createElement("div", {
    className: "searchDrop"
  }, results.length === 0 ? /*#__PURE__*/React.createElement("div", {
    className: "searchItem sub2"
  }, "\u041D\u0438\u0447\u0435\u0433\u043E \u043D\u0435 \u043D\u0430\u0439\u0434\u0435\u043D\u043E") : results.map(r => /*#__PURE__*/React.createElement("div", {
    className: "searchItem",
    key: r.name,
    onMouseDown: () => pick(r.name)
  }, /*#__PURE__*/React.createElement("b", null, r.name), /*#__PURE__*/React.createElement("div", {
    className: "sub2"
  }, [r.ips, r.os, r.role].filter(Boolean).join(" · "))))));
}
function App() {
  const [tasks, setTasks] = useState([]);
  const [activeId, setActiveId] = useState(null);
  const [D, setD] = useState(null);
  const [diff, setDiff] = useState(null);
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
      setDiff(null);
      return;
    }
    api("/tasks/" + activeId).then(t => {
      setD(t.dashboard || null);
      setDiff(t.diff || null);
    }).catch(() => {
      setD(null);
      setDiff(null);
    });
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
    go: go,
    diff: diff
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
    go: go,
    taskId: activeId,
    onRoleChange: () => api("/tasks/" + activeId).then(t => setD(t.dashboard || null)).catch(() => {})
  });else if (nav.view === "netmap") screen = /*#__PURE__*/React.createElement(NetMap, {
    taskId: activeId,
    go: go,
    diff: diff
  });else if (nav.view === "schedules") screen = /*#__PURE__*/React.createElement(Schedules, {
    savedCreds: savedCreds
  });else if (nav.view === "creds") screen = /*#__PURE__*/React.createElement(Credentials, {
    onChange: loadCreds
  });else if (nav.view === "connectors") screen = /*#__PURE__*/React.createElement(Connectors, null);else screen = /*#__PURE__*/React.createElement(Dash, {
    D: D,
    tasks: tasks,
    go: go,
    diff: diff
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
  }, crumb), /*#__PURE__*/React.createElement(SearchBox, {
    taskId: activeId,
    go: go
  }), /*#__PURE__*/React.createElement("div", {
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
