import { jsxDEV as _jsxDEV, Fragment as _Fragment } from "react/jsx-dev-runtime";
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
  return /*#__PURE__*/_jsxDEV("div", {
    children: [/*#__PURE__*/_jsxDEV("h1", {
      className: "h1",
      children: "Новое сканирование"
    }, void 0, false), /*#__PURE__*/_jsxDEV("p", {
      className: "sub",
      children: "Укажите подсети и хосты. Сбор — сетевой (nmap): живые хосты, порты, версии сервисов, ОС → схема сети. Выберите учётные записи — сканер подключится к активам (SSH/WinRM/SNMP) и соберёт полный инвентарь; к каждому активу УЗ подбирается автоматически."
    }, void 0, false), /*#__PURE__*/_jsxDEV("div", {
      className: "card",
      style: {
        maxWidth: 820
      },
      children: /*#__PURE__*/_jsxDEV("div", {
        className: "cb",
        children: [/*#__PURE__*/_jsxDEV("div", {
          className: "field",
          children: [/*#__PURE__*/_jsxDEV("label", {
            children: "Цели: подсети / хосты"
          }, void 0, false), /*#__PURE__*/_jsxDEV("textarea", {
            rows: "4",
            value: targets,
            onChange: e => setTargets(e.target.value),
            placeholder: "10.0.0.0/24, 10.0.1.5\nsrv01.corp",
            style: {
              fontFamily: "JetBrains Mono, monospace",
              fontSize: 13
            }
          }, void 0, false), /*#__PURE__*/_jsxDEV("div", {
            className: "sub2",
            children: ["Через запятую, пробел или с новой строки. Примеры: ", /*#__PURE__*/_jsxDEV("span", {
              className: "mono",
              children: "192.168.1.0/24"
            }, void 0, false), ", ", /*#__PURE__*/_jsxDEV("span", {
              className: "mono",
              children: "10.0.0.5"
            }, void 0, false)]
          }, void 0, true)]
        }, void 0, true), /*#__PURE__*/_jsxDEV("div", {
          className: "field",
          style: {
            marginTop: 18
          },
          children: [/*#__PURE__*/_jsxDEV("div", {
            style: {
              display: "flex",
              alignItems: "center"
            },
            children: [/*#__PURE__*/_jsxDEV("label", {
              style: {
                margin: 0
              },
              children: ["Учётные записи для сбора ", /*#__PURE__*/_jsxDEV("span", {
                className: "sub2",
                style: {
                  fontWeight: 400
                },
                children: "(опционально — без них только сетевое обнаружение)"
              }, void 0, false)]
            }, void 0, true), /*#__PURE__*/_jsxDEV("span", {
              className: "more",
              style: {
                marginLeft: "auto"
              },
              onClick: () => go({
                view: "creds"
              }),
              children: "Управление УЗ →"
            }, void 0, false)]
          }, void 0, true), !savedCreds || savedCreds.length === 0 ? /*#__PURE__*/_jsxDEV("div", {
            className: "sub2",
            style: {
              margin: "8px 0"
            },
            children: ["Сохранённых УЗ нет. ", /*#__PURE__*/_jsxDEV("span", {
              className: "link",
              onClick: () => go({
                view: "creds"
              }),
              children: "Добавьте учётную запись"
            }, void 0, false), " во вкладке «Учётные записи» — затем выбирайте её здесь."]
          }, void 0, true) : /*#__PURE__*/_jsxDEV("div", {
            className: "credpick",
            children: savedCreds.map(c => /*#__PURE__*/_jsxDEV("label", {
              className: "credopt" + (sel.includes(c.id) ? " on" : ""),
              children: [/*#__PURE__*/_jsxDEV("input", {
                type: "checkbox",
                checked: sel.includes(c.id),
                onChange: () => toggle(c.id)
              }, void 0, false), /*#__PURE__*/_jsxDEV("span", {
                className: "cn",
                children: c.name
              }, void 0, false), /*#__PURE__*/_jsxDEV("span", {
                className: "ct",
                children: CRED_KIND[c.type] || c.type
              }, void 0, false), /*#__PURE__*/_jsxDEV("span", {
                className: "cu mono",
                children: [c.type === "snmp" ? "community" : c.username || "—", c.port ? ":" + c.port : ""]
              }, void 0, true)]
            }, c.id, true))
          }, void 0, false)]
        }, void 0, true), /*#__PURE__*/_jsxDEV("div", {
          style: {
            display: "flex",
            gap: 10,
            marginTop: 18
          },
          children: [/*#__PURE__*/_jsxDEV("button", {
            className: "btn",
            disabled: busy || !targets.trim(),
            onClick: () => onRun(targets, sel),
            children: busy ? "Запуск…" : "Запустить скан"
          }, void 0, false), /*#__PURE__*/_jsxDEV("button", {
            className: "btn ghost",
            onClick: () => go({
              view: "dash"
            }),
            children: "Отмена"
          }, void 0, false)]
        }, void 0, true)]
      }, void 0, true)
    }, void 0, false), /*#__PURE__*/_jsxDEV("div", {
      className: "warn",
      style: {
        maxWidth: 820,
        marginTop: 14
      },
      children: "Секреты хранятся в базе в зашифрованном виде (ключ — в переменной окружения, не в БД) и расшифровываются только на время задачи. К каждому активу применяется подходящая по типу УЗ (перебор до первой успешной); в сводке фиксируется только логин."
    }, void 0, false)]
  }, void 0, true);
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
  return /*#__PURE__*/_jsxDEV("div", {
    children: [/*#__PURE__*/_jsxDEV("h1", {
      className: "h1",
      children: "Учётные записи"
    }, void 0, false), /*#__PURE__*/_jsxDEV("p", {
      className: "sub",
      children: "Хранилище УЗ для аутентифицированного сбора. Заводятся один раз — затем выбираются в форме скана. Секреты шифруются в БД (ключ в переменной окружения, не в базе)."
    }, void 0, false), /*#__PURE__*/_jsxDEV("div", {
      className: "card",
      style: {
        marginBottom: 16,
        maxWidth: 820
      },
      children: /*#__PURE__*/_jsxDEV("div", {
        className: "cb",
        children: [/*#__PURE__*/_jsxDEV("div", {
          className: "credrow",
          children: [/*#__PURE__*/_jsxDEV("input", {
            placeholder: "Имя: Linux-аудит",
            value: f.name,
            style: {
              flex: 1.4
            },
            onChange: e => setFF("name", e.target.value)
          }, void 0, false), /*#__PURE__*/_jsxDEV("select", {
            value: f.type,
            onChange: e => setFF("type", e.target.value),
            children: [/*#__PURE__*/_jsxDEV("option", {
              value: "ssh",
              children: "SSH · Linux"
            }, void 0, false), /*#__PURE__*/_jsxDEV("option", {
              value: "winrm",
              children: "WinRM · Windows"
            }, void 0, false), /*#__PURE__*/_jsxDEV("option", {
              value: "snmp",
              children: "SNMP · оборуд."
            }, void 0, false)]
          }, void 0, true), /*#__PURE__*/_jsxDEV("input", {
            placeholder: f.type === "snmp" ? "— (не нужно)" : "логин",
            value: f.username,
            disabled: f.type === "snmp",
            onChange: e => setFF("username", e.target.value)
          }, void 0, false), /*#__PURE__*/_jsxDEV("input", {
            type: "password",
            placeholder: f.type === "snmp" ? "community" : "пароль / ключ",
            value: f.secret,
            autoComplete: "new-password",
            onChange: e => setFF("secret", e.target.value)
          }, void 0, false), f.type === "winrm" ? /*#__PURE__*/_jsxDEV("input", {
            placeholder: "домен",
            value: f.domain,
            style: {
              width: 90
            },
            onChange: e => setFF("domain", e.target.value)
          }, void 0, false) : null, /*#__PURE__*/_jsxDEV("input", {
            placeholder: "порт",
            value: f.port,
            style: {
              width: 64
            },
            onChange: e => setFF("port", e.target.value)
          }, void 0, false), /*#__PURE__*/_jsxDEV("button", {
            className: "btn sm",
            onClick: add,
            children: "Сохранить"
          }, void 0, false)]
        }, void 0, true), err ? /*#__PURE__*/_jsxDEV("div", {
          className: "sub2",
          style: {
            color: "var(--crit,#b4232a)",
            marginTop: 8
          },
          children: err
        }, void 0, false) : null]
      }, void 0, true)
    }, void 0, false), /*#__PURE__*/_jsxDEV("div", {
      className: "card",
      style: {
        maxWidth: 820
      },
      children: /*#__PURE__*/_jsxDEV("div", {
        className: "cb",
        children: /*#__PURE__*/_jsxDEV("table", {
          children: [/*#__PURE__*/_jsxDEV("thead", {
            children: /*#__PURE__*/_jsxDEV("tr", {
              children: [/*#__PURE__*/_jsxDEV("th", {
                children: "Имя"
              }, void 0, false), /*#__PURE__*/_jsxDEV("th", {
                children: "Тип"
              }, void 0, false), /*#__PURE__*/_jsxDEV("th", {
                children: "Логин / порт"
              }, void 0, false), /*#__PURE__*/_jsxDEV("th", {
                children: "Добавлена"
              }, void 0, false), /*#__PURE__*/_jsxDEV("th", {}, void 0, false)]
            }, void 0, true)
          }, void 0, false), /*#__PURE__*/_jsxDEV("tbody", {
            children: [list.map(c => /*#__PURE__*/_jsxDEV("tr", {
              children: [/*#__PURE__*/_jsxDEV("td", {
                children: /*#__PURE__*/_jsxDEV("b", {
                  children: c.name
                }, void 0, false)
              }, void 0, false), /*#__PURE__*/_jsxDEV("td", {
                children: CRED_KIND[c.type] || c.type
              }, void 0, false), /*#__PURE__*/_jsxDEV("td", {
                className: "mono sub2",
                children: [c.type === "snmp" ? "community" : c.username || "—", c.port ? ":" + c.port : "", c.domain ? " · " + c.domain : ""]
              }, void 0, true), /*#__PURE__*/_jsxDEV("td", {
                className: "sub2",
                children: c.created_at ? c.created_at.replace("T", " ").slice(0, 16) : ""
              }, void 0, false), /*#__PURE__*/_jsxDEV("td", {
                style: {
                  textAlign: "right"
                },
                children: /*#__PURE__*/_jsxDEV("button", {
                  className: "xbtn",
                  title: "Удалить",
                  onClick: () => del(c.id),
                  children: "✕"
                }, void 0, false)
              }, void 0, false)]
            }, c.id, true)), list.length === 0 && /*#__PURE__*/_jsxDEV("tr", {
              children: /*#__PURE__*/_jsxDEV("td", {
                colSpan: "5",
                className: "sub2",
                children: "УЗ не заведены. Добавьте первую выше."
              }, void 0, false)
            }, void 0, false)]
          }, void 0, true)]
        }, void 0, true)
      }, void 0, false)
    }, void 0, false), /*#__PURE__*/_jsxDEV("div", {
      className: "warn",
      style: {
        maxWidth: 820,
        marginTop: 14
      },
      children: ["Пароли, ключи и community хранятся зашифрованными (Fernet). Мастер-ключ берётся из ", /*#__PURE__*/_jsxDEV("span", {
        className: "mono",
        children: "SURVEYSCAN_SECRET_KEY"
      }, void 0, false), " и в базе не лежит — дамп БД сам по себе секреты не раскроет. Задайте эту переменную в своём окружении (иначе ключ генерируется в томе данных и теряется вместе с ним)."]
    }, void 0, true)]
  }, void 0, true);
}

/* ----------------------------------------------------------------- Дашборд */
function Dash({
  D,
  tasks,
  go
}) {
  if (!D) return /*#__PURE__*/_jsxDEV("div", {
    className: "empty",
    children: "Нет данных. Запустите сканирование: «+ Новое сканирование»."
  }, void 0, false);
  const ts = D.topology && D.topology.stats || {};
  const assets = D.assets || [];
  const kpi = (n, l, c) => /*#__PURE__*/_jsxDEV("div", {
    className: "kpi",
    children: [/*#__PURE__*/_jsxDEV("div", {
      className: "l",
      children: l
    }, void 0, false), /*#__PURE__*/_jsxDEV("div", {
      className: "n",
      style: c ? {
        color: c
      } : null,
      children: n
    }, void 0, false)]
  }, void 0, true);
  return /*#__PURE__*/_jsxDEV("div", {
    children: [/*#__PURE__*/_jsxDEV("h1", {
      className: "h1",
      children: D.survey && D.survey.name || "Обследование"
    }, void 0, false), /*#__PURE__*/_jsxDEV("p", {
      className: "sub",
      children: ["Инвентаризация сети · ", D.generated]
    }, void 0, true), /*#__PURE__*/_jsxDEV("div", {
      className: "kpis",
      children: [kpi(D.totals ? D.totals.assets : assets.length, "Активов"), kpi(ts.hosts != null ? ts.hosts : "—", "Хостов"), kpi(ts.devices != null ? ts.devices : "—", "Сетевых устройств"), kpi(ts.subnets != null ? ts.subnets : "—", "Подсетей"), kpi(ts.services != null ? ts.services : "—", "Открытых сервисов")]
    }, void 0, true), /*#__PURE__*/_jsxDEV("div", {
      className: "cols dash",
      children: [/*#__PURE__*/_jsxDEV("div", {
        className: "card",
        children: [/*#__PURE__*/_jsxDEV("div", {
          className: "ch",
          children: [/*#__PURE__*/_jsxDEV("h3", {
            children: "Активы"
          }, void 0, false), /*#__PURE__*/_jsxDEV("span", {
            className: "more",
            onClick: () => go({
              view: "assets"
            }),
            children: "Все активы →"
          }, void 0, false)]
        }, void 0, true), /*#__PURE__*/_jsxDEV("div", {
          className: "cb",
          children: /*#__PURE__*/_jsxDEV("table", {
            children: [/*#__PURE__*/_jsxDEV("thead", {
              children: /*#__PURE__*/_jsxDEV("tr", {
                children: [/*#__PURE__*/_jsxDEV("th", {
                  children: "Актив"
                }, void 0, false), /*#__PURE__*/_jsxDEV("th", {
                  children: "IP"
                }, void 0, false), /*#__PURE__*/_jsxDEV("th", {
                  children: "ОС / платформа"
                }, void 0, false), /*#__PURE__*/_jsxDEV("th", {
                  children: "Сервисы"
                }, void 0, false)]
              }, void 0, true)
            }, void 0, false), /*#__PURE__*/_jsxDEV("tbody", {
              children: [assets.slice(0, 6).map(a => /*#__PURE__*/_jsxDEV("tr", {
                className: "click",
                onClick: () => go({
                  view: "asset",
                  assetName: a.name
                }),
                children: [/*#__PURE__*/_jsxDEV("td", {
                  children: /*#__PURE__*/_jsxDEV("b", {
                    children: a.name
                  }, void 0, false)
                }, void 0, false), /*#__PURE__*/_jsxDEV("td", {
                  className: "mono",
                  children: a.ips
                }, void 0, false), /*#__PURE__*/_jsxDEV("td", {
                  children: a.os || "—"
                }, void 0, false), /*#__PURE__*/_jsxDEV("td", {
                  className: "num",
                  children: (a.services || []).length
                }, void 0, false)]
              }, a.name, true)), assets.length === 0 && /*#__PURE__*/_jsxDEV("tr", {
                children: /*#__PURE__*/_jsxDEV("td", {
                  colSpan: "4",
                  className: "sub2",
                  children: "Активы не найдены."
                }, void 0, false)
              }, void 0, false)]
            }, void 0, true)]
          }, void 0, true)
        }, void 0, false)]
      }, void 0, true), /*#__PURE__*/_jsxDEV("div", {
        className: "card",
        children: [/*#__PURE__*/_jsxDEV("div", {
          className: "ch",
          children: [/*#__PURE__*/_jsxDEV("h3", {
            children: "Схема сети"
          }, void 0, false), /*#__PURE__*/_jsxDEV("span", {
            className: "more",
            onClick: () => go({
              view: "netmap"
            }),
            children: "Открыть →"
          }, void 0, false)]
        }, void 0, true), /*#__PURE__*/_jsxDEV("div", {
          className: "cb",
          children: [/*#__PURE__*/_jsxDEV("div", {
            style: {
              fontSize: 13,
              color: "var(--muted)",
              lineHeight: 1.7
            },
            children: ["Узлов: ", /*#__PURE__*/_jsxDEV("b", {
              style: {
                color: "var(--ink)"
              },
              children: ts.nodes || 0
            }, void 0, false), /*#__PURE__*/_jsxDEV("br", {}, void 0, false), "Подсетей: ", /*#__PURE__*/_jsxDEV("b", {
              style: {
                color: "var(--ink)"
              },
              children: ts.subnets || 0
            }, void 0, false), /*#__PURE__*/_jsxDEV("br", {}, void 0, false), "Сетевых устройств: ", /*#__PURE__*/_jsxDEV("b", {
              style: {
                color: "var(--ink)"
              },
              children: ts.devices || 0
            }, void 0, false), /*#__PURE__*/_jsxDEV("br", {}, void 0, false), "Связей: ", /*#__PURE__*/_jsxDEV("b", {
              style: {
                color: "var(--ink)"
              },
              children: ts.edges || 0
            }, void 0, false)]
          }, void 0, true), /*#__PURE__*/_jsxDEV("button", {
            className: "btn",
            style: {
              marginTop: 12
            },
            onClick: () => go({
              view: "netmap"
            }),
            children: "Открыть схему сети"
          }, void 0, false)]
        }, void 0, true)]
      }, void 0, true), /*#__PURE__*/_jsxDEV("div", {
        className: "card",
        children: [/*#__PURE__*/_jsxDEV("div", {
          className: "ch",
          children: [/*#__PURE__*/_jsxDEV("h3", {
            children: "Сканирования"
          }, void 0, false), /*#__PURE__*/_jsxDEV("span", {
            className: "more",
            onClick: () => go({
              view: "surveys"
            }),
            children: "Все →"
          }, void 0, false)]
        }, void 0, true), /*#__PURE__*/_jsxDEV("div", {
          className: "cb",
          children: [tasks.slice(0, 6).map(tk => {
            const cls = tk.status === "done" ? "d-ok" : tk.status === "running" ? "d-run" : tk.status === "error" ? "d-err" : "d-wait";
            const st = {
              done: "готово",
              running: "идёт",
              queued: "в очереди",
              error: "ошибка"
            }[tk.status];
            return /*#__PURE__*/_jsxDEV("div", {
              className: "scan",
              children: [/*#__PURE__*/_jsxDEV("span", {
                className: "dotc " + cls
              }, void 0, false), /*#__PURE__*/_jsxDEV("div", {
                children: /*#__PURE__*/_jsxDEV("div", {
                  className: "nm",
                  children: tk.name || "Скан #" + tk.id
                }, void 0, false)
              }, void 0, false), /*#__PURE__*/_jsxDEV("span", {
                className: "pct",
                children: st
              }, void 0, false)]
            }, tk.id, true);
          }), tasks.length === 0 && /*#__PURE__*/_jsxDEV("div", {
            className: "sub2",
            children: "Пока нет сканирований."
          }, void 0, false)]
        }, void 0, true)]
      }, void 0, true)]
    }, void 0, true)]
  }, void 0, true);
}

/* ----------------------------------------------------------------- Активы */
function Assets({
  D,
  go
}) {
  if (!D) return /*#__PURE__*/_jsxDEV("div", {
    className: "empty",
    children: "Нет данных. Запустите сканирование."
  }, void 0, false);
  const assets = D.assets || [];
  return /*#__PURE__*/_jsxDEV("div", {
    children: [/*#__PURE__*/_jsxDEV("h1", {
      className: "h1",
      children: "Активы"
    }, void 0, false), /*#__PURE__*/_jsxDEV("p", {
      className: "sub",
      children: ["Инвентаризация активов обследования «", D.survey && D.survey.name, "»."]
    }, void 0, true), /*#__PURE__*/_jsxDEV("div", {
      className: "card",
      children: /*#__PURE__*/_jsxDEV("div", {
        className: "cb",
        children: /*#__PURE__*/_jsxDEV("table", {
          children: [/*#__PURE__*/_jsxDEV("thead", {
            children: /*#__PURE__*/_jsxDEV("tr", {
              children: [/*#__PURE__*/_jsxDEV("th", {
                children: "Актив"
              }, void 0, false), /*#__PURE__*/_jsxDEV("th", {
                children: "IP"
              }, void 0, false), /*#__PURE__*/_jsxDEV("th", {
                children: "ОС / платформа"
              }, void 0, false), /*#__PURE__*/_jsxDEV("th", {
                children: "Тип"
              }, void 0, false), /*#__PURE__*/_jsxDEV("th", {
                className: "num",
                children: "ПО"
              }, void 0, false), /*#__PURE__*/_jsxDEV("th", {
                className: "num",
                children: "Сервисов"
              }, void 0, false)]
            }, void 0, true)
          }, void 0, false), /*#__PURE__*/_jsxDEV("tbody", {
            children: [assets.map(a => /*#__PURE__*/_jsxDEV("tr", {
              className: "click",
              onClick: () => go({
                view: "asset",
                assetName: a.name
              }),
              children: [/*#__PURE__*/_jsxDEV("td", {
                children: [/*#__PURE__*/_jsxDEV("b", {
                  children: a.name
                }, void 0, false), a.partial ? /*#__PURE__*/_jsxDEV("span", {
                  className: "chip c-medium",
                  style: {
                    marginLeft: 8
                  },
                  children: "сбор без root"
                }, void 0, false) : null]
              }, void 0, true), /*#__PURE__*/_jsxDEV("td", {
                className: "mono",
                children: a.ips || "—"
              }, void 0, false), /*#__PURE__*/_jsxDEV("td", {
                children: [a.os || "—", a.build ? /*#__PURE__*/_jsxDEV("div", {
                  className: "sub2 mono",
                  children: a.build
                }, void 0, false) : null]
              }, void 0, true), /*#__PURE__*/_jsxDEV("td", {
                children: a.kind
              }, void 0, false), /*#__PURE__*/_jsxDEV("td", {
                className: "num",
                children: a.software || 0
              }, void 0, false), /*#__PURE__*/_jsxDEV("td", {
                className: "num",
                children: (a.services || []).length
              }, void 0, false)]
            }, a.name, true)), assets.length === 0 && /*#__PURE__*/_jsxDEV("tr", {
              children: /*#__PURE__*/_jsxDEV("td", {
                colSpan: "6",
                className: "sub2",
                children: "Активы не найдены."
              }, void 0, false)
            }, void 0, false)]
          }, void 0, true)]
        }, void 0, true)
      }, void 0, false)
    }, void 0, false)]
  }, void 0, true);
}

/* --- вспомогательные блоки карточки актива --- */
function KV({
  k,
  v
}) {
  return /*#__PURE__*/_jsxDEV("div", {
    className: "kv",
    children: [/*#__PURE__*/_jsxDEV("span", {
      className: "k",
      children: k
    }, void 0, false), /*#__PURE__*/_jsxDEV("span", {
      className: "v",
      children: v === null || v === undefined || v === "" ? "—" : String(v)
    }, void 0, false)]
  }, void 0, true);
}
function SimpleTable({
  cols,
  rows,
  empty
}) {
  if (!rows || rows.length === 0) return /*#__PURE__*/_jsxDEV("div", {
    className: "sub2",
    children: empty
  }, void 0, false);
  return /*#__PURE__*/_jsxDEV("table", {
    children: [/*#__PURE__*/_jsxDEV("thead", {
      children: /*#__PURE__*/_jsxDEV("tr", {
        children: cols.map(c => /*#__PURE__*/_jsxDEV("th", {
          className: c.num ? "num" : "",
          children: c.label
        }, c.key, false))
      }, void 0, false)
    }, void 0, false), /*#__PURE__*/_jsxDEV("tbody", {
      children: rows.map((r, i) => /*#__PURE__*/_jsxDEV("tr", {
        children: cols.map(c => /*#__PURE__*/_jsxDEV("td", {
          className: c.mono ? "mono" : c.num ? "num" : "",
          children: c.render ? c.render(r) : r[c.key] ?? "—"
        }, c.key, false))
      }, i, false))
    }, void 0, false)]
  }, void 0, true);
}
function AssetDetail({
  D,
  name,
  go
}) {
  const a = (D.assets || []).find(x => x.name === name);
  const [tab, setTab] = useState("overview");
  const [swFilter, setSwFilter] = useState("");
  if (!a) return /*#__PURE__*/_jsxDEV("div", {
    className: "empty",
    children: "Актив не найден."
  }, void 0, false);
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
  return /*#__PURE__*/_jsxDEV("div", {
    children: [/*#__PURE__*/_jsxDEV("div", {
      className: "crumb",
      style: {
        marginBottom: 10
      },
      children: [/*#__PURE__*/_jsxDEV("span", {
        className: "link",
        onClick: () => go({
          view: "assets"
        }),
        children: "Активы"
      }, void 0, false), /*#__PURE__*/_jsxDEV("span", {
        className: "sep",
        children: "/"
      }, void 0, false), /*#__PURE__*/_jsxDEV("b", {
        children: name
      }, void 0, false)]
    }, void 0, true), /*#__PURE__*/_jsxDEV("div", {
      className: "pagehead",
      children: [/*#__PURE__*/_jsxDEV("div", {
        className: "ic",
        children: (a.kind || "").toLowerCase().includes("сетев") ? "🖧" : "🖥"
      }, void 0, false), /*#__PURE__*/_jsxDEV("div", {
        children: [/*#__PURE__*/_jsxDEV("div", {
          className: "h1",
          style: {
            margin: 0
          },
          children: name
        }, void 0, false), /*#__PURE__*/_jsxDEV("div", {
          className: "meta mono",
          children: [a.ips, a.os ? " · " + a.os : ""]
        }, void 0, true)]
      }, void 0, true)]
    }, void 0, true), a.partial ? /*#__PURE__*/_jsxDEV("div", {
      className: "warn",
      style: {
        margin: "10px 0"
      },
      children: "Сбор выполнен без root/sudo — часть данных (учётки, конфиги) может быть неполной."
    }, void 0, false) : null, /*#__PURE__*/_jsxDEV("div", {
      className: "tabs",
      children: tabs.map(t => /*#__PURE__*/_jsxDEV("div", {
        className: "tab" + (tab === t.id ? " on" : ""),
        onClick: () => setTab(t.id),
        children: [t.label, t.count !== undefined ? /*#__PURE__*/_jsxDEV("span", {
          className: "cnt",
          children: t.count
        }, void 0, false) : null]
      }, t.id, true))
    }, void 0, false), tab === "overview" && /*#__PURE__*/_jsxDEV("div", {
      className: "detail",
      children: [/*#__PURE__*/_jsxDEV("div", {
        className: "card",
        children: [/*#__PURE__*/_jsxDEV("div", {
          className: "ch",
          children: /*#__PURE__*/_jsxDEV("h3", {
            children: "Сведения"
          }, void 0, false)
        }, void 0, false), /*#__PURE__*/_jsxDEV("div", {
          className: "cb",
          children: [/*#__PURE__*/_jsxDEV(KV, {
            k: "Тип",
            v: a.kind
          }, void 0, false), /*#__PURE__*/_jsxDEV(KV, {
            k: "IP",
            v: a.ips
          }, void 0, false), /*#__PURE__*/_jsxDEV(KV, {
            k: "ОС / платформа",
            v: a.os
          }, void 0, false), /*#__PURE__*/_jsxDEV(KV, {
            k: "Сборка / версия",
            v: a.build
          }, void 0, false), fam === "windows" ? /*#__PURE__*/_jsxDEV(_Fragment, {
            children: [/*#__PURE__*/_jsxDEV(KV, {
              k: "Домен",
              v: inv.part_of_domain ? inv.domain : "рабочая группа"
            }, void 0, false), /*#__PURE__*/_jsxDEV(KV, {
              k: "Архитектура",
              v: inv.architecture
            }, void 0, false), /*#__PURE__*/_jsxDEV(KV, {
              k: "Тип установки",
              v: inv.installation_type
            }, void 0, false), /*#__PURE__*/_jsxDEV(KV, {
              k: "Последняя загрузка",
              v: inv.last_boot
            }, void 0, false), /*#__PURE__*/_jsxDEV(KV, {
              k: "Сбор от администратора",
              v: inv.is_admin === true ? "да" : inv.is_admin === false ? "нет" : "—"
            }, void 0, false)]
          }, void 0, true) : null, fam === "linux" ? /*#__PURE__*/_jsxDEV(KV, {
            k: "Сбор от root",
            v: inv.is_root === true ? "да" : inv.is_root === false ? "нет (sudo/частично)" : "—"
          }, void 0, false) : null, /*#__PURE__*/_jsxDEV(KV, {
            k: "Источник сбора",
            v: a.source
          }, void 0, false), /*#__PURE__*/_jsxDEV(KV, {
            k: "Собрано",
            v: a.collected_at
          }, void 0, false)]
        }, void 0, true)]
      }, void 0, true), /*#__PURE__*/_jsxDEV("div", {
        children: [/*#__PURE__*/_jsxDEV("div", {
          className: "card",
          children: [/*#__PURE__*/_jsxDEV("div", {
            className: "ch",
            children: /*#__PURE__*/_jsxDEV("h3", {
              children: "Итоги"
            }, void 0, false)
          }, void 0, false), /*#__PURE__*/_jsxDEV("div", {
            className: "cb",
            children: [/*#__PURE__*/_jsxDEV(KV, {
              k: "Пакетов / ПО",
              v: software.length
            }, void 0, false), /*#__PURE__*/_jsxDEV(KV, {
              k: "Открытых сервисов (сеть)",
              v: (a.services || []).length
            }, void 0, false), /*#__PURE__*/_jsxDEV(KV, {
              k: "Слушающих портов (ОС)",
              v: listening.length
            }, void 0, false), fam === "windows" ? /*#__PURE__*/_jsxDEV(KV, {
              k: "Обновлений (KB)",
              v: (inv.hotfixes || []).length
            }, void 0, false) : null]
          }, void 0, true)]
        }, void 0, true), a.sec_tools && a.sec_tools.length ? /*#__PURE__*/_jsxDEV("div", {
          className: "card",
          style: {
            marginTop: 16
          },
          children: [/*#__PURE__*/_jsxDEV("div", {
            className: "ch",
            children: /*#__PURE__*/_jsxDEV("h3", {
              children: "Средства защиты"
            }, void 0, false)
          }, void 0, false), /*#__PURE__*/_jsxDEV("div", {
            className: "cb",
            children: a.sec_tools.map((t, i) => /*#__PURE__*/_jsxDEV("div", {
              style: {
                padding: "5px 0"
              },
              children: [/*#__PURE__*/_jsxDEV("span", {
                style: {
                  color: "var(--ok)"
                },
                children: "✓"
              }, void 0, false), " ", t]
            }, i, true))
          }, void 0, false)]
        }, void 0, true) : null]
      }, void 0, true)]
    }, void 0, true), tab === "software" && /*#__PURE__*/_jsxDEV("div", {
      className: "card",
      children: [/*#__PURE__*/_jsxDEV("div", {
        className: "ch",
        children: [/*#__PURE__*/_jsxDEV("h3", {
          children: "Установленное ПО / пакеты"
        }, void 0, false), /*#__PURE__*/_jsxDEV("input", {
          value: swFilter,
          onChange: e => setSwFilter(e.target.value),
          placeholder: "Фильтр по имени…",
          style: {
            marginLeft: "auto",
            fontSize: 12.5,
            padding: "4px 8px"
          }
        }, void 0, false)]
      }, void 0, true), /*#__PURE__*/_jsxDEV("div", {
        className: "cb",
        children: /*#__PURE__*/_jsxDEV(SimpleTable, {
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
        }, void 0, false)
      }, void 0, false)]
    }, void 0, true), tab === "hotfixes" && /*#__PURE__*/_jsxDEV("div", {
      className: "card",
      children: [/*#__PURE__*/_jsxDEV("div", {
        className: "ch",
        children: /*#__PURE__*/_jsxDEV("h3", {
          children: "Установленные обновления"
        }, void 0, false)
      }, void 0, false), /*#__PURE__*/_jsxDEV("div", {
        className: "cb",
        children: (inv.hotfixes || []).length ? /*#__PURE__*/_jsxDEV("div", {
          style: {
            display: "flex",
            flexWrap: "wrap",
            gap: 8
          },
          children: inv.hotfixes.map(kb => /*#__PURE__*/_jsxDEV("span", {
            className: "mono chip c-low",
            children: ["KB", kb]
          }, kb, true))
        }, void 0, false) : /*#__PURE__*/_jsxDEV("div", {
          className: "sub2",
          children: "Обновления не собраны."
        }, void 0, false)
      }, void 0, false)]
    }, void 0, true), tab === "users" && /*#__PURE__*/_jsxDEV("div", {
      className: "detail",
      children: [/*#__PURE__*/_jsxDEV("div", {
        className: "card",
        children: [/*#__PURE__*/_jsxDEV("div", {
          className: "ch",
          children: /*#__PURE__*/_jsxDEV("h3", {
            children: "Учётные записи"
          }, void 0, false)
        }, void 0, false), /*#__PURE__*/_jsxDEV("div", {
          className: "cb",
          children: fam === "windows" ? /*#__PURE__*/_jsxDEV(SimpleTable, {
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
          }, void 0, false) : /*#__PURE__*/_jsxDEV(SimpleTable, {
            empty: "Пользователи не собраны.",
            cols: [{
              key: "name",
              label: "Логин"
            }],
            rows: (inv.login_users || []).map(n => ({
              name: n
            }))
          }, void 0, false)
        }, void 0, false)]
      }, void 0, true), /*#__PURE__*/_jsxDEV("div", {
        children: fam === "windows" ? /*#__PURE__*/_jsxDEV("div", {
          className: "card",
          children: [/*#__PURE__*/_jsxDEV("div", {
            className: "ch",
            children: /*#__PURE__*/_jsxDEV("h3", {
              children: "Администраторы"
            }, void 0, false)
          }, void 0, false), /*#__PURE__*/_jsxDEV("div", {
            className: "cb",
            children: (inv.admins || []).length ? inv.admins.map((n, i) => /*#__PURE__*/_jsxDEV("div", {
              className: "mono",
              style: {
                padding: "4px 0",
                fontSize: 12.5
              },
              children: n
            }, i, false)) : /*#__PURE__*/_jsxDEV("div", {
              className: "sub2",
              children: "Группа «Администраторы» пуста или не собрана."
            }, void 0, false)
          }, void 0, false)]
        }, void 0, true) : /*#__PURE__*/_jsxDEV(_Fragment, {
          children: /*#__PURE__*/_jsxDEV("div", {
            className: "card",
            children: [/*#__PURE__*/_jsxDEV("div", {
              className: "ch",
              children: /*#__PURE__*/_jsxDEV("h3", {
                children: "UID 0 / sudo без пароля"
              }, void 0, false)
            }, void 0, false), /*#__PURE__*/_jsxDEV("div", {
              className: "cb",
              children: [/*#__PURE__*/_jsxDEV(KV, {
                k: "UID 0 (кроме root)",
                v: (inv.uid0_users || []).join(", ") || "—"
              }, void 0, false), /*#__PURE__*/_jsxDEV(KV, {
                k: "sudo NOPASSWD",
                v: inv.sudo_nopasswd === null ? "нет доступа к данным" : (inv.sudo_nopasswd || []).join("; ") || "нет"
              }, void 0, false), /*#__PURE__*/_jsxDEV(KV, {
                k: "Пустой пароль",
                v: inv.empty_password_users === null ? "нет доступа к данным" : (inv.empty_password_users || []).join(", ") || "нет"
              }, void 0, false)]
            }, void 0, true)]
          }, void 0, true)
        }, void 0, false)
      }, void 0, false)]
    }, void 0, true), tab === "network" && /*#__PURE__*/_jsxDEV("div", {
      className: "detail",
      children: [/*#__PURE__*/_jsxDEV("div", {
        className: "card",
        children: [/*#__PURE__*/_jsxDEV("div", {
          className: "ch",
          children: /*#__PURE__*/_jsxDEV("h3", {
            children: "Открытые сервисы (сетевой скан)"
          }, void 0, false)
        }, void 0, false), /*#__PURE__*/_jsxDEV("div", {
          className: "cb",
          children: (a.services || []).length ? (a.services || []).map((s, i) => /*#__PURE__*/_jsxDEV("div", {
            className: "mono",
            style: {
              padding: "5px 0",
              fontSize: 12.5
            },
            children: s
          }, i, false)) : /*#__PURE__*/_jsxDEV("div", {
            className: "sub2",
            children: "Открытых сервисов не обнаружено."
          }, void 0, false)
        }, void 0, false)]
      }, void 0, true), /*#__PURE__*/_jsxDEV("div", {
        className: "card",
        children: [/*#__PURE__*/_jsxDEV("div", {
          className: "ch",
          children: /*#__PURE__*/_jsxDEV("h3", {
            children: "Слушающие порты (на хосте)"
          }, void 0, false)
        }, void 0, false), /*#__PURE__*/_jsxDEV("div", {
          className: "cb",
          children: /*#__PURE__*/_jsxDEV(SimpleTable, {
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
          }, void 0, false)
        }, void 0, false)]
      }, void 0, true), fam === "windows" && (inv.services || []).length ? /*#__PURE__*/_jsxDEV("div", {
        className: "card",
        style: {
          gridColumn: "1 / -1"
        },
        children: [/*#__PURE__*/_jsxDEV("div", {
          className: "ch",
          children: /*#__PURE__*/_jsxDEV("h3", {
            children: "Службы Windows"
          }, void 0, false)
        }, void 0, false), /*#__PURE__*/_jsxDEV("div", {
          className: "cb",
          children: /*#__PURE__*/_jsxDEV(SimpleTable, {
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
          }, void 0, false)
        }, void 0, false)]
      }, void 0, true) : null]
    }, void 0, true), tab === "security" && /*#__PURE__*/_jsxDEV("div", {
      className: "detail",
      children: fam === "windows" ? /*#__PURE__*/_jsxDEV(_Fragment, {
        children: [/*#__PURE__*/_jsxDEV("div", {
          className: "card",
          children: [/*#__PURE__*/_jsxDEV("div", {
            className: "ch",
            children: /*#__PURE__*/_jsxDEV("h3", {
              children: "Межсетевой экран"
            }, void 0, false)
          }, void 0, false), /*#__PURE__*/_jsxDEV("div", {
            className: "cb",
            children: Object.keys(inv.firewall || {}).length ? Object.entries(inv.firewall).map(([k, v]) => /*#__PURE__*/_jsxDEV(KV, {
              k: k,
              v: v ? "включён" : "отключён"
            }, k, false)) : /*#__PURE__*/_jsxDEV("div", {
              className: "sub2",
              children: "Не собрано."
            }, void 0, false)
          }, void 0, false)]
        }, void 0, true), /*#__PURE__*/_jsxDEV("div", {
          className: "card",
          children: [/*#__PURE__*/_jsxDEV("div", {
            className: "ch",
            children: /*#__PURE__*/_jsxDEV("h3", {
              children: "Антивирус / Defender"
            }, void 0, false)
          }, void 0, false), /*#__PURE__*/_jsxDEV("div", {
            className: "cb",
            children: [(inv.antivirus || []).map((av, i) => /*#__PURE__*/_jsxDEV("div", {
              style: {
                padding: "4px 0"
              },
              children: [/*#__PURE__*/_jsxDEV("span", {
                style: {
                  color: "var(--ok)"
                },
                children: "✓"
              }, void 0, false), " ", av.name]
            }, i, true)), inv.defender ? /*#__PURE__*/_jsxDEV(_Fragment, {
              children: [/*#__PURE__*/_jsxDEV(KV, {
                k: "Defender включён",
                v: inv.defender.enabled ? "да" : "нет"
              }, void 0, false), /*#__PURE__*/_jsxDEV(KV, {
                k: "Защита в реальном времени",
                v: inv.defender.realtime ? "да" : "нет"
              }, void 0, false), /*#__PURE__*/_jsxDEV(KV, {
                k: "Обновление сигнатур",
                v: inv.defender.signatures
              }, void 0, false)]
            }, void 0, true) : null, (!inv.antivirus || inv.antivirus.length === 0) && !inv.defender ? /*#__PURE__*/_jsxDEV("div", {
              className: "sub2",
              children: "Не собрано."
            }, void 0, false) : null]
          }, void 0, true)]
        }, void 0, true)]
      }, void 0, true) : /*#__PURE__*/_jsxDEV(_Fragment, {
        children: [/*#__PURE__*/_jsxDEV("div", {
          className: "card",
          children: [/*#__PURE__*/_jsxDEV("div", {
            className: "ch",
            children: /*#__PURE__*/_jsxDEV("h3", {
              children: "SSH"
            }, void 0, false)
          }, void 0, false), /*#__PURE__*/_jsxDEV("div", {
            className: "cb",
            children: inv.sshd ? Object.entries(inv.sshd).map(([k, v]) => /*#__PURE__*/_jsxDEV(KV, {
              k: k,
              v: v
            }, k, false)) : /*#__PURE__*/_jsxDEV("div", {
              className: "sub2",
              children: "sshd не собран."
            }, void 0, false)
          }, void 0, false)]
        }, void 0, true), /*#__PURE__*/_jsxDEV("div", {
          className: "card",
          children: [/*#__PURE__*/_jsxDEV("div", {
            className: "ch",
            children: /*#__PURE__*/_jsxDEV("h3", {
              children: "Активные службы безопасности"
            }, void 0, false)
          }, void 0, false), /*#__PURE__*/_jsxDEV("div", {
            className: "cb",
            children: Object.keys(inv.services_active || {}).length ? Object.entries(inv.services_active).map(([k, v]) => /*#__PURE__*/_jsxDEV(KV, {
              k: k,
              v: v
            }, k, false)) : /*#__PURE__*/_jsxDEV("div", {
              className: "sub2",
              children: "Не собрано."
            }, void 0, false)
          }, void 0, false)]
        }, void 0, true)]
      }, void 0, true)
    }, void 0, false), tab === "config" && /*#__PURE__*/_jsxDEV("div", {
      className: "card",
      children: [/*#__PURE__*/_jsxDEV("div", {
        className: "ch",
        children: [/*#__PURE__*/_jsxDEV("h3", {
          children: "Конфигурация устройства"
        }, void 0, false), /*#__PURE__*/_jsxDEV("span", {
          className: "sub2",
          children: "секреты замаскированы"
        }, void 0, false)]
      }, void 0, true), /*#__PURE__*/_jsxDEV("div", {
        className: "cb",
        children: /*#__PURE__*/_jsxDEV("pre", {
          className: "mono",
          style: {
            whiteSpace: "pre-wrap",
            fontSize: 12,
            margin: 0
          },
          children: inv.config
        }, void 0, false)
      }, void 0, false)]
    }, void 0, true)]
  }, void 0, true);
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
  if (err) return /*#__PURE__*/_jsxDEV("div", {
    children: [/*#__PURE__*/_jsxDEV("h1", {
      className: "h1",
      children: "Схема сети"
    }, void 0, false), /*#__PURE__*/_jsxDEV("div", {
      className: "empty",
      children: [err, ". Запустите сканирование и дождитесь готовности."]
    }, void 0, true)]
  }, void 0, true);
  return /*#__PURE__*/_jsxDEV("div", {
    children: [/*#__PURE__*/_jsxDEV("div", {
      className: "maptools",
      children: [/*#__PURE__*/_jsxDEV("h1", {
        className: "h1",
        style: {
          margin: 0
        },
        children: "Схема сети"
      }, void 0, false), /*#__PURE__*/_jsxDEV("span", {
        className: "sp"
      }, void 0, false), /*#__PURE__*/_jsxDEV("button", {
        className: "btn ghost",
        onClick: fit,
        children: "Вписать"
      }, void 0, false), /*#__PURE__*/_jsxDEV("button", {
        className: "btn ghost",
        onClick: () => relayout("breadthfirst"),
        children: "Слои"
      }, void 0, false), /*#__PURE__*/_jsxDEV("button", {
        className: "btn ghost",
        onClick: () => relayout("cose"),
        children: "Свободно"
      }, void 0, false), /*#__PURE__*/_jsxDEV("button", {
        className: "btn ghost",
        onClick: exportPng,
        children: "Экспорт PNG"
      }, void 0, false), /*#__PURE__*/_jsxDEV("a", {
        className: "btn",
        href: "/tasks/" + taskId + "/topology.svg",
        target: "_blank",
        style: {
          textDecoration: "none"
        },
        children: "Экспорт SVG"
      }, void 0, false)]
    }, void 0, true), /*#__PURE__*/_jsxDEV("div", {
      id: "cy",
      ref: box
    }, void 0, false), /*#__PURE__*/_jsxDEV("div", {
      className: "legend2",
      children: [/*#__PURE__*/_jsxDEV("span", {
        children: [/*#__PURE__*/_jsxDEV("i", {
          style: {
            background: "#3D4EA6",
            transform: "rotate(45deg)"
          }
        }, void 0, false), "Ядро сети"]
      }, void 0, true), /*#__PURE__*/_jsxDEV("span", {
        children: [/*#__PURE__*/_jsxDEV("i", {
          style: {
            background: "#E8EAEF"
          }
        }, void 0, false), "Подсеть"]
      }, void 0, true), /*#__PURE__*/_jsxDEV("span", {
        children: [/*#__PURE__*/_jsxDEV("i", {
          style: {
            background: "#11141B"
          }
        }, void 0, false), "Сетевое устройство"]
      }, void 0, true), /*#__PURE__*/_jsxDEV("span", {
        children: [/*#__PURE__*/_jsxDEV("i", {
          style: {
            background: "#fff",
            border: "1px solid #C4CAD4"
          }
        }, void 0, false), "Хост"]
      }, void 0, true), /*#__PURE__*/_jsxDEV("span", {
        style: {
          marginLeft: "auto"
        },
        children: ["клик по узлу — карточка актива", stats ? ` · узлов ${stats.nodes}, связей ${stats.edges}` : ""]
      }, void 0, true)]
    }, void 0, true)]
  }, void 0, true);
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
  if (!t) return /*#__PURE__*/_jsxDEV("div", {
    className: "empty",
    children: "Загрузка задачи…"
  }, void 0, false);
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
  return /*#__PURE__*/_jsxDEV("div", {
    children: [/*#__PURE__*/_jsxDEV("div", {
      className: "crumb",
      style: {
        marginBottom: 10
      },
      children: [/*#__PURE__*/_jsxDEV("span", {
        className: "link",
        onClick: () => go({
          view: "surveys"
        }),
        children: "Сканирования"
      }, void 0, false), /*#__PURE__*/_jsxDEV("span", {
        className: "sep",
        children: "/"
      }, void 0, false), /*#__PURE__*/_jsxDEV("b", {
        children: t.name || "Задача #" + t.id
      }, void 0, false)]
    }, void 0, true), /*#__PURE__*/_jsxDEV("div", {
      style: {
        display: "flex",
        alignItems: "center",
        gap: 12,
        flexWrap: "wrap"
      },
      children: [/*#__PURE__*/_jsxDEV("h1", {
        className: "h1",
        style: {
          margin: 0
        },
        children: t.name || "Задача #" + t.id
      }, void 0, false), /*#__PURE__*/_jsxDEV("span", {
        className: "chip c-" + (ST_CHIP[t.status] || "medium"),
        children: ST_LABEL[t.status] || t.status
      }, void 0, false), /*#__PURE__*/_jsxDEV("div", {
        style: {
          marginLeft: "auto",
          display: "flex",
          gap: 8
        },
        children: [running ? /*#__PURE__*/_jsxDEV("button", {
          className: "btn ghost",
          disabled: busy,
          onClick: cancel,
          children: "Отменить"
        }, void 0, false) : null, /*#__PURE__*/_jsxDEV("button", {
          className: "btn ghost",
          onClick: repeat,
          children: "Повторить"
        }, void 0, false), t.status === "done" && t.has_report ? /*#__PURE__*/_jsxDEV("button", {
          className: "btn ghost",
          onClick: () => {
            setActive(t.id);
            go({
              view: "netmap"
            });
          },
          children: "Схема сети"
        }, void 0, false) : null, t.status === "done" ? /*#__PURE__*/_jsxDEV("button", {
          className: "btn",
          onClick: () => {
            setActive(t.id);
            go({
              view: "dash"
            });
          },
          children: "Открыть результат"
        }, void 0, false) : null]
      }, void 0, true)]
    }, void 0, true), /*#__PURE__*/_jsxDEV("p", {
      className: "sub",
      children: ["Цели: ", /*#__PURE__*/_jsxDEV("span", {
        className: "mono",
        children: p.targets || (r.targets || []).join(", ") || "—"
      }, void 0, false), running ? " · обновляется каждые 2 c" : ""]
    }, void 0, true), /*#__PURE__*/_jsxDEV("div", {
      className: "cols dash",
      style: {
        marginTop: 4
      },
      children: [/*#__PURE__*/_jsxDEV("div", {
        className: "card",
        style: {
          gridColumn: "span 2"
        },
        children: [/*#__PURE__*/_jsxDEV("div", {
          className: "ch",
          children: /*#__PURE__*/_jsxDEV("h3", {
            children: "Журнал выполнения"
          }, void 0, false)
        }, void 0, false), /*#__PURE__*/_jsxDEV("div", {
          className: "cb",
          children: [/*#__PURE__*/_jsxDEV("div", {
            className: "tasklog",
            ref: logRef,
            children: (t.progress || []).length === 0 ? /*#__PURE__*/_jsxDEV("div", {
              className: "sub2",
              children: "Пока нет записей. Для демо-задач журнал не ведётся."
            }, void 0, false) : (t.progress || []).map((l, i) => /*#__PURE__*/_jsxDEV("div", {
              children: [/*#__PURE__*/_jsxDEV("span", {
                className: "lt",
                children: l.t
              }, void 0, false), " ", l.m]
            }, i, true))
          }, void 0, false), t.status === "error" && t.error ? /*#__PURE__*/_jsxDEV("div", {
            className: "warn",
            style: {
              marginTop: 10,
              whiteSpace: "pre-wrap",
              fontFamily: "JetBrains Mono, monospace",
              fontSize: 12
            },
            children: t.error
          }, void 0, false) : null]
        }, void 0, true)]
      }, void 0, true), /*#__PURE__*/_jsxDEV("div", {
        className: "card",
        children: [/*#__PURE__*/_jsxDEV("div", {
          className: "ch",
          children: /*#__PURE__*/_jsxDEV("h3", {
            children: "Учётные записи"
          }, void 0, false)
        }, void 0, false), /*#__PURE__*/_jsxDEV("div", {
          className: "cb",
          children: (p.creds || []).length === 0 ? /*#__PURE__*/_jsxDEV("div", {
            className: "sub2",
            children: "Без УЗ — только сетевое обнаружение."
          }, void 0, false) : (p.creds || []).map((c, i) => /*#__PURE__*/_jsxDEV("div", {
            style: {
              padding: "4px 0",
              fontSize: 13
            },
            children: [/*#__PURE__*/_jsxDEV("b", {
              children: c.name || c.username || c.type
            }, void 0, false), " ", /*#__PURE__*/_jsxDEV("span", {
              className: "sub2",
              children: ["· ", c.type, c.username ? " · " + c.username : ""]
            }, void 0, true)]
          }, i, true))
        }, void 0, false)]
      }, void 0, true)]
    }, void 0, true), coll ? /*#__PURE__*/_jsxDEV("div", {
      className: "card",
      style: {
        marginTop: 16
      },
      children: [/*#__PURE__*/_jsxDEV("div", {
        className: "ch",
        children: [/*#__PURE__*/_jsxDEV("h3", {
          children: "Сбор по активам"
        }, void 0, false), /*#__PURE__*/_jsxDEV("span", {
          className: "sub2",
          children: ["успешно ", coll.collected.length, " · не удалось ", coll.failed.length]
        }, void 0, true)]
      }, void 0, true), /*#__PURE__*/_jsxDEV("div", {
        className: "cb",
        children: /*#__PURE__*/_jsxDEV("table", {
          children: [/*#__PURE__*/_jsxDEV("thead", {
            children: /*#__PURE__*/_jsxDEV("tr", {
              children: [/*#__PURE__*/_jsxDEV("th", {
                children: "Актив"
              }, void 0, false), /*#__PURE__*/_jsxDEV("th", {
                children: "IP"
              }, void 0, false), /*#__PURE__*/_jsxDEV("th", {
                children: "Протокол"
              }, void 0, false), /*#__PURE__*/_jsxDEV("th", {
                children: "Результат"
              }, void 0, false)]
            }, void 0, true)
          }, void 0, false), /*#__PURE__*/_jsxDEV("tbody", {
            children: [coll.collected.map((c, i) => /*#__PURE__*/_jsxDEV("tr", {
              children: [/*#__PURE__*/_jsxDEV("td", {
                children: /*#__PURE__*/_jsxDEV("b", {
                  children: c.asset
                }, void 0, false)
              }, void 0, false), /*#__PURE__*/_jsxDEV("td", {
                className: "mono",
                children: c.ip
              }, void 0, false), /*#__PURE__*/_jsxDEV("td", {
                children: c.proto
              }, void 0, false), /*#__PURE__*/_jsxDEV("td", {
                style: {
                  color: "var(--ok,#2e7d32)"
                },
                children: ["✓ собрано (УЗ ", c.cred || "—", ")"]
              }, void 0, true)]
            }, "c" + i, true)), coll.failed.map((c, i) => /*#__PURE__*/_jsxDEV("tr", {
              children: [/*#__PURE__*/_jsxDEV("td", {
                children: /*#__PURE__*/_jsxDEV("b", {
                  children: c.asset
                }, void 0, false)
              }, void 0, false), /*#__PURE__*/_jsxDEV("td", {
                className: "mono",
                children: c.ip
              }, void 0, false), /*#__PURE__*/_jsxDEV("td", {
                children: c.proto
              }, void 0, false), /*#__PURE__*/_jsxDEV("td", {
                className: "sub2",
                children: ["✕ ", c.error]
              }, void 0, true)]
            }, "f" + i, true)), coll.collected.length === 0 && coll.failed.length === 0 && /*#__PURE__*/_jsxDEV("tr", {
              children: /*#__PURE__*/_jsxDEV("td", {
                colSpan: "4",
                className: "sub2",
                children: "Активов для сбора не было."
              }, void 0, false)
            }, void 0, false)]
          }, void 0, true)]
        }, void 0, true)
      }, void 0, false)]
    }, void 0, true) : null]
  }, void 0, true);
}

/* ----------------------------------------------------------------- Обследования */
function Surveys({
  tasks,
  go,
  onNew,
  setActive
}) {
  return /*#__PURE__*/_jsxDEV("div", {
    children: [/*#__PURE__*/_jsxDEV("div", {
      style: {
        display: "flex",
        alignItems: "center",
        marginBottom: 16
      },
      children: [/*#__PURE__*/_jsxDEV("div", {
        children: [/*#__PURE__*/_jsxDEV("h1", {
          className: "h1",
          style: {
            margin: 0
          },
          children: "Сканирования"
        }, void 0, false), /*#__PURE__*/_jsxDEV("p", {
          className: "sub",
          style: {
            margin: "2px 0 0"
          },
          children: "Запуск, статус, схема и активы."
        }, void 0, false)]
      }, void 0, true), /*#__PURE__*/_jsxDEV("button", {
        className: "btn",
        style: {
          marginLeft: "auto"
        },
        onClick: onNew,
        children: "+ Новое сканирование"
      }, void 0, false)]
    }, void 0, true), /*#__PURE__*/_jsxDEV("div", {
      className: "card",
      children: /*#__PURE__*/_jsxDEV("div", {
        className: "cb",
        children: /*#__PURE__*/_jsxDEV("table", {
          children: [/*#__PURE__*/_jsxDEV("thead", {
            children: /*#__PURE__*/_jsxDEV("tr", {
              children: [/*#__PURE__*/_jsxDEV("th", {
                children: "#"
              }, void 0, false), /*#__PURE__*/_jsxDEV("th", {
                children: "Скан"
              }, void 0, false), /*#__PURE__*/_jsxDEV("th", {
                children: "Цели"
              }, void 0, false), /*#__PURE__*/_jsxDEV("th", {
                children: "Статус"
              }, void 0, false), /*#__PURE__*/_jsxDEV("th", {
                className: "num",
                children: "Собрано по УЗ"
              }, void 0, false), /*#__PURE__*/_jsxDEV("th", {
                children: "Схема"
              }, void 0, false)]
            }, void 0, true)
          }, void 0, false), /*#__PURE__*/_jsxDEV("tbody", {
            children: [tasks.map(t => {
              const st = ST_LABEL[t.status] || t.status;
              const p = t.params || {};
              const tg = p.targets || t.result && (t.result.targets || []).join(", ") || (p.kind === "demo" ? "демо" : "—");
              const nc = (p.creds || []).length;
              const coll = t.result && t.result.collect;
              return /*#__PURE__*/_jsxDEV("tr", {
                children: [/*#__PURE__*/_jsxDEV("td", {
                  className: "mono",
                  children: t.id
                }, void 0, false), /*#__PURE__*/_jsxDEV("td", {
                  className: "link",
                  onClick: () => go({
                    view: "task",
                    taskId: t.id
                  }),
                  children: [/*#__PURE__*/_jsxDEV("b", {
                    children: t.name || "—"
                  }, void 0, false), nc ? /*#__PURE__*/_jsxDEV("div", {
                    className: "sub2",
                    children: [nc, " УЗ", coll ? ` · собрано ${coll.collected.length}` : ""]
                  }, void 0, true) : null]
                }, void 0, true), /*#__PURE__*/_jsxDEV("td", {
                  className: "sub2 mono",
                  children: tg
                }, void 0, false), /*#__PURE__*/_jsxDEV("td", {
                  children: /*#__PURE__*/_jsxDEV("span", {
                    className: "chip c-" + (ST_CHIP[t.status] || "medium"),
                    children: st
                  }, void 0, false)
                }, void 0, false), /*#__PURE__*/_jsxDEV("td", {
                  className: "num",
                  children: coll ? coll.collected.length : "—"
                }, void 0, false), /*#__PURE__*/_jsxDEV("td", {
                  children: t.has_report ? /*#__PURE__*/_jsxDEV("span", {
                    className: "link",
                    onClick: () => {
                      setActive(t.id);
                      go({
                        view: "netmap"
                      });
                    },
                    children: "схема →"
                  }, void 0, false) : /*#__PURE__*/_jsxDEV("span", {
                    className: "link",
                    onClick: () => go({
                      view: "task",
                      taskId: t.id
                    }),
                    children: "открыть →"
                  }, void 0, false)
                }, void 0, false)]
              }, t.id, true);
            }), tasks.length === 0 && /*#__PURE__*/_jsxDEV("tr", {
              children: /*#__PURE__*/_jsxDEV("td", {
                colSpan: "6",
                className: "sub2",
                children: "Пока нет сканирований — запустите «+ Новое сканирование»."
              }, void 0, false)
            }, void 0, false)]
          }, void 0, true)]
        }, void 0, true)
      }, void 0, false)
    }, void 0, false)]
  }, void 0, true);
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
  return /*#__PURE__*/_jsxDEV("div", {
    children: [/*#__PURE__*/_jsxDEV("h1", {
      className: "h1",
      children: "Коннекторы"
    }, void 0, false), /*#__PURE__*/_jsxDEV("p", {
      className: "sub",
      children: "Агенты сбора у заказчика (pull-модель, только исходящие соединения; офлайн-курьер для изолированного контура)."
    }, void 0, false), /*#__PURE__*/_jsxDEV("div", {
      className: "card",
      style: {
        marginBottom: 16
      },
      children: /*#__PURE__*/_jsxDEV("div", {
        className: "cb row",
        children: [/*#__PURE__*/_jsxDEV("div", {
          className: "field",
          children: [/*#__PURE__*/_jsxDEV("label", {
            children: "Название коннектора"
          }, void 0, false), /*#__PURE__*/_jsxDEV("input", {
            value: name,
            onChange: e => setName(e.target.value),
            placeholder: "Коннектор-1",
            style: {
              minWidth: 260
            }
          }, void 0, false)]
        }, void 0, true), /*#__PURE__*/_jsxDEV("button", {
          className: "btn",
          onClick: add,
          children: "Зарегистрировать"
        }, void 0, false)]
      }, void 0, true)
    }, void 0, false), /*#__PURE__*/_jsxDEV("div", {
      className: "card",
      children: /*#__PURE__*/_jsxDEV("div", {
        className: "cb",
        children: /*#__PURE__*/_jsxDEV("table", {
          children: [/*#__PURE__*/_jsxDEV("thead", {
            children: /*#__PURE__*/_jsxDEV("tr", {
              children: [/*#__PURE__*/_jsxDEV("th", {
                children: "#"
              }, void 0, false), /*#__PURE__*/_jsxDEV("th", {
                children: "Коннектор"
              }, void 0, false), /*#__PURE__*/_jsxDEV("th", {
                children: "Последний дозвон"
              }, void 0, false)]
            }, void 0, true)
          }, void 0, false), /*#__PURE__*/_jsxDEV("tbody", {
            children: [list.map(c => /*#__PURE__*/_jsxDEV("tr", {
              children: [/*#__PURE__*/_jsxDEV("td", {
                className: "mono",
                children: c.id
              }, void 0, false), /*#__PURE__*/_jsxDEV("td", {
                children: /*#__PURE__*/_jsxDEV("b", {
                  children: c.name
                }, void 0, false)
              }, void 0, false), /*#__PURE__*/_jsxDEV("td", {
                className: "sub2",
                children: c.last_seen ? c.last_seen.replace("T", " ").slice(0, 16) : "ни разу"
              }, void 0, false)]
            }, c.id, true)), list.length === 0 && /*#__PURE__*/_jsxDEV("tr", {
              children: /*#__PURE__*/_jsxDEV("td", {
                colSpan: "3",
                className: "sub2",
                children: "Коннекторы не зарегистрированы."
              }, void 0, false)
            }, void 0, false)]
          }, void 0, true)]
        }, void 0, true)
      }, void 0, false)
    }, void 0, false)]
  }, void 0, true);
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
  if (nav.view === "dash") screen = /*#__PURE__*/_jsxDEV(Dash, {
    D: D,
    tasks: tasks,
    go: go
  }, void 0, false);else if (nav.view === "surveys") screen = /*#__PURE__*/_jsxDEV(Surveys, {
    tasks: tasks,
    go: go,
    onNew: () => go({
      view: "newscan"
    }),
    setActive: setActive
  }, void 0, false);else if (nav.view === "task") screen = /*#__PURE__*/_jsxDEV(TaskDetail, {
    taskId: nav.taskId,
    go: go,
    setActive: setActive
  }, void 0, false);else if (nav.view === "newscan") screen = /*#__PURE__*/_jsxDEV(NewScan, {
    onRun: runScan,
    busy: busy,
    go: go,
    savedCreds: savedCreds,
    initTargets: nav.initTargets,
    initCreds: nav.initCreds
  }, void 0, false);else if (nav.view === "assets") screen = /*#__PURE__*/_jsxDEV(Assets, {
    D: D,
    go: go
  }, void 0, false);else if (nav.view === "asset") screen = /*#__PURE__*/_jsxDEV(AssetDetail, {
    D: D,
    name: nav.assetName,
    go: go
  }, void 0, false);else if (nav.view === "netmap") screen = /*#__PURE__*/_jsxDEV(NetMap, {
    taskId: activeId,
    go: go
  }, void 0, false);else if (nav.view === "creds") screen = /*#__PURE__*/_jsxDEV(Credentials, {
    onChange: loadCreds
  }, void 0, false);else if (nav.view === "connectors") screen = /*#__PURE__*/_jsxDEV(Connectors, {}, void 0, false);else screen = /*#__PURE__*/_jsxDEV(Dash, {
    D: D,
    tasks: tasks,
    go: go
  }, void 0, false);
  const crumb = nav.view === "asset" ? /*#__PURE__*/_jsxDEV(_Fragment, {
    children: [/*#__PURE__*/_jsxDEV("span", {
      className: "link",
      onClick: () => go({
        view: "assets"
      }),
      children: "Активы"
    }, void 0, false), /*#__PURE__*/_jsxDEV("span", {
      className: "sep",
      children: "/"
    }, void 0, false), /*#__PURE__*/_jsxDEV("b", {
      children: nav.assetName
    }, void 0, false)]
  }, void 0, true) : /*#__PURE__*/_jsxDEV("b", {
    children: TITLES[nav.view] || "Дашборд"
  }, void 0, false);
  return /*#__PURE__*/_jsxDEV("div", {
    className: "app",
    children: [/*#__PURE__*/_jsxDEV("aside", {
      className: "nav",
      children: [/*#__PURE__*/_jsxDEV("div", {
        className: "brand",
        children: [/*#__PURE__*/_jsxDEV("span", {
          className: "logo",
          children: "◢"
        }, void 0, false), "surveyscan"]
      }, void 0, true), NAV.map(g => /*#__PURE__*/_jsxDEV(React.Fragment, {
        children: [/*#__PURE__*/_jsxDEV("div", {
          className: "navsec",
          children: g.sec
        }, void 0, false), g.items.map(it => {
          const on = nav.view === it.id || it.id === "assets" && nav.view === "asset";
          const cc = it.cnt && counts[it.cnt] != null ? counts[it.cnt] : null;
          return /*#__PURE__*/_jsxDEV("button", {
            className: "navi" + (on ? " on" : ""),
            onClick: () => go({
              view: it.id
            }),
            children: [/*#__PURE__*/_jsxDEV("span", {
              className: "ico",
              children: it.ic
            }, void 0, false), it.l, cc ? /*#__PURE__*/_jsxDEV("span", {
              className: "cnt",
              children: cc
            }, void 0, false) : null]
          }, it.id, true);
        })]
      }, g.sec, true)), /*#__PURE__*/_jsxDEV("div", {
        className: "foot",
        children: ["сканер инвентаризации", /*#__PURE__*/_jsxDEV("br", {}, void 0, false), "и схемы сети"]
      }, void 0, true)]
    }, void 0, true), /*#__PURE__*/_jsxDEV("div", {
      className: "main",
      children: [/*#__PURE__*/_jsxDEV("div", {
        className: "top",
        children: [/*#__PURE__*/_jsxDEV("div", {
          className: "crumb",
          children: crumb
        }, void 0, false), /*#__PURE__*/_jsxDEV("div", {
          className: "search",
          children: "⌕ Поиск по активам, IP…"
        }, void 0, false), /*#__PURE__*/_jsxDEV("div", {
          className: "right",
          children: [/*#__PURE__*/_jsxDEV("button", {
            className: "btn",
            onClick: () => go({
              view: "newscan"
            }),
            children: "+ Новое сканирование"
          }, void 0, false), /*#__PURE__*/_jsxDEV("div", {
            className: "av",
            children: "ИП"
          }, void 0, false)]
        }, void 0, true)]
      }, void 0, true), /*#__PURE__*/_jsxDEV("div", {
        className: "body",
        children: screen
      }, void 0, false)]
    }, void 0, true)]
  }, void 0, true);
}
ReactDOM.createRoot(document.getElementById("root")).render(/*#__PURE__*/_jsxDEV(App, {}, void 0, false));
