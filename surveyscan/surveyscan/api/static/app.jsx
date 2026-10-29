const {useState, useEffect, useRef, useCallback} = React;
const api = (p, opts) => fetch(p, opts).then(r => r.ok ? r.json() : r.json().then(e => Promise.reject(e)));

/* ----------------------------------------------------------------- Новое сканирование */
const CRED_KIND = {ssh: "SSH · Linux", winrm: "WinRM · Windows", snmp: "SNMP · оборуд."};
function NewScan({onRun, busy, go, savedCreds, initTargets, initCreds}) {
  const [targets, setTargets] = useState(initTargets || "");
  const [sel, setSel] = useState(initCreds || []);
  const toggle = (id) => setSel(s => s.includes(id) ? s.filter(x => x !== id) : [...s, id]);
  return (
    <div>
      <h1 className="h1">Новое сканирование</h1>
      <p className="sub">Укажите подсети и хосты. Сбор — сетевой (nmap): живые хосты, порты, версии сервисов, ОС → схема сети. Выберите учётные записи — сканер подключится к активам (SSH/WinRM/SNMP) и соберёт полный инвентарь; к каждому активу УЗ подбирается автоматически.</p>
      <div className="card" style={{maxWidth: 820}}><div className="cb">
        <div className="field">
          <label>Цели: подсети / хосты</label>
          <textarea rows="4" value={targets} onChange={e => setTargets(e.target.value)}
                    placeholder="10.0.0.0/24, 10.0.1.5&#10;srv01.corp" style={{fontFamily: "JetBrains Mono, monospace", fontSize: 13}}/>
          <div className="sub2">Через запятую, пробел или с новой строки. Примеры: <span className="mono">192.168.1.0/24</span>, <span className="mono">10.0.0.5</span></div>
        </div>

        <div className="field" style={{marginTop: 18}}>
          <div style={{display: "flex", alignItems: "center"}}>
            <label style={{margin: 0}}>Учётные записи для сбора <span className="sub2" style={{fontWeight: 400}}>(опционально — без них только сетевое обнаружение)</span></label>
            <span className="more" style={{marginLeft: "auto"}} onClick={() => go({view: "creds"})}>Управление УЗ →</span>
          </div>
          {(!savedCreds || savedCreds.length === 0)
            ? <div className="sub2" style={{margin: "8px 0"}}>Сохранённых УЗ нет. <span className="link" onClick={() => go({view: "creds"})}>Добавьте учётную запись</span> во вкладке «Учётные записи» — затем выбирайте её здесь.</div>
            : <div className="credpick">
                {savedCreds.map(c => (
                  <label className={"credopt" + (sel.includes(c.id) ? " on" : "")} key={c.id}>
                    <input type="checkbox" checked={sel.includes(c.id)} onChange={() => toggle(c.id)}/>
                    <span className="cn">{c.name}</span>
                    <span className="ct">{CRED_KIND[c.type] || c.type}</span>
                    <span className="cu mono">{c.type === "snmp" ? "community" : (c.username || "—")}{c.port ? ":" + c.port : ""}</span>
                  </label>
                ))}
              </div>}
        </div>

        <div style={{display: "flex", gap: 10, marginTop: 18}}>
          <button className="btn" disabled={busy || !targets.trim()} onClick={() => onRun(targets, sel)}>{busy ? "Запуск…" : "Запустить скан"}</button>
          <button className="btn ghost" onClick={() => go({view: "dash"})}>Отмена</button>
        </div>
      </div></div>
      <div className="warn" style={{maxWidth: 820, marginTop: 14}}>Секреты хранятся в базе в зашифрованном виде (ключ — в переменной окружения, не в БД) и расшифровываются только на время задачи. К каждому активу применяется подходящая по типу УЗ (перебор до первой успешной); в сводке фиксируется только логин.</div>
    </div>
  );
}

function Credentials({onChange}) {
  const [list, setList] = useState([]);
  const [f, setF] = useState({name: "", type: "ssh", username: "", secret: "", domain: "", port: ""});
  const [err, setErr] = useState("");
  const refresh = () => api("/credentials").then(setList).catch(() => {});
  useEffect(() => { refresh(); }, []);
  const setFF = (k, v) => setF(p => ({...p, [k]: v}));
  const add = async () => {
    setErr("");
    const body = {name: f.name, type: f.type, username: f.type === "snmp" ? null : f.username,
                  secret: f.secret, domain: f.domain || null, port: f.port ? parseInt(f.port, 10) : null};
    try {
      await api("/credentials", {method: "POST", headers: {"Content-Type": "application/json"}, body: JSON.stringify(body)});
      setF({name: "", type: "ssh", username: "", secret: "", domain: "", port: ""});
      refresh(); onChange && onChange();
    } catch (e) { setErr(e && e.detail ? e.detail : "не удалось сохранить"); }
  };
  const del = async (id) => { await fetch("/credentials/" + id, {method: "DELETE"}); refresh(); onChange && onChange(); };
  return (
    <div>
      <h1 className="h1">Учётные записи</h1>
      <p className="sub">Хранилище УЗ для аутентифицированного сбора. Заводятся один раз — затем выбираются в форме скана. Секреты шифруются в БД (ключ в переменной окружения, не в базе).</p>
      <div className="card" style={{marginBottom: 16, maxWidth: 820}}><div className="cb">
        <div className="credrow">
          <input placeholder="Имя: Linux-аудит" value={f.name} style={{flex: 1.4}} onChange={e => setFF("name", e.target.value)}/>
          <select value={f.type} onChange={e => setFF("type", e.target.value)}>
            <option value="ssh">SSH · Linux</option>
            <option value="winrm">WinRM · Windows</option>
            <option value="snmp">SNMP · оборуд.</option>
          </select>
          <input placeholder={f.type === "snmp" ? "— (не нужно)" : "логин"} value={f.username} disabled={f.type === "snmp"}
                 onChange={e => setFF("username", e.target.value)}/>
          <input type="password" placeholder={f.type === "snmp" ? "community" : "пароль / ключ"} value={f.secret}
                 autoComplete="new-password" onChange={e => setFF("secret", e.target.value)}/>
          {f.type === "winrm" ? <input placeholder="домен" value={f.domain} style={{width: 90}} onChange={e => setFF("domain", e.target.value)}/> : null}
          <input placeholder="порт" value={f.port} style={{width: 64}} onChange={e => setFF("port", e.target.value)}/>
          <button className="btn sm" onClick={add}>Сохранить</button>
        </div>
        {err ? <div className="sub2" style={{color: "var(--crit,#b4232a)", marginTop: 8}}>{err}</div> : null}
      </div></div>
      <div className="card" style={{maxWidth: 820}}><div className="cb">
        <table>
          <thead><tr><th>Имя</th><th>Тип</th><th>Логин / порт</th><th>Добавлена</th><th></th></tr></thead>
          <tbody>
            {list.map(c => (
              <tr key={c.id}>
                <td><b>{c.name}</b></td>
                <td>{CRED_KIND[c.type] || c.type}</td>
                <td className="mono sub2">{c.type === "snmp" ? "community" : (c.username || "—")}{c.port ? ":" + c.port : ""}{c.domain ? " · " + c.domain : ""}</td>
                <td className="sub2">{c.created_at ? c.created_at.replace("T", " ").slice(0, 16) : ""}</td>
                <td style={{textAlign: "right"}}><button className="xbtn" title="Удалить" onClick={() => del(c.id)}>✕</button></td>
              </tr>
            ))}
            {list.length === 0 && <tr><td colSpan="5" className="sub2">УЗ не заведены. Добавьте первую выше.</td></tr>}
          </tbody>
        </table>
      </div></div>
      <div className="warn" style={{maxWidth: 820, marginTop: 14}}>Пароли, ключи и community хранятся зашифрованными (Fernet). Мастер-ключ берётся из <span className="mono">SURVEYSCAN_SECRET_KEY</span> и в базе не лежит — дамп БД сам по себе секреты не раскроет. Задайте эту переменную в своём окружении (иначе ключ генерируется в томе данных и теряется вместе с ним).</div>
    </div>
  );
}

/* ----------------------------------------------------------------- Дашборд */
function Dash({D, tasks, go}) {
  if (!D) return <div className="empty">Нет данных. Запустите сканирование: «+ Новое сканирование».</div>;
  const ts = (D.topology && D.topology.stats) || {};
  const assets = D.assets || [];
  const kpi = (n, l, c) => <div className="kpi"><div className="l">{l}</div><div className="n" style={c ? {color: c} : null}>{n}</div></div>;
  return (
    <div>
      <h1 className="h1">{(D.survey && D.survey.name) || "Обследование"}</h1>
      <p className="sub">Инвентаризация сети · {D.generated}</p>
      <div className="kpis">
        {kpi(D.totals ? D.totals.assets : assets.length, "Активов")}
        {kpi(ts.hosts != null ? ts.hosts : "—", "Хостов")}
        {kpi(ts.devices != null ? ts.devices : "—", "Сетевых устройств")}
        {kpi(ts.subnets != null ? ts.subnets : "—", "Подсетей")}
        {kpi(ts.services != null ? ts.services : "—", "Открытых сервисов")}
      </div>
      <div className="cols dash">
        <div className="card">
          <div className="ch"><h3>Активы</h3><span className="more" onClick={() => go({view: "assets"})}>Все активы →</span></div>
          <div className="cb">
            <table>
              <thead><tr><th>Актив</th><th>IP</th><th>ОС / платформа</th><th>Сервисы</th></tr></thead>
              <tbody>
                {assets.slice(0, 6).map(a => (
                  <tr key={a.name} className="click" onClick={() => go({view: "asset", assetName: a.name})}>
                    <td><b>{a.name}</b></td><td className="mono">{a.ips}</td><td>{a.os || "—"}</td>
                    <td className="num">{(a.services || []).length}</td>
                  </tr>
                ))}
                {assets.length === 0 && <tr><td colSpan="4" className="sub2">Активы не найдены.</td></tr>}
              </tbody>
            </table>
          </div>
        </div>
        <div className="card">
          <div className="ch"><h3>Схема сети</h3><span className="more" onClick={() => go({view: "netmap"})}>Открыть →</span></div>
          <div className="cb">
            <div style={{fontSize: 13, color: "var(--muted)", lineHeight: 1.7}}>
              Узлов: <b style={{color: "var(--ink)"}}>{ts.nodes || 0}</b><br/>
              Подсетей: <b style={{color: "var(--ink)"}}>{ts.subnets || 0}</b><br/>
              Сетевых устройств: <b style={{color: "var(--ink)"}}>{ts.devices || 0}</b><br/>
              Связей: <b style={{color: "var(--ink)"}}>{ts.edges || 0}</b>
            </div>
            <button className="btn" style={{marginTop: 12}} onClick={() => go({view: "netmap"})}>Открыть схему сети</button>
          </div>
        </div>
        <div className="card">
          <div className="ch"><h3>Сканирования</h3><span className="more" onClick={() => go({view: "surveys"})}>Все →</span></div>
          <div className="cb">
            {tasks.slice(0, 6).map(tk => {
              const cls = tk.status === "done" ? "d-ok" : tk.status === "running" ? "d-run" : tk.status === "error" ? "d-err" : "d-wait";
              const st = {done: "готово", running: "идёт", queued: "в очереди", error: "ошибка"}[tk.status];
              return <div className="scan" key={tk.id}><span className={"dotc " + cls}></span><div><div className="nm">{tk.name || "Скан #" + tk.id}</div></div><span className="pct">{st}</span></div>;
            })}
            {tasks.length === 0 && <div className="sub2">Пока нет сканирований.</div>}
          </div>
        </div>
      </div>
    </div>
  );
}

/* ----------------------------------------------------------------- Активы */
function Assets({D, go}) {
  if (!D) return <div className="empty">Нет данных. Запустите сканирование.</div>;
  const assets = D.assets || [];
  return (
    <div>
      <h1 className="h1">Активы</h1>
      <p className="sub">Инвентаризация активов обследования «{D.survey && D.survey.name}».</p>
      <div className="card"><div className="cb">
        <table>
          <thead><tr><th>Актив</th><th>IP</th><th>ОС / платформа</th><th>Тип</th><th className="num">Сервисов</th></tr></thead>
          <tbody>
            {assets.map(a => (
              <tr key={a.name} className="click" onClick={() => go({view: "asset", assetName: a.name})}>
                <td><b>{a.name}</b></td>
                <td className="mono">{a.ips || "—"}</td>
                <td>{a.os || "—"}{a.build ? <div className="sub2 mono">{a.build}</div> : null}</td>
                <td>{a.kind}</td>
                <td className="num">{(a.services || []).length}</td>
              </tr>
            ))}
            {assets.length === 0 && <tr><td colSpan="5" className="sub2">Активы не найдены.</td></tr>}
          </tbody>
        </table>
      </div></div>
    </div>
  );
}

function AssetDetail({D, name, go}) {
  const a = (D.assets || []).find(x => x.name === name);
  if (!a) return <div className="empty">Актив не найден.</div>;
  return (
    <div>
      <div className="crumb" style={{marginBottom: 10}}><span className="link" onClick={() => go({view: "assets"})}>Активы</span><span className="sep">/</span><b>{name}</b></div>
      <div className="pagehead">
        <div className="ic">{(a.kind || "").toLowerCase().includes("сетев") ? "🖧" : "🖥"}</div>
        <div><div className="h1" style={{margin: 0}}>{name}</div><div className="meta mono">{a.ips}{a.os ? " · " + a.os : ""}</div></div>
      </div>
      <div className="detail" style={{marginTop: 10}}>
        <div className="card"><div className="ch"><h3>Открытые сервисы</h3></div><div className="cb">
          {(a.services || []).length
            ? (a.services || []).map((s, i) => <div key={i} className="mono" style={{padding: "5px 0", fontSize: 12.5}}>{s}</div>)
            : <div className="sub2">Открытых сервисов не обнаружено.</div>}
        </div></div>
        <div>
          <div className="card"><div className="ch"><h3>Сведения</h3></div><div className="cb">
            <div className="kv"><span className="k">Тип</span><span className="v">{a.kind}</span></div>
            <div className="kv"><span className="k">IP</span><span className="v mono">{a.ips || "—"}</span></div>
            <div className="kv"><span className="k">ОС / платформа</span><span className="v">{a.os || "—"}</span></div>
            <div className="kv"><span className="k">Пакетов / ПО</span><span className="v">{a.software || 0}</span></div>
            <div className="kv"><span className="k">Открытых сервисов</span><span className="v">{(a.services || []).length}</span></div>
          </div></div>
          {a.sec_tools && a.sec_tools.length ? (
            <div className="card" style={{marginTop: 16}}><div className="ch"><h3>Средства защиты</h3></div><div className="cb">
              {a.sec_tools.map((t, i) => <div key={i} style={{padding: "5px 0"}}><span style={{color: "var(--ok)"}}>✓</span> {t}</div>)}
            </div></div>) : null}
        </div>
      </div>
    </div>
  );
}

/* ----------------------------------------------------------------- Схема сети */
const CY_STYLE = [
  {selector: "node", style: {"label": "data(label)", "font-size": 11, "font-family": "Inter, sans-serif", "text-valign": "center", "text-halign": "center", "width": "label", "height": 28, "padding": "8px"}},
  {selector: 'node[type="core"]', style: {"background-color": "#3D4EA6", "shape": "diamond", "color": "#fff", "width": 60, "height": 60, "font-weight": 600}},
  {selector: 'node[type="subnet"]', style: {"background-color": "#E8EAEF", "shape": "round-rectangle", "color": "#44506a", "font-weight": 600}},
  {selector: 'node[type="device"]', style: {"background-color": "#11141B", "shape": "round-rectangle", "color": "#fff"}},
  {selector: 'node[type="host"]', style: {"background-color": "#ffffff", "shape": "round-rectangle", "color": "#16181D", "border-color": "#C4CAD4", "border-width": 1}},
  {selector: "edge", style: {"line-color": "#C4CAD4", "width": 1.5, "curve-style": "bezier"}},
  {selector: 'edge[type="uplink"]', style: {"line-color": "#AEB4C0", "width": 2}},
  {selector: 'edge[type="l2"]', style: {"line-color": "#3D4EA6", "line-style": "dashed"}},
];

function NetMap({taskId, go}) {
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
        layout: {name: "breadthfirst", roots: ["core"], directed: false, spacingFactor: 1.1, padding: 24},
        wheelSensitivity: 0.25,
      });
      cy.on("tap", "node", ev => {
        const d = ev.target.data();
        if (d.type === "host" || d.type === "device") go({view: "asset", assetName: d.label});
      });
      cyRef.current = cy;
    }).catch(e => setErr(e && e.detail ? e.detail : "схема недоступна"));
    return () => { if (cy) cy.destroy(); };
  }, [taskId]);

  const fit = () => cyRef.current && cyRef.current.fit(undefined, 30);
  const relayout = (name) => cyRef.current && cyRef.current.layout(name === "cose"
    ? {name: "cose", padding: 20, animate: false} : {name: "breadthfirst", roots: ["core"], directed: false, spacingFactor: 1.1, padding: 24}).run();
  const exportPng = () => {
    if (!cyRef.current) return;
    const png = cyRef.current.png({scale: 2, full: true, bg: "#ffffff"});
    const a = document.createElement("a"); a.href = png; a.download = "network-map.png"; a.click();
  };

  if (err) return <div><h1 className="h1">Схема сети</h1><div className="empty">{err}. Запустите сканирование и дождитесь готовности.</div></div>;
  return (
    <div>
      <div className="maptools">
        <h1 className="h1" style={{margin: 0}}>Схема сети</h1>
        <span className="sp"></span>
        <button className="btn ghost" onClick={fit}>Вписать</button>
        <button className="btn ghost" onClick={() => relayout("breadthfirst")}>Слои</button>
        <button className="btn ghost" onClick={() => relayout("cose")}>Свободно</button>
        <button className="btn ghost" onClick={exportPng}>Экспорт PNG</button>
        <a className="btn" href={"/tasks/" + taskId + "/topology.svg"} target="_blank" style={{textDecoration: "none"}}>Экспорт SVG</a>
      </div>
      <div id="cy" ref={box}></div>
      <div className="legend2">
        <span><i style={{background: "#3D4EA6", transform: "rotate(45deg)"}}></i>Ядро сети</span>
        <span><i style={{background: "#E8EAEF"}}></i>Подсеть</span>
        <span><i style={{background: "#11141B"}}></i>Сетевое устройство</span>
        <span><i style={{background: "#fff", border: "1px solid #C4CAD4"}}></i>Хост</span>
        <span style={{marginLeft: "auto"}}>клик по узлу — карточка актива{stats ? ` · узлов ${stats.nodes}, связей ${stats.edges}` : ""}</span>
      </div>
    </div>
  );
}

/* ----------------------------------------------------------------- Карточка задачи */
const ST_LABEL = {done: "готово", running: "идёт", queued: "в очереди", error: "ошибка", cancelling: "отмена…", cancelled: "отменено"};
const ST_CHIP = {done: "low", error: "critical", cancelled: "medium", running: "medium", queued: "medium"};
function TaskDetail({taskId, go, setActive}) {
  const [t, setT] = useState(null);
  const [busy, setBusy] = useState(false);
  const logRef = useRef(null);
  const load = useCallback(() => taskId && api("/tasks/" + taskId).then(setT).catch(() => {}), [taskId]);
  useEffect(() => { load(); }, [load]);
  useEffect(() => {
    if (!t || (t.status !== "running" && t.status !== "queued")) return;
    const h = setInterval(load, 2000);
    return () => clearInterval(h);
  }, [t, load]);
  useEffect(() => { if (logRef.current) logRef.current.scrollTop = logRef.current.scrollHeight; }, [t]);
  if (!t) return <div className="empty">Загрузка задачи…</div>;
  const p = t.params || {}, r = t.result || {}, coll = r.collect;
  const running = t.status === "running" || t.status === "queued";
  const cancel = async () => { setBusy(true); try { await api("/tasks/" + taskId + "/cancel", {method: "POST"}); } catch (e) {} setBusy(false); load(); };
  const repeat = () => go({view: "newscan", initTargets: p.targets || (r.targets || []).join(", "),
                           initCreds: (p.creds || []).map(c => c.id).filter(Boolean)});
  return (
    <div>
      <div className="crumb" style={{marginBottom: 10}}><span className="link" onClick={() => go({view: "surveys"})}>Сканирования</span><span className="sep">/</span><b>{t.name || "Задача #" + t.id}</b></div>
      <div style={{display: "flex", alignItems: "center", gap: 12, flexWrap: "wrap"}}>
        <h1 className="h1" style={{margin: 0}}>{t.name || "Задача #" + t.id}</h1>
        <span className={"chip c-" + (ST_CHIP[t.status] || "medium")}>{ST_LABEL[t.status] || t.status}</span>
        <div style={{marginLeft: "auto", display: "flex", gap: 8}}>
          {running ? <button className="btn ghost" disabled={busy} onClick={cancel}>Отменить</button> : null}
          <button className="btn ghost" onClick={repeat}>Повторить</button>
          {t.status === "done" && t.has_report ? <button className="btn ghost" onClick={() => { setActive(t.id); go({view: "netmap"}); }}>Схема сети</button> : null}
          {t.status === "done" ? <button className="btn" onClick={() => { setActive(t.id); go({view: "dash"}); }}>Открыть результат</button> : null}
        </div>
      </div>
      <p className="sub">Цели: <span className="mono">{p.targets || (r.targets || []).join(", ") || "—"}</span>{running ? " · обновляется каждые 2 c" : ""}</p>

      <div className="cols dash" style={{marginTop: 4}}>
        <div className="card" style={{gridColumn: "span 2"}}>
          <div className="ch"><h3>Журнал выполнения</h3></div>
          <div className="cb">
            <div className="tasklog" ref={logRef}>
              {(t.progress || []).length === 0
                ? <div className="sub2">Пока нет записей. Для демо-задач журнал не ведётся.</div>
                : (t.progress || []).map((l, i) => <div key={i}><span className="lt">{l.t}</span> {l.m}</div>)}
            </div>
            {t.status === "error" && t.error
              ? <div className="warn" style={{marginTop: 10, whiteSpace: "pre-wrap", fontFamily: "JetBrains Mono, monospace", fontSize: 12}}>{t.error}</div>
              : null}
          </div>
        </div>
        <div className="card">
          <div className="ch"><h3>Учётные записи</h3></div>
          <div className="cb">
            {(p.creds || []).length === 0 ? <div className="sub2">Без УЗ — только сетевое обнаружение.</div>
              : (p.creds || []).map((c, i) => <div key={i} style={{padding: "4px 0", fontSize: 13}}><b>{c.name || c.username || c.type}</b> <span className="sub2">· {c.type}{c.username ? " · " + c.username : ""}</span></div>)}
          </div>
        </div>
      </div>

      {coll ? (
        <div className="card" style={{marginTop: 16}}>
          <div className="ch"><h3>Сбор по активам</h3><span className="sub2">успешно {coll.collected.length} · не удалось {coll.failed.length}</span></div>
          <div className="cb">
            <table>
              <thead><tr><th>Актив</th><th>IP</th><th>Протокол</th><th>Результат</th></tr></thead>
              <tbody>
                {coll.collected.map((c, i) => <tr key={"c" + i}><td><b>{c.asset}</b></td><td className="mono">{c.ip}</td><td>{c.proto}</td><td style={{color: "var(--ok,#2e7d32)"}}>✓ собрано (УЗ {c.cred || "—"})</td></tr>)}
                {coll.failed.map((c, i) => <tr key={"f" + i}><td><b>{c.asset}</b></td><td className="mono">{c.ip}</td><td>{c.proto}</td><td className="sub2">✕ {c.error}</td></tr>)}
                {coll.collected.length === 0 && coll.failed.length === 0 && <tr><td colSpan="4" className="sub2">Активов для сбора не было.</td></tr>}
              </tbody>
            </table>
          </div>
        </div>
      ) : null}
    </div>
  );
}

/* ----------------------------------------------------------------- Обследования */
function Surveys({tasks, go, onNew, setActive}) {
  return (
    <div>
      <div style={{display: "flex", alignItems: "center", marginBottom: 16}}>
        <div><h1 className="h1" style={{margin: 0}}>Сканирования</h1><p className="sub" style={{margin: "2px 0 0"}}>Запуск, статус, схема и активы.</p></div>
        <button className="btn" style={{marginLeft: "auto"}} onClick={onNew}>+ Новое сканирование</button>
      </div>
      <div className="card"><div className="cb">
        <table>
          <thead><tr><th>#</th><th>Скан</th><th>Цели</th><th>Статус</th><th className="num">Собрано по УЗ</th><th>Схема</th></tr></thead>
          <tbody>
            {tasks.map(t => {
              const st = ST_LABEL[t.status] || t.status;
              const p = t.params || {};
              const tg = p.targets || (t.result && (t.result.targets || []).join(", ")) || (p.kind === "demo" ? "демо" : "—");
              const nc = (p.creds || []).length;
              const coll = t.result && t.result.collect;
              return (
                <tr key={t.id}>
                  <td className="mono">{t.id}</td>
                  <td className="link" onClick={() => go({view: "task", taskId: t.id})}><b>{t.name || "—"}</b>
                    {nc ? <div className="sub2">{nc} УЗ{coll ? ` · собрано ${coll.collected.length}` : ""}</div> : null}</td>
                  <td className="sub2 mono">{tg}</td>
                  <td><span className={"chip c-" + (ST_CHIP[t.status] || "medium")}>{st}</span></td>
                  <td className="num">{coll ? coll.collected.length : "—"}</td>
                  <td>{t.has_report ? <span className="link" onClick={() => { setActive(t.id); go({view: "netmap"}); }}>схема →</span> : <span className="link" onClick={() => go({view: "task", taskId: t.id})}>открыть →</span>}</td>
                </tr>
              );
            })}
            {tasks.length === 0 && <tr><td colSpan="6" className="sub2">Пока нет сканирований — запустите «+ Новое сканирование».</td></tr>}
          </tbody>
        </table>
      </div></div>
    </div>
  );
}

/* ----------------------------------------------------------------- Коннекторы */
function Connectors() {
  const [list, setList] = useState([]);
  const [name, setName] = useState("");
  const refresh = () => api("/connectors").then(setList).catch(() => {});
  useEffect(() => { refresh(); }, []);
  const add = async () => { if (!name) return; await api("/connectors", {method: "POST", headers: {"Content-Type": "application/json"}, body: JSON.stringify({name})}); setName(""); refresh(); };
  return (
    <div>
      <h1 className="h1">Коннекторы</h1>
      <p className="sub">Агенты сбора у заказчика (pull-модель, только исходящие соединения; офлайн-курьер для изолированного контура).</p>
      <div className="card" style={{marginBottom: 16}}><div className="cb row">
        <div className="field"><label>Название коннектора</label><input value={name} onChange={e => setName(e.target.value)} placeholder="Коннектор-1" style={{minWidth: 260}}/></div>
        <button className="btn" onClick={add}>Зарегистрировать</button>
      </div></div>
      <div className="card"><div className="cb">
        <table>
          <thead><tr><th>#</th><th>Коннектор</th><th>Последний дозвон</th></tr></thead>
          <tbody>
            {list.map(c => <tr key={c.id}><td className="mono">{c.id}</td><td><b>{c.name}</b></td><td className="sub2">{c.last_seen ? c.last_seen.replace("T", " ").slice(0, 16) : "ни разу"}</td></tr>)}
            {list.length === 0 && <tr><td colSpan="3" className="sub2">Коннекторы не зарегистрированы.</td></tr>}
          </tbody>
        </table>
      </div></div>
    </div>
  );
}

/* ----------------------------------------------------------------- приложение */
const NAV = [
  {sec: "Обзор", items: [{id: "dash", ic: "▦", l: "Дашборд"}, {id: "surveys", ic: "▤", l: "Сканирования"}]},
  {sec: "Сеть", items: [{id: "assets", ic: "🖥", l: "Активы", cnt: "assets"}, {id: "netmap", ic: "◈", l: "Схема сети"}]},
  {sec: "Система", items: [{id: "creds", ic: "🔑", l: "Учётные записи"}, {id: "connectors", ic: "⇄", l: "Коннекторы"}]},
];
const TITLES = {dash: "Дашборд", surveys: "Сканирования", task: "Задача", assets: "Активы", asset: "Актив", netmap: "Схема сети", newscan: "Новое сканирование", creds: "Учётные записи", connectors: "Коннекторы"};

function App() {
  const [tasks, setTasks] = useState([]);
  const [activeId, setActiveId] = useState(null);
  const [D, setD] = useState(null);
  const [nav, setNav] = useState({view: "dash"});
  const [busy, setBusy] = useState(false);
  const [savedCreds, setSavedCreds] = useState([]);
  const loadCreds = useCallback(() => api("/credentials").then(setSavedCreds).catch(() => {}), []);
  useEffect(() => { loadCreds(); }, [loadCreds]);

  const loadTasks = useCallback(() => api("/tasks?limit=50").then(ts => {
    setTasks(ts);
    setActiveId(id => id || (ts.find(t => t.status === "done") || {}).id || null);
    return ts;
  }).catch(() => []), []);
  useEffect(() => { loadTasks(); }, [loadTasks]);
  const activeStatus = (tasks.find(t => t.id === activeId) || {}).status;
  useEffect(() => {
    if (!activeId) { setD(null); return; }
    api("/tasks/" + activeId).then(t => setD(t.dashboard || null)).catch(() => setD(null));
  }, [activeId, activeStatus]);
  useEffect(() => {
    if (!tasks.some(t => t.status === "running" || t.status === "queued")) return;
    const h = setInterval(() => loadTasks().then(ts => {
      const run = ts.find(t => t.status === "running" || t.status === "queued");
      if (!run) { const done = ts.find(t => t.status === "done"); if (done) setActiveId(done.id); }
    }), 2000);
    return () => clearInterval(h);
  }, [tasks, loadTasks]);

  const go = (n) => { setNav(n); window.scrollTo(0, 0); };
  const setActive = (id) => { setActiveId(id); go({view: "dash"}); };

  const runScan = async (targets, credIds) => {
    const nm = "Скан — " + (targets.split(/[\s,;]+/)[0] || "");
    const body = {kind: "inventory", run: "async", name: nm, customer: null, targets};
    if (credIds && credIds.length) body.cred_ids = credIds;
    setBusy(true);
    try {
      const t = await api("/tasks", {method: "POST", headers: {"Content-Type": "application/json"}, body: JSON.stringify(body)});
      await loadTasks(); setActiveId(t.id); go({view: "task", taskId: t.id});
    } catch (e) { alert("Не удалось запустить: " + (e && e.detail ? e.detail : JSON.stringify(e))); }
    setBusy(false);
  };

  const counts = D ? (D.totals || {}) : {};
  let screen;
  if (nav.view === "dash") screen = <Dash D={D} tasks={tasks} go={go}/>;
  else if (nav.view === "surveys") screen = <Surveys tasks={tasks} go={go} onNew={() => go({view: "newscan"})} setActive={setActive}/>;
  else if (nav.view === "task") screen = <TaskDetail taskId={nav.taskId} go={go} setActive={setActive}/>;
  else if (nav.view === "newscan") screen = <NewScan onRun={runScan} busy={busy} go={go} savedCreds={savedCreds} initTargets={nav.initTargets} initCreds={nav.initCreds}/>;
  else if (nav.view === "assets") screen = <Assets D={D} go={go}/>;
  else if (nav.view === "asset") screen = <AssetDetail D={D} name={nav.assetName} go={go}/>;
  else if (nav.view === "netmap") screen = <NetMap taskId={activeId} go={go}/>;
  else if (nav.view === "creds") screen = <Credentials onChange={loadCreds}/>;
  else if (nav.view === "connectors") screen = <Connectors/>;
  else screen = <Dash D={D} tasks={tasks} go={go}/>;

  const crumb = nav.view === "asset"
    ? <><span className="link" onClick={() => go({view: "assets"})}>Активы</span><span className="sep">/</span><b>{nav.assetName}</b></>
    : <b>{TITLES[nav.view] || "Дашборд"}</b>;

  return (
    <div className="app">
      <aside className="nav">
        <div className="brand"><span className="logo">◢</span>surveyscan</div>
        {NAV.map(g => (
          <React.Fragment key={g.sec}>
            <div className="navsec">{g.sec}</div>
            {g.items.map(it => {
              const on = nav.view === it.id || (it.id === "assets" && nav.view === "asset");
              const cc = it.cnt && counts[it.cnt] != null ? counts[it.cnt] : null;
              return (
                <button className={"navi" + (on ? " on" : "")} key={it.id} onClick={() => go({view: it.id})}>
                  <span className="ico">{it.ic}</span>{it.l}{cc ? <span className="cnt">{cc}</span> : null}
                </button>
              );
            })}
          </React.Fragment>
        ))}
        <div className="foot">сканер инвентаризации<br/>и схемы сети</div>
      </aside>
      <div className="main">
        <div className="top">
          <div className="crumb">{crumb}</div>
          <div className="search">⌕ Поиск по активам, IP…</div>
          <div className="right">
            <button className="btn" onClick={() => go({view: "newscan"})}>+ Новое сканирование</button>
            <div className="av">ИП</div>
          </div>
        </div>
        <div className="body">{screen}</div>
      </div>
    </div>
  );
}
ReactDOM.createRoot(document.getElementById("root")).render(<App/>);
