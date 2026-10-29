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

/* ----------------------------------------------------------------- Diff между прогонами */
function DiffBanner({diff}) {
  if (!diff) return null;
  const nNew = (diff.new_hosts || []).length, nGone = (diff.gone_hosts || []).length, nChg = (diff.changed || []).length;
  if (!nNew && !nGone && !nChg) return <div className="diffbar">Без изменений с прошлого прогона по этой цели.</div>;
  return (
    <div className="diffbar">
      <div><b>Изменения с прошлого прогона:</b>{" "}
        {nNew ? <span className="chip c-low" style={{marginRight: 6}}>+{nNew} новых</span> : null}
        {nGone ? <span className="chip c-critical" style={{marginRight: 6}}>−{nGone} исчезло</span> : null}
        {nChg ? <span className="chip c-medium">{nChg} изменили сервисы</span> : null}
      </div>
      <details style={{marginTop: 6}}>
        <summary className="sub2" style={{cursor: "pointer"}}>Подробнее</summary>
        {nNew ? <div className="sub2" style={{marginTop: 4}}>Новые: {diff.new_hosts.join(", ")}</div> : null}
        {nGone ? <div className="sub2" style={{marginTop: 4}}>Исчезли: {diff.gone_hosts.join(", ")}</div> : null}
        {diff.changed.map(c => (
          <div key={c.name} className="sub2" style={{marginTop: 4}}>
            <b>{c.name}</b>: {c.added_services.length ? "+ " + c.added_services.join("; ") : ""}
            {c.added_services.length && c.removed_services.length ? " · " : ""}
            {c.removed_services.length ? "− " + c.removed_services.join("; ") : ""}
          </div>
        ))}
      </details>
    </div>
  );
}

/* ----------------------------------------------------------------- Дашборд */
function Dash({D, tasks, go, diff}) {
  if (!D) return <div className="empty">Нет данных. Запустите сканирование: «+ Новое сканирование».</div>;
  const ts = (D.topology && D.topology.stats) || {};
  const assets = D.assets || [];
  const kpi = (n, l, c) => <div className="kpi"><div className="l">{l}</div><div className="n" style={c ? {color: c} : null}>{n}</div></div>;
  return (
    <div>
      <h1 className="h1">{(D.survey && D.survey.name) || "Обследование"}</h1>
      <p className="sub">Инвентаризация сети · {D.generated}</p>
      <DiffBanner diff={diff}/>
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

/* ----------------------------------------------------------------- Роль актива (ИТ/сетевое/АСУ ТП/СЗИ) */
const ROLE_LABELS = {"": "— не задано —", it: "ИТ-хост", netdev: "Сетевое устройство", ics: "АСУ ТП (ПЛК/SCADA)", security: "СЗИ"};
const ROLE_CHIP = {it: "tag-ro", netdev: "tagline", ics: "c-ics", security: "c-security"};

function RoleBadge({role}) {
  const r = role || "";
  const cls = ROLE_CHIP[r] || "tag-ro";
  return <span className={(cls === "tag-ro" || cls === "tagline") ? "tagline " + cls : "chip " + cls}>{ROLE_LABELS[r] || r}</span>;
}

function RoleSelect({value, onChange}) {
  return (
    <select value={value || ""} onChange={e => onChange(e.target.value)} style={{fontSize: 12.5, padding: "4px 8px"}}>
      {Object.entries(ROLE_LABELS).map(([k, l]) => <option key={k} value={k}>{l}</option>)}
    </select>
  );
}

function assetIcon(a) {
  if (a.role === "ics") return "🏭";
  if (a.role === "security") return "🛡";
  return (a.kind || "").toLowerCase().includes("сетев") ? "🖧" : "🖥";
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
          <thead><tr><th>Актив</th><th>IP</th><th>ОС / платформа</th><th>Тип</th><th>Роль</th><th className="num">ПО</th><th className="num">Сервисов</th></tr></thead>
          <tbody>
            {assets.map(a => (
              <tr key={a.name} className="click" onClick={() => go({view: "asset", assetName: a.name})}>
                <td><b>{a.name}</b>{a.partial ? <span className="chip c-medium" style={{marginLeft: 8}}>сбор без root</span> : null}</td>
                <td className="mono">{a.ips || "—"}</td>
                <td>{a.os || "—"}{a.build ? <div className="sub2 mono">{a.build}</div> : null}</td>
                <td>{a.kind}</td>
                <td><RoleBadge role={a.role}/></td>
                <td className="num">{a.software || 0}</td>
                <td className="num">{(a.services || []).length}</td>
              </tr>
            ))}
            {assets.length === 0 && <tr><td colSpan="7" className="sub2">Активы не найдены.</td></tr>}
          </tbody>
        </table>
      </div></div>
    </div>
  );
}

/* --- вспомогательные блоки карточки актива --- */
function KV({k, v}) {
  return <div className="kv"><span className="k">{k}</span><span className="v">{v === null || v === undefined || v === "" ? "—" : String(v)}</span></div>;
}

function SimpleTable({cols, rows, empty}) {
  if (!rows || rows.length === 0) return <div className="sub2">{empty}</div>;
  return (
    <table>
      <thead><tr>{cols.map(c => <th key={c.key} className={c.num ? "num" : ""}>{c.label}</th>)}</tr></thead>
      <tbody>
        {rows.map((r, i) => (
          <tr key={i}>{cols.map(c => <td key={c.key} className={c.mono ? "mono" : (c.num ? "num" : "")}>{c.render ? c.render(r) : (r[c.key] ?? "—")}</td>)}</tr>
        ))}
      </tbody>
    </table>
  );
}

function AssetDetail({D, name, go, taskId, onRoleChange}) {
  const a = (D.assets || []).find(x => x.name === name);
  const [tab, setTab] = useState("overview");
  const [swFilter, setSwFilter] = useState("");
  const [svcFilter, setSvcFilter] = useState("");
  const [roleErr, setRoleErr] = useState("");
  if (!a) return <div className="empty">Актив не найден.</div>;
  const saveRole = async (role) => {
    setRoleErr("");
    try {
      await api("/tasks/" + taskId + "/assets/" + a.id + "/role",
        {method: "PATCH", headers: {"Content-Type": "application/json"}, body: JSON.stringify({role})});
      onRoleChange && onRoleChange();
    } catch (e) { setRoleErr(e && e.detail ? e.detail : "не удалось сохранить роль"); }
  };
  const inv = a.inventory || {};
  const fam = a.os_family || "";
  const software = inv.software || [];
  const swShown = swFilter ? software.filter(s => (s.name || "").toLowerCase().includes(swFilter.toLowerCase())) : software;
  const listening = inv.listening || [];
  const connections = inv.connections || [];
  const winServices = inv.services || [];
  const svcShown = svcFilter
    ? winServices.filter(s => ((s.display || "") + " " + (s.name || "")).toLowerCase().includes(svcFilter.toLowerCase()))
    : winServices;
  const hasDevices = (inv.disks || []).length || (inv.shares || []).length || (inv.usb_devices || []).length;

  const tabs = [
    {id: "overview", label: "Обзор"},
    {id: "software", label: "ПО", count: software.length},
  ];
  if (fam === "windows") tabs.push({id: "hotfixes", label: "Обновления", count: (inv.hotfixes || []).length});
  if (fam === "windows" || fam === "linux") tabs.push({id: "users", label: "Пользователи"});
  tabs.push({id: "network", label: "Сеть и службы", count: (a.services || []).length + listening.length});
  if (fam === "windows" || fam === "linux") tabs.push({id: "security", label: "Защита"});
  if (fam === "windows" && hasDevices) tabs.push({id: "devices", label: "Диски и устройства"});
  if (inv.config) tabs.push({id: "config", label: "Конфигурация"});

  return (
    <div>
      <div className="crumb" style={{marginBottom: 10}}><span className="link" onClick={() => go({view: "assets"})}>Активы</span><span className="sep">/</span><b>{name}</b></div>
      <div className="pagehead">
        <div className="ic">{assetIcon(a)}</div>
        <div><div className="h1" style={{margin: 0}}>{name}</div><div className="meta mono">{a.ips}{a.os ? " · " + a.os : ""}</div></div>
      </div>
      {a.partial ? <div className="warn" style={{margin: "10px 0"}}>Сбор выполнен без root/sudo — часть данных (учётки, конфиги) может быть неполной.</div> : null}

      <div className="tabs">
        {tabs.map(t => (
          <div key={t.id} className={"tab" + (tab === t.id ? " on" : "")} onClick={() => setTab(t.id)}>
            {t.label}{t.count !== undefined ? <span className="cnt">{t.count}</span> : null}
          </div>
        ))}
      </div>

      {tab === "overview" && (
        <div className="detail">
          <div className="card"><div className="ch"><h3>Сведения</h3></div><div className="cb">
            <KV k="Тип" v={a.kind}/>
            <div className="kv"><span className="k">Роль</span><span className="v"><RoleSelect value={a.role} onChange={saveRole}/></span></div>
            {roleErr ? <div className="sub2" style={{color: "var(--crit,#b4232a)", margin: "2px 0 6px"}}>{roleErr}</div> : null}
            <KV k="IP" v={a.ips}/>
            <KV k="ОС / платформа" v={a.os}/>
            <KV k="Сборка / версия" v={a.build}/>
            {fam === "windows" ? <>
              <KV k="Домен" v={inv.part_of_domain ? inv.domain : "рабочая группа"}/>
              <KV k="Архитектура" v={inv.architecture}/>
              <KV k="Тип установки" v={inv.installation_type}/>
              <KV k="Последняя загрузка" v={inv.last_boot}/>
              <KV k="Сбор от администратора" v={inv.is_admin === true ? "да" : (inv.is_admin === false ? "нет" : "—")}/>
            </> : null}
            {fam === "linux" ? <KV k="Сбор от root" v={inv.is_root === true ? "да" : (inv.is_root === false ? "нет (sudo/частично)" : "—")}/> : null}
            <KV k="Источник сбора" v={a.source}/>
            <KV k="Собрано" v={a.collected_at}/>
          </div></div>
          <div>
            <div className="card"><div className="ch"><h3>Итоги</h3></div><div className="cb">
              <KV k="Пакетов / ПО" v={software.length}/>
              <KV k="Открытых сервисов (сеть)" v={(a.services || []).length}/>
              <KV k="Слушающих портов (ОС)" v={listening.length}/>
              {fam === "windows" ? <KV k="Обновлений (KB)" v={(inv.hotfixes || []).length}/> : null}
            </div></div>
            {a.sec_tools && a.sec_tools.length ? (
              <div className="card" style={{marginTop: 16}}><div className="ch"><h3>Средства защиты</h3></div><div className="cb">
                {a.sec_tools.map((t, i) => <div key={i} style={{padding: "5px 0"}}><span style={{color: "var(--ok)"}}>✓</span> {t}</div>)}
              </div></div>) : null}
          </div>
        </div>
      )}

      {tab === "software" && (
        <div className="card"><div className="ch"><h3>Установленное ПО / пакеты</h3>
          <input value={swFilter} onChange={e => setSwFilter(e.target.value)} placeholder="Фильтр по имени…"
                 style={{marginLeft: "auto", fontSize: 12.5, padding: "4px 8px"}}/>
        </div><div className="cb">
          <SimpleTable empty="ПО не обнаружено." cols={[
            {key: "name", label: "Название"}, {key: "version", label: "Версия", mono: true},
            {key: "vendor", label: "Производитель"}, {key: "ecosystem", label: "Тип"},
          ]} rows={swShown}/>
        </div></div>
      )}

      {tab === "hotfixes" && (
        <div className="card"><div className="ch"><h3>Установленные обновления</h3></div><div className="cb">
          {(inv.hotfixes || []).length
            ? <div style={{display: "flex", flexWrap: "wrap", gap: 8}}>
                {inv.hotfixes.map(kb => <span key={kb} className="mono chip c-low">KB{kb}</span>)}
              </div>
            : <div className="sub2">Обновления не собраны.</div>}
        </div></div>
      )}

      {tab === "users" && (
        <div className="detail">
          <div className="card"><div className="ch"><h3>Учётные записи</h3></div><div className="cb">
            {fam === "windows"
              ? <SimpleTable empty="Локальные учётки не собраны." cols={[
                  {key: "name", label: "Имя"},
                  {key: "disabled", label: "Отключена", render: r => r.disabled ? "да" : "нет"},
                  {key: "password_required", label: "Треб. пароль", render: r => r.password_required ? "да" : "нет"},
                  {key: "password_expires", label: "Пароль истекает", render: r => r.password_expires ? "да" : "нет"},
                ]} rows={inv.users}/>
              : <SimpleTable empty="Пользователи не собраны." cols={[{key: "name", label: "Логин"}]}
                  rows={(inv.login_users || []).map(n => ({name: n}))}/>}
          </div></div>
          <div>
            {fam === "windows" ? (
              <>
                <div className="card"><div className="ch"><h3>Администраторы</h3></div><div className="cb">
                  {(inv.admins || []).length
                    ? inv.admins.map((n, i) => <div key={i} className="mono" style={{padding: "4px 0", fontSize: 12.5}}>{n}</div>)
                    : <div className="sub2">Группа «Администраторы» пуста или не собрана.</div>}
                </div></div>
                <div className="card" style={{marginTop: 16}}><div className="ch"><h3>Локальные группы</h3></div><div className="cb">
                  <SimpleTable empty="Группы не собраны." cols={[
                    {key: "name", label: "Наименование"}, {key: "sid", label: "SID", mono: true},
                    {key: "description", label: "Описание"},
                    {key: "members", label: "Члены группы", render: r => (r.members || []).join(", ") || "—"},
                  ]} rows={inv.groups}/>
                </div></div>
              </>
            ) : (
              <>
                <div className="card"><div className="ch"><h3>UID 0 / sudo без пароля</h3></div><div className="cb">
                  <KV k="UID 0 (кроме root)" v={(inv.uid0_users || []).join(", ") || "—"}/>
                  <KV k="sudo NOPASSWD" v={inv.sudo_nopasswd === null ? "нет доступа к данным" : ((inv.sudo_nopasswd || []).join("; ") || "нет")}/>
                  <KV k="Пустой пароль" v={inv.empty_password_users === null ? "нет доступа к данным" : ((inv.empty_password_users || []).join(", ") || "нет")}/>
                </div></div>
              </>
            )}
          </div>
        </div>
      )}

      {tab === "network" && (
        <div className="detail">
          {(fam === "windows" || fam === "linux") && (inv.nics || []).length ? (
            <div className="card" style={{gridColumn: "1 / -1"}}><div className="ch"><h3>Сетевые интерфейсы</h3></div><div className="cb">
              {fam === "windows"
                ? <SimpleTable empty="Не собрано." cols={[
                    {key: "name", label: "Наименование"}, {key: "mac", label: "MAC адрес", mono: true},
                    {key: "status", label: "Статус"},
                    {key: "ip", label: "IP адрес", mono: true, render: r => (r.ip || []).join(", ") || "—"},
                    {key: "mask", label: "Маска подсети", mono: true, render: r => (r.mask || []).join(", ") || "—"},
                    {key: "gateway", label: "Основной шлюз", mono: true, render: r => (r.gateway || []).join(", ") || "—"},
                    {key: "dns", label: "DNS сервер", mono: true, render: r => (r.dns || []).join(", ") || "—"},
                    {key: "dhcp_server", label: "DHCP сервер", mono: true, render: r => r.dhcp_enabled ? (r.dhcp_server || "да") : "отключён"},
                  ]} rows={inv.nics}/>
                : <SimpleTable empty="Не собрано." cols={[
                    {key: "name", label: "Наименование"}, {key: "mac", label: "MAC адрес", mono: true},
                    {key: "addresses", label: "IP адрес / маска", mono: true,
                     render: r => (r.addresses || []).map(x => x.ip + "/" + x.prefix).join(", ") || "—"},
                  ]} rows={inv.nics}/>}
            </div></div>
          ) : null}

          {(fam === "windows" || fam === "linux") && (inv.routes || []).length ? (
            <div className="card" style={{gridColumn: "1 / -1"}}><div className="ch"><h3>Таблица маршрутизации</h3></div><div className="cb">
              <SimpleTable empty="Не собрано." cols={[
                {key: "destination", label: "Сеть", mono: true}, {key: "gateway", label: "Шлюз", mono: true},
                {key: "interface", label: "Интерфейс"},
              ]} rows={inv.routes}/>
            </div></div>
          ) : null}

          <div className="card"><div className="ch"><h3>Открытые сервисы (сетевой скан)</h3></div><div className="cb">
            {(a.services || []).length
              ? (a.services || []).map((s, i) => <div key={i} className="mono" style={{padding: "5px 0", fontSize: 12.5}}>{s}</div>)
              : <div className="sub2">Открытых сервисов не обнаружено.</div>}
          </div></div>
          <div className="card"><div className="ch"><h3>Слушающие порты (на хосте)</h3></div><div className="cb">
            <SimpleTable empty="Не собрано." cols={[
              {key: "proto", label: "Протокол"}, {key: "port", label: "Порт", num: true},
              {key: "address", label: "Адрес", mono: true}, {key: "process", label: "Процесс"},
            ]} rows={listening}/>
          </div></div>

          {connections.length ? (
            <div className="card" style={{gridColumn: "1 / -1"}}><div className="ch"><h3>Используемые сетевые соединения</h3></div><div className="cb">
              <SimpleTable empty="Не собрано." cols={[
                {key: "local_address", label: "Локальный адрес", mono: true}, {key: "local_port", label: "Локальный порт", num: true},
                {key: "remote_address", label: "Удалённый адрес", mono: true}, {key: "remote_port", label: "Удалённый порт", num: true},
                {key: "process", label: "Процесс"},
              ]} rows={connections}/>
            </div></div>
          ) : null}

          {fam === "windows" && winServices.length ? (
            <div className="card" style={{gridColumn: "1 / -1"}}>
              <div className="ch"><h3>Службы Windows</h3><span className="sub2">{winServices.length}</span>
                <input value={svcFilter} onChange={e => setSvcFilter(e.target.value)} placeholder="Фильтр по имени…"
                       style={{marginLeft: "auto", fontSize: 12.5, padding: "4px 8px"}}/>
              </div>
              <div className="cb">
                <SimpleTable empty="Не найдено." cols={[
                  {key: "display", label: "Полное имя"}, {key: "name", label: "Имя службы", mono: true},
                  {key: "state", label: "Статус"}, {key: "start_mode", label: "Тип запуска"},
                  {key: "account", label: "Учётная запись", mono: true}, {key: "path", label: "Путь до файла", mono: true},
                ]} rows={svcShown}/>
              </div>
            </div>
          ) : null}
        </div>
      )}

      {tab === "devices" && (
        <div className="detail">
          <div className="card"><div className="ch"><h3>Жёсткие диски</h3></div><div className="cb">
            <SimpleTable empty="Не собрано." cols={[
              {key: "id", label: "ID диска", mono: true}, {key: "name", label: "Наименование"},
              {key: "size_gb", label: "Объём, ГБ", num: true}, {key: "free_gb", label: "Свободно, ГБ", num: true},
            ]} rows={inv.disks}/>
          </div></div>
          <div className="card"><div className="ch"><h3>Общие папки</h3></div><div className="cb">
            <SimpleTable empty="Не собрано." cols={[
              {key: "name", label: "Наименование"}, {key: "path", label: "Путь", mono: true},
              {key: "description", label: "Описание"},
            ]} rows={inv.shares}/>
          </div></div>
          <div className="card" style={{gridColumn: "1 / -1"}}><div className="ch"><h3>Подключённые USB-устройства</h3></div><div className="cb">
            <SimpleTable empty="Не собрано." cols={[
              {key: "name", label: "Наименование"}, {key: "device_id", label: "ID устройства", mono: true},
              {key: "description", label: "Описание"},
            ]} rows={inv.usb_devices}/>
          </div></div>
        </div>
      )}

      {tab === "security" && (
        <div className="detail">
          {fam === "windows" ? (
            <>
              <div className="card"><div className="ch"><h3>Межсетевой экран</h3></div><div className="cb">
                {Object.keys(inv.firewall || {}).length
                  ? Object.entries(inv.firewall).map(([k, v]) => <KV key={k} k={k} v={v ? "включён" : "отключён"}/>)
                  : <div className="sub2">Не собрано.</div>}
              </div></div>
              <div className="card"><div className="ch"><h3>Антивирус / Defender</h3></div><div className="cb">
                {(inv.antivirus || []).map((av, i) => <div key={i} style={{padding: "4px 0"}}><span style={{color: "var(--ok)"}}>✓</span> {av.name}</div>)}
                {inv.defender ? <>
                  <KV k="Defender включён" v={inv.defender.enabled ? "да" : "нет"}/>
                  <KV k="Защита в реальном времени" v={inv.defender.realtime ? "да" : "нет"}/>
                  <KV k="Обновление сигнатур" v={inv.defender.signatures}/>
                </> : null}
                {(!inv.antivirus || inv.antivirus.length === 0) && !inv.defender ? <div className="sub2">Не собрано.</div> : null}
              </div></div>
            </>
          ) : (
            <>
              <div className="card"><div className="ch"><h3>SSH</h3></div><div className="cb">
                {inv.sshd ? Object.entries(inv.sshd).map(([k, v]) => <KV key={k} k={k} v={v}/>) : <div className="sub2">sshd не собран.</div>}
              </div></div>
              <div className="card"><div className="ch"><h3>Активные службы безопасности</h3></div><div className="cb">
                {Object.keys(inv.services_active || {}).length
                  ? Object.entries(inv.services_active).map(([k, v]) => <KV key={k} k={k} v={v}/>)
                  : <div className="sub2">Не собрано.</div>}
              </div></div>
            </>
          )}
        </div>
      )}

      {tab === "config" && (
        <div className="card"><div className="ch"><h3>Конфигурация устройства</h3><span className="sub2">секреты замаскированы</span></div><div className="cb">
          <pre className="mono" style={{whiteSpace: "pre-wrap", fontSize: 12, margin: 0}}>{inv.config}</pre>
        </div></div>
      )}
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
  // роль (см. roleguess.py) переопределяет цвет независимо от type — чтобы АСУ ТП/СЗИ были заметны сразу
  {selector: 'node[role="ics"]', style: {"background-color": "#8A4B16", "color": "#fff"}},
  {selector: 'node[role="security"]', style: {"background-color": "#1B6B4A", "color": "#fff"}},
  {selector: "edge", style: {"line-color": "#C4CAD4", "width": 1.5, "curve-style": "bezier"}},
  {selector: 'edge[type="uplink"]', style: {"line-color": "#AEB4C0", "width": 2}},
  {selector: 'edge[type="l2"]', style: {"line-color": "#3D4EA6", "line-style": "dashed"}},
];

function NetMap({taskId, go, diff}) {
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
      <DiffBanner diff={diff}/>
      <div id="cy" ref={box}></div>
      <div className="legend2">
        <span><i style={{background: "#3D4EA6", transform: "rotate(45deg)"}}></i>Ядро сети</span>
        <span><i style={{background: "#E8EAEF"}}></i>Подсеть</span>
        <span><i style={{background: "#11141B"}}></i>Сетевое устройство</span>
        <span><i style={{background: "#fff", border: "1px solid #C4CAD4"}}></i>Хост</span>
        <span><i style={{background: "#8A4B16"}}></i>АСУ ТП</span>
        <span><i style={{background: "#1B6B4A"}}></i>СЗИ</span>
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
      <DiffBanner diff={t.diff}/>

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

/* ----------------------------------------------------------------- Расписания */
const SCHED_KINDS = {demo: "Демо", inventory: "Инвентаризация", vuln: "Уязвимости", config: "Конфигурации"};
function Schedules({savedCreds}) {
  const [list, setList] = useState([]);
  const [f, setF] = useState({name: "", kind: "inventory", targets: "", interval_minutes: 60, cred_ids: []});
  const [err, setErr] = useState("");
  const refresh = () => api("/schedules").then(setList).catch(() => {});
  useEffect(() => { refresh(); const h = setInterval(refresh, 5000); return () => clearInterval(h); }, []);
  const setFF = (k, v) => setF(p => ({...p, [k]: v}));
  const toggleCred = (id) => setFF("cred_ids", f.cred_ids.includes(id) ? f.cred_ids.filter(x => x !== id) : [...f.cred_ids, id]);
  const add = async () => {
    setErr("");
    try {
      await api("/schedules", {method: "POST", headers: {"Content-Type": "application/json"}, body: JSON.stringify({
        name: f.name || null, kind: f.kind, targets: f.targets || null,
        interval_minutes: parseInt(f.interval_minutes, 10) || 60, cred_ids: f.cred_ids})});
      setF({name: "", kind: "inventory", targets: "", interval_minutes: 60, cred_ids: []});
      refresh();
    } catch (e) { setErr(e && e.detail ? e.detail : "не удалось сохранить"); }
  };
  const del = async (id) => { await fetch("/schedules/" + id, {method: "DELETE"}); refresh(); };
  const toggleEnabled = async (s) => {
    await api("/schedules/" + s.id, {method: "PATCH", headers: {"Content-Type": "application/json"}, body: JSON.stringify({enabled: !s.enabled})});
    refresh();
  };
  const runNow = async (id) => { await api("/schedules/" + id + "/run", {method: "POST"}); refresh(); };
  const fmt = (s) => s ? s.replace("T", " ").slice(0, 16) : "—";
  return (
    <div>
      <h1 className="h1">Расписания</h1>
      <p className="sub">Периодический пересбор по заданным целям — без ручного запуска. При срабатывании ставится обычная задача сканирования; изменения с прошлого прогона видны в карточке задачи и на дашборде.</p>
      <div className="card" style={{marginBottom: 16, maxWidth: 820}}><div className="cb">
        <div className="field"><label>Название</label><input value={f.name} onChange={e => setFF("name", e.target.value)} placeholder="Периметр — ежечасно"/></div>
        <div className="field" style={{marginTop: 10}}>
          <label>Цели: подсети / хосты {f.kind === "demo" ? <span className="sub2" style={{fontWeight: 400}}>(не нужны для демо)</span> : null}</label>
          <textarea rows="2" value={f.targets} onChange={e => setFF("targets", e.target.value)} placeholder="10.0.0.0/24, srv01.corp"/>
        </div>
        <div style={{display: "flex", gap: 10, marginTop: 10, flexWrap: "wrap"}}>
          <div className="field">
            <label>Вид</label>
            <select value={f.kind} onChange={e => setFF("kind", e.target.value)}>
              {Object.entries(SCHED_KINDS).map(([k, l]) => <option key={k} value={k}>{l}</option>)}
            </select>
          </div>
          <div className="field"><label>Интервал, мин</label>
            <input type="number" min="1" style={{width: 100}} value={f.interval_minutes} onChange={e => setFF("interval_minutes", e.target.value)}/></div>
        </div>
        {savedCreds && savedCreds.length ? (
          <div className="field" style={{marginTop: 10}}>
            <label>Учётные записи для сбора <span className="sub2" style={{fontWeight: 400}}>(опционально)</span></label>
            <div className="credpick">
              {savedCreds.map(c => (
                <label className={"credopt" + (f.cred_ids.includes(c.id) ? " on" : "")} key={c.id}>
                  <input type="checkbox" checked={f.cred_ids.includes(c.id)} onChange={() => toggleCred(c.id)}/>
                  <span className="cn">{c.name}</span><span className="ct">{CRED_KIND[c.type] || c.type}</span>
                </label>
              ))}
            </div>
          </div>
        ) : null}
        <button className="btn" style={{marginTop: 14}} onClick={add}>Создать расписание</button>
        {err ? <div className="sub2" style={{color: "var(--crit,#b4232a)", marginTop: 8}}>{err}</div> : null}
      </div></div>
      <div className="card"><div className="cb">
        <table>
          <thead><tr><th>Название</th><th>Цели</th><th>Интервал</th><th>Включено</th><th>Последний запуск</th><th>Следующий</th><th></th></tr></thead>
          <tbody>
            {list.map(s => (
              <tr key={s.id}>
                <td><b>{s.name || "Расписание #" + s.id}</b><div className="sub2">{SCHED_KINDS[s.kind] || s.kind}</div></td>
                <td className="sub2 mono">{s.targets || "демо"}</td>
                <td>{s.interval_minutes} мин</td>
                <td><label style={{display: "inline-flex", alignItems: "center", gap: 6, cursor: "pointer"}}>
                  <input type="checkbox" checked={s.enabled} onChange={() => toggleEnabled(s)}/>{s.enabled ? "да" : "нет"}
                </label></td>
                <td className="sub2">{fmt(s.last_run_at)}</td>
                <td className="sub2">{fmt(s.next_run_at)}</td>
                <td style={{textAlign: "right", whiteSpace: "nowrap"}}>
                  <button className="btn sm ghost" onClick={() => runNow(s.id)}>Запустить сейчас</button>{" "}
                  <button className="xbtn" title="Удалить" onClick={() => del(s.id)}>✕</button>
                </td>
              </tr>
            ))}
            {list.length === 0 && <tr><td colSpan="7" className="sub2">Расписаний нет. Создайте первое выше — пересбор будет запускаться автоматически.</td></tr>}
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
  {sec: "Система", items: [{id: "schedules", ic: "⏱", l: "Расписания"}, {id: "creds", ic: "🔑", l: "Учётные записи"}, {id: "connectors", ic: "⇄", l: "Коннекторы"}]},
];
const TITLES = {dash: "Дашборд", surveys: "Сканирования", task: "Задача", assets: "Активы", asset: "Актив", netmap: "Схема сети", newscan: "Новое сканирование", schedules: "Расписания", creds: "Учётные записи", connectors: "Коннекторы"};

/* ----------------------------------------------------------------- поиск по активам */
function SearchBox({taskId, go}) {
  const [q, setQ] = useState("");
  const [results, setResults] = useState([]);
  const [open, setOpen] = useState(false);

  useEffect(() => {
    if (!taskId || !q.trim()) { setResults([]); return; }
    const h = setTimeout(() => {
      api("/tasks/" + taskId + "/assets/search?q=" + encodeURIComponent(q))
        .then(r => { setResults(r); setOpen(true); })
        .catch(() => setResults([]));
    }, 250);
    return () => clearTimeout(h);
  }, [q, taskId]);

  const pick = (name) => {
    setOpen(false); setQ("");
    go({view: "asset", assetName: name});
  };

  return (
    <div className="search">
      <span>⌕</span>
      <input
        value={q}
        placeholder="Поиск по активам, IP…"
        disabled={!taskId}
        onChange={e => setQ(e.target.value)}
        onFocus={() => q.trim() && setOpen(true)}
        onBlur={() => setTimeout(() => setOpen(false), 150)}
        onKeyDown={e => { if (e.key === "Escape") { setQ(""); setOpen(false); } }}
      />
      {open && q.trim() && (
        <div className="searchDrop">
          {results.length === 0
            ? <div className="searchItem sub2">Ничего не найдено</div>
            : results.map(r => (
              <div className="searchItem" key={r.name} onMouseDown={() => pick(r.name)}>
                <b>{r.name}</b>
                <div className="sub2">{[r.ips, r.os, r.role].filter(Boolean).join(" · ")}</div>
              </div>
            ))}
        </div>
      )}
    </div>
  );
}

function App() {
  const [tasks, setTasks] = useState([]);
  const [activeId, setActiveId] = useState(null);
  const [D, setD] = useState(null);
  const [diff, setDiff] = useState(null);
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
    if (!activeId) { setD(null); setDiff(null); return; }
    api("/tasks/" + activeId).then(t => { setD(t.dashboard || null); setDiff(t.diff || null); })
      .catch(() => { setD(null); setDiff(null); });
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
  if (nav.view === "dash") screen = <Dash D={D} tasks={tasks} go={go} diff={diff}/>;
  else if (nav.view === "surveys") screen = <Surveys tasks={tasks} go={go} onNew={() => go({view: "newscan"})} setActive={setActive}/>;
  else if (nav.view === "task") screen = <TaskDetail taskId={nav.taskId} go={go} setActive={setActive}/>;
  else if (nav.view === "newscan") screen = <NewScan onRun={runScan} busy={busy} go={go} savedCreds={savedCreds} initTargets={nav.initTargets} initCreds={nav.initCreds}/>;
  else if (nav.view === "assets") screen = <Assets D={D} go={go}/>;
  else if (nav.view === "asset") screen = <AssetDetail D={D} name={nav.assetName} go={go} taskId={activeId}
                                                        onRoleChange={() => api("/tasks/" + activeId).then(t => setD(t.dashboard || null)).catch(() => {})}/>;
  else if (nav.view === "netmap") screen = <NetMap taskId={activeId} go={go} diff={diff}/>;
  else if (nav.view === "schedules") screen = <Schedules savedCreds={savedCreds}/>;
  else if (nav.view === "creds") screen = <Credentials onChange={loadCreds}/>;
  else if (nav.view === "connectors") screen = <Connectors/>;
  else screen = <Dash D={D} tasks={tasks} go={go} diff={diff}/>;

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
          <SearchBox taskId={activeId} go={go}/>
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
