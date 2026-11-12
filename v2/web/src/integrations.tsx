import {useEffect,useState} from 'react';
import {api,ApiError,errorMessage,type CSVImportResult,type DirectorySettingsView,type DirectoryTestResult,type DirectoryWebSettings,type DirectorySyncStatus,type SyncRun,type WebhookDelivery,type WebhookEventType,type WebhookList} from './api';

// C31.02 — интеграции в Web: синхронизация оргструктуры из Active Directory (только чтение) и CSV ручных полей активов.
const time=(v:string)=>new Date(v).toLocaleString('ru-RU',{day:'2-digit',month:'short',hour:'2-digit',minute:'2-digit'});
const expired=(e:unknown,onExpired:()=>void)=>{if(e instanceof ApiError&&e.status===401)onExpired()};
const runSummary=(r:SyncRun)=>{const c=r.counters;return r.status==='failed'?'Ошибка: '+(r.error??'неизвестно'):[`людей ${c.people_seen??0}`,`команд ${c.teams_seen??0}`,`новых ${c.created??0}`,`изменено ${c.updated??0}`,`выбыло ${c.deactivated??0}`,`передано ролей ${c.assignments_reassigned??0}`].join(', ')};


const presets:Record<string,Partial<DirectoryWebSettings>>={
 ad:{user_filter:'(&(objectCategory=person)(objectClass=user))',guid_attribute:'objectGUID',login_attribute:'sAMAccountName',changed_attribute:'whenChanged'},
 openldap:{user_filter:'(objectClass=inetOrgPerson)',guid_attribute:'entryUUID',login_attribute:'uid',changed_attribute:'modifyTimestamp'}};

// C31.05 — настройка синхронизации в Web: пароль только записывается (в хранилище секретов центра), обратно не показывается.
export function DirectorySettingsForm({csrf,onExpired,onSaved,onClose}:{csrf:string;onExpired:()=>void;onSaved:()=>void;onClose:()=>void}){
 const [view,setView]=useState<DirectorySettingsView|null>(null),[s,setS]=useState<DirectoryWebSettings>({url:'',base_dn:'',bind_dn:'',...presets.ad,interval_minutes:15}),[password,setPassword]=useState('');
 const [busy,setBusy]=useState(false),[error,setError]=useState<unknown>(null),[test,setTest]=useState<DirectoryTestResult|null>(null);
 useEffect(()=>{api.directorySettings().then(v=>{setView(v);if(v.settings)setS(v.settings)}).catch(e=>{setError(e);expired(e,onExpired)})},[]);
 if(!view)return error?<div className="error" role="alert">{errorMessage(error)}</div>:null;
 if(view.source==='config')return <div className="notice">Синхронизация задана в конфигурации центра (блок <code>ldap_sync</code>) — здесь только просмотр. <button className="text-link" onClick={onClose}>Закрыть</button></div>;
 if(!view.secrets_available)return <div className="notice">Центр не может хранить пароль служебной учётки: не включено хранилище секретов интеграций (OpenBao, раздел <code>integrations_path</code>) — см. руководство администратора, раздел «Установка». <button className="text-link" onClick={onClose}>Закрыть</button></div>;
 const body=()=>({revision:view.revision??'',settings:{...s,interval_minutes:Number(s.interval_minutes)||undefined},...(password?{password}:{})});
 const set=(k:keyof DirectoryWebSettings)=>(e:{target:{value:string}})=>setS({...s,[k]:e.target.value});
 async function act(fn:()=>Promise<void>){setBusy(true);setError(null);try{await fn()}catch(e){setError(e);expired(e,onExpired)}finally{setBusy(false)}}
 return <form className="directory-form" onSubmit={e=>{e.preventDefault();void act(async()=>{await api.saveDirectorySettings(csrf,body());setPassword('');onSaved();onClose()})}}>
  <h3>Подключение к Active Directory</h3>
  <label>Адрес контроллера<input aria-label="Адрес контроллера" placeholder="ldaps://dc01.corp.example:636" value={s.url} onChange={set('url')}/></label>
  <label>Где искать (base DN)<input aria-label="Base DN" placeholder="DC=corp,DC=example" value={s.base_dn} onChange={set('base_dn')}/></label>
  <label>Учётка только для чтения (DN)<input aria-label="Bind DN" placeholder="CN=svc-surveyscan-read,OU=Service,DC=corp,DC=example" value={s.bind_dn} onChange={set('bind_dn')}/></label>
  <label>Пароль учётки<input aria-label="Пароль учётки" type="password" autoComplete="new-password" placeholder={view.password_set?'сохранён — оставьте пустым, чтобы не менять':'обязательно при первой настройке'} value={password} onChange={e=>setPassword(e.target.value)}/></label>
  <label>Тип каталога<select aria-label="Тип каталога" value={s.guid_attribute==='entryUUID'?'openldap':'ad'} onChange={e=>setS({...s,...presets[e.target.value]})}><option value="ad">Active Directory</option><option value="openldap">OpenLDAP / совместимый</option></select></label>
  <label>Фильтр людей<input aria-label="Фильтр людей" value={s.user_filter??''} onChange={set('user_filter')}/></label>
  <label>Группы как команды (фильтр, необязательно)<input aria-label="Фильтр групп" placeholder="(&(objectClass=group)(cn=IT-*))" value={s.group_filter??''} onChange={set('group_filter')}/></label>
  <label>Имя контроллера в сертификате (если адрес — IP)<input aria-label="Имя в сертификате" placeholder="dc01.corp.example" value={s.tls_server_name??''} onChange={set('tls_server_name')}/></label>
  <label>Сертификат CA контроллера (PEM, если не доверен системой)<textarea aria-label="Сертификат CA" rows={3} placeholder="-----BEGIN CERTIFICATE-----" value={s.ca_certificate_pem??''} onChange={set('ca_certificate_pem')}/></label>
  <label>Интервал, минут<input aria-label="Интервал" type="number" min={1} max={1440} value={s.interval_minutes??15} onChange={e=>setS({...s,interval_minutes:Number(e.target.value)})}/></label>
  {test?<div className={test.ok?'notice':'error'} role="status">{test.ok?`Подключение работает: найдено людей ${test.people_found}, команд ${test.teams_found}. Ничего не изменено.`:'Не удалось: '+test.error}</div>:null}
  {error?<div className="error" role="alert">{errorMessage(error)}</div>:null}
  <div className="org-form"><button type="button" className="button small secondary" disabled={busy||!s.url||!s.base_dn||!s.bind_dn} onClick={()=>void act(async()=>setTest(await api.testDirectory(csrf,body())))}>Проверить подключение</button>
   <button className="button small" disabled={busy||!s.url||!s.base_dn||!s.bind_dn||(!view.password_set&&!password)}>Сохранить</button>
   {view.revision?<button type="button" className="button small secondary" disabled={busy} onClick={()=>{if(window.confirm('Подтвердите: отключить синхронизацию с AD. Люди из каталога останутся, но обновляться не будут.'))void act(async()=>{await api.deleteDirectorySettings(csrf,view.revision!);onSaved();onClose()})}}>Отключить</button>:null}
   <button type="button" className="text-link" onClick={onClose}>Отмена</button></div>
 </form>;
}

export function DirectorySyncPanel({csrf,onExpired,onSynced}:{csrf:string;onExpired:()=>void;onSynced:()=>void}){
 const [status,setStatus]=useState<DirectorySyncStatus|null>(null),[busy,setBusy]=useState(false),[error,setError]=useState<unknown>(null),[editing,setEditing]=useState(false);
 const load=()=>{api.directorySync().then(setStatus).catch(e=>{setError(e);expired(e,onExpired)})};
 useEffect(load,[]);
 async function run(mode:'full'|'auto'){setBusy(true);setError(null);try{await api.runDirectorySync(csrf,mode);onSynced()}catch(e){setError(e);expired(e,onExpired)}finally{setBusy(false);load()}}
 if(!status)return error?<div className="error" role="alert">{errorMessage(error)}</div>:null;
 const last=status.runs[0];
 if(editing)return <DirectorySettingsForm csrf={csrf} onExpired={onExpired} onSaved={()=>{load();onSynced()}} onClose={()=>setEditing(false)}/>;
 return <div className="notice sync-panel" role="status">
  {status.configured?<><strong>Синхронизация с Active Directory</strong> — {status.source}, каждые {status.interval_minutes} мин, полная — раз в {status.full_sync_hours} ч{status.teams_enabled?', с командами из групп':''}. Людей и команды с отметкой «AD» ведёт каталог: здесь их не переименовывают и не отключают.
   <div>{last?<>Последний прогон {time(last.started_at)} ({last.mode==='full'?'полный':'изменения'}): <span className={last.status==='failed'?'error-text':''}>{runSummary(last)}</span>{last.counters.problems?.length?<details><summary>Замечания: {last.counters.problems.length}</summary><ul>{last.counters.problems.map((p,i)=><li key={i}>{p}</li>)}</ul></details>:null}</>:'Прогонов ещё не было.'}</div>
   <div className="org-form"><button className="button small" disabled={busy} onClick={()=>void run('auto')}>{busy?'Синхронизация…':'Синхронизировать сейчас'}</button><button className="button small secondary" disabled={busy} onClick={()=>void run('full')}>Полная синхронизация</button><button className="text-link" onClick={()=>setEditing(true)}>Настройки</button></div></>
  :<>Синхронизация с Active Directory не настроена: люди и команды ведутся здесь вручную. <button className="button small" onClick={()=>setEditing(true)}>Настроить подключение к AD</button></>}
  {error?<div className="error" role="alert">{errorMessage(error)}</div>:null}
 </div>;
}

const statusNames:Record<string,string>={applied:'будет применено',unchanged:'без изменений',stale_revision:'карточку уже изменили',not_found:'актив не найден',invalid:'ошибка в поле'};

export function CSVPanel({csrf,canWrite,onExpired,onImported}:{csrf:string;canWrite:boolean;onExpired:()=>void;onImported:()=>void}){
 const [text,setText]=useState(''),[name,setName]=useState(''),[result,setResult]=useState<CSVImportResult|null>(null),[busy,setBusy]=useState(false),[error,setError]=useState<unknown>(null),[done,setDone]=useState('');
 async function send(dry:boolean){setBusy(true);setError(null);setDone('');try{const r=await api.importCSV(csrf,text,dry);if(dry)setResult(r);else{setResult(null);setText('');setName('');setDone(`Применено строк: ${r.counts.applied}. Остальные — без изменений или с замечаниями (${r.counts.stale_revision+r.counts.not_found+r.counts.invalid}).`);onImported()}}catch(e){setError(e);expired(e,onExpired)}finally{setBusy(false)}}
 const issues=result?.results.filter(r=>r.status!=='applied'&&r.status!=='unchanged')??[];
 return <section className="table-panel csv-panel"><div className="table-toolbar"><h2>Обмен с Excel / 1С</h2><a className="button small secondary" href="/api/v1/assets/export.csv" download>⇩ Выгрузить CSV</a></div>
  <p className="muted">В файле можно менять имя, назначение, критичность, теги и класс. Пустая ячейка — не менять; «-» в классе — снять. Строка применяется, только если карточку не меняли после выгрузки.</p>
  {canWrite?<div className="org-form"><label className="button small secondary">Выбрать файл…<input type="file" accept=".csv,text/csv" hidden onChange={e=>{const f=e.target.files?.[0];setResult(null);setDone('');if(f){setName(f.name);void f.text().then(setText)}}}/></label>{name?<span className="mono">{name}</span>:null}<button className="button small" disabled={busy||!text} onClick={()=>void send(true)}>Проверить</button>{result&&result.counts.applied>0?<button className="button small" disabled={busy} onClick={()=>{if(window.confirm(`Подтвердите: применить ${result.counts.applied} строк. Изменения попадут в историю и аудит.`))void send(false)}}>Применить</button>:null}</div>:null}
  {result?<div role="status">Проверка: применится {result.counts.applied}, без изменений {result.counts.unchanged}, устарело {result.counts.stale_revision}, не найдено {result.counts.not_found}, ошибок {result.counts.invalid}.
   {issues.length?<div className="table-scroll"><table><thead><tr><th>Строка</th><th>Актив</th><th>Итог</th></tr></thead><tbody>{issues.slice(0,100).map(r=><tr key={r.line}><td>{r.line}</td><td className="mono">{r.asset_uid}</td><td>{statusNames[r.status]}{r.field?' «'+r.field+'»':''}</td></tr>)}</tbody></table></div>:null}</div>:null}
  {done?<div className="notice" role="status">{done}</div>:null}
  {error?<div className="error" role="alert">{error instanceof ApiError&&error.code==='INVALID_INPUT'?'Файл не похож на выгрузку SurveyScan (первая строка «#surveyscan-assets-csv;v1»).':errorMessage(error)}</div>:null}
 </section>;
}

// C31.03 — исходящие уведомления (webhook): подписки, секрет подписи (показывается один раз), доставки и ручной повтор.
const eventNames:Record<string,string>={'asset.created.v1':'Новый актив','asset.facts_changed.v1':'Изменение актива','responsibility.assigned.v1':'Смена ответственного','observation.recorded.v1':'Получены данные сбора','source.contact_updated.v1':'Контакт источника','source.profile_updated.v1':'Профиль источника'};
const deliveryNames:Record<string,string>={pending:'в очереди',delivered:'доставлено',dead:'не доставлено'};

export function WebhooksView({csrf,onExpired}:{csrf:string;onExpired:()=>void}){
 const [list,setList]=useState<WebhookList|null>(null),[url,setUrl]=useState(''),[types,setTypes]=useState<WebhookEventType[]>(['asset.facts_changed.v1','responsibility.assigned.v1']);
 const [secret,setSecret]=useState(''),[open,setOpen]=useState(''),[deliveries,setDeliveries]=useState<WebhookDelivery[]>([]),[busy,setBusy]=useState(false),[error,setError]=useState<unknown>(null);
 const load=()=>{api.webhooks().then(setList).catch(e=>{setError(e);expired(e,onExpired)})};
 const loadDeliveries=(id:string)=>{api.webhookDeliveries(id,'').then(p=>setDeliveries(p.items)).catch(e=>{setError(e);expired(e,onExpired)})};
 useEffect(load,[]);
 async function act(fn:()=>Promise<unknown>){setBusy(true);setError(null);try{await fn();load();if(open)loadDeliveries(open)}catch(e){setError(e);expired(e,onExpired)}finally{setBusy(false)}}
 if(!list)return error?<div className="error" role="alert">{errorMessage(error)}</div>:null;
 return <div className="table-panel"><div className="table-toolbar"><h2>Подписки <span>{list.items.length}</span></h2></div>
  {!list.enabled?(list.can_enable?<div className="notice" role="status">Уведомления выключены. Центр создаст ключ подписи сам и будет хранить его в защищённом хранилище — показывать и копировать его не нужно. <button className="button small" disabled={busy} onClick={()=>void act(async()=>setList(await api.enableWebhooks(csrf)))}>Включить уведомления</button></div>
   :<div className="notice" role="status">Уведомления недоступны: не включено хранилище секретов интеграций центра (OpenBao, раздел <code>integrations_path</code>) — см. руководство администратора, раздел «Установка».</div>):null}
  {error?<div className="error" role="alert">{errorMessage(error)}</div>:null}
  {secret?<div className="notice" role="status"><strong>Секрет подписи — сохраните его сейчас, больше он не показывается:</strong><div className="mono secret">{secret}</div>Получатель проверяет заголовок <code>X-SurveyScan-Signature: v1=HMAC-SHA256(секрет, timestamp + "." + тело)</code> и отбрасывает повторы по <code>X-SurveyScan-Event-Id</code>.<div><button className="button small" onClick={()=>setSecret('')}>Сохранил</button></div></div>:null}
  {list.enabled?<form className="org-form" onSubmit={e=>{e.preventDefault();void act(async()=>{const r=await api.createWebhook(csrf,{url:url.trim(),event_types:types});setSecret(r.signing_secret);setUrl('')})}}>
   <input aria-label="Адрес получателя" placeholder="https://itsm.example/hook" value={url} onChange={e=>setUrl(e.target.value)}/>
   {list.event_types.map(t=><label key={t} className="inline-check"><input type="checkbox" checked={types.includes(t)} onChange={e=>setTypes(e.target.checked?[...types,t]:types.filter(x=>x!==t))}/> {eventNames[t]??t}</label>)}
   <button className="button small" disabled={busy||!url.trim()||!types.length}>Подписать</button></form>:null}
  <div className="table-scroll"><table><thead><tr><th>Получатель</th><th>События</th><th>Доставлено / в очереди / не доставлено</th><th>Состояние</th><th/></tr></thead><tbody>{list.items.map(s=><tr key={s.subscription_id}><td className="mono">{s.url}</td><td>{s.event_types.map(t=>eventNames[t]??t).join(', ')}</td><td>{s.delivered} / {s.pending} / <span className={s.dead?'error-text':''}>{s.dead}</span></td><td>{s.active?'Включена':'Выключена'}</td>
   <td><button className="text-link" onClick={()=>{const next=open===s.subscription_id?'':s.subscription_id;setOpen(next);setDeliveries([]);if(next)loadDeliveries(next)}}>Доставки</button> <button className="text-link" disabled={busy} onClick={()=>void act(()=>api.patchWebhook(s.subscription_id,csrf,{revision:s.revision,active:!s.active}))}>{s.active?'Выключить':'Включить'}</button></td></tr>)}</tbody></table></div>
  {open?<div className="table-scroll"><table><thead><tr><th>Событие</th><th>Когда</th><th>Итог</th><th>Попыток</th><th>Ответ</th><th/></tr></thead><tbody>{deliveries.map(d=><tr key={d.event_id}><td>{eventNames[d.event_type]??d.event_type}<small className="mono">{d.event_id}</small></td><td>{time(d.occurred_at)}</td><td className={d.state==='dead'?'error-text':''}>{deliveryNames[d.state]}{d.state==='pending'&&d.next_attempt_at?', следующая попытка '+time(d.next_attempt_at):''}</td><td>{d.attempts}</td><td>{d.last_error??(d.last_status?String(d.last_status):'—')}</td><td>{d.state==='dead'?<button className="text-link" disabled={busy} onClick={()=>{if(window.confirm('Подтвердите: отправить событие повторно. Действие попадёт в аудит.'))void act(()=>api.retryWebhook(open,d.event_id,csrf))}}>Повторить</button>:null}</td></tr>)}</tbody></table>{deliveries.length?null:<div className="empty" role="status">Доставок пока нет</div>}</div>:null}
 </div>;
}
