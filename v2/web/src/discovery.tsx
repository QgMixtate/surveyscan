import {useEffect,useState} from 'react';
import {api,ApiError,errorMessage,type CollectCredential,type CollectKind,type CollectSecret,type RemoteTarget,type DiscoveryHost,type DiscoveryNetworkPage,type DiscoveryProbe,type DiscoveryRun,type Source} from './api';

// C51 — «Обследования сети» (ADR D13): администратор заводит подсети, оператор запускает, все видят результаты.
const time=(v:string|null)=>v?new Date(v).toLocaleString('ru-RU',{day:'2-digit',month:'short',hour:'2-digit',minute:'2-digit'}):'—';
const expired=(e:unknown,onExpired:()=>void)=>{if(e instanceof ApiError&&e.status===401)onExpired()};
const stateName:{[k in DiscoveryRun['state']]:string}={queued:'в очереди',running:'идёт',done:'завершено',failed:'ошибка'};
const probeName:{[k in DiscoveryProbe]:string}={tcp:'TCP-порты',arp:'ARP',icmp:'ICMP (пинг)'};
const errName=(e:string)=>e==='icmp:not_permitted'?'у сборщика нет права на ICMP (CAP_NET_RAW)':e==='collector:timeout'?'сборщик не сдал результат за 2 ч':e==='job:invalid'?'задание вне правил D-13':e;

export function DiscoveryView({csrf,isAdmin,canRun,onExpired}:{csrf:string;isAdmin:boolean;canRun:boolean;onExpired:()=>void}){
 const [page,setPage]=useState<DiscoveryNetworkPage|null>(null),[open,setOpen]=useState(''),[hosts,setHosts]=useState<DiscoveryHost[]>([]),[runs,setRuns]=useState<DiscoveryRun[]>([]);
 const [error,setError]=useState<unknown>(null),[busy,setBusy]=useState(false),[collect,setCollect]=useState(''),[targetsVersion,setTargetsVersion]=useState(0);
 const load=()=>{api.discoveryNetworks().then(setPage).catch(e=>{setError(e);expired(e,onExpired)})};
 const loadOne=(id:string)=>{Promise.all([api.discoveryHosts(id),api.discoveryRuns(id)]).then(([h,r])=>{setHosts(h.items);setRuns(r.items)}).catch(e=>{setError(e);expired(e,onExpired)})};
 useEffect(load,[]);
 useEffect(()=>{ // пока обследование идёт — обновлять раз в 5 с
  const active=page?.items.some(n=>n.last_run&&(n.last_run.state==='queued'||n.last_run.state==='running'));
  if(!active)return;const t=setInterval(()=>{load();if(open)loadOne(open)},5000);return ()=>clearInterval(t)},[page,open]);
 async function act(fn:()=>Promise<unknown>){setBusy(true);setError(null);try{await fn();load();if(open)loadOne(open)}catch(e){setError(e);expired(e,onExpired)}finally{setBusy(false)}}
 if(!page)return error?<div className="error" role="alert">{errorMessage(error)}</div>:<p className="muted">Загрузка…</p>;
 const l=page.limits;const net=page.items.find(n=>n.network_id===open);
 return <div className="stack">
  {error?<div className="error" role="alert">{errorMessage(error)}</div>:null}
  <p className="muted">Правила: подсеть IPv4 не шире /{l.max_prefix} ({2**(32-l.max_prefix)} адресов), не более {l.rate_per_second} проб в секунду, расписание не чаще раза в {l.min_schedule_minutes} мин. TCP-порты: {l.tcp_ports.join(', ')}. Вне заведённых подсетей ничего не сканируется.</p>
  {isAdmin?<CredentialsPanel csrf={csrf} onExpired={onExpired}/>:null}
  <TargetsPanel csrf={csrf} isAdmin={isAdmin} version={targetsVersion} onExpired={onExpired}/>
  {isAdmin?<NewNetwork busy={busy} onCreate={b=>act(()=>api.createDiscoveryNetwork(csrf,b))} onExpired={onExpired}/>:null}
  {page.items.length===0?<p className="muted">Подсетей пока нет.{isAdmin?'':' Их заводит администратор.'}</p>:
  <div className="table-scroll"><table><thead><tr><th>Подсеть</th><th>Пробы</th><th>Расписание</th><th>Последнее обследование</th><th>Узлы</th><th/></tr></thead><tbody>{page.items.map(n=><tr key={n.network_id} className={n.active?'':'muted'}>
   <td><button className="text-link" onClick={()=>{setOpen(open===n.network_id?'':n.network_id);if(open!==n.network_id)loadOne(n.network_id)}}>{n.name}</button><div className="mono">{n.cidr}</div></td>
   <td>{n.probes.map(p=>probeName[p]).join(', ')}</td>
   <td>{n.schedule_minutes?'раз в '+(n.schedule_minutes%60===0?n.schedule_minutes/60+' ч':n.schedule_minutes+' мин'):'вручную'}</td>
   <td>{n.last_run?<>{stateName[n.last_run.state]} · {time(n.last_run.finished_at??n.last_run.requested_at)}{n.last_run.found!==null?<div className="muted">найдено {n.last_run.found}, новых {n.last_run.new_hosts}, пропало {n.last_run.missing}</div>:null}{n.last_run.errors.length?<div className="error-text">{n.last_run.errors.map(errName).join('; ')}</div>:null}</>:'—'}</td>
   <td>{n.present_hosts}{n.missing_hosts?<span className="muted"> · пропало {n.missing_hosts}</span>:null}</td>
   <td>{canRun&&n.active?<button className="button secondary" disabled={busy||n.last_run?.state==='queued'||n.last_run?.state==='running'} onClick={()=>void act(()=>api.startDiscovery(n.network_id,csrf))}>Обследовать</button>:null}
    {isAdmin?<button className="text-link" disabled={busy} onClick={()=>void act(()=>api.patchDiscoveryNetwork(n.network_id,csrf,{revision:n.revision,active:!n.active}))}>{n.active?'Отключить':'Включить'}</button>:null}</td>
  </tr>)}</tbody></table></div>}
  {open?<section className="panel"><h3>Узлы подсети</h3>
   {hosts.length===0?<p className="muted">Узлов пока нет — запустите обследование.</p>:<div className="table-scroll"><table><thead><tr><th>Адрес</th><th>MAC</th><th>Открытые порты</th><th>Пинг</th><th>Впервые</th><th>Последний раз</th><th>Состояние</th>{isAdmin?<th/>:null}</tr></thead><tbody>
    {hosts.map(h=><tr key={h.ip}><td className="mono">{h.ip}</td><td className="mono">{h.mac??'—'}</td><td>{h.ports.length?h.ports.join(', '):'—'}</td><td>{h.icmp?'да':'—'}</td><td>{time(h.first_seen)}</td><td>{time(h.last_seen)}</td><td>{h.state==='present'?'на месте':<b>пропал</b>}</td>{isAdmin?<td><button className="text-link" onClick={()=>setCollect(collect===h.ip?'':h.ip)}>Собирать</button></td>:null}</tr>)}
   </tbody></table></div>}
   {isAdmin&&collect&&net?<CollectForm address={collect} ports={hosts.find(h=>h.ip===collect)?.ports??[]} network={net} busy={busy} onExpired={onExpired} onCreate={b=>act(async()=>{await api.createRemoteTarget(csrf,b);setCollect('');setTargetsVersion(v=>v+1)})}/>:null}
   <h3>История обследований</h3>
   <ul className="plain">{runs.map(r=><li key={r.run_id}>{time(r.requested_at)} · {r.trigger==='manual'?'вручную':'по расписанию'} · {stateName[r.state]}{r.found!==null?' · найдено '+r.found+' из '+r.addresses+' адресов':''}{r.errors.length?' · '+r.errors.map(errName).join('; '):''}</li>)}</ul>
  </section>:null}
 </div>;
}

function NewNetwork({busy,onCreate,onExpired}:{busy:boolean;onCreate:(b:{site_id:string;collector_id:string;name:string;cidr:string;probes:DiscoveryProbe[];schedule_minutes:number|null})=>void;onExpired:()=>void}){
 const [collectors,setCollectors]=useState<Source[]>([]),[collector,setCollector]=useState(''),[name,setName]=useState(''),[cidr,setCidr]=useState('');
 const [probes,setProbes]=useState<DiscoveryProbe[]>(['tcp','arp','icmp']),[schedule,setSchedule]=useState('');

 useEffect(()=>{api.sources().then(p=>{const c=p.items.filter(s=>s.source_kind==='collector'&&s.state==='active');setCollectors(c);if(c[0])setCollector(c[0].source_id)}).catch(e=>expired(e,onExpired))},[]);
 const chosen=collectors.find(c=>c.source_id===collector);
 const toggle=(p:DiscoveryProbe)=>setProbes(probes.includes(p)?probes.filter(x=>x!==p):[...probes,p]);
 return <form className="panel form-grid" onSubmit={e=>{e.preventDefault();if(chosen)onCreate({site_id:chosen.site_id,collector_id:chosen.source_id,name:name.trim(),cidr:cidr.trim(),probes,schedule_minutes:schedule?Number(schedule):null})}}>
  <h3>Новая подсеть</h3>
  <label>Название<input value={name} onChange={e=>setName(e.target.value)} placeholder="Офис, 2 этаж" required maxLength={128}/></label>
  <label>Подсеть (CIDR)<input value={cidr} onChange={e=>setCidr(e.target.value)} placeholder="10.170.108.0/24" required className="mono"/></label>
  <label>Сборщик (collector)<select value={collector} onChange={e=>setCollector(e.target.value)} required>{collectors.length===0?<option value="">нет активных сборщиков</option>:null}{collectors.map(c=><option key={c.source_id} value={c.source_id}>{c.source_id.slice(0,8)} · площадка {c.site_id.slice(0,8)}</option>)}</select></label>
  <fieldset><legend>Пробы</legend>{(['tcp','arp','icmp'] as DiscoveryProbe[]).map(p=><label key={p} className="inline"><input type="checkbox" checked={probes.includes(p)} onChange={()=>toggle(p)}/> {probeName[p]}</label>)}</fieldset>
  <label>Расписание<select value={schedule} onChange={e=>setSchedule(e.target.value)}><option value="">только вручную</option><option value="60">раз в час</option><option value="360">раз в 6 часов</option><option value="1440">раз в сутки</option><option value="10080">раз в неделю</option></select></label>
  <button className="button" disabled={busy||!chosen||probes.length===0}>Добавить подсеть</button>
 </form>;
}

const kindName:{[k in CollectKind]:string}={ssh:'SSH (Linux)',winrm:'WinRM (Windows)',snmp:'SNMPv3 (сетевые устройства)'};

// Учётки сбора: вводит администратор; секрет уходит в хранилище секретов центра и обратно не показывается.
function CredentialsPanel({csrf,onExpired}:{csrf:string;onExpired:()=>void}){
 const [items,setItems]=useState<CollectCredential[]>([]),[available,setAvailable]=useState(true),[error,setError]=useState<unknown>(null),[busy,setBusy]=useState(false);
 const [name,setName]=useState(''),[kind,setKind]=useState<CollectKind>('ssh'),[username,setUsername]=useState(''),[password,setPassword]=useState(''),[key,setKey]=useState('');
 const [authProto,setAuthProto]=useState('SHA256'),[authKey,setAuthKey]=useState(''),[privProto,setPrivProto]=useState('AES'),[privKey,setPrivKey]=useState('');
 const load=()=>{api.collectCredentials().then(p=>{setItems(p.items);setAvailable(p.secrets_available)}).catch(e=>{setError(e);expired(e,onExpired)})};
 useEffect(load,[]);
 const secret=():CollectSecret=>kind==='snmp'?{auth_protocol:authProto,auth_key:authKey,priv_protocol:privProto,priv_key:privKey}:kind==='ssh'&&key?{private_key:key}:{password};
 async function save(e:React.FormEvent){e.preventDefault();setBusy(true);setError(null);try{await api.createCollectCredential(csrf,{name:name.trim(),kind,username:username.trim(),secret:secret()});setName('');setUsername('');setPassword('');setKey('');setAuthKey('');setPrivKey('');load()}catch(err){setError(err);expired(err,onExpired)}finally{setBusy(false)}}
 return <section className="panel"><h3>Учётки сбора</h3>
  <p className="muted">Пароли и ключи хранятся в хранилище секретов центра и больше нигде не показываются. Сборщик получает учётку у центра по защищённому каналу перед каждым сбором.</p>
  {!available?<div className="error" role="alert">Хранилище секретов центра не настроено — учётки сохранить нельзя.</div>:null}
  {error?<div className="error" role="alert">{errorMessage(error)}</div>:null}
  {items.length?<div className="table-scroll"><table><thead><tr><th>Название</th><th>Тип</th><th>Логин</th><th>Целей</th><th>Секрет сменён</th></tr></thead><tbody>{items.map(c=><tr key={c.credential_id} className={c.active?'':'muted'}><td>{c.name}</td><td>{kindName[c.kind]}</td><td className="mono">{c.username}</td><td>{c.targets}</td><td>{time(c.secret_changed_at)}</td></tr>)}</tbody></table></div>:null}
  <form className="form-grid" onSubmit={e=>void save(e)} autoComplete="off">
   <label>Название<input value={name} onChange={e=>setName(e.target.value)} placeholder="Linux только чтение" required maxLength={128}/></label>
   <label>Тип<select value={kind} onChange={e=>setKind(e.target.value as CollectKind)}>{(['ssh','winrm','snmp'] as CollectKind[]).map(k=><option key={k} value={k}>{kindName[k]}</option>)}</select></label>
   <label>Логин<input value={username} onChange={e=>setUsername(e.target.value)} placeholder={kind==='winrm'?'AWM\\scanwinrm':'scanprobe'} required/></label>
   {kind==='snmp'?<>
    <label>Аутентификация<select value={authProto} onChange={e=>setAuthProto(e.target.value)}><option>SHA</option><option>SHA256</option><option>SHA512</option></select></label>
    <label>Ключ аутентификации<input type="password" value={authKey} onChange={e=>setAuthKey(e.target.value)} required minLength={8} autoComplete="new-password"/></label>
    <label>Шифрование<select value={privProto} onChange={e=>setPrivProto(e.target.value)}><option>AES</option><option>AES256</option></select></label>
    <label>Ключ шифрования<input type="password" value={privKey} onChange={e=>setPrivKey(e.target.value)} required minLength={8} autoComplete="new-password"/></label>
   </>:<>
    <label>Пароль<input type="password" value={password} onChange={e=>setPassword(e.target.value)} required={!key} disabled={!!key} autoComplete="new-password"/></label>
    {kind==='ssh'?<label>или закрытый ключ (вместо пароля)<textarea value={key} onChange={e=>setKey(e.target.value)} rows={2} disabled={!!password} placeholder="-----BEGIN OPENSSH PRIVATE KEY-----"/></label>:null}
   </>}
   <button className="button" disabled={busy||!available}>Сохранить учётку</button>
  </form>
 </section>;
}

// Цели сбора: созданные кнопкой «Собирать» узлы; сборщик регистрирует для каждой отдельный источник сам.
function TargetsPanel({csrf,isAdmin,version,onExpired}:{csrf:string;isAdmin:boolean;version:number;onExpired:()=>void}){
 const [items,setItems]=useState<RemoteTarget[]>([]),[error,setError]=useState<unknown>(null);
 const load=()=>{api.remoteTargets().then(p=>setItems(p.items)).catch(e=>{setError(e);expired(e,onExpired)})};
 useEffect(load,[version]);
 if(!items.length&&!error)return null;
 const stateText=(t:RemoteTarget)=>t.state==='disabled'?'отключена':t.state==='pending'?'регистрируется сборщиком…':t.last_error?'ошибка: '+t.last_error:t.last_collected_at?'собрано '+time(t.last_collected_at):'ожидает первого сбора';
 return <section className="panel"><h3>Цели сбора</h3>{error?<div className="error" role="alert">{errorMessage(error)}</div>:null}
  <div className="table-scroll"><table><thead><tr><th>Адрес</th><th>Способ</th><th>Состояние</th>{isAdmin?<th/>:null}</tr></thead><tbody>{items.map(t=><tr key={t.target_id} className={t.state==='disabled'?'muted':''}>
   <td className="mono">{t.address}:{t.port}</td><td>{kindName[t.kind]}</td><td className={t.last_error?'error-text':''}>{stateText(t)}</td>
   {isAdmin?<td><button className="text-link" onClick={()=>void api.patchRemoteTarget(t.target_id,csrf,{revision:t.revision,disabled:t.state!=='disabled'}).then(load).catch(e=>{setError(e);expired(e,onExpired)})}>{t.state==='disabled'?'Включить':'Отключить'}</button></td>:null}
  </tr>)}</tbody></table></div></section>;
}

// «Собирать» у найденного узла: способ, учётка, для SSH — отпечаток ключа хоста (сверить с узлом), для WinRM — сертификат.
function CollectForm({address,ports,network,busy,onCreate,onExpired}:{address:string;ports:number[];network:{network_id:string;collector_id:string};busy:boolean;onExpired:()=>void;onCreate:(b:Parameters<typeof api.createRemoteTarget>[1])=>void}){
 const [creds,setCreds]=useState<CollectCredential[]>([]),[kind,setKind]=useState<CollectKind>(ports.includes(5986)&&!ports.includes(22)?'winrm':'ssh'),[cred,setCred]=useState('');
 const [hostKey,setHostKey]=useState(''),[ca,setCa]=useState(''),[serverName,setServerName]=useState(''),[interval,setInterval_]=useState('3600');
 useEffect(()=>{api.collectCredentials().then(p=>setCreds(p.items.filter(c=>c.active))).catch(e=>expired(e,onExpired))},[]);
 const usable=creds.filter(c=>c.kind===kind);
 useEffect(()=>{setCred(usable[0]?.credential_id??'')},[kind,creds.length]);
 return <form className="panel form-grid" onSubmit={e=>{e.preventDefault();onCreate({collector_id:network.collector_id,network_id:network.network_id,address,kind,credential_id:cred,interval_seconds:Number(interval),...(kind==='ssh'?{host_key_sha256:hostKey.trim()}:kind==='winrm'?{tls_ca_pem:ca,tls_server_name:serverName.trim()}:{})})}}>
  <h3>Собирать {address}</h3>
  <label>Способ<select value={kind} onChange={e=>setKind(e.target.value as CollectKind)}><option value="ssh">SSH (Linux)</option><option value="winrm">WinRM (Windows)</option><option value="snmp">SNMPv3 (коммутатор, маршрутизатор)</option></select></label>
  <label>Учётка<select value={cred} onChange={e=>setCred(e.target.value)} required>{usable.length===0?<option value="">нет учёток этого типа — добавьте выше</option>:null}{usable.map(c=><option key={c.credential_id} value={c.credential_id}>{c.name} ({c.username})</option>)}</select></label>
  {kind==='snmp'?<p className="muted">SNMPv3 authPriv: подлинность и шифрование — ключами учётки. Передаются имя устройства, интерфейсы с адресами и таблица ARP.</p>:kind==='ssh'?<label>Отпечаток ключа хоста<input value={hostKey} onChange={e=>setHostKey(e.target.value)} placeholder="SHA256:…" required pattern="SHA256:[A-Za-z0-9+/]{43}" className="mono"/><small className="muted">На узле: ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub</small></label>:<>
   <label>Сертификат WinRM (.cer, PEM)<textarea value={ca} onChange={e=>setCa(e.target.value)} rows={3} required placeholder="-----BEGIN CERTIFICATE-----"/></label>
   <label>Имя в сертификате<input value={serverName} onChange={e=>setServerName(e.target.value)} placeholder="win-ar.awm.local" required/></label></>}
  <label>Как часто<select value={interval} onChange={e=>setInterval_(e.target.value)}><option value="3600">раз в час</option><option value="21600">раз в 6 часов</option><option value="86400">раз в сутки</option></select></label>
  <button className="button" disabled={busy||!cred}>Создать цель сбора</button>
 </form>;
}
