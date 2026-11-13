import {useEffect,useState} from 'react';
import {api,ApiError,errorMessage,type DiscoveryHost,type DiscoveryNetworkPage,type DiscoveryProbe,type DiscoveryRun,type Source} from './api';

// C51 — «Обследования сети» (ADR D13): администратор заводит подсети, оператор запускает, все видят результаты.
const time=(v:string|null)=>v?new Date(v).toLocaleString('ru-RU',{day:'2-digit',month:'short',hour:'2-digit',minute:'2-digit'}):'—';
const expired=(e:unknown,onExpired:()=>void)=>{if(e instanceof ApiError&&e.status===401)onExpired()};
const stateName:{[k in DiscoveryRun['state']]:string}={queued:'в очереди',running:'идёт',done:'завершено',failed:'ошибка'};
const probeName:{[k in DiscoveryProbe]:string}={tcp:'TCP-порты',arp:'ARP',icmp:'ICMP (пинг)'};
const errName=(e:string)=>e==='icmp:not_permitted'?'у сборщика нет права на ICMP (CAP_NET_RAW)':e==='collector:timeout'?'сборщик не сдал результат за 2 ч':e==='job:invalid'?'задание вне правил D-13':e;

export function DiscoveryView({csrf,isAdmin,canRun,onExpired}:{csrf:string;isAdmin:boolean;canRun:boolean;onExpired:()=>void}){
 const [page,setPage]=useState<DiscoveryNetworkPage|null>(null),[open,setOpen]=useState(''),[hosts,setHosts]=useState<DiscoveryHost[]>([]),[runs,setRuns]=useState<DiscoveryRun[]>([]);
 const [error,setError]=useState<unknown>(null),[busy,setBusy]=useState(false);
 const load=()=>{api.discoveryNetworks().then(setPage).catch(e=>{setError(e);expired(e,onExpired)})};
 const loadOne=(id:string)=>{Promise.all([api.discoveryHosts(id),api.discoveryRuns(id)]).then(([h,r])=>{setHosts(h.items);setRuns(r.items)}).catch(e=>{setError(e);expired(e,onExpired)})};
 useEffect(load,[]);
 useEffect(()=>{ // пока обследование идёт — обновлять раз в 5 с
  const active=page?.items.some(n=>n.last_run&&(n.last_run.state==='queued'||n.last_run.state==='running'));
  if(!active)return;const t=setInterval(()=>{load();if(open)loadOne(open)},5000);return ()=>clearInterval(t)},[page,open]);
 async function act(fn:()=>Promise<unknown>){setBusy(true);setError(null);try{await fn();load();if(open)loadOne(open)}catch(e){setError(e);expired(e,onExpired)}finally{setBusy(false)}}
 if(!page)return error?<div className="error" role="alert">{errorMessage(error)}</div>:<p className="muted">Загрузка…</p>;
 const l=page.limits;
 return <div className="stack">
  {error?<div className="error" role="alert">{errorMessage(error)}</div>:null}
  <p className="muted">Правила: подсеть IPv4 не шире /{l.max_prefix} ({2**(32-l.max_prefix)} адресов), не более {l.rate_per_second} проб в секунду, расписание не чаще раза в {l.min_schedule_minutes} мин. TCP-порты: {l.tcp_ports.join(', ')}. Вне заведённых подсетей ничего не сканируется.</p>
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
   {hosts.length===0?<p className="muted">Узлов пока нет — запустите обследование.</p>:<div className="table-scroll"><table><thead><tr><th>Адрес</th><th>MAC</th><th>Открытые порты</th><th>Пинг</th><th>Впервые</th><th>Последний раз</th><th>Состояние</th></tr></thead><tbody>
    {hosts.map(h=><tr key={h.ip}><td className="mono">{h.ip}</td><td className="mono">{h.mac??'—'}</td><td>{h.ports.length?h.ports.join(', '):'—'}</td><td>{h.icmp?'да':'—'}</td><td>{time(h.first_seen)}</td><td>{time(h.last_seen)}</td><td>{h.state==='present'?'на месте':<b>пропал</b>}</td></tr>)}
   </tbody></table></div>}
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
