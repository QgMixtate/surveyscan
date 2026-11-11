import React,{useEffect,useState} from 'react';
import {api,ApiError,errorMessage,type RecordPage12} from './api';

// Разделы профиля инвентаризации 1.2 (агенты run12, SSH/WinRM-цели, portable). Данные читаются постранично по запросу.
const sections12:[string,string][]=[['identity','Идентификация'],['os','Операционная система'],['network','Сеть'],['hardware','Оборудование'],['software','Программное обеспечение'],['updates','Обновления'],['services','Службы'],['users_groups','Пользователи и группы'],['routes_ports','Маршруты и порты'],['resources','Ресурсы и диски'],['protection','Средства защиты'],['neighbors','Соседи (LLDP/ARP)']];
const status12:Record<string,string>={partial:'Собрано частично',unavailable:'Сбор недоступен',unsupported:'Не поддерживается',not_requested:'Не запрошено'};
const kinds:Record<string,string>={agent:'Агент / SSH / WinRM',collector:'Collector',portable:'Portable-аудит'};
const acquisitions:Record<string,string>={agent:'Агент',ssh:'SSH',winrm:'WinRM'};
const time=(v:string)=>new Date(v).toLocaleString('ru-RU',{day:'2-digit',month:'short',hour:'2-digit',minute:'2-digit'});

const fieldNames:Record<string,string>={name:'имя',kind:'тип',hostname:'имя хоста',domain:'домен',machine_uuid:'UUID машины',display_name:'название',version:'версия',architecture:'архитектура',scope:'область',source:'откуда',publisher:'издатель',vendor:'производитель',model:'модель',ip:'IP',mac:'MAC',addresses:'адреса',gateways:'шлюзы',dns_servers:'DNS',dhcp_enabled:'DHCP',mtu:'MTU',state:'состояние',status:'статус',start_type:'запуск',family:'семейство',destination:'назначение',gateway:'шлюз',interface:'интерфейс',metric:'метрика',local_address:'локальный адрес',local_port:'локальный порт',remote_address:'удалённый адрес',remote_port:'удалённый порт',bytes:'объём',logical_processors:'логических ЦП',mount_point:'точка монтирования',filesystem:'ФС',size_bytes:'размер',free_bytes:'свободно',uid:'UID',gid:'GID',sid:'SID',installed_on:'установлено',id:'ID'};
const label=(f:string)=>fieldNames[f]??f.replaceAll('_',' ');
function show(value:unknown):string{
 if(value===null||value===undefined)return '—';
 if(Array.isArray(value)){
  if(value.every(v=>v&&typeof v==='object'&&'ip' in v))return value.map(v=>(v as {ip:string;prefix?:number}).ip+((v as {prefix?:number}).prefix!==undefined?'/'+(v as {prefix:number}).prefix:'')).join(', ')||'—';
  return value.map(v=>typeof v==='object'?JSON.stringify(v):String(v)).join(', ')||'—';
 }
 if(typeof value==='object')return JSON.stringify(value);
 if(typeof value==='number'&&value>1e9&&Number.isInteger(value))return (value/1073741824).toFixed(1)+' ГиБ ('+value+')';
 return String(value);
}

type Rows={keys:string[];records:Map<string,Map<string,unknown>>};
function group(pages:RecordPage12[]):Rows{
 const records=new Map<string,Map<string,unknown>>();const fields=new Map<string,number>();
 for(const page of pages)for(const item of page.items){let row=records.get(item.record_key);if(!row){row=new Map();records.set(item.record_key,row)}row.set(item.field,item.value);fields.set(item.field,(fields.get(item.field)??0)+1)}
 const preferred=['name','kind','hostname','display_name','version','ip','mac','addresses','state','status','local_address','local_port','remote_address','remote_port','destination','gateway','vendor','publisher','model'];
 const keys=[...fields.keys()].sort((a,b)=>{const ia=preferred.indexOf(a),ib=preferred.indexOf(b);return (ia<0?99:ia)-(ib<0?99:ib)||(fields.get(b)!-fields.get(a)!)||a.localeCompare(b)});
 return {keys,records};
}

function Section({asset,name,title,labels,onExpired}:{asset:string;name:string;title:string;labels:Record<string,string>;onExpired:()=>void}){
 const [pages,setPages]=useState<RecordPage12[]>([]),[loading,setLoading]=useState(false),[error,setError]=useState<unknown>(null),[filter,setFilter]=useState('');
 async function load(cursor:string|null){setLoading(true);setError(null);try{const page=await api.records12(asset,name,cursor);if(page.section!==name)throw new ApiError(0,'INVALID_RESPONSE');setPages(p=>cursor?[...p,page]:[page])}catch(e){setError(e);if(e instanceof ApiError&&e.status===401)onExpired()}finally{setLoading(false)}}
 const first=pages[0],state=first?.section_state,last=pages.at(-1);
 const {keys,records}=group(pages);const shown=keys.slice(0,4);
 const rows=[...records.entries()].filter(([,row])=>!filter||[...row.values()].some(v=>show(v).toLowerCase().includes(filter.toLowerCase())));
 return <details className="inv12" onToggle={e=>{if((e.target as HTMLDetailsElement).open&&!pages.length&&!loading)void load(null)}}>
  <summary><span>{title}</span>{state?<span className={'badge state-'+state.status}><i/>{status12[state.status]??state.status}</span>:first?<span className="badge"><i/>Нет данных</span>:null}</summary>
  {error?<div className="error" role="alert">{errorMessage(error)}</div>:null}
  {loading&&!pages.length?<p role="status">Загружаем…</p>:null}
  {state?<small className="inv12-meta">Сбор: {time(state.last_attempt.collected_at)} · {kinds[state.last_attempt.origin.source_kind]??state.last_attempt.origin.source_kind} · часы: {state.last_attempt.clock_quality==='trusted'?'доверенные':'не подтверждены'}<br/><span className="mono">Источник: {state.last_attempt.origin.source_id}</span>{state.sources&&state.sources.length>1?<><br/>По источникам: {state.sources.map(x=>(labels[x.source_id]??x.source_id.slice(0,8))+' — '+(status12[x.status]??x.status).toLowerCase()).join('; ')}</>:null}</small>:first?<small className="inv12-meta">Раздел этим активом ещё не собирался.</small>:null}
  {records.size>8?<input className="inv12-filter" aria-label={'Фильтр: '+title} placeholder="Фильтр по загруженным записям…" value={filter} onChange={e=>setFilter(e.target.value)}/>:null}
  {rows.length?<div className="inv12-records">{rows.map(([key,row])=><details key={key} className="inv12-record"><summary>{shown.map(f=>row.has(f)?<span key={f}><b>{label(f)}</b> {show(row.get(f))}</span>:null)}</summary><dl>{keys.filter(f=>row.has(f)).map(f=><React.Fragment key={f}><dt>{label(f)}</dt><dd>{show(row.get(f))}</dd></React.Fragment>)}</dl></details>)}</div>:null}
  {first?<small className="inv12-meta">Загружено записей: {records.size}{last?.next_cursor?' · есть ещё':''}</small>:null}
  {last?.next_cursor?<button className="button small" disabled={loading} onClick={()=>void load(last.next_cursor)}>{loading?'Загружаем…':'Показать ещё'}</button>:null}
 </details>;
}

export function Inventory12({asset,onExpired}:{asset:string;onExpired:()=>void}){
 // подписи источников для статусов «по источникам»: способ сбора и начало идентификатора
 const [labels,setLabels]=useState<Record<string,string>>({});
 useEffect(()=>{let live=true;api.sources().then(p=>{if(live)setLabels(Object.fromEntries(p.items.map(x=>[x.source_id,(x.source_kind==='agent'?acquisitions[x.acquisition??'agent']??'Агент':x.source_kind==='portable'?'Portable':'Collector')+' '+x.source_id.slice(0,8)])))}).catch(()=>{});return ()=>{live=false}},[]);
 return <><h3>Инвентаризация · профиль 1.2</h3><p className="card-note">Данные агентов run12, SSH/WinRM-целей и portable-аудита. Откройте раздел, чтобы загрузить записи.</p><div className="inv12-list">{sections12.map(([name,title])=><Section key={name} asset={asset} name={name} title={title} labels={labels} onExpired={onExpired}/>)}</div></>;
}
