import {useEffect,useState} from 'react';
import {api,ApiError,errorMessage,type AssetCMDB,type AssetClassName,type CIEnd,type CIService,type Component,type Evidence,type Installation,type Product,type Relation,type ServiceDetail} from './api';

// C26 — CMDB в Web: класс актива, ПО и компоненты с provenance, связи; сервисы и поиск ПО по реестру.
export const classNames:Record<AssetClassName,string>={server:'Сервер',workstation:'Рабочая станция',network_device:'Сетевое устройство',printer:'Принтер',virtual_machine:'Виртуальная машина',unknown:'Не определён'};
const reasons:Record<string,string>={HARDWARE_MODEL_VIRTUAL:'по модели оборудования (виртуализация)',OS_SERVER_EDITION:'по серверной редакции ОС',OS_CLIENT_EDITION:'по клиентской редакции ОС',OS_LINUX_ASSUMED_SERVER:'Linux — считаем сервером',OS_UNRECOGNIZED:'ОС не распознана',NO_FACTS:'нет фактов'};
export const relationNames:Record<string,string>={runs_on:'работает на',uses:'использует',depends_on:'зависит от',hosts:'размещает',connected_to:'подключён к'};
const criticalities:Record<string,string>={unknown:'Не задана',low:'Низкая',medium:'Средняя',high:'Высокая',critical:'Критичная'};
const kinds:Record<string,string>={agent:'Агент',collector:'Collector',portable:'Portable'};
const time=(v:string)=>new Date(v).toLocaleString('ru-RU',{day:'2-digit',month:'short',hour:'2-digit',minute:'2-digit'});
const bytes=(v:string|null)=>{if(!v)return '—';const n=Number(v);return Number.isFinite(n)&&n>1048576?(n/1073741824).toFixed(1)+' ГиБ':v};
function Provenance({e}:{e:Evidence}){return <small className="provenance">{kinds[e.source_kind]??e.source_kind} · {time(e.collected_at)} · часы: {e.clock_quality==='trusted'?'доверенные':'не подтверждены'}<span className="mono"> · {e.source_id.slice(0,8)}</span></small>}
function useLoad<T>(load:()=>Promise<T>,deps:unknown[],onExpired:()=>void):[T|null,unknown,()=>void]{
 const [data,setData]=useState<T|null>(null),[error,setError]=useState<unknown>(null),[n,setN]=useState(0);
 useEffect(()=>{let live=true;setError(null);load().then(d=>{if(live)setData(d)}).catch(e=>{if(live){setError(e);if(e instanceof ApiError&&e.status===401)onExpired()}});return()=>{live=false}},[...deps,n]);
 return [data,error,()=>setN(x=>x+1)];
}
const confirmAction=(what:string)=>window.confirm('Подтвердите: '+what+'. Изменение попадёт в историю и аудит.');

export function AssetClassBlock({asset,csrf,onExpired}:{asset:string;csrf:string;onExpired:()=>void}){
 const [data,error,reload]=useLoad(()=>api.assetCMDB(asset),[asset],onExpired);
 const [busy,setBusy]=useState(false),[failure,setFailure]=useState<unknown>(null);
 if(error)return <div className="error" role="alert">{errorMessage(error)}</div>;
 if(!data)return null;
 async function set(value:string){
  const next=value===''?null:value as AssetClassName;
  if(!confirmAction(next?'установить класс «'+classNames[next]+'»':'снять ручной класс (будет использоваться наблюдаемый)'))return;
  setBusy(true);setFailure(null);try{await api.setAssetClass(asset,csrf,{asset_class:next,revision:data!.business_revision});reload()}catch(e){setFailure(e);if(e instanceof ApiError&&e.status===401)onExpired()}finally{setBusy(false)}
 }
 return <div className="class-block"><div><span className="muted">Класс</span><strong>{classNames[data.class.effective]}</strong><small>{data.class.manual?'задан вручную · по фактам: '+classNames[data.class.observed]:'по фактам: '+(reasons[data.class.observed_reason]??data.class.observed_reason)}</small></div>
  <label>Изменить<select aria-label="Класс актива" disabled={busy} value={data.class.manual??''} onChange={e=>void set(e.target.value)}><option value="">Как в фактах</option>{Object.entries(classNames).map(([k,v])=><option key={k} value={k}>{v}</option>)}</select></label>
  {failure?<div className="error" role="alert">{errorMessage(failure)}</div>:null}
  <span className="class-counts">ПО: {data.software_count} · компонентов: {data.component_count} · связей: {data.relations.length}</span></div>;
}

export function SoftwareTab({asset,onExpired}:{asset:string;onExpired:()=>void}){
 const [items,setItems]=useState<Installation[]>([]),[next,setNext]=useState<string|null>(null),[filter,setFilter]=useState(''),[applied,setApplied]=useState(''),[error,setError]=useState<unknown>(null),[loading,setLoading]=useState(false);
 async function load(cursor:string|null){setLoading(true);setError(null);try{const p=await api.software(asset,applied,cursor);if(p.asset_uid!==asset)throw new ApiError(0,'INVALID_RESPONSE');setItems(x=>cursor?[...x,...p.items]:p.items);setNext(p.next_cursor)}catch(e){setError(e);if(e instanceof ApiError&&e.status===401)onExpired()}finally{setLoading(false)}}
 useEffect(()=>{void load(null)},[asset,applied]);
 return <div className="tab-body"><form className="tab-filter" onSubmit={e=>{e.preventDefault();setApplied(filter.trim())}}><input aria-label="Фильтр ПО" placeholder="Название или издатель…" value={filter} onChange={e=>setFilter(e.target.value)}/><button className="button small">Найти</button></form>
  {error?<div className="error" role="alert">{errorMessage(error)}</div>:null}
  {!items.length&&!loading&&!error?<p className="card-note">{applied?'Ничего не найдено.':'Сведений о ПО нет: раздел ещё не собирался или источник его не поддерживает.'}</p>:null}
  <table className="mini-table"><thead><tr><th>Название</th><th>Версия</th><th>Издатель</th></tr></thead><tbody>{items.map(i=><tr key={i.record_key}><td>{i.name??'—'}<Provenance e={i.evidence}/></td><td>{i.version??'—'}</td><td>{i.publisher??'—'}</td></tr>)}</tbody></table>
  <small className="card-note">Показано: {items.length}{next?' · есть ещё':''}</small>
  {next?<button className="button small" disabled={loading} onClick={()=>void load(next)}>{loading?'Загружаем…':'Показать ещё'}</button>:null}
 </div>;
}

export function ComponentsTab({asset,onExpired}:{asset:string;onExpired:()=>void}){
 const [data,error]=useLoad(()=>api.components(asset),[asset],onExpired);
 if(error)return <div className="error" role="alert">{errorMessage(error)}</div>;
 if(!data)return <p role="status">Загружаем…</p>;
 if(!data.items.length)return <p className="card-note">Сведений о компонентах нет.</p>;
 return <table className="mini-table"><thead><tr><th>Вид</th><th>Название</th><th>Производитель / модель</th><th>Объём</th></tr></thead><tbody>{data.items.map((c:Component)=><tr key={c.section+c.record_key}><td>{c.kind??'—'}</td><td>{c.name??'—'}{c.serial?<small className="mono">s/n {c.serial}</small>:null}<Provenance e={c.evidence}/></td><td>{[c.vendor,c.model].filter(Boolean).join(' · ')||'—'}</td><td>{bytes(c.size_bytes)}</td></tr>)}</tbody></table>;
}

function useServiceNames(){
 const [names,setNames]=useState<Record<string,string>>({});
 useEffect(()=>{let live=true;api.services().then(p=>{if(live)setNames(Object.fromEntries(p.items.map(s=>[s.service_uid,s.name])))}).catch(()=>{});return()=>{live=false}},[]);
 return names;
}
function EndLabel({end,names,onOpenAsset,onOpenService}:{end:CIEnd;names:Record<string,string>;onOpenAsset?:(uid:string)=>void;onOpenService?:(uid:string)=>void}){
 if(end.kind==='service')return <button className="text-link" onClick={()=>onOpenService?.(end.id)}>сервис «{names[end.id]??end.id.slice(0,8)}»</button>;
 return <button className="text-link mono" onClick={()=>onOpenAsset?.(end.id)}>актив {end.id.slice(0,8)}</button>;
}

export function RelationsTab({asset,csrf,onOpenAsset,onExpired}:{asset:string;csrf:string;onOpenAsset:(uid:string)=>void;onExpired:()=>void}){
 const [data,error,reload]=useLoad(()=>api.assetCMDB(asset),[asset],onExpired);
 const names=useServiceNames();
 const [service,setService]=useState(''),[type,setType]=useState('runs_on'),[busy,setBusy]=useState(false),[failure,setFailure]=useState<unknown>(null);
 async function act(fn:()=>Promise<unknown>,what:string){if(!confirmAction(what))return;setBusy(true);setFailure(null);try{await fn();reload()}catch(e){setFailure(e);if(e instanceof ApiError&&e.status===401)onExpired()}finally{setBusy(false)}}
 if(error)return <div className="error" role="alert">{errorMessage(error)}</div>;
 if(!data)return <p role="status">Загружаем…</p>;
 return <div className="tab-body">
  {data.relations.length?<ul className="relations">{data.relations.map((r:Relation)=><li key={r.relation_id}><EndLabel end={r.from} names={names} onOpenAsset={onOpenAsset}/> <b>{relationNames[r.relation_type]}</b> <EndLabel end={r.to} names={names} onOpenAsset={onOpenAsset}/><small>{r.origin==='manual'?'вручную':'наблюдаемая'} · с {time(r.valid_from)}</small><button className="text-link" disabled={busy} onClick={()=>void act(()=>api.retireRelation(r.relation_id,csrf),'удалить связь')}>Удалить</button></li>)}</ul>:<p className="card-note">Связей нет. Сервис можно привязать ниже; сетевые связи — на «Схеме сети».</p>}
  {failure?<div className="error" role="alert">{errorMessage(failure)}</div>:null}
  <div className="relation-form"><select aria-label="Тип связи" value={type} onChange={e=>setType(e.target.value)}><option value="runs_on">Сервис работает на этом активе</option><option value="uses">Сервис использует этот актив</option></select>
   <select aria-label="Сервис" value={service} onChange={e=>setService(e.target.value)}><option value="">Выберите сервис…</option>{Object.entries(names).map(([k,v])=><option key={k} value={k}>{v}</option>)}</select>
   <button className="button small" disabled={busy||!service} onClick={()=>void act(()=>api.createRelation(csrf,{relation_type:type,from:{kind:'service',id:service},to:{kind:'asset',id:asset}}),'добавить связь')}>Добавить связь</button></div>
 </div>;
}

export function ServicesView({csrf,onOpenAsset,onExpired}:{csrf:string;onOpenAsset:(uid:string)=>void;onExpired:()=>void}){
 const [page,error,reload]=useLoad(()=>api.services(),[],onExpired);
 const [open,setOpen]=useState<string|null>(null),[name,setName]=useState(''),[criticality,setCriticality]=useState('unknown'),[busy,setBusy]=useState(false),[failure,setFailure]=useState<unknown>(null);
 async function create(){if(!name.trim())return;setBusy(true);setFailure(null);try{const s=await api.createService(csrf,{name:name.trim(),criticality});setName('');reload();setOpen(s.service_uid)}catch(e){setFailure(e);if(e instanceof ApiError&&e.status===401)onExpired()}finally{setBusy(false)}}
 return <div className="table-panel"><div className="table-toolbar"><h2>Бизнес-сервисы <span>{page?.items.length??0}</span></h2>
  <form className="filters" onSubmit={e=>{e.preventDefault();void create()}}><label className="search-field"><input aria-label="Название нового сервиса" placeholder="Новый сервис, например «1С Бухгалтерия»" value={name} onChange={e=>setName(e.target.value)}/></label><select aria-label="Критичность" value={criticality} onChange={e=>setCriticality(e.target.value)}>{Object.entries(criticalities).map(([k,v])=><option key={k} value={k}>{v}</option>)}</select><button className="button small" disabled={busy||!name.trim()}>Создать</button></form></div>
  {error||failure?<div className="error" role="alert">{errorMessage(error??failure)}</div>:null}
  {page&&!page.items.length?<div className="empty"><span>◇</span><h3>Сервисов пока нет</h3><p>Создайте сервис и укажите, на каких активах он работает и от чего зависит.</p></div>:null}
  <div className="conflict-list">{page?.items.map((s:CIService)=><article key={s.service_uid} className="conflict"><header><strong>{s.name}</strong><span className="badge"><i/>{criticalities[s.criticality]}</span></header>{s.description?<p>{s.description}</p>:null}<div className="actions"><button className="button small" onClick={()=>setOpen(open===s.service_uid?null:s.service_uid)}>{open===s.service_uid?'Скрыть':'Связи и изменение'}</button></div>{open===s.service_uid?<ServiceCard uid={s.service_uid} csrf={csrf} onOpenAsset={onOpenAsset} onChanged={reload} onExpired={onExpired}/>:null}</article>)}</div>
 </div>;
}

function ServiceCard({uid,csrf,onOpenAsset,onChanged,onExpired}:{uid:string;csrf:string;onOpenAsset:(uid:string)=>void;onChanged:()=>void;onExpired:()=>void}){
 const [data,error,reload]=useLoad<ServiceDetail>(()=>api.service(uid),[uid],onExpired);
 const names=useServiceNames();
 const [description,setDescription]=useState<string|null>(null),[target,setTarget]=useState(''),[kind,setKind]=useState('runs_on'),[busy,setBusy]=useState(false),[failure,setFailure]=useState<unknown>(null);
 async function act(fn:()=>Promise<unknown>,what:string,after?:()=>void){if(!confirmAction(what))return;setBusy(true);setFailure(null);try{await fn();reload();after?.()}catch(e){setFailure(e);if(e instanceof ApiError&&e.status===401)onExpired()}finally{setBusy(false)}}
 if(error)return <div className="error" role="alert">{errorMessage(error)}</div>;
 if(!data)return <p role="status">Загружаем…</p>;
 const other=target.trim().toLowerCase(),toService=kind==='depends_on',valid=/^[0-9a-f-]{36}$/.test(other)||toService&&!!target;
 return <div className="service-card">
  <label className="merge-field">Описание<textarea className="inv12-filter" rows={2} value={description??data.description??''} onChange={e=>setDescription(e.target.value)}/></label>
  <div className="actions"><button className="button small" disabled={busy||description===null} onClick={()=>void act(()=>api.patchService(uid,csrf,{revision:data.revision,description:description??''}),'сохранить описание',()=>setDescription(null))}>Сохранить</button><button className="button small" disabled={busy} onClick={()=>void act(()=>api.patchService(uid,csrf,{revision:data.revision,retire:true}),'вывести сервис из эксплуатации (его связи будут закрыты)',onChanged)}>Вывести из эксплуатации</button></div>
  <h4>Связи</h4>
  {data.relations.length?<ul className="relations">{data.relations.map(r=><li key={r.relation_id}><EndLabel end={r.from} names={names} onOpenAsset={onOpenAsset}/> <b>{relationNames[r.relation_type]}</b> <EndLabel end={r.to} names={names} onOpenAsset={onOpenAsset}/><button className="text-link" disabled={busy} onClick={()=>void act(()=>api.retireRelation(r.relation_id,csrf),'удалить связь')}>Удалить</button></li>)}</ul>:<p className="card-note">Связей нет.</p>}
  <div className="relation-form"><select aria-label="Тип связи сервиса" value={kind} onChange={e=>{setKind(e.target.value);setTarget('')}}><option value="runs_on">работает на активе (UID)</option><option value="uses">использует актив (UID)</option><option value="depends_on">зависит от сервиса</option></select>
   {toService?<select aria-label="Сервис-зависимость" value={target} onChange={e=>setTarget(e.target.value)}><option value="">Выберите сервис…</option>{Object.entries(names).filter(([k])=>k!==uid).map(([k,v])=><option key={k} value={k}>{v}</option>)}</select>:<input className="mono" aria-label="UID актива" placeholder="UID актива из реестра" value={target} onChange={e=>setTarget(e.target.value)}/>}
   <button className="button small" disabled={busy||!valid} onClick={()=>void act(()=>api.createRelation(csrf,{relation_type:kind,from:{kind:'service',id:uid},to:{kind:toService?'service':'asset',id:toService?target:other}}),'добавить связь',()=>setTarget(''))}>Добавить</button></div>
  {failure?<div className="error" role="alert">{errorMessage(failure)}</div>:null}
 </div>;
}

export function SoftwareSearchView({onOpenAsset,onExpired}:{onOpenAsset:(uid:string)=>void;onExpired:()=>void}){
 const [q,setQ]=useState(''),[items,setItems]=useState<Product[]|null>(null),[error,setError]=useState<unknown>(null),[loading,setLoading]=useState(false);
 async function search(){const query=q.trim();if(query.length<2)return;setLoading(true);setError(null);try{setItems((await api.products(query)).items)}catch(e){setError(e);if(e instanceof ApiError&&e.status===401)onExpired()}finally{setLoading(false)}}
 return <div className="table-panel"><div className="table-toolbar"><h2>Поиск ПО по реестру</h2><form className="filters" onSubmit={e=>{e.preventDefault();void search()}}><label className="search-field"><span>⌕</span><input aria-label="Название ПО" placeholder="Например, openssl или 7-Zip (от 2 символов)" value={q} onChange={e=>setQ(e.target.value)}/></label><button className="button small" disabled={loading||q.trim().length<2}>Найти</button></form></div>
  {error?<div className="error" role="alert">{errorMessage(error)}</div>:null}
  {items&&!items.length?<div className="empty"><span>⌕</span><h3>Не найдено</h3><p>ПО с таким названием в собранных данных нет.</p></div>:null}
  {items?.length?<div className="table-scroll"><table><thead><tr><th>Продукт</th><th>Издатель</th><th>Версии</th><th>Установок</th><th>Активы</th></tr></thead><tbody>{items.map(p=><tr key={p.name+(p.publisher??'')}><td>{p.name}</td><td>{p.publisher??'—'}</td><td>{p.versions.join(', ')||'—'}</td><td>{p.installations}</td><td>{p.asset_uids.slice(0,5).map(u=><button key={u} className="text-link mono" onClick={()=>onOpenAsset(u)}>{u.slice(0,8)} </button>)}{p.assets>5?<small> и ещё {p.assets-5}</small>:null}</td></tr>)}</tbody></table></div>:null}
 </div>;
}
export type {AssetCMDB};
