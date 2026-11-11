import {useEffect,useState} from 'react';
import {api,ApiError,errorMessage,type Conflict} from './api';

// C25.02 — очередь разбора: записи источников, которые не сопоставились с активом автоматически.
const reasons:Record<string,string>={IDENTITY_CONFLICT:'Признаки совпадают с существующими активами, но автоматически сводить нельзя'};
const states:[string,string][]=[['open','Ожидают решения'],['resolved','Разобраны'],['dismissed','Отложены']];

export function ReconciliationView({csrf,onOpenAsset,onExpired}:{csrf:string;onOpenAsset:(uid:string)=>void;onExpired:()=>void}){
 const [state,setState]=useState('open'),[items,setItems]=useState<Conflict[]>([]),[loading,setLoading]=useState(true),[error,setError]=useState<unknown>(null),[notice,setNotice]=useState(''),[busy,setBusy]=useState<string|null>(null),[refresh,setRefresh]=useState(0);
 useEffect(()=>{let active=true;setLoading(true);setError(null);api.conflicts(state).then(p=>{if(active)setItems(p.items)}).catch(e=>{if(active){setError(e);if(e instanceof ApiError&&e.status===401)onExpired()}}).finally(()=>{if(active)setLoading(false)});return()=>{active=false}},[state,refresh,onExpired]);
 async function act(c:Conflict,action:string,asset?:string){
  const what=action==='attach'?'привязать запись к выбранному активу':action==='create_asset'?'создать для записи новый актив':action==='confirm'?'подтвердить текущую привязку':'отложить конфликт';
  if(!window.confirm('Подтвердите: '+what+'. Решение попадёт в историю и аудит.'))return;
  setBusy(c.conflict_id);setError(null);setNotice('');
  try{const r=await api.resolveConflict(c.conflict_id,csrf,{action,...(asset?{asset_uid:asset}:{}),revision:c.revision});setNotice(action==='dismiss'?'Конфликт отложен.':`Готово: запись привязана к активу${r.asset_uid?' '+r.asset_uid.slice(0,8):''}, применено наблюдений: ${r.replayed_observations}.`);setRefresh(n=>n+1)}
  catch(e){setError(e);if(e instanceof ApiError&&e.status===401)onExpired()}finally{setBusy(null)}
 }
 return <section className="table-panel">
  <div className="table-toolbar"><h2>Конфликты сопоставления <span>{items.length}</span></h2><div className="filters">{states.map(([k,t])=><button key={k} className={'button small'+(state===k?' primary-lite':'')} aria-pressed={state===k} onClick={()=>setState(k)}>{t}</button>)}<button className="button small" onClick={()=>setRefresh(n=>n+1)} disabled={loading}>↻ Обновить</button></div></div>
  {error?<div className="error" role="alert" style={{margin:'12px 20px'}}>{errorMessage(error)}</div>:null}
  {notice?<div className="notice" role="status">{notice}</div>:null}
  {loading?<div className="empty" role="status">Загружаем очередь…</div>:!items.length?<div className="empty"><span>✓</span><h3>{state==='open'?'Разбирать нечего':'Пусто'}</h3><p>{state==='open'?'Все записи источников сопоставлены с активами автоматически.':'В этом состоянии конфликтов нет.'}</p></div>:
  <div className="conflict-list">{items.map(c=><article key={c.conflict_id} className="conflict">
   <header><strong>{c.observed_hostname||c.source_local_id}</strong><span className={'badge state-'+(c.state==='open'?'pending':c.state==='resolved'?'ok':'unknown')}><i/>{states.find(s=>s[0]===c.state)?.[1]}</span></header>
   <p>{reasons[c.reason_code]??c.reason_code}</p>
   <dl><dt>Источник</dt><dd className="mono">{c.source_id}</dd><dt>Запись источника</dt><dd className="mono">{c.namespace} · {c.source_local_id}</dd><dt>Ожидающих наблюдений</dt><dd>{c.pending_observations}</dd><dt>Текущий актив</dt><dd>{c.asset_uid?<button className="text-link mono" onClick={()=>onOpenAsset(c.asset_uid!)}>{c.asset_uid}</button>:'нет — данные не попадают в реестр'}</dd></dl>
   {c.candidate_asset_uids.length?<div className="candidates"><span>Кандидаты:</span>{c.candidate_asset_uids.map(uid=><span key={uid} className="candidate"><button className="text-link mono" onClick={()=>onOpenAsset(uid)}>{uid.slice(0,8)}…</button>{c.state==='open'&&!c.asset_uid?<button className="button small" disabled={busy!==null} onClick={()=>void act(c,'attach',uid)}>Привязать</button>:null}</span>)}</div>:null}
   {c.state==='open'?<div className="actions">{!c.asset_uid?<button className="button small" disabled={busy!==null||!c.pending_observations} title={c.pending_observations?'':'Нет ожидающих наблюдений, по которым можно создать актив'} onClick={()=>void act(c,'create_asset')}>Создать новый актив</button>:<button className="button small" disabled={busy!==null} onClick={()=>void act(c,'confirm')}>Подтвердить текущую привязку</button>}<button className="button small" disabled={busy!==null} onClick={()=>void act(c,'dismiss')}>Отложить</button></div>:null}
  </article>)}</div>}
  <p className="card-note" style={{padding:'0 20px 16px'}}>Автоматически сводятся только записи разных источников с единственным надёжным сильным идентификатором (machine UUID, BIOS UUID, серийный номер). Остальное — сюда: решение оператора записывается в историю актива и аудит. Перепривязка уже сопоставленных записей и разделение активов — следующий этап (C25.03).</p>
 </section>;
}
