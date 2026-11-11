import {useEffect,useState} from 'react';
import {api,ApiError,errorMessage,type SourceRecordPage} from './api';

// C25.03 — сопоставление карточки: записи источников, из которых она собрана; слияние с другой карточкой того же
// устройства и разделение (выделение записей в новый актив или перенос в существующий). Решения — в истории и аудите.
const acquisitions:Record<string,string>={agent:'Агент',ssh:'SSH',winrm:'WinRM'};
const uidPattern=/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;

export function AssetOperations({asset,csrf,onOpenAsset,onExpired}:{asset:string;csrf:string;onOpenAsset:(uid:string)=>void;onExpired:()=>void}){
 const [page,setPage]=useState<SourceRecordPage|null>(null),[error,setError]=useState<unknown>(null),[busy,setBusy]=useState(false),[notice,setNotice]=useState(''),[created,setCreated]=useState<string|null>(null);
 const [selected,setSelected]=useState<string[]>([]),[other,setOther]=useState(''),[labels,setLabels]=useState<Record<string,string>>({}),[refresh,setRefresh]=useState(0);
 useEffect(()=>{let live=true;setError(null);api.sourceRecords(asset).then(p=>{if(p.asset_uid!==asset)throw new ApiError(0,'INVALID_RESPONSE');if(live){setPage(p);setSelected([])}}).catch(e=>{if(live){setError(e);if(e instanceof ApiError&&e.status===401)onExpired()}});return()=>{live=false}},[asset,refresh]);
 useEffect(()=>{let live=true;api.sources().then(p=>{if(live)setLabels(Object.fromEntries(p.items.map(x=>[x.source_id,(x.source_kind==='agent'?acquisitions[x.acquisition??'agent']??'Агент':x.source_kind==='portable'?'Portable':'Collector')+' '+x.source_id.slice(0,8)])))}).catch(()=>{});return()=>{live=false}},[]);
 const target=other.trim().toLowerCase(),validTarget=uidPattern.test(target)&&target!==asset;
 async function run(what:string,op:()=>Promise<{to_asset_uid:string;moved_records:number;rebuilt_observations:number;created:boolean}>){
  if(!window.confirm('Подтвердите: '+what+'. Операция попадёт в историю и аудит; прежний UID останется ссылкой на актуальную карточку.'))return;
  setBusy(true);setError(null);setNotice('');setCreated(null);
  try{const r=await op();setNotice('Готово: перенесено записей — '+r.moved_records+', пересобрано наблюдений — '+r.rebuilt_observations+(r.created?', создан новый актив.':'.'));if(r.created)setCreated(r.to_asset_uid);setOther('');onOpenAsset(asset);setRefresh(x=>x+1)}
  catch(e){setError(e);if(e instanceof ApiError&&e.status===401)onExpired()}
  finally{setBusy(false)}
 }
 const merge=()=>run('присоединить карточку '+target+' к этой',()=>api.mergeAssets(csrf,{target_asset_uid:asset,absorbed_asset_uid:target,target_version:page?.version}));
 const split=(into?:string)=>run(into?'перенести выбранные записи в актив '+into:'выделить выбранные записи в новый актив',()=>api.splitAsset(asset,csrf,{source_record_keys:selected,target_asset_uid:into,version:page?.version}));
 const all=!!page&&selected.length===page.items.length;
 return <><h3>Сопоставление и слияние</h3>
  <p className="card-note">Записи источников, из которых собрана карточка. Ошибочно сведённые записи можно выделить в новый актив или перенести в другой; дубль этой карточки — присоединить по его UID.</p>
  {error?<div className="error" role="alert">{errorMessage(error)}</div>:null}
  {notice?<div className="notice" role="status">{notice}{created?<> <button className="text-link" onClick={()=>onOpenAsset(created)}>Открыть новый актив</button></>:null}</div>:null}
  {page?<div className="source-records">{page.items.map(r=><label key={r.source_record_key} className="source-record"><input type="checkbox" disabled={busy} checked={selected.includes(r.source_record_key)} onChange={e=>setSelected(s=>e.target.checked?[...s,r.source_record_key]:s.filter(x=>x!==r.source_record_key))}/><span><b>{labels[r.source_id]??r.source_id.slice(0,8)}</b> · {r.source_local_id}<small>наблюдений: {r.observations} · <span className="mono">{r.source_record_key}</span></small></span></label>)}{!page.items.length?<p className="card-note">Записей нет.</p>:null}</div>:<p role="status">Загружаем…</p>}
  <div className="actions">
   <button className="button small" disabled={busy||!selected.length||all} onClick={()=>void split()}>Выделить в новый актив</button>
   <button className="button small" disabled={busy||!selected.length||!validTarget} onClick={()=>void split(target)}>Перенести в актив по UID</button>
  </div>
  <label className="merge-field">UID другой карточки<input className="inv12-filter mono" aria-label="UID другой карточки" placeholder="xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx" value={other} disabled={busy} onChange={e=>setOther(e.target.value)}/></label>
  <div className="actions"><button className="button small primary-lite" disabled={busy||!validTarget} onClick={()=>void merge()}>Присоединить карточку к этой</button></div>
 </>;
}
