import {useEffect,useState} from 'react';
import {api,ApiError,errorMessage,type CSVImportResult,type DirectorySyncStatus,type SyncRun} from './api';

// C31.02 — интеграции в Web: синхронизация оргструктуры из Active Directory (только чтение) и CSV ручных полей активов.
const time=(v:string)=>new Date(v).toLocaleString('ru-RU',{day:'2-digit',month:'short',hour:'2-digit',minute:'2-digit'});
const expired=(e:unknown,onExpired:()=>void)=>{if(e instanceof ApiError&&e.status===401)onExpired()};
const runSummary=(r:SyncRun)=>{const c=r.counters;return r.status==='failed'?'Ошибка: '+(r.error??'неизвестно'):[`людей ${c.people_seen??0}`,`команд ${c.teams_seen??0}`,`новых ${c.created??0}`,`изменено ${c.updated??0}`,`выбыло ${c.deactivated??0}`,`передано ролей ${c.assignments_reassigned??0}`].join(', ')};

export function DirectorySyncPanel({csrf,onExpired,onSynced}:{csrf:string;onExpired:()=>void;onSynced:()=>void}){
 const [status,setStatus]=useState<DirectorySyncStatus|null>(null),[busy,setBusy]=useState(false),[error,setError]=useState<unknown>(null);
 const load=()=>{api.directorySync().then(setStatus).catch(e=>{setError(e);expired(e,onExpired)})};
 useEffect(load,[]);
 async function run(mode:'full'|'auto'){setBusy(true);setError(null);try{await api.runDirectorySync(csrf,mode);onSynced()}catch(e){setError(e);expired(e,onExpired)}finally{setBusy(false);load()}}
 if(!status)return error?<div className="error" role="alert">{errorMessage(error)}</div>:null;
 const last=status.runs[0];
 return <div className="notice sync-panel" role="status">
  {status.configured?<><strong>Синхронизация с Active Directory</strong> — {status.source}, каждые {status.interval_minutes} мин, полная — раз в {status.full_sync_hours} ч{status.teams_enabled?', с командами из групп':''}. Людей и команды с отметкой «AD» ведёт каталог: здесь их не переименовывают и не отключают.
   <div>{last?<>Последний прогон {time(last.started_at)} ({last.mode==='full'?'полный':'изменения'}): <span className={last.status==='failed'?'error-text':''}>{runSummary(last)}</span>{last.counters.problems?.length?<details><summary>Замечания: {last.counters.problems.length}</summary><ul>{last.counters.problems.map((p,i)=><li key={i}>{p}</li>)}</ul></details>:null}</>:'Прогонов ещё не было.'}</div>
   <div className="org-form"><button className="button small" disabled={busy} onClick={()=>void run('auto')}>{busy?'Синхронизация…':'Синхронизировать сейчас'}</button><button className="button small secondary" disabled={busy} onClick={()=>void run('full')}>Полная синхронизация</button></div></>
  :<>Синхронизация с Active Directory не настроена: люди и команды ведутся здесь вручную. Настройка — блок <code>ldap_sync</code> конфигурации центра.</>}
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
