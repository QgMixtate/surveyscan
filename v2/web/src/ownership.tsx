import {useEffect,useState} from 'react';
import {DirectorySyncPanel} from './integrations';
import {api,ApiError,errorMessage,type AssetAssignments,type RoleName,type Subject,type WorklistItem} from './api';

// C27 — ответственность в Web: роли актива и история передач, рабочие списки и массовое назначение, оргструктура.
export const roleNames:Record<RoleName,string>={accountable:'Ответственный',business_owner:'Бизнес-владелец',technical:'Технический ответственный',custodian:'Пользователь (хранитель)'};
const reasonNames:Record<string,string>={SITE_FALLBACK:'резервная команда площадки',MANUAL_ASSIGNMENT:'назначено оператором',SUBJECT_DEACTIVATED:'прежний ответственный выбыл',ASSET_MERGE:'при слиянии карточек'};
const scopes:[string,string][]=[['mine','На мне'],['team','На моих командах'],['unassigned','Не распределено'],['attention','Требует передачи']];
const time=(v:string)=>new Date(v).toLocaleString('ru-RU',{day:'2-digit',month:'short',year:'numeric',hour:'2-digit',minute:'2-digit'});
const confirmAction=(what:string)=>window.confirm('Подтвердите: '+what+'. Изменение попадёт в историю и аудит.');
const expired=(e:unknown,onExpired:()=>void)=>{if(e instanceof ApiError&&e.status===401)onExpired()};

function useSubjects(onExpired:()=>void,inactive=false):[Subject[],()=>void]{
 const [items,setItems]=useState<Subject[]>([]),[n,setN]=useState(0);
 useEffect(()=>{let live=true;api.subjects('',inactive).then(p=>{if(live)setItems(p.items)}).catch(e=>expired(e,onExpired));return()=>{live=false}},[n,inactive]);
 return [items,()=>setN(x=>x+1)];
}
function SubjectSelect({subjects,role,value,onChange,label}:{subjects:Subject[];role:RoleName;value:string;onChange:(v:string)=>void;label:string}){
 return <select aria-label={label} value={value} onChange={e=>onChange(e.target.value)}><option value="">Выберите…</option>{subjects.filter(s=>s.active&&(role!=='custodian'||s.kind==='person')).map(s=><option key={s.subject_id} value={s.subject_id}>{s.kind==='team'?'Команда: ':''}{s.name}{s.site_fallback?' (резервная)':''}</option>)}</select>;
}

export function AssignmentsTab({asset,csrf,onExpired}:{asset:string;csrf:string;onExpired:()=>void}){
 const [data,setData]=useState<AssetAssignments|null>(null),[error,setError]=useState<unknown>(null),[n,setN]=useState(0);
 const [subjects]=useSubjects(onExpired);
 const [role,setRole]=useState<RoleName>('accountable'),[subject,setSubject]=useState(''),[note,setNote]=useState(''),[busy,setBusy]=useState(false);
 useEffect(()=>{let live=true;setError(null);api.assignments(asset).then(d=>{if(live)setData(d)}).catch(e=>{if(live){setError(e);expired(e,onExpired)}});return()=>{live=false}},[asset,n]);
 async function act(body:{role:RoleName;subject_id:string|null},what:string){if(!data||!confirmAction(what))return;setBusy(true);setError(null);try{setData(await api.assign(asset,csrf,{...body,note:note.trim()||undefined,expected_version:data.version}));setSubject('');setNote('')}catch(e){setError(e);expired(e,onExpired);setN(x=>x+1)}finally{setBusy(false)}}
 if(!data)return error?<div className="error" role="alert">{errorMessage(error)}</div>:<p role="status">Загружаем…</p>;
 const byRole=Object.fromEntries(data.active.map(a=>[a.role,a]));
 return <div className="tab-body">
  {error?<div className="error" role="alert">{errorMessage(error)}</div>:null}
  <dl className="roles">{(Object.keys(roleNames) as RoleName[]).map(r=><div key={r}><dt>{roleNames[r]}</dt><dd>{byRole[r]?<>{byRole[r].subject_kind==='team'?'Команда: ':''}{byRole[r].subject_name}<small>с {time(byRole[r].valid_from)} · {reasonNames[byRole[r].reason_code]??byRole[r].reason_code}</small>{r!=='accountable'?<button className="text-link" disabled={busy} onClick={()=>void act({role:r,subject_id:null},'снять роль «'+roleNames[r]+'»')}>Снять</button>:null}</>:<span className="muted">не назначен</span>}</dd></div>)}</dl>
  <div className="relation-form"><select aria-label="Роль" value={role} onChange={e=>{setRole(e.target.value as RoleName);setSubject('')}}>{(Object.keys(roleNames) as RoleName[]).map(r=><option key={r} value={r}>{roleNames[r]}</option>)}</select>
   <SubjectSelect subjects={subjects} role={role} value={subject} onChange={setSubject} label="Кому передать"/>
   <input aria-label="Основание" placeholder="Основание (необязательно)" value={note} maxLength={1024} onChange={e=>setNote(e.target.value)}/>
   <button className="button small" disabled={busy||!subject} onClick={()=>void act({role,subject_id:subject},'передать роль «'+roleNames[role]+'»')}>Передать</button></div>
  <h4>История передач</h4>
  <table className="mini-table"><thead><tr><th>Роль</th><th>Кому</th><th>Период</th><th>Основание</th></tr></thead><tbody>{data.history.map((h,i)=><tr key={i}><td>{roleNames[h.role]}</td><td>{h.subject_name}</td><td>{time(h.valid_from)} — {h.valid_to?time(h.valid_to):'сейчас'}</td><td>{reasonNames[h.reason_code]??h.reason_code}{h.note?<small>{h.note}</small>:null}<small className="mono">{h.actor_ref}</small></td></tr>)}</tbody></table>
 </div>;
}

export function WorklistView({csrf,canWrite,onOpenAsset,onExpired}:{csrf:string;canWrite:boolean;onOpenAsset:(uid:string)=>void;onExpired:()=>void}){
 const [scope,setScope]=useState('mine'),[items,setItems]=useState<WorklistItem[]>([]),[next,setNext]=useState<string|null>(null),[error,setError]=useState<unknown>(null),[notice,setNotice]=useState(''),[loading,setLoading]=useState(false),[n,setN]=useState(0);
 const [selected,setSelected]=useState<string[]>([]),[role,setRole]=useState<RoleName>('accountable'),[subject,setSubject]=useState(''),[busy,setBusy]=useState(false);
 const [subjects]=useSubjects(onExpired);
 async function load(cursor:string|null){setLoading(true);setError(null);try{const p=await api.worklist(scope,cursor);setItems(x=>cursor?[...x,...p.items]:p.items);setNext(p.next_cursor)}catch(e){setError(e);expired(e,onExpired)}finally{setLoading(false)}}
 useEffect(()=>{setSelected([]);void load(null)},[scope,n]);
 async function bulk(){
  const chosen=items.filter(i=>selected.includes(i.asset_uid));if(!chosen.length||!subject||!confirmAction('назначить роль «'+roleNames[role]+'» для '+chosen.length+' актив(ов)'))return;
  setBusy(true);setError(null);setNotice('');
  try{const r=await api.bulkAssign(csrf,{role,subject_id:subject,items:chosen.map(i=>({asset_uid:i.asset_uid,expected_version:i.version}))});setNotice('Назначено: '+r.applied+(r.unchanged?', уже было так: '+r.unchanged:'')+'.');setSubject('');setN(x=>x+1)}
  catch(e){if(e instanceof ApiError&&e.status===412){setNotice('Некоторые активы изменились, пока вы выбирали: ничего не изменено, список обновлён — повторите.');setN(x=>x+1)}else{setError(e);expired(e,onExpired)}}
  finally{setBusy(false)}
 }
 const accountable=(i:WorklistItem)=>i.assignments.find(a=>a.role==='accountable');
 return <div className="table-panel"><div className="table-toolbar"><div className="scope-tabs" role="tablist">{scopes.map(([k,v])=><button key={k} role="tab" aria-selected={scope===k} className={scope===k?'active':''} onClick={()=>setScope(k)}>{v}</button>)}</div></div>
  {error?<div className="error" role="alert">{errorMessage(error)}</div>:null}
  {notice?<div className="notice" role="status">{notice}</div>:null}
  {canWrite&&items.length?<div className="bulk-bar"><span>Выбрано: {selected.length}</span><select aria-label="Роль для назначения" value={role} onChange={e=>{setRole(e.target.value as RoleName);setSubject('')}}>{(Object.keys(roleNames) as RoleName[]).map(r=><option key={r} value={r}>{roleNames[r]}</option>)}</select><SubjectSelect subjects={subjects} role={role} value={subject} onChange={setSubject} label="Назначить на"/><button className="button small primary-lite" disabled={busy||!selected.length||!subject} onClick={()=>void bulk()}>Назначить выбранным</button></div>:null}
  {!items.length&&!loading?<div className="empty"><span>✓</span><h3>Список пуст</h3><p>{scope==='mine'?'На вас не назначено активов — или ваш вход ещё не связан с человеком в оргструктуре.':'Здесь пока ничего нет.'}</p></div>:null}
  {items.length?<div className="table-scroll"><table><thead><tr>{canWrite?<th><input type="checkbox" aria-label="Выбрать все" checked={selected.length===items.length} onChange={e=>setSelected(e.target.checked?items.map(i=>i.asset_uid):[])}/></th>:null}<th>Актив</th><th>Ответственный</th><th>Другие роли</th></tr></thead><tbody>{items.map(i=><tr key={i.asset_uid}>{canWrite?<td><input type="checkbox" aria-label={'Выбрать '+(i.display_name??i.observed_hostname??i.asset_uid)} checked={selected.includes(i.asset_uid)} onChange={e=>setSelected(s=>e.target.checked?[...s,i.asset_uid]:s.filter(x=>x!==i.asset_uid))}/></td>:null}<td><button className="asset-link" onClick={()=>onOpenAsset(i.asset_uid)}><span><strong>{i.display_name??i.observed_hostname??'Без имени'}</strong><small className="mono">{i.asset_uid}</small></span></button></td><td>{accountable(i)?.subject_name??'—'}<small>{reasonNames[accountable(i)?.reason_code??'']??''}</small></td><td>{i.assignments.filter(a=>a.role!=='accountable').map(a=>roleNames[a.role]+': '+a.subject_name).join('; ')||'—'}</td></tr>)}</tbody></table></div>:null}
  {next?<div className="pager"><button className="button small" disabled={loading} onClick={()=>void load(next)}>Показать ещё</button></div>:null}
 </div>;
}

export function OrgView({csrf,onExpired}:{csrf:string;onExpired:()=>void}){
 const [inactive,setInactive]=useState(false);
 const [subjects,reload]=useSubjects(onExpired,inactive);
 const [kind,setKind]=useState<'person'|'team'>('person'),[name,setName]=useState(''),[contact,setContact]=useState(''),[username,setUsername]=useState(''),[busy,setBusy]=useState(false),[error,setError]=useState<unknown>(null),[notice,setNotice]=useState('');
 const [team,setTeam]=useState(''),[person,setPerson]=useState('');
 async function act(fn:()=>Promise<unknown>,what:string,done?:(r:unknown)=>void){if(!confirmAction(what))return;setBusy(true);setError(null);setNotice('');try{const r=await fn();done?.(r);reload()}catch(e){setError(e);expired(e,onExpired)}finally{setBusy(false)}}
 const people=subjects.filter(s=>s.kind==='person'&&s.active),teams=subjects.filter(s=>s.kind==='team'&&s.active&&s.origin==='local');
 return <div className="table-panel"><div className="table-toolbar"><h2>Люди и команды <span>{subjects.length}</span></h2><label className="inline-check"><input type="checkbox" checked={inactive} onChange={e=>setInactive(e.target.checked)}/> показывать выбывших</label></div>
  <DirectorySyncPanel csrf={csrf} onExpired={onExpired} onSynced={reload}/>
  {error?<div className="error" role="alert">{errorMessage(error)}</div>:null}
  {notice?<div className="notice" role="status">{notice}</div>:null}
  <form className="org-form" onSubmit={e=>{e.preventDefault();void act(()=>api.createSubject(csrf,{kind,name:name.trim(),contact:contact.trim(),username:kind==='person'&&username.trim()?username.trim():undefined}),'добавить '+(kind==='team'?'команду':'человека')+' «'+name.trim()+'»',()=>{setName('');setContact('');setUsername('')})}}>
   <select aria-label="Вид" value={kind} onChange={e=>setKind(e.target.value as 'person'|'team')}><option value="person">Человек</option><option value="team">Команда</option></select>
   <input aria-label="Имя" placeholder="ФИО или название команды" value={name} onChange={e=>setName(e.target.value)}/>
   <input aria-label="Контакт" placeholder="Почта или телефон" value={contact} onChange={e=>setContact(e.target.value)}/>
   {kind==='person'?<input aria-label="Логин" placeholder="Логин входа (необязательно)" value={username} onChange={e=>setUsername(e.target.value)}/>:null}
   <button className="button small" disabled={busy||!name.trim()||!contact.trim()}>Добавить</button></form>
  <div className="org-form"><span>Состав команды:</span><select aria-label="Команда" value={team} onChange={e=>setTeam(e.target.value)}><option value="">Команда…</option>{teams.map(s=><option key={s.subject_id} value={s.subject_id}>{s.name}</option>)}</select><select aria-label="Человек" value={person} onChange={e=>setPerson(e.target.value)}><option value="">Человек…</option>{people.map(s=><option key={s.subject_id} value={s.subject_id}>{s.name}</option>)}</select>
   <button className="button small" disabled={busy||!team||!person} onClick={()=>void act(()=>api.member(team,person,csrf,true),'включить в команду')}>Включить</button><button className="button small" disabled={busy||!team||!person} onClick={()=>void act(()=>api.member(team,person,csrf,false),'исключить из команды')}>Исключить</button></div>
  <div className="table-scroll"><table><thead><tr><th>Имя</th><th>Вид</th><th>Контакт</th><th>Логин AD</th><th>Вход SurveyScan</th><th>Состояние</th><th/></tr></thead><tbody>{subjects.map(s=><tr key={s.subject_id}><td>{s.name}{s.origin==='ldap'?<span className="tag" title={'Из Active Directory'+(s.synced_at?', синхронизировано '+time(s.synced_at):'')}> AD</span>:null}</td><td>{s.kind==='team'?'Команда ('+s.members+')':'Человек'}</td><td>{s.contact}</td><td className="mono">{s.directory_login??'—'}</td><td className="mono">{s.username??'—'}</td><td>{s.active?(s.site_fallback?'Резервная команда площадки':'Действует'):'Выбыл'}</td><td>{s.active&&!s.site_fallback&&s.origin==='local'?<button className="text-link" disabled={busy} onClick={()=>void act(()=>api.patchSubject(s.subject_id,csrf,{revision:s.revision,deactivate:true}),'отметить «'+s.name+'» выбывшим: его активы перейдут резервной команде площадки',r=>setNotice('Переназначено ролей: '+(r as {reassigned_assignments:number}).reassigned_assignments+'.'))}>Выбыл</button>:null}</td></tr>)}</tbody></table></div>
 </div>;
}
