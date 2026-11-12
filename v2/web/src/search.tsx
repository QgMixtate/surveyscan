import {useState,type FormEvent,type ReactNode} from 'react';
import {api,ApiError,errorMessage,type SearchItem,type SearchPage} from './api';
import {classNames} from './cmdb';

// C29 — поиск по реестру: полнотекстовый (сервис поиска) или запасной точный режим, о котором говорится прямо.
const osNames:Record<string,string>={linux:'Linux',windows:'Windows',unknown:'Не определена'};
function Highlighted({text,ranges}:{text:string;ranges:[number,number][]}){
 const chars=[...text],out:ReactNode[]=[];let at=0;
 ranges.forEach(([a,b],i)=>{if(a>at)out.push(chars.slice(at,a).join(''));out.push(<mark key={i}>{chars.slice(a,b).join('')}</mark>);at=b});
 if(at<chars.length)out.push(chars.slice(at).join(''));
 return <>{out}</>;
}
export function SearchView({onOpenAsset,onExpired}:{onOpenAsset:(uid:string)=>void;onExpired:()=>void}){
 const [q,setQ]=useState(''),[page,setPage]=useState<SearchPage|null>(null),[items,setItems]=useState<SearchItem[]>([]),[filters,setFilters]=useState<{os?:string;class?:string}>({}),[error,setError]=useState<unknown>(null),[loading,setLoading]=useState(false);
 async function run(query:string,f:{os?:string;class?:string},cursor:string|null){
  if(query.trim().length<2)return;setLoading(true);setError(null);
  try{const p=await api.search(query.trim(),f,cursor);setPage(p);setItems(x=>cursor?[...x,...p.items]:p.items)}catch(e){setError(e);if(e instanceof ApiError&&e.status===401)onExpired()}finally{setLoading(false)}
 }
 function submit(e:FormEvent){e.preventDefault();setFilters({});void run(q,{},null)}
 function facet(kind:'os'|'class',value:string){const f={...filters,[kind]:filters[kind]===value?undefined:value};setFilters(f);void run(q,f,null)}
 const label=(kind:'os'|'class',v:string)=>kind==='os'?(osNames[v]??v):(classNames[v as keyof typeof classNames]??v);
 return <div className="table-panel"><form className="table-toolbar" onSubmit={submit}><label className="search-field search-wide"><span>⌕</span><input aria-label="Запрос" placeholder="Имя, IP, серийный номер, ПО, назначение, ответственный…" value={q} onChange={e=>setQ(e.target.value)}/></label><button className="button small" disabled={loading||q.trim().length<2}>Найти</button></form>
  {error?<div className="error" role="alert">{errorMessage(error)}</div>:null}
  {page?.mode==='fallback_exact'?<div className="error" role="status">{page.notice}</div>:null}
  {page&&page.mode==='fulltext'&&page.pending_index_events>0?<p className="card-note search-lag">Индекс догоняет изменения: ожидают индексации {page.pending_index_events}. Самые свежие правки могут ещё не находиться.</p>:null}
  {page?<div className="search-layout"><aside className="facets">{(['class','os'] as const).map(kind=><div key={kind}><h4>{kind==='os'?'ОС':'Класс'}</h4>{Object.entries(page.facets[kind]).sort((a,b)=>b[1]-a[1]).map(([v,n])=><button key={v} className={filters[kind]===v?'active':''} onClick={()=>facet(kind,v)}>{label(kind,v)} <b>{n}</b></button>)}</div>)}</aside>
   <div className="search-results">{!items.length?<div className="empty"><span>⌕</span><h3>Ничего не найдено</h3><p>{page.mode==='fallback_exact'?'В запасном режиме ищутся только точные значения.':'Проверьте написание или уберите фильтры.'}</p></div>:null}
    {items.map(it=><article key={it.asset_uid} className="search-hit"><button className="asset-link" onClick={()=>onOpenAsset(it.asset_uid)}><span><strong>{it.display_name??it.observed_hostname??'Без имени'}</strong><small>{it.observed_os??''}<span className="mono"> · {it.asset_uid}</span></small></span></button>{it.fragment?<p><Highlighted text={it.fragment} ranges={it.highlights}/></p>:null}</article>)}
    {page.next_cursor?<button className="button small" disabled={loading} onClick={()=>void run(q,filters,page.next_cursor)}>Показать ещё</button>:null}</div></div>:<div className="empty"><span>⌕</span><h3>Поиск по реестру</h3><p>Ищет по именам и FQDN, IP, серийным номерам, установленному ПО, назначению, ответственным и сервисам. Учитывает словоформы.</p></div>}
 </div>;
}
