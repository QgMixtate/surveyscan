import {useEffect,useMemo,useRef,useState} from 'react';
import {api,ApiError,errorMessage,type Topology,type TopologyLink,type TopologyNode} from './api';

// Схема сети L3 по наблюдаемым фактам: подсети — сетка, хосты — кольца вокруг своей подсети,
// маршрутизаторы (активы-шлюзы и хосты в нескольких подсетях) — между подсетями. Раскладка детерминирована.
type Placed=TopologyNode&{x:number;y:number};
const level:Record<string,string>={confirmed:'подтверждено',probable:'прямое наблюдение',weak:'косвенно'};
const sourceName:Record<string,string>={'interface-address':'адрес на интерфейсе',route:'маршрут/шлюз',lldp:'LLDP',fdb:'таблица MAC',  'ip-subnet':'общая подсеть'};

function layout(t:Topology):{nodes:Placed[];width:number;height:number}{
 const subnets=t.nodes.filter(n=>n.kind==='subnet').sort((a,b)=>a.label.localeCompare(b.label,undefined,{numeric:true}));
 const member=new Map<string,string[]>();
 for(const l of t.links)if(l.a.startsWith('host:')&&l.b.startsWith('subnet:')){const list=member.get(l.a)??[];if(!list.includes(l.b))list.push(l.b);member.set(l.a,list)}
 const gwOf=new Map<string,string>();for(const l of t.links)if(l.role==='gateway'&&l.b.startsWith('gw:'))gwOf.set(l.b,l.a);
 const single=new Map<string,string[]>();const multi:string[]=[];const orphan:string[]=[];
 for(const n of t.nodes.filter(n=>n.kind==='host')){const s=(member.get(n.id)??[]).sort();if(!s.length)orphan.push(n.id);else if(s.length>1||n.router)multi.push(n.id);if(s.length){const list=single.get(s[0])??[];if(!(s.length>1||n.router))list.push(n.id);single.set(s[0],list)}}
 const ring=(count:number)=>70+Math.min(count,30)*7;
 const rmax=Math.max(90,...subnets.map(s=>ring((single.get(s.id)??[]).length)+((single.get(s.id)??[]).length>30?60:0)));
 const cell=2*rmax+120,cols=Math.max(1,Math.ceil(Math.sqrt(subnets.length||1)));
 const pos=new Map<string,{x:number;y:number}>();
 subnets.forEach((s,i)=>pos.set(s.id,{x:cell/2+(i%cols)*cell,y:cell/2+Math.floor(i/cols)*cell}));
 for(const s of subnets){const c=pos.get(s.id)!;const hosts=(single.get(s.id)??[]).sort();hosts.forEach((h,i)=>{const perRing=30,ringIndex=Math.floor(i/perRing),inRing=Math.min(perRing,hosts.length-ringIndex*perRing);const r=ring(Math.min(hosts.length,perRing))+ringIndex*60;const a=2*Math.PI*(i%perRing)/inRing-Math.PI/2;pos.set(h,{x:c.x+r*Math.cos(a),y:c.y+r*Math.sin(a)})})}
 const taken=new Map<string,number>();multi.sort().forEach(h=>{const s=(member.get(h)??[]).map(id=>pos.get(id)).filter(Boolean) as {x:number;y:number}[];const x=s.reduce((a,p)=>a+p.x,0)/s.length,y=s.reduce((a,p)=>a+p.y,0)/s.length;const used=taken.get(Math.round(x/40)+':'+Math.round(y/40))??0;taken.set(Math.round(x/40)+':'+Math.round(y/40),used+1);pos.set(h,{x:x+(s.length===1?rmax*0.55:0)+(used%2?1:-1)*Math.ceil(used/2)*110,y:s.length===1?y-rmax*0.55:Math.max(1,Math.round(y/cell))*cell})});
 let gi=0;for(const [gw,subnet] of gwOf){const c=pos.get(subnet);if(c){pos.set(gw,{x:c.x-rmax*0.6,y:c.y-rmax*0.6-(gi++%3)*18})}}
 const rows=Math.max(1,Math.ceil(subnets.length/cols));const baseY=rows*cell+40;
 orphan.sort().forEach((h,i)=>pos.set(h,{x:80+(i%12)*120,y:baseY+Math.floor(i/12)*90}));
 const nodes=t.nodes.map(n=>({...n,...(pos.get(n.id)??{x:40,y:40})}));
 const width=Math.max(cols*cell,orphan.length?Math.min(12,orphan.length)*120+80:0,600);
 const height=baseY+(orphan.length?Math.ceil(orphan.length/12)*90+40:0);
 return {nodes,width,height};
}

export function TopologyView({onOpenAsset,onExpired}:{onOpenAsset:(uid:string)=>void;onExpired:()=>void}){
 const [data,setData]=useState<Topology|null>(null),[error,setError]=useState<unknown>(null),[loading,setLoading]=useState(true),[selected,setSelected]=useState<string|null>(null),[search,setSearch]=useState(''),[refresh,setRefresh]=useState(0);
 const [view,setView]=useState({x:0,y:0,k:1});const drag=useRef<{x:number;y:number;vx:number;vy:number}|null>(null);const svg=useRef<SVGSVGElement>(null);
 useEffect(()=>{let active=true;setLoading(true);setError(null);api.topology().then(t=>{if(active){setData(t);setSelected(null)}}).catch(e=>{if(active){setError(e);if(e instanceof ApiError&&e.status===401)onExpired()}}).finally(()=>{if(active)setLoading(false)});return()=>{active=false}},[refresh,onExpired]);
 const placed=useMemo(()=>data?layout(data):null,[data]);
 const byId=useMemo(()=>new Map((placed?.nodes??[]).map(n=>[n.id,n])),[placed]);
 useEffect(()=>{if(placed&&svg.current){const w=svg.current.clientWidth||1000,h=svg.current.clientHeight||640;const k=Math.min(1.2,Math.max(0.15,Math.min(w/placed.width,h/placed.height)));setView({x:(w-placed.width*k)/2,y:Math.max(10,(h-placed.height*k)/2),k})}},[placed]);
 const match=search.trim().toLowerCase();
 const evidenceText=useMemo(()=>{const m=new Map<string,string>();for(const l of data?.links??[]){const t=l.evidence.map(e=>e.detail).join(' ').toLowerCase();if(l.role!=='gateway')m.set(l.a,(m.get(l.a)??'')+' '+t)}return m},[data]);
 const hit=(n:TopologyNode)=>!!match&&(n.label.toLowerCase().includes(match)||(n.detail??'').toLowerCase().includes(match)||n.id.toLowerCase().includes(match)||(evidenceText.get(n.id)??'').includes(match));
 const related=useMemo(()=>{const s=new Set<string>();if(selected&&data){s.add(selected);for(const l of data.links)if(l.a===selected||l.b===selected){s.add(l.a);s.add(l.b)}}return s},[selected,data]);
 function zoom(f:number,cx?:number,cy?:number){const r=svg.current?.getBoundingClientRect();const px=cx??(r?r.width/2:0),py=cy??(r?r.height/2:0);setView(v=>{const k=Math.min(4,Math.max(0.08,v.k*f));return {k,x:px-(px-v.x)*k/v.k,y:py-(py-v.y)*k/v.k}})}
 function exportSvg(){if(!svg.current||!placed)return;const clone=svg.current.cloneNode(true) as SVGSVGElement;clone.setAttribute('xmlns','http://www.w3.org/2000/svg');clone.setAttribute('viewBox',`0 0 ${placed.width} ${placed.height}`);clone.setAttribute('width',String(placed.width));clone.setAttribute('height',String(placed.height));clone.querySelector('g')?.setAttribute('transform','');const style=document.createElementNS('http://www.w3.org/2000/svg','style');style.textContent=SVG_STYLE;clone.insertBefore(style,clone.firstChild);const blob=new Blob([new XMLSerializer().serializeToString(clone)],{type:'image/svg+xml'});const a=document.createElement('a');a.href=URL.createObjectURL(blob);a.download='surveyscan-network.svg';a.click();setTimeout(()=>URL.revokeObjectURL(a.href),1000)}
 const sel=selected?byId.get(selected):undefined;const selLinks:TopologyLink[]=selected&&data?data.links.filter(l=>l.a===selected||l.b===selected):[];
 const counts=data?{hosts:data.nodes.filter(n=>n.kind==='host').length,subnets:data.nodes.filter(n=>n.kind==='subnet').length,gw:data.nodes.filter(n=>n.kind==='gateway'||n.router).length,conflicts:data.links.filter(l=>l.conflicts?.length).length}:null;
 return <section className="topology">
  {error?<div className="error" role="alert">{errorMessage(error)}</div>:null}
  {counts?<div className="stats"><div className="stat"><span>Активы на схеме</span><strong>{counts.hosts}</strong><small>С сетевыми фактами: {data!.hosts_with_network_facts}{data!.truncated?' · показаны первые 2000':''}</small></div><div className="stat"><span>Подсети</span><strong>{counts.subnets}</strong><small>По адресам интерфейсов</small></div><div className="stat"><span>Шлюзы</span><strong>{counts.gw}</strong><small>Маршруты по умолчанию{counts.conflicts?` · конфликтов IP: ${counts.conflicts}`:''}</small></div></div>:null}
  <div className="table-panel topo-panel">
   <div className="table-toolbar"><h2>Схема L3 <span>{data?new Date(data.generated_at).toLocaleTimeString('ru-RU'):''}</span></h2><div className="filters"><label className="search-field"><span>⌕</span><input aria-label="Найти на схеме" placeholder="Хост, подсеть, IP…" value={search} onChange={e=>setSearch(e.target.value)}/></label><button className="button small" onClick={()=>zoom(1.25)} aria-label="Приблизить">+</button><button className="button small" onClick={()=>zoom(0.8)} aria-label="Отдалить">−</button><button className="button small" onClick={()=>setRefresh(n=>n+1)} disabled={loading}>↻ Обновить</button><button className="button small" onClick={exportSvg} disabled={!placed?.nodes.length}>Экспорт SVG</button></div></div>
   <div className="topo-body">
    {loading&&!data?<div className="empty" role="status">Строим схему…</div>:placed&&!placed.nodes.length?<div className="empty"><span>⌘</span><h3>Схема пока пуста</h3><p>Схема строится из адресов интерфейсов, которые сообщают агенты, SSH/WinRM-цели и portable-аудит. Как только появятся сетевые факты, здесь появятся подсети и хосты.</p></div>:
    <svg ref={svg} className="topo-svg" role="img" aria-label="Схема сети" onWheel={e=>{const r=svg.current!.getBoundingClientRect();zoom(e.deltaY<0?1.12:0.89,e.clientX-r.left,e.clientY-r.top)}} onPointerDown={e=>{if((e.target as Element).closest('.topo-node'))return;drag.current={x:e.clientX,y:e.clientY,vx:view.x,vy:view.y};(e.target as Element).setPointerCapture?.(e.pointerId)}} onPointerMove={e=>{if(drag.current){const d=drag.current;setView(v=>({...v,x:d.vx+e.clientX-d.x,y:d.vy+e.clientY-d.y}))}}} onPointerUp={()=>{drag.current=null}} onClick={e=>{if(!(e.target as Element).closest('.topo-node'))setSelected(null)}}>
     <g transform={`translate(${view.x},${view.y}) scale(${view.k})`}>
      {data!.links.map((l,i)=>{const a=byId.get(l.a),b=byId.get(l.b);if(!a||!b)return null;const dim=selected&&!(related.has(l.a)&&related.has(l.b));return <line key={i} x1={a.x} y1={a.y} x2={b.x} y2={b.y} className={'topo-link '+l.confidence+(l.role==='gateway'?' gateway':'')+(l.conflicts?.length?' conflict':'')+(dim?' dim':'')}/>})}
      {placed!.nodes.map(n=>{const dim=(selected&&!related.has(n.id))||(match&&!hit(n));const cls='topo-node '+n.kind+(n.router?' router':'')+(selected===n.id?' selected':'')+(hit(n)?' hit':'')+(dim?' dim':'');
       return <g key={n.id} className={cls} transform={`translate(${n.x},${n.y})`} tabIndex={0} role="button" aria-label={(n.kind==='subnet'?'Подсеть ':n.kind==='gateway'?'Шлюз ':'Хост ')+n.label} onClick={e=>{e.stopPropagation();setSelected(n.id)}} onDoubleClick={()=>n.asset_uid&&onOpenAsset(n.asset_uid)} onKeyDown={e=>{if(e.key==='Enter')setSelected(n.id)}}>
        {n.kind==='subnet'?<><rect x={-62} y={-17} width={124} height={34} rx={17}/><text y={5}>{n.label}</text></>:n.kind==='gateway'?<><polygon points="0,-16 16,0 0,16 -16,0"/><text y={30}>{n.label}</text></>:<><rect x={-13} y={-13} width={26} height={26} rx={n.router?13:5}/><text className="glyph" y={5}>{n.router?'⇄':'▤'}</text><text y={30}>{n.label.length>22?n.label.slice(0,21)+'…':n.label}</text></>}
       </g>})}
     </g>
    </svg>}
    <aside className="topo-side">{sel?<>
     <span className="eyebrow muted">{sel.kind==='subnet'?'Подсеть':sel.kind==='gateway'?'Шлюз':sel.router?'Хост · маршрутизатор':'Хост'}</span><h3>{sel.label}</h3>{sel.detail?<p>{sel.detail}</p>:null}
     {sel.asset_uid?<button className="button small" onClick={()=>onOpenAsset(sel.asset_uid!)}>Открыть карточку актива</button>:null}
     <h4>Связи · доказательства</h4>
     {selLinks.map((l,i)=>{const other=byId.get(l.a===sel.id?l.b:l.a);return <article key={i} className={l.conflicts?.length?'conflict':''}><strong>{other?.label??(l.a===sel.id?l.b:l.a)}{l.role==='gateway'?' · шлюз':''}</strong><small>{l.layer} · {level[l.confidence]??l.confidence}</small>{l.evidence.map((ev,j)=><small key={j}>{sourceName[ev.source]??ev.source}: {ev.detail}{ev.origin?<span className="mono"> · источник {ev.origin.slice(0,8)}</span>:null}</small>)}{l.conflicts?.map((c,j)=><small key={j} className="conflict-text">⚠ {c}</small>)}</article>})}
    </>:<>
     <span className="eyebrow muted">Как читать схему</span>
     <div className="legend"><span><i className="lg subnet"/>Подсеть (по адресам интерфейсов)</span><span><i className="lg host"/>Хост из реестра</span><span><i className="lg router"/>Хост-маршрутизатор (шлюз для других)</span><span><i className="lg gateway"/>Шлюз, не найденный в реестре</span><span><i className="lg line"/>Адрес на интерфейсе</span><span><i className="lg line gw"/>Маршрут по умолчанию</span><span><i className="lg line bad"/>Конфликт: один IP у разных активов</span></div>
     <p className="card-note">Схема строится только из наблюдаемых фактов инвентаризации, сеть не опрашивается. Нажмите на узел, чтобы увидеть доказательства; двойной щелчок по хосту открывает карточку. Колесо мыши — масштаб, перетаскивание — сдвиг. L2 (LLDP/таблицы MAC коммутаторов по SNMP) появится после подключения SNMP-коллектора к центру.</p>
    </>}</aside>
   </div>
  </div>
 </section>;
}

// Стили для экспортируемого SVG (в приложении те же правила задаёт style.css).
const SVG_STYLE=`.topo-link{stroke:#b9c8b3;stroke-width:1.4}.topo-link.weak{stroke-dasharray:4 4}.topo-link.gateway{stroke:#3f7a5c;stroke-width:2.4;stroke-dasharray:7 4}.topo-link.conflict{stroke:#c0634f;stroke-width:2.4}.topo-node text{font:11px sans-serif;fill:#2d4636;text-anchor:middle}.topo-node.subnet rect{fill:#e8f2e4;stroke:#7fa877}.topo-node.subnet text{font-weight:600}.topo-node.host rect{fill:#fff;stroke:#8da582}.topo-node.router rect{fill:#214d3b;stroke:#214d3b}.topo-node.router .glyph{fill:#fff}.topo-node.gateway polygon{fill:#fbf4e3;stroke:#b69a4f}`;
