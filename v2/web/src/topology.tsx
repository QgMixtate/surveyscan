import {useCallback,useEffect,useMemo,useRef,useState} from 'react';
import {api,ApiError,errorMessage,type DeviceType,type LinkKind,type MapDocument,type MapPoint,type Topology,type TopologyLink,type TopologyNode} from './api';

// Схема сети (C22, C22.04). Наблюдаемый слой строится центром из фактов инвентаризации; поверх него — общий для
// организации ручной слой: раскладка, свои устройства, связи (кабели), группы-зоны, подписи и переопределения
// типа/имени. Ручной слой хранится в центре с ревизией; правят администраторы и операторы.

type Point={x:number;y:number};
type Shown={id:string;kind:'host'|'subnet'|'gateway'|'manual';label:string;detail?:string;asset_uid?:string;router?:boolean;device:DeviceType|'subnet'|'gateway';observed:boolean;hidden:boolean;x:number;y:number};
type Selection={kind:'node'|'link'|'group'|'note'|'olink';id:string}|null;
type Drag={kind:'pan';x:number;y:number;vx:number;vy:number}|{kind:'move';start:Point;moved:boolean;items:{node?:string;group?:string;note?:string;from:Point}[]}|{kind:'resize';group:string;start:Point;w:number;h:number};

const level:Record<string,string>={confirmed:'подтверждено',probable:'прямое наблюдение',weak:'косвенно'};
const sourceName:Record<string,string>={'interface-address':'адрес на интерфейсе',route:'маршрут/шлюз',lldp:'LLDP',fdb:'таблица MAC','ip-subnet':'общая подсеть'};
export const deviceName:Record<DeviceType,string>={server:'Сервер',workstation:'АРМ',virtual_machine:'Виртуальная машина',hypervisor:'Гипервизор',switch:'Коммутатор',router:'Маршрутизатор',firewall:'Межсетевой экран',access_point:'Точка доступа Wi-Fi',printer:'Принтер / МФУ',storage:'СХД / NAS',cloud:'Облако / Интернет',other:'Другое'};
const deviceTypes=Object.keys(deviceName) as DeviceType[];
const linkName:Record<LinkKind,string>={copper:'Медь (Ethernet)',fiber:'Оптика',wireless:'Беспроводная',trunk:'Транк VLAN',vpn:'VPN-туннель',virtual:'ВМ на гипервизоре',logical:'Логическая'};
const colorName:Record<MapDocument['groups'][number]['color'],string>={green:'Зелёная',blue:'Синяя',amber:'Жёлтая',red:'Красная',gray:'Серая',violet:'Фиолетовая'};
const emptyDoc=():MapDocument=>({positions:{},devices:[],links:[],groups:[],notes:[],overrides:{}});
const newId=()=>'m:'+Math.random().toString(36).slice(2,10)+Date.now().toString(36).slice(-4);
const clone=<T,>(v:T):T=>JSON.parse(JSON.stringify(v));
const round=(p:Point):MapPoint=>({x:Math.round(p.x),y:Math.round(p.y)});

// Значки устройств: рисуются в квадрате 24×24 с центром в (0,0), цвет — от класса узла.
export function DeviceIcon({type}:{type:DeviceType|'subnet'|'gateway'}){
 switch(type){
  case 'server':return <g className="ico"><rect x={-9} y={-10} width={18} height={6} rx={1.5}/><rect x={-9} y={-3} width={18} height={6} rx={1.5}/><rect x={-9} y={4} width={18} height={6} rx={1.5}/><circle className="dot" cx={5} cy={-7} r={1}/><circle className="dot" cx={5} cy={0} r={1}/><circle className="dot" cx={5} cy={7} r={1}/></g>;
  case 'workstation':return <g className="ico"><rect x={-10} y={-9} width={20} height={13} rx={1.5}/><path d="M-4 9h8M0 4v5"/></g>;
  case 'virtual_machine':return <g className="ico"><rect x={-10} y={-9} width={20} height={14} rx={2} strokeDasharray="3 2"/><rect x={-5} y={-5} width={10} height={6} rx={1}/><path d="M-4 9h8"/></g>;
  case 'hypervisor':return <g className="ico"><rect x={-10} y={-10} width={20} height={20} rx={2}/><rect x={-7} y={-7} width={6} height={6} rx={1}/><rect x={1} y={-7} width={6} height={6} rx={1}/><rect x={-7} y={1} width={6} height={6} rx={1}/><rect x={1} y={1} width={6} height={6} rx={1} strokeDasharray="2 1.5"/></g>;
  case 'switch':return <g className="ico"><rect x={-11} y={-6} width={22} height={12} rx={2}/><path d="M-7 -1h3M-2 -1h3M3 -1h3M-7 3h3M-2 3h3M3 3h3"/><path d="M-6 -10h12M3 -12l3 2-3 2M-3 -12l-3 2 3 2"/></g>;
  case 'router':return <g className="ico"><circle r={10}/><path d="M-6 0h12M0 -6v12M4 -3l2 3-2 3M-4 -3l-2 3 2 3M-3 -4l3 -2 3 2M-3 4l3 2 3 -2"/></g>;
  case 'firewall':return <g className="ico"><rect x={-10} y={-9} width={20} height={18} rx={1.5}/><path d="M-10 -3h20M-10 3h20M-4 -9v6M4 -9v6M0 -3v6M-6 3v6M6 3v6"/></g>;
  case 'access_point':return <g className="ico"><circle className="dot" cx={0} cy={6} r={2}/><path d="M-5 1a7 7 0 0 1 10 0M-8 -3a12 12 0 0 1 16 0M-11 -7a17 17 0 0 1 22 0"/></g>;
  case 'printer':return <g className="ico"><rect x={-10} y={-3} width={20} height={9} rx={1.5}/><path d="M-6 -3v-6h12v6M-6 6v4h12v-4"/></g>;
  case 'storage':return <g className="ico"><ellipse cx={0} cy={-7} rx={9} ry={3}/><path d="M-9 -7v14a9 3 0 0 0 18 0v-14M-9 0a9 3 0 0 0 18 0"/></g>;
  case 'cloud':return <g className="ico"><path d="M-8 6h15a5 5 0 0 0 0-10a7 7 0 0 0-13-1a5 5 0 0 0-2 11z"/></g>;
  case 'gateway':return <g className="ico"><path d="M0 -10l10 10-10 10-10-10z"/></g>;
  case 'subnet':return null;
  default:return <g className="ico"><circle r={9}/><circle className="dot" r={2}/></g>;
 }
}

// Начальная раскладка наблюдаемого слоя (без сохранённых позиций): подсети — сетка, хосты — кольца вокруг подсети.
function autoLayout(t:Topology):Map<string,Point>{
 const subnets=t.nodes.filter(n=>n.kind==='subnet').sort((a,b)=>a.label.localeCompare(b.label,undefined,{numeric:true}));
 const member=new Map<string,string[]>();
 for(const l of t.links)if(l.a.startsWith('host:')&&l.b.startsWith('subnet:')){const list=member.get(l.a)??[];if(!list.includes(l.b))list.push(l.b);member.set(l.a,list)}
 const gwOf=new Map<string,string>();for(const l of t.links)if(l.role==='gateway'&&l.b.startsWith('gw:'))gwOf.set(l.b,l.a);
 const single=new Map<string,string[]>(),multi:string[]=[],orphan:string[]=[];
 for(const n of t.nodes.filter(n=>n.kind==='host')){const s=(member.get(n.id)??[]).sort();if(!s.length)orphan.push(n.id);else if(s.length>1||n.router)multi.push(n.id);if(s.length){const list=single.get(s[0])??[];if(!(s.length>1||n.router))list.push(n.id);single.set(s[0],list)}}
 const ring=(count:number)=>90+Math.min(count,30)*8;
 const rmax=Math.max(110,...subnets.map(s=>ring((single.get(s.id)??[]).length)+((single.get(s.id)??[]).length>30?70:0)));
 const cell=2*rmax+140,cols=Math.max(1,Math.ceil(Math.sqrt(subnets.length||1)));
 const pos=new Map<string,Point>();
 subnets.forEach((s,i)=>pos.set(s.id,{x:cell/2+(i%cols)*cell,y:cell/2+Math.floor(i/cols)*cell}));
 for(const s of subnets){const c=pos.get(s.id)!;const hosts=(single.get(s.id)??[]).sort();hosts.forEach((h,i)=>{const per=30,ri=Math.floor(i/per),inRing=Math.min(per,hosts.length-ri*per);const r=ring(Math.min(hosts.length,per))+ri*70;const a=2*Math.PI*(i%per)/inRing-Math.PI/2;pos.set(h,{x:c.x+r*Math.cos(a),y:c.y+r*Math.sin(a)})})}
 const taken=new Map<string,number>();
 multi.sort().forEach(h=>{const s=(member.get(h)??[]).map(id=>pos.get(id)).filter(Boolean) as Point[];const x=s.reduce((a,p)=>a+p.x,0)/s.length,y=s.reduce((a,p)=>a+p.y,0)/s.length;const key=Math.round(x/40)+':'+Math.round(y/40);const used=taken.get(key)??0;taken.set(key,used+1);pos.set(h,{x:x+(s.length===1?rmax*0.55:0)+(used%2?1:-1)*Math.ceil(used/2)*120,y:s.length===1?y-rmax*0.55:y})});
 let gi=0;for(const [gw,subnet] of gwOf){const c=pos.get(subnet);if(c)pos.set(gw,{x:c.x-rmax*0.6,y:c.y-rmax*0.6-(gi++%3)*20})}
 const baseY=Math.max(1,Math.ceil(subnets.length/cols))*cell+40;
 orphan.sort().forEach((h,i)=>pos.set(h,{x:80+(i%12)*130,y:baseY+Math.floor(i/12)*100}));
 return pos;
}

function nodeDevice(n:TopologyNode):DeviceType|'subnet'|'gateway'{
 if(n.kind==='subnet')return 'subnet';
 if(n.kind==='gateway')return 'gateway';
 const d=n.device;if(d&&d!=='unknown')return d;
 return n.router?'router':'other';
}

export function TopologyView({csrf,canWrite,onOpenAsset,onExpired}:{csrf:string;canWrite:boolean;onOpenAsset:(uid:string)=>void;onExpired:()=>void}){
 const [data,setData]=useState<Topology|null>(null),[error,setError]=useState<unknown>(null),[loading,setLoading]=useState(true),[refresh,setRefresh]=useState(0);
 const [doc,setDoc]=useState<MapDocument>(emptyDoc()),[revision,setRevision]=useState('0'),[savedAt,setSavedAt]=useState<string|null>(null),[dirty,setDirty]=useState(false),[saving,setSaving]=useState(false),[notice,setNotice]=useState<string|null>(null);
 const [edit,setEdit]=useState(false),[linking,setLinking]=useState<string|null|false>(false),[linkKind,setLinkKind]=useState<LinkKind>('copper'),[showHidden,setShowHidden]=useState(false);
 const [selected,setSelected]=useState<Selection>(null),[search,setSearch]=useState(''),[view,setView]=useState({x:0,y:0,k:1}),[pointer,setPointer]=useState<Point|null>(null),[animating,setAnimating]=useState(false);
 const history=useRef<MapDocument[]>([]),drag=useRef<Drag|null>(null),svg=useRef<SVGSVGElement>(null),fitted=useRef(false),anim=useRef(0);

 useEffect(()=>{let active=true;setLoading(true);setError(null);
  Promise.all([api.topology(),api.networkMap()]).then(([t,m])=>{if(!active)return;setData(t);setDoc(m.document);setRevision(m.revision);setSavedAt(m.updated_at);setDirty(false);history.current=[]}).catch(e=>{if(active){setError(e);if(e instanceof ApiError&&e.status===401)onExpired()}}).finally(()=>{if(active)setLoading(false)});
  return()=>{active=false}},[refresh,onExpired]);
 useEffect(()=>{if(!dirty)return;const h=(e:BeforeUnloadEvent)=>{e.preventDefault()};window.addEventListener('beforeunload',h);return()=>window.removeEventListener('beforeunload',h)},[dirty]);
 useEffect(()=>()=>cancelAnimationFrame(anim.current),[]);

 const auto=useMemo(()=>data?autoLayout(data):new Map<string,Point>(),[data]);
 const nodes=useMemo<Shown[]>(()=>{
  const out:Shown[]=[];
  for(const n of data?.nodes??[]){const o=doc.overrides[n.id];const p=doc.positions[n.id]??auto.get(n.id)??{x:40,y:40};
   out.push({id:n.id,kind:n.kind,label:o?.label||n.label,detail:n.detail,asset_uid:n.asset_uid,router:n.router,device:o?.type??nodeDevice(n),observed:true,hidden:!!o?.hidden,x:p.x,y:p.y})}
  for(const d of doc.devices)out.push({id:d.id,kind:'manual',label:d.label,detail:[d.address,d.note].filter(Boolean).join(' · '),device:d.type,observed:false,hidden:false,x:d.at.x,y:d.at.y});
  return out},[data,doc,auto]);
 const byId=useMemo(()=>new Map(nodes.map(n=>[n.id,n])),[nodes]);
 const visible=useMemo(()=>nodes.filter(n=>!n.hidden||showHidden),[nodes,showHidden]);
 const hiddenCount=nodes.length-nodes.filter(n=>!n.hidden).length;

 const world=useCallback((clientX:number,clientY:number):Point=>{const r=svg.current!.getBoundingClientRect();return {x:(clientX-r.left-view.x)/view.k,y:(clientY-r.top-view.y)/view.k}},[view]);
 const center=():Point=>{const r=svg.current?.getBoundingClientRect();return r?{x:(r.width/2-view.x)/view.k,y:(r.height/2-view.y)/view.k}:{x:0,y:0}};
 function fit(){if(!svg.current||!visible.length)return;const xs=[...visible.map(n=>n.x),...doc.groups.flatMap(g=>[g.at.x,g.at.x+g.width]),...doc.notes.map(n=>n.at.x)],ys=[...visible.map(n=>n.y),...doc.groups.flatMap(g=>[g.at.y,g.at.y+g.height]),...doc.notes.map(n=>n.at.y)];
  const minX=Math.min(...xs)-80,maxX=Math.max(...xs)+80,minY=Math.min(...ys)-80,maxY=Math.max(...ys)+80;const w=svg.current.clientWidth||1000,h=svg.current.clientHeight||680;
  const k=Math.min(1.4,Math.max(0.1,Math.min(w/(maxX-minX),h/(maxY-minY))));setView({k,x:(w-(maxX-minX)*k)/2-minX*k,y:(h-(maxY-minY)*k)/2-minY*k})}
 useEffect(()=>{if(data&&!fitted.current&&nodes.length){fitted.current=true;requestAnimationFrame(fit)}});
 function zoom(f:number,cx?:number,cy?:number){const r=svg.current?.getBoundingClientRect();const px=cx??(r?r.width/2:0),py=cy??(r?r.height/2:0);setView(v=>{const k=Math.min(4,Math.max(0.06,v.k*f));return {k,x:px-(px-v.x)*k/v.k,y:py-(py-v.y)*k/v.k}})}

 // Любая правка: снимок для отмены, новая версия документа, признак несохранённых изменений.
 function change(mut:(d:MapDocument)=>void,record=true){setDoc(prev=>{if(record){history.current.push(clone(prev));if(history.current.length>80)history.current.shift()}const next=clone(prev);mut(next);return next});setDirty(true)}
 function undo(){const prev=history.current.pop();if(prev){setDoc(prev);setDirty(true)}}
 const setPos=(d:MapDocument,id:string,p:Point)=>{const dev=d.devices.find(v=>v.id===id);if(dev)dev.at=round(p);else d.positions[id]=round(p)};

 async function save(){setSaving(true);setNotice(null);
  const out=clone(doc);for(const v of out.devices)v.label=v.label.trim()||deviceName[v.type];for(const g of out.groups)g.label=g.label.trim()||'Зона';out.notes=out.notes.filter(n=>n.text.trim());
  try{const m=await api.saveNetworkMap(csrf,revision,out);setRevision(m.revision);setSavedAt(m.updated_at);setDoc(m.document);setDirty(false);setNotice('Схема сохранена');setTimeout(()=>setNotice(n=>n==='Схема сохранена'?null:n),4000)}
  catch(e){if(e instanceof ApiError&&e.status===401)onExpired();setNotice(e instanceof ApiError&&e.status===412?'Схему уже изменил другой пользователь. Нажмите «Обновить», чтобы загрузить его версию (ваши несохранённые правки будут потеряны).':errorMessage(e))}
  finally{setSaving(false)}}
 function discard(){setRefresh(n=>n+1);setSelected(null);setLinking(false)}

 function addDevice(type:DeviceType){const id=newId();const c=center();change(d=>{d.devices.push({id,type,label:deviceName[type],at:round(c)})});setSelected({kind:'node',id})}
 function addGroup(){const id=newId();const c=center();change(d=>{d.groups.push({id,label:'Новая зона',color:'green',at:round({x:c.x-200,y:c.y-140}),width:400,height:280})});setSelected({kind:'group',id})}
 function addNote(){const id=newId();const c=center();change(d=>{d.notes.push({id,text:'Подпись',at:round(c)})});setSelected({kind:'note',id})}
 function removeSelected(){if(!selected)return;const s=selected;change(d=>{
  if(s.kind==='node'){d.devices=d.devices.filter(v=>v.id!==s.id);d.links=d.links.filter(l=>l.a!==s.id&&l.b!==s.id);delete d.positions[s.id]}
  if(s.kind==='link')d.links=d.links.filter(l=>l.id!==s.id);if(s.kind==='group')d.groups=d.groups.filter(g=>g.id!==s.id);if(s.kind==='note')d.notes=d.notes.filter(n=>n.id!==s.id)});setSelected(null)}
 function nodeClick(id:string){
  if(edit&&linking!==false){if(linking===null){setLinking(id);return}if(linking!==id){const lid=newId(),a=linking;change(d=>{d.links.push({id:lid,a,b:id,kind:linkKind})});setSelected({kind:'link',id:lid})}setLinking(null);return}
  setSelected({kind:'node',id})}

 // Авто-раскладка: силовая модель (притяжение по связям, отталкивание по сетке соседей), анимируется ~2 с.
 function relayout(){if(!data)return;cancelAnimationFrame(anim.current);
  const ids=visible.map(n=>n.id);const idx=new Map(ids.map((id,i)=>[id,i]));const P=visible.map(n=>({x:n.x,y:n.y,vx:0,vy:0}));
  const E:[number,number][]=[];for(const l of [...data.links,...doc.links]){const a=idx.get(l.a),b=idx.get(l.b);if(a!==undefined&&b!==undefined)E.push([a,b])}
  history.current.push(clone(doc));setDirty(true);setAnimating(true);let tick=0;const ticks=150,cell=160,ideal=130;
  const step=()=>{const grid=new Map<string,number[]>();P.forEach((p,i)=>{const k=Math.floor(p.x/cell)+':'+Math.floor(p.y/cell);(grid.get(k)??grid.set(k,[]).get(k)!).push(i)});
   const t=1-tick/ticks;
   P.forEach((p,i)=>{const gx=Math.floor(p.x/cell),gy=Math.floor(p.y/cell);for(let dx=-1;dx<=1;dx++)for(let dy=-1;dy<=1;dy++)for(const j of grid.get((gx+dx)+':'+(gy+dy))??[]){if(j<=i)continue;const q=P[j];let x=p.x-q.x,y=p.y-q.y;let d2=x*x+y*y;if(d2<1){x=Math.random()-.5;y=Math.random()-.5;d2=1}if(d2>cell*cell)continue;const f=ideal*ideal/d2*0.9;const d=Math.sqrt(d2);p.vx+=x/d*f;p.vy+=y/d*f;q.vx-=x/d*f;q.vy-=y/d*f}});
   for(const [a,b] of E){const p=P[a],q=P[b];const x=q.x-p.x,y=q.y-p.y;const d=Math.max(1,Math.sqrt(x*x+y*y));const f=(d-ideal)*0.06;p.vx+=x/d*f;p.vy+=y/d*f;q.vx-=x/d*f;q.vy-=y/d*f}
   P.forEach(p=>{const cap=40*t+2;const v=Math.hypot(p.vx,p.vy);const s=v>cap?cap/v:1;p.x+=p.vx*s;p.y+=p.vy*s;p.vx*=0.5;p.vy*=0.5});
   setDoc(prev=>{const next={...prev,positions:{...prev.positions},devices:prev.devices.map(v=>({...v}))};ids.forEach((id,i)=>setPos(next,id,P[i]));return next});
   if(++tick<ticks)anim.current=requestAnimationFrame(step);else{setAnimating(false);requestAnimationFrame(fit)}};
  anim.current=requestAnimationFrame(step)}

 function onPointerDown(e:React.PointerEvent<SVGSVGElement>){
  const el=(e.target as Element);const w=world(e.clientX,e.clientY);
  const handle=el.closest('[data-resize]');if(edit&&handle){const g=doc.groups.find(x=>x.id===handle.getAttribute('data-resize'))!;drag.current={kind:'resize',group:g.id,start:w,w:g.width,h:g.height};return}
  const node=el.closest('[data-node]'),group=el.closest('[data-group]'),note=el.closest('[data-note]');
  if(edit&&linking===false&&node){const id=node.getAttribute('data-node')!;const n=byId.get(id)!;drag.current={kind:'move',start:w,moved:false,items:[{node:id,from:{x:n.x,y:n.y}}]};return}
  if(edit&&note){const id=note.getAttribute('data-note')!;const n=doc.notes.find(x=>x.id===id)!;drag.current={kind:'move',start:w,moved:false,items:[{note:id,from:n.at}]};return}
  if(edit&&group&&!node){const id=group.getAttribute('data-group')!;const g=doc.groups.find(x=>x.id===id)!;const inside=(p:Point)=>p.x>=g.at.x&&p.x<=g.at.x+g.width&&p.y>=g.at.y&&p.y<=g.at.y+g.height;
   drag.current={kind:'move',start:w,moved:false,items:[{group:id,from:g.at},...visible.filter(inside).map(n=>({node:n.id,from:{x:n.x,y:n.y}})),...doc.notes.filter(n=>inside(n.at)).map(n=>({note:n.id,from:n.at}))]};return}
  if(!node&&!note&&!el.closest('[data-link]')&&(!group||!edit))drag.current={kind:'pan',x:e.clientX,y:e.clientY,vx:view.x,vy:view.y}}
 function onPointerMove(e:React.PointerEvent<SVGSVGElement>){
  const d=drag.current;if(linking)setPointer(world(e.clientX,e.clientY));if(!d)return;
  if(d.kind==='pan'){setView(v=>({...v,x:d.vx+e.clientX-d.x,y:d.vy+e.clientY-d.y}));return}
  const w=world(e.clientX,e.clientY);const dx=w.x-d.start.x,dy=w.y-d.start.y;
  if(d.kind==='resize'){change(doc=>{const g=doc.groups.find(x=>x.id===d.group);if(g){g.width=Math.max(80,Math.round(d.w+dx));g.height=Math.max(60,Math.round(d.h+dy))}},false);return}
  if(!d.moved&&Math.hypot(dx,dy)*view.k<4)return;
  if(!d.moved){d.moved=true;history.current.push(clone(doc))}
  change(doc=>{for(const it of d.items){const p={x:it.from.x+dx,y:it.from.y+dy};if(it.node)setPos(doc,it.node,p);if(it.group){const g=doc.groups.find(x=>x.id===it.group);if(g)g.at=round(p)}if(it.note){const n=doc.notes.find(x=>x.id===it.note);if(n)n.at=round(p)}}},false)}
 function onPointerUp(){const d=drag.current;drag.current=null;if(d?.kind==='resize')history.current.push(clone(doc))}
 function onKey(e:React.KeyboardEvent){if(!edit)return;if((e.ctrlKey||e.metaKey)&&e.key.toLowerCase()==='z'){e.preventDefault();undo()}if((e.key==='Delete'||e.key==='Backspace')&&selected&&selected.kind!=='olink'&&!(selected.kind==='node'&&byId.get(selected.id)?.observed)&&!(e.target as Element).closest('input,textarea,select')){e.preventDefault();removeSelected()}if(e.key==='Escape'){setLinking(l=>l===false?false:null);setSelected(null)}}

 const match=search.trim().toLowerCase();
 const evidenceText=useMemo(()=>{const m=new Map<string,string>();for(const l of data?.links??[]){const t=l.evidence.map(e=>e.detail).join(' ').toLowerCase();if(l.role!=='gateway')m.set(l.a,(m.get(l.a)??'')+' '+t)}return m},[data]);
 const hit=(n:Shown)=>!!match&&(n.label.toLowerCase().includes(match)||(n.detail??'').toLowerCase().includes(match)||n.id.toLowerCase().includes(match)||(evidenceText.get(n.id)??'').includes(match));
 const selNode=selected?.kind==='node'?byId.get(selected.id):undefined;
 const related=useMemo(()=>{const s=new Set<string>();if(selNode&&data){s.add(selNode.id);for(const l of [...data.links,...doc.links])if(l.a===selNode.id||l.b===selNode.id){s.add(l.a);s.add(l.b)}}return s},[selNode,data,doc.links]);
 const selLinks:TopologyLink[]=selNode&&data?data.links.filter(l=>l.a===selNode.id||l.b===selNode.id):[];
 const counts=data?{hosts:data.nodes.filter(n=>n.kind==='host').length,manual:doc.devices.length,subnets:data.nodes.filter(n=>n.kind==='subnet').length,links:doc.links.length,conflicts:data.links.filter(l=>l.conflicts?.length).length}:null;

 function exportSvg(){if(!svg.current)return;const c=svg.current.cloneNode(true) as SVGSVGElement;const g=c.querySelector('g.viewport');const b=(svg.current.querySelector('g.viewport') as SVGGElement).getBBox();
  c.setAttribute('xmlns','http://www.w3.org/2000/svg');c.setAttribute('viewBox',`${b.x-40} ${b.y-40} ${b.width+80} ${b.height+80}`);c.setAttribute('width',String(Math.round(b.width+80)));c.setAttribute('height',String(Math.round(b.height+80)));g?.setAttribute('transform','');
  c.querySelectorAll('.map-handle,.rubber').forEach(x=>x.remove());const st=document.createElementNS('http://www.w3.org/2000/svg','style');st.textContent=SVG_STYLE;c.insertBefore(st,c.firstChild);
  const blob=new Blob([new XMLSerializer().serializeToString(c)],{type:'image/svg+xml'});const a=document.createElement('a');a.href=URL.createObjectURL(blob);a.download='surveyscan-network.svg';a.click();setTimeout(()=>URL.revokeObjectURL(a.href),1000)}

 const linkEnds=(a:string,b:string)=>{const p=byId.get(a),q=byId.get(b);if(!p||!q||(!showHidden&&(p.hidden||q.hidden)))return null;return {p,q}};
 const mlink=selected?.kind==='link'?doc.links.find(l=>l.id===selected.id):undefined,mgroup=selected?.kind==='group'?doc.groups.find(g=>g.id===selected.id):undefined,mnote=selected?.kind==='note'?doc.notes.find(n=>n.id===selected.id):undefined;
 const mdev=selNode&&!selNode.observed?doc.devices.find(d=>d.id===selNode.id):undefined;

 return <section className="topology" onKeyDown={onKey}>
  {error?<div className="error" role="alert">{errorMessage(error)}</div>:null}
  {counts?<div className="stats"><div className="stat"><span>Устройства на схеме</span><strong>{counts.hosts+counts.manual}</strong><small>Из реестра: {counts.hosts}{data!.truncated?' (первые 2000)':''} · добавлено вручную: {counts.manual}</small></div><div className="stat"><span>Подсети</span><strong>{counts.subnets}</strong><small>По адресам интерфейсов</small></div><div className="stat"><span>Связи вручную</span><strong>{counts.links}</strong><small>{counts.conflicts?`Конфликтов IP: ${counts.conflicts}`:'Кабели, туннели, ВМ на гипервизорах'}</small></div></div>:null}
  <div className={'table-panel topo-panel'+(edit?' editing':'')}>
   <div className="table-toolbar"><h2>Схема сети <span>{dirty?'есть несохранённые изменения':savedAt?'сохранена '+new Date(savedAt).toLocaleString('ru-RU'):data?'собрана '+new Date(data.generated_at).toLocaleTimeString('ru-RU'):''}</span></h2>
    <div className="filters"><label className="search-field"><span>⌕</span><input aria-label="Найти на схеме" placeholder="Хост, подсеть, IP…" value={search} onChange={e=>setSearch(e.target.value)}/></label>
     <button className="button small" onClick={()=>zoom(1.25)} aria-label="Приблизить">+</button><button className="button small" onClick={()=>zoom(0.8)} aria-label="Отдалить">−</button><button className="button small" onClick={fit} title="Показать всю схему">⤢ Вся схема</button>
     {hiddenCount?<button className="button small" aria-pressed={showHidden} onClick={()=>setShowHidden(v=>!v)}>{showHidden?'Скрыть':'Показать'} скрытые ({hiddenCount})</button>:null}
     <button className="button small" onClick={discard} disabled={loading||saving}>↻ Обновить</button><button className="button small" onClick={exportSvg} disabled={!visible.length}>Экспорт SVG</button>
     {canWrite?<button className={'button small'+(edit?' primary-small':'')} aria-pressed={edit} onClick={()=>{setEdit(v=>!v);setLinking(false)}}>{edit?'✓ Готово':'✎ Редактировать'}</button>:null}</div></div>
   {edit?<div className="map-toolbar" role="toolbar" aria-label="Редактирование схемы">
    <label className="map-add"><span>+ Устройство</span><select aria-label="Добавить устройство" value="" onChange={e=>{if(e.target.value)addDevice(e.target.value as DeviceType)}}><option value="">выберите тип…</option>{deviceTypes.map(t=><option key={t} value={t}>{deviceName[t]}</option>)}</select></label>
    <button className={'button small'+(linking!==false?' primary-small':'')} aria-pressed={linking!==false} onClick={()=>setLinking(l=>l===false?null:false)}>⟷ Связь</button>
    {linking!==false?<select aria-label="Тип новой связи" value={linkKind} onChange={e=>setLinkKind(e.target.value as LinkKind)}>{(Object.keys(linkName) as LinkKind[]).map(k=><option key={k} value={k}>{linkName[k]}</option>)}</select>:null}
    <button className="button small" onClick={addGroup}>▢ Зона</button><button className="button small" onClick={addNote}>✎ Подпись</button>
    <button className="button small" onClick={relayout} disabled={animating||!visible.length}>✦ Разложить</button>
    <button className="button small" onClick={undo} disabled={!history.current.length} title="Ctrl+Z">↶ Отменить</button>
    <span className="map-hint">{linking===null?'Связь: выберите первый узел':linking?'Связь: выберите второй узел (Esc — отмена)':'Перетаскивайте узлы, зоны и подписи; угол зоны меняет её размер'}</span>
    <span className="map-save"><button className="button small" onClick={discard} disabled={!dirty||saving}>Отменить всё</button><button className="button small primary-small" onClick={()=>void save()} disabled={!dirty||saving||animating}>{saving?'Сохраняем…':'Сохранить схему'}</button></span>
   </div>:null}
   {notice?<div className={notice==='Схема сохранена'?'map-notice ok':'map-notice'} role="status">{notice}</div>:null}
   <div className="topo-body">
    {loading&&!data?<div className="empty" role="status">Строим схему…</div>:data&&!nodes.length&&!edit?<div className="empty"><span>⌘</span><h3>Схема пока пуста</h3><p>Схема строится из адресов интерфейсов, которые сообщают агенты, цели сбора и portable-аудит. Устройства без инвентаризации (коммутаторы, межсетевые экраны) можно добавить вручную — кнопка «Редактировать».</p></div>:
    <svg ref={svg} className={'topo-svg'+(linking!==false?' linking':'')} role="img" aria-label="Схема сети" tabIndex={0} onWheel={e=>{const r=svg.current!.getBoundingClientRect();zoom(e.deltaY<0?1.12:0.89,e.clientX-r.left,e.clientY-r.top)}} onPointerDown={onPointerDown} onPointerMove={onPointerMove} onPointerUp={onPointerUp} onPointerCancel={onPointerUp} onPointerLeave={onPointerUp}
     onClick={e=>{if(!(e.target as Element).closest('[data-node],[data-link],[data-group],[data-note]')){setSelected(null);if(linking)setLinking(null)}}}>
     <defs><pattern id="map-grid" width={40} height={40} patternUnits="userSpaceOnUse"><path d="M40 0H0V40" className="grid-line"/></pattern></defs>
     <g className="viewport" transform={`translate(${view.x},${view.y}) scale(${view.k})`}>
      {edit?<rect className="grid-bg map-handle" x={-1e5} y={-1e5} width={2e5} height={2e5} fill="url(#map-grid)"/>:null}
      {doc.groups.map(g=><g key={g.id} data-group={g.id} className={'map-group '+g.color+(selected?.id===g.id?' selected':'')} onClick={e=>{e.stopPropagation();setSelected({kind:'group',id:g.id})}}>
       <rect x={g.at.x} y={g.at.y} width={g.width} height={g.height} rx={14}/><text x={g.at.x+14} y={g.at.y+22}>{g.label}</text>
       {edit?<rect data-resize={g.id} className="map-handle resize" x={g.at.x+g.width-14} y={g.at.y+g.height-14} width={14} height={14} rx={3}/>:null}</g>)}
      {data!.links.map((l,i)=>{const e=linkEnds(l.a,l.b);if(!e)return null;const dim=selNode&&!(related.has(l.a)&&related.has(l.b));return <line key={'o'+i} x1={e.p.x} y1={e.p.y} x2={e.q.x} y2={e.q.y} className={'topo-link '+l.confidence+(l.role==='gateway'?' gateway':'')+(l.conflicts?.length?' conflict':'')+(dim?' dim':'')}/>})}
      {doc.links.map(l=>{const e=linkEnds(l.a,l.b);if(!e)return null;const dim=selNode&&!(related.has(l.a)&&related.has(l.b));const mx=(e.p.x+e.q.x)/2,my=(e.p.y+e.q.y)/2;const ux=(e.q.x-e.p.x),uy=(e.q.y-e.p.y),len=Math.max(1,Math.hypot(ux,uy));
       return <g key={l.id} data-link={l.id} className={'map-link '+l.kind+(selected?.id===l.id?' selected':'')+(dim?' dim':'')} onClick={ev=>{ev.stopPropagation();setSelected({kind:'link',id:l.id})}}>
        <line className="hit" x1={e.p.x} y1={e.p.y} x2={e.q.x} y2={e.q.y}/>{l.kind==='trunk'?<line className="under" x1={e.p.x} y1={e.p.y} x2={e.q.x} y2={e.q.y}/>:null}<line className="stroke" x1={e.p.x} y1={e.p.y} x2={e.q.x} y2={e.q.y}/>
        {l.label?<text x={mx} y={my-6}>{l.label}</text>:null}{l.port_a?<text className="port" x={e.p.x+ux/len*38} y={e.p.y+uy/len*38-4}>{l.port_a}</text>:null}{l.port_b?<text className="port" x={e.q.x-ux/len*38} y={e.q.y-uy/len*38-4}>{l.port_b}</text>:null}</g>})}
      {linking&&pointer&&byId.get(linking)?<line className="rubber" x1={byId.get(linking)!.x} y1={byId.get(linking)!.y} x2={pointer.x} y2={pointer.y}/>:null}
      {visible.map(n=>{const dim=(selNode&&!related.has(n.id))||(match&&!hit(n));const cls='topo-node '+(n.kind==='manual'?'host manual':n.kind)+' dev-'+n.device+(n.router?' router':'')+(selected?.id===n.id?' selected':'')+(linking===n.id?' link-from':'')+(hit(n)?' hit':'')+(dim?' dim':'')+(n.hidden?' is-hidden':'');
       const label=n.label.length>24?n.label.slice(0,23)+'…':n.label;
       return <g key={n.id} data-node={n.id} className={cls} transform={`translate(${n.x},${n.y})`} tabIndex={0} role="button" aria-label={(n.kind==='subnet'?'Подсеть ':n.kind==='gateway'?'Шлюз ':(deviceName[n.device as DeviceType]??'Узел')+' ')+n.label}
        onClick={e=>{e.stopPropagation();nodeClick(n.id)}} onDoubleClick={()=>n.asset_uid&&onOpenAsset(n.asset_uid)} onKeyDown={e=>{if(e.key==='Enter')nodeClick(n.id)}}>
        {n.kind==='subnet'?<><rect className="pill" x={-66} y={-18} width={132} height={36} rx={18}/><text className="name" y={5}>{n.label}</text></>:
         <><rect className="tile" x={-21} y={-21} width={42} height={42} rx={n.device==='router'||n.device==='gateway'?21:10}/><DeviceIcon type={n.device}/>{n.kind==='manual'?<circle className="manual-mark" cx={17} cy={-17} r={4}/>:null}<text className="name" y={36}>{label}</text></>}
       </g>})}
      {doc.notes.map(n=><g key={n.id} data-note={n.id} className={'map-note'+(selected?.id===n.id?' selected':'')} transform={`translate(${n.at.x},${n.at.y})`} onClick={e=>{e.stopPropagation();setSelected({kind:'note',id:n.id})}}>{n.text.split('\n').slice(0,8).map((line,i)=><text key={i} y={i*16}>{line}</text>)}</g>)}
     </g>
    </svg>}
    <aside className="topo-side">
     {mdev&&edit?<div className="form-stack">
      <span className="eyebrow muted">Устройство (добавлено вручную)</span>
      <label className="field"><span>Тип</span><select value={mdev.type} onChange={e=>change(d=>{d.devices.find(v=>v.id===mdev.id)!.type=e.target.value as DeviceType})}>{deviceTypes.map(t=><option key={t} value={t}>{deviceName[t]}</option>)}</select></label>
      <label className="field"><span>Название</span><input value={mdev.label} maxLength={120} onChange={e=>change(d=>{d.devices.find(v=>v.id===mdev.id)!.label=e.target.value||' '})}/></label>
      <label className="field"><span>Адрес</span><input value={mdev.address??''} maxLength={120} placeholder="IP, имя или расположение" onChange={e=>change(d=>{d.devices.find(v=>v.id===mdev.id)!.address=e.target.value||undefined})}/></label>
      <label className="field"><span>Заметка</span><textarea rows={3} value={mdev.note??''} maxLength={1000} onChange={e=>change(d=>{d.devices.find(v=>v.id===mdev.id)!.note=e.target.value||undefined})}/></label>
      <button className="button small danger" onClick={removeSelected}>Удалить устройство и его связи</button></div>
     :mlink&&edit?<div className="form-stack">
      <span className="eyebrow muted">Связь</span><p className="panel-note">{byId.get(mlink.a)?.label??mlink.a} ⟷ {byId.get(mlink.b)?.label??mlink.b}</p>
      <label className="field"><span>Тип связи</span><select value={mlink.kind} onChange={e=>change(d=>{d.links.find(l=>l.id===mlink.id)!.kind=e.target.value as LinkKind})}>{(Object.keys(linkName) as LinkKind[]).map(k=><option key={k} value={k}>{linkName[k]}</option>)}</select></label>
      <label className="field"><span>Порт у «{byId.get(mlink.a)?.label??'А'}»</span><input value={mlink.port_a??''} maxLength={64} placeholder="Gi0/1, eth0…" onChange={e=>change(d=>{d.links.find(l=>l.id===mlink.id)!.port_a=e.target.value||undefined})}/></label>
      <label className="field"><span>Порт у «{byId.get(mlink.b)?.label??'Б'}»</span><input value={mlink.port_b??''} maxLength={64} onChange={e=>change(d=>{d.links.find(l=>l.id===mlink.id)!.port_b=e.target.value||undefined})}/></label>
      <label className="field"><span>Подпись</span><input value={mlink.label??''} maxLength={120} placeholder="10G, VLAN 20…" onChange={e=>change(d=>{d.links.find(l=>l.id===mlink.id)!.label=e.target.value||undefined})}/></label>
      <button className="button small danger" onClick={removeSelected}>Удалить связь</button></div>
     :mgroup&&edit?<div className="form-stack">
      <span className="eyebrow muted">Зона</span>
      <label className="field"><span>Название</span><input value={mgroup.label} maxLength={120} onChange={e=>change(d=>{d.groups.find(g=>g.id===mgroup.id)!.label=e.target.value||' '})}/></label>
      <label className="field"><span>Цвет</span><select value={mgroup.color} onChange={e=>change(d=>{d.groups.find(g=>g.id===mgroup.id)!.color=e.target.value as typeof mgroup.color})}>{(Object.keys(colorName) as (keyof typeof colorName)[]).map(c=><option key={c} value={c}>{colorName[c]}</option>)}</select></label>
      <p className="panel-note">Перетаскивание зоны двигает всё, что внутри неё. Размер — за правый нижний угол.</p>
      <button className="button small danger" onClick={removeSelected}>Удалить зону</button></div>
     :mnote&&edit?<div className="form-stack">
      <span className="eyebrow muted">Подпись</span>
      <label className="field"><span>Текст</span><textarea rows={4} value={mnote.text} maxLength={1000} onChange={e=>change(d=>{d.notes.find(n=>n.id===mnote.id)!.text=e.target.value||' '})}/></label>
      <button className="button small danger" onClick={removeSelected}>Удалить подпись</button></div>
     :selNode?<>
      <span className="eyebrow muted">{selNode.kind==='subnet'?'Подсеть':selNode.kind==='gateway'?'Шлюз':deviceName[selNode.device as DeviceType]??'Узел'}{selNode.observed?'':' · добавлено вручную'}</span><h3>{selNode.label}</h3>{selNode.detail?<p>{selNode.detail}</p>:null}
      {selNode.asset_uid?<button className="button small" onClick={()=>onOpenAsset(selNode.asset_uid!)}>Открыть карточку актива</button>:null}
      {edit&&selNode.observed&&selNode.kind!=='subnet'?<div className="form-stack">
       <label className="field"><span>Тип на схеме</span><select value={doc.overrides[selNode.id]?.type??''} onChange={e=>change(d=>{const o={...d.overrides[selNode.id]};if(e.target.value)o.type=e.target.value as DeviceType;else delete o.type;if(o.type||o.label||o.hidden)d.overrides[selNode.id]=o;else delete d.overrides[selNode.id]})}><option value="">Как определено по данным</option>{deviceTypes.map(t=><option key={t} value={t}>{deviceName[t]}</option>)}</select></label>
       <label className="field"><span>Имя на схеме</span><input value={doc.overrides[selNode.id]?.label??''} maxLength={120} placeholder="Как в реестре" onChange={e=>change(d=>{const o={...d.overrides[selNode.id]};if(e.target.value)o.label=e.target.value;else delete o.label;if(o.type||o.label||o.hidden)d.overrides[selNode.id]=o;else delete d.overrides[selNode.id]})}/></label>
      </div>:null}
      {edit&&selNode.observed?<button className="button small" onClick={()=>change(d=>{const o={...d.overrides[selNode.id]};o.hidden=!o.hidden;if(!o.hidden)delete o.hidden;if(o.type||o.label||o.hidden)d.overrides[selNode.id]=o;else delete d.overrides[selNode.id]})}>{selNode.hidden?'Показать на схеме':'Скрыть со схемы'}</button>:null}
      {selLinks.length?<h4>Связи · доказательства</h4>:null}
      {selLinks.map((l,i)=>{const other=byId.get(l.a===selNode.id?l.b:l.a);return <article key={i} className={l.conflicts?.length?'conflict':''}><strong>{other?.label??(l.a===selNode.id?l.b:l.a)}{l.role==='gateway'?' · шлюз':''}</strong><small>{l.layer} · {level[l.confidence]??l.confidence}</small>{l.evidence.map((ev,j)=><small key={j}>{sourceName[ev.source]??ev.source}: {ev.detail}{ev.origin?<span className="mono"> · источник {ev.origin.slice(0,8)}</span>:null}</small>)}{l.conflicts?.map((c,j)=><small key={j} className="conflict-text">⚠ {c}</small>)}</article>})}
      {doc.links.filter(l=>l.a===selNode.id||l.b===selNode.id).map(l=><article key={l.id}><strong>{byId.get(l.a===selNode.id?l.b:l.a)?.label??'—'}</strong><small>{linkName[l.kind]}{l.port_a||l.port_b?` · ${l.port_a??'?'} ⟷ ${l.port_b??'?'}`:''}{l.label?' · '+l.label:''} · вручную</small></article>)}
     </>:mlink||mgroup||mnote?<><span className="eyebrow muted">{mlink?'Связь':mgroup?'Зона':'Подпись'}</span><h3>{mlink?linkName[mlink.kind]:mgroup?mgroup.label:mnote!.text}</h3>{mlink?<p>{byId.get(mlink.a)?.label} ⟷ {byId.get(mlink.b)?.label}{mlink.port_a||mlink.port_b?` · ${mlink.port_a??'?'} ⟷ ${mlink.port_b??'?'}`:''}</p>:null}{canWrite?<p className="card-note">Изменить — кнопка «Редактировать».</p>:null}</>
     :<>
      <span className="eyebrow muted">Обозначения</span>
      <div className="map-legend">{(['server','workstation','virtual_machine','hypervisor','switch','router','firewall','access_point','storage','printer','cloud'] as DeviceType[]).map(t=><span key={t}><svg width={30} height={30} viewBox="-15 -15 30 30" className={'topo-node legend dev-'+t}><rect className="tile" x={-14} y={-14} width={28} height={28} rx={t==='router'?14:7}/><g transform="scale(0.85)"><DeviceIcon type={t}/></g></svg>{deviceName[t]}</span>)}</div>
      <div className="legend"><span><i className="lg subnet"/>Подсеть (по адресам интерфейсов)</span><span><i className="lg gateway"/>Шлюз, не найденный в реестре</span><span><i className="lg line"/>Адрес на интерфейсе</span><span><i className="lg line gw"/>Маршрут по умолчанию</span><span><i className="lg line bad"/>Конфликт: один IP у разных активов</span><span><i className="lg line manual"/>Связь, проведённая вручную</span></div>
      <p className="card-note">Узлы из реестра строятся по фактам инвентаризации, сеть не опрашивается. Тип устройства определяется по ОС, модели оборудования и ПО виртуализации; его можно поправить на схеме. Колесо мыши — масштаб, перетаскивание фона — сдвиг, двойной щелчок по хосту — карточка актива.{canWrite?' «Редактировать» — раскладка, свои устройства, кабели, зоны и подписи; изменения общие для всей организации.':''}</p>
     </>}
    </aside>
   </div>
  </div>
 </section>;
}

// Стили экспортируемого SVG (в приложении те же правила задаёт style.css).
const SVG_STYLE=`text{font:11px sans-serif}.topo-link{stroke:#b9c8b3;stroke-width:1.4}.topo-link.weak{stroke-dasharray:4 4}.topo-link.gateway{stroke:#3f7a5c;stroke-width:2.4;stroke-dasharray:7 4}.topo-link.conflict{stroke:#c0634f;stroke-width:2.4}.topo-node .name{fill:#2d4636;text-anchor:middle}.topo-node .pill{fill:#e8f2e4;stroke:#7fa877}.topo-node.subnet .name{font-weight:600}.topo-node .tile{fill:#fff;stroke:#c9d6c3}.ico{fill:none;stroke:#3f6b52;stroke-width:1.6;stroke-linecap:round;stroke-linejoin:round}.ico .dot{fill:#3f6b52;stroke:none}.dev-switch .tile,.dev-router .tile{fill:#214d3b;stroke:#214d3b}.dev-switch .ico,.dev-router .ico{stroke:#fff}.dev-firewall .ico{stroke:#b0503c}.dev-hypervisor .ico,.dev-virtual_machine .ico{stroke:#6b4fa0}.dev-server .ico{stroke:#2f6f8f}.dev-gateway .tile{fill:#fbf4e3;stroke:#b69a4f}.dev-gateway .ico{stroke:#b69a4f}.manual-mark{fill:#e0a23b}.map-group rect{fill:#f2f7f0;stroke:#9fbf98;stroke-dasharray:6 4}.map-group.blue rect{fill:#eef4fa;stroke:#8fb0cc}.map-group.amber rect{fill:#fcf6e8;stroke:#d2b56a}.map-group.red rect{fill:#fbefec;stroke:#d39a8c}.map-group.gray rect{fill:#f3f4f2;stroke:#b5bcb2}.map-group.violet rect{fill:#f4f0fa;stroke:#ac98cf}.map-group text{font-weight:600;fill:#4f6a57;font-size:13px}.map-link .hit{display:none}.map-link .stroke{stroke:#40594a;stroke-width:2}.map-link.fiber .stroke{stroke:#d07a2c;stroke-width:2.6}.map-link.wireless .stroke{stroke-dasharray:2 5;stroke-linecap:round}.map-link.trunk .under{stroke:#40594a;stroke-width:6}.map-link.trunk .stroke{stroke:#fff;stroke-width:2}.map-link.vpn .stroke{stroke:#7a5bb5;stroke-dasharray:8 4}.map-link.virtual .stroke{stroke:#8a6fc0;stroke-dasharray:3 3}.map-link.logical .stroke{stroke:#9aa892;stroke-width:1.2;stroke-dasharray:1 4}.map-link text{fill:#40594a;text-anchor:middle;font-size:10px}.map-note text{fill:#40594a;font-size:13px}`;
