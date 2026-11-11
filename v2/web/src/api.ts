import validators from './generated/wire.cjs';
import type {components as DetailComponents} from './generated/c09';
export type InventoryDetail=DetailComponents['schemas']['InventoryDetail'];
import type { components } from './generated/c03';

export type Asset=components['schemas']['Asset'];
export type AssetPage=components['schemas']['AssetPage'];
export type Source=components['schemas']['Source'];
export type SourcePage=components['schemas']['SourcePage'];
export type SourceProfile={tenant_id:string;source_id:string;source_state:string;managed:boolean;config:{profile_revision:string;heartbeat_seconds:number;inventory_seconds:number;spool_limit_bytes:number};applied_revision:string|null;last_config_contact_at:string|null;last_contact_at:string|null;last_successful_inventory_at:string|null};
export type Session=components['schemas']['Session'];
export type FactEvidence12={observation_id:string;origin:{source_id:string;source_kind:'agent'|'collector'|'portable';generation_id:string};source_sequence:string;collected_at:string;clock_quality:string};
export type RecordPage12={section:string;projection_revision:string;section_state:{status:string;clock_uncertain:boolean;last_attempt:FactEvidence12}|null;items:{record_key:string;field:string;value:unknown;evidence:FactEvidence12}[];next_cursor:string|null};
export type TopologyNode={id:string;kind:'host'|'subnet'|'gateway';label:string;detail?:string;asset_uid?:string;router?:boolean};
export type TopologyLink={a:string;b:string;role?:'gateway';layer:'L2'|'L3';confidence:'confirmed'|'probable'|'weak';evidence:{source:string;detail:string;origin?:string}[];conflicts?:string[]};
export type Conflict={conflict_id:string;reason_code:string;state:'open'|'resolved'|'dismissed';revision:string;source_record_key:string;source_id:string;namespace:string;source_local_id:string;resolution_state:string;asset_uid:string|null;candidate_asset_uids:string[];pending_observations:number;observed_hostname?:string};
export type ConflictPage={tenant_id:string;state:string;items:Conflict[];next_cursor:string|null};
export type ConflictResult={conflict_id:string;action:string;asset_uid:string|null;replayed_observations:number};
export type Topology={tenant_id:string;generated_at:string;nodes:TopologyNode[];links:TopologyLink[];truncated:boolean;hosts_with_network_facts:number};
export class ApiError extends Error {
 constructor(public status:number,public code:string,public requestId?:string){super(code)}
}
const messages:Record<string,string>={CONFLICT:'Состояние изменилось: обновите список.',INVALID_RESOLUTION:'Это действие недоступно для выбранного конфликта.',AUTHENTICATION_REQUIRED:'Сессия завершилась. Войдите снова.',INVALID_CREDENTIALS:'Не удалось войти. Проверьте имя и пароль.',FORBIDDEN:'Недостаточно прав для этого действия.',NOT_FOUND:'Объект не найден или недоступен.',REVISION_MISMATCH:'Карточка изменилась. Обновите данные.',RATE_LIMITED:'Слишком много запросов. Повторите немного позже.',CONTRACT_MISMATCH:'Версии интерфейса и API несовместимы. Обратитесь к администратору.',INVALID_RESPONSE:'Сервер вернул ответ неизвестного формата.',NETWORK_ERROR:'Нет связи с сервером. Проверьте соединение.',CAPABILITY_NOT_ENABLED:'Эта возможность пока недоступна.'};
export function errorMessage(error:unknown){return error instanceof ApiError?(messages[error.code]??'Не удалось выполнить запрос. Повторите позже.'):'Не удалось выполнить запрос. Повторите позже.'}
async function call<T>(path:string,name:string|undefined,init:RequestInit={}):Promise<T>{
 let response:Response;
 try{response=await fetch(path,{...init,credentials:'same-origin',cache:'no-store',signal:AbortSignal.timeout(15000),headers:{Accept:'application/json',...(init.body?{'Content-Type':'application/json'}:{}),...init.headers}})}catch{throw new ApiError(0,'NETWORK_ERROR')}
 const raw=await response.text();if(raw.length>1048576)throw new ApiError(response.status,'INVALID_RESPONSE');
 let value:unknown;try{value=raw?JSON.parse(raw):undefined}catch{throw new ApiError(response.status,'INVALID_RESPONSE')}
 if(!response.ok){const error=value as {code?:string;request_id?:string}|undefined;throw new ApiError(response.status,error?.code??'REQUEST_FAILED',error?.request_id)}
 if(name){const check=validators[name];if(!check?.(value))throw new ApiError(response.status,'INVALID_RESPONSE')}
 return value as T;
}
export const api={
 login:(username:string,password:string)=>call<Session>('/api/v1/auth/sessions','Session',{method:'POST',body:JSON.stringify({username,password})}),
 logout:(csrf:string)=>call<void>('/api/v1/auth/session',undefined,{method:'DELETE',headers:{'X-CSRF-Token':csrf}}),
 assets:(cursor:string|null=null)=>call<AssetPage>('/api/v1/assets?limit=50'+(cursor?'&cursor='+encodeURIComponent(cursor):''),'AssetPage'),
 asset:(uid:string)=>call<Asset>('/api/v1/assets/'+encodeURIComponent(uid),'Asset'),
 inventory:(uid:string)=>call<InventoryDetail>('/api/v1/assets/'+encodeURIComponent(uid)+'/inventory','InventoryDetail'),
 profile:(source:string)=>call<SourceProfile>('/api/v1/sources/'+encodeURIComponent(source)+'/profile','SourceProfile'),
 records12:(uid:string,section:string,cursor:string|null=null)=>call<RecordPage12>('/api/v1/assets/'+encodeURIComponent(uid)+'/inventory/facts/'+encodeURIComponent(section)+'?limit=100'+(cursor?'&cursor='+encodeURIComponent(cursor):''),'RecordFactPage12'),
 conflicts:(state:string,cursor:string|null=null)=>call<ConflictPage>('/api/v1/reconciliation/conflicts?state='+encodeURIComponent(state)+'&limit=50'+(cursor?'&cursor='+encodeURIComponent(cursor):''),'ConflictPage'),
 resolveConflict:(id:string,csrf:string,body:{action:string;asset_uid?:string;revision?:string})=>call<ConflictResult>('/api/v1/reconciliation/conflicts/'+encodeURIComponent(id)+'/resolve','ConflictResult',{method:'POST',body:JSON.stringify(body),headers:{'X-CSRF-Token':csrf}}),
 topology:()=>call<Topology>('/api/v1/topology','Topology'),
 sources:(cursor:string|null=null)=>call<SourcePage>('/api/v1/sources?limit=50'+(cursor?'&cursor='+encodeURIComponent(cursor):''),'SourcePage')
};
export async function checkCompatibility(){
 try{
 const [manifest,contract,extension]=await Promise.all([fetch('/version.json',{cache:'no-store'}),fetch('/contracts/openapi.json',{cache:'no-store'}),fetch('/contracts/c09.openapi.json',{cache:'no-store'})]);
 if(!manifest.ok||!contract.ok||!extension.ok)throw new Error();
 const version=await manifest.json() as {wire?:{major:number;minor:number};openapi_sha256?:string;c09_version?:string;c09_sha256?:string};
 async function digest(response:Response){const bytes=await response.arrayBuffer();if(bytes.byteLength>1048576)throw new Error();return Array.from(new Uint8Array(await crypto.subtle.digest('SHA-256',bytes)),n=>n.toString(16).padStart(2,'0')).join('')}
 if(version.wire?.major!==1||version.wire?.minor!==0||version.c09_version!=='1.0'||version.openapi_sha256!==await digest(contract)||version.c09_sha256!==await digest(extension))throw new Error();
 }catch{throw new ApiError(0,'CONTRACT_MISMATCH')}
}
