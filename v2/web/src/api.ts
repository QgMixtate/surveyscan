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
export type RecordPage12={section:string;projection_revision:string;section_state:{status:string;clock_uncertain:boolean;last_attempt:FactEvidence12;sources?:{source_id:string;status:string;collected_at:string}[]}|null;items:{record_key:string;field:string;value:unknown;evidence:FactEvidence12}[];next_cursor:string|null};
export type TopologyNode={id:string;kind:'host'|'subnet'|'gateway';label:string;detail?:string;asset_uid?:string;router?:boolean};
export type TopologyLink={a:string;b:string;role?:'gateway';layer:'L2'|'L3';confidence:'confirmed'|'probable'|'weak';evidence:{source:string;detail:string;origin?:string}[];conflicts?:string[]};
export type Conflict={conflict_id:string;reason_code:string;state:'open'|'resolved'|'dismissed';revision:string;source_record_key:string;source_id:string;namespace:string;source_local_id:string;resolution_state:string;asset_uid:string|null;candidate_asset_uids:string[];pending_observations:number;observed_hostname?:string};
export type ConflictPage={tenant_id:string;state:string;items:Conflict[];next_cursor:string|null};
export type ConflictResult={conflict_id:string;action:string;asset_uid:string|null;replayed_observations:number};
export type SourceRecord={source_record_key:string;source_id:string;namespace:string;source_local_id:string;observations:number};
export type SourceRecordPage={tenant_id:string;asset_uid:string;version:string;items:SourceRecord[]};
export type AssetOperation={operation_id:string;kind:'merge'|'split';from_asset_uid:string;to_asset_uid:string;created:boolean;moved_records:number;relinked_observations:number;rebuilt_observations:number};
export type Evidence={observation_id:string;source_id:string;source_kind:'agent'|'collector'|'portable';collected_at:string;clock_quality:string};
export type AssetClassName='server'|'workstation'|'network_device'|'printer'|'virtual_machine'|'unknown';
export type CIEnd={kind:'asset'|'service';id:string};
export type Relation={relation_id:string;relation_type:'runs_on'|'uses'|'depends_on'|'hosts'|'connected_to';from:CIEnd;to:CIEnd;origin:'manual'|'observed';confidence:'confirmed'|'probable'|'weak';note:string|null;valid_from:string;valid_to:string|null;actor_ref:string};
export type AssetCMDB={tenant_id:string;asset_uid:string;class:{observed:AssetClassName;observed_reason:string;manual:AssetClassName|null;effective:AssetClassName};business_revision:string;software_count:number;component_count:number;relations:Relation[]};
export type Installation={record_key:string;name:string|null;version:string|null;publisher:string|null;architecture:string|null;package_source:string|null;evidence:Evidence};
export type SoftwarePage={tenant_id:string;asset_uid:string;items:Installation[];next_cursor:string|null};
export type Component={section:'hardware'|'resources';record_key:string;kind:string|null;name:string|null;vendor:string|null;model:string|null;serial:string|null;size_bytes:string|null;evidence:Evidence};
export type ComponentList={tenant_id:string;asset_uid:string;items:Component[]};
export type Product={name:string;publisher:string|null;installations:number;assets:number;versions:string[];asset_uids:string[]};
export type ProductList={tenant_id:string;query:string;items:Product[]};
export type CIService={service_uid:string;name:string;description:string|null;criticality:'unknown'|'low'|'medium'|'high'|'critical';revision:string;created_at:string;retired_at:string|null};
export type ServicePage={tenant_id:string;items:CIService[];next_cursor:string|null};
export type ServiceDetail=CIService&{tenant_id:string;relations:Relation[]};
export type RoleName='accountable'|'business_owner'|'technical'|'custodian';
export type Subject={subject_id:string;kind:'person'|'team';name:string;contact:string;active:boolean;username:string|null;revision:string;site_fallback:boolean;members:number;origin:'local'|'ldap';synced_at:string|null};
export type SubjectPage={tenant_id:string;items:Subject[];next_cursor:string|null};
export type SubjectResult={subject:Subject;reassigned_assignments:number};
export type Assignment={role:RoleName;subject_id:string;subject_name:string;subject_kind:'person'|'team';valid_from:string;valid_to:string|null;reason_code:string;note:string|null;actor_ref:string};
export type AssetAssignments={tenant_id:string;asset_uid:string;version:string;active:Assignment[];history:Assignment[]};
export type BulkAssignResult={applied:number;unchanged:number;stale_asset_uids:string[]};
export type WorklistItem={asset_uid:string;version:string;display_name:string|null;observed_hostname:string|null;assignments:Assignment[]};
export type WorklistPage={tenant_id:string;scope:'mine'|'team'|'unassigned'|'attention';items:WorklistItem[];next_cursor:string|null};
export type SearchItem={asset_uid:string;display_name:string|null;observed_hostname:string|null;observed_os:string|null;score:number|null;fragment:string;highlights:[number,number][]};
export type SearchPage={tenant_id:string;query:string;mode:'fulltext'|'fallback_exact';notice?:string;pending_index_events:number;items:SearchItem[];facets:{os:Record<string,number>;class:Record<string,number>};next_cursor:string|null};
export type Topology={tenant_id:string;generated_at:string;nodes:TopologyNode[];links:TopologyLink[];truncated:boolean;hosts_with_network_facts:number};
export type SyncCounters={people_seen?:number;teams_seen?:number;created?:number;updated?:number;deactivated?:number;reactivated?:number;members_added?:number;members_removed?:number;logins_linked?:number;assignments_reassigned?:number;problems?:string[]};
export type SyncRun={run_id:string;mode:'full'|'incremental';started_at:string;finished_at:string;status:'succeeded'|'failed';counters:SyncCounters;error:string|null};
export type DirectorySyncStatus={tenant_id:string;configured:boolean;source:string|null;interval_minutes:number;full_sync_hours:number;teams_enabled:boolean;runs:SyncRun[]};
export type CSVRowResult={line:number;asset_uid:string;status:'applied'|'unchanged'|'stale_revision'|'not_found'|'invalid';field:string|null;business_revision:string|null};
export type CSVImportResult={tenant_id:string;dry_run:boolean;format:string;counts:Record<CSVRowResult['status'],number>;results:CSVRowResult[]};
export type WebhookEventType='asset.created.v1'|'asset.facts_changed.v1'|'responsibility.assigned.v1'|'observation.recorded.v1'|'source.contact_updated.v1'|'source.profile_updated.v1';
export type WebhookSubscription={subscription_id:string;url:string;event_types:WebhookEventType[];active:boolean;revision:string;created_at:string;pending:number;delivered:number;dead:number};
export type WebhookList={tenant_id:string;enabled:boolean;event_types:WebhookEventType[];items:WebhookSubscription[]};
export type WebhookCreated={subscription:WebhookSubscription;signing_secret:string};
export type WebhookDelivery={event_id:string;event_type:WebhookEventType;occurred_at:string;state:'pending'|'delivered'|'dead';attempts:number;next_attempt_at:string|null;last_status:number|null;last_error:string|null;delivered_at:string|null};
export type WebhookDeliveryPage={tenant_id:string;subscription_id:string;items:WebhookDelivery[]};
export class ApiError extends Error {
 constructor(public status:number,public code:string,public requestId?:string){super(code)}
}
const messages:Record<string,string>={INVALID_INPUT:'Проверьте введённые данные.',ASSET_MERGED:'Карточка уже объединена с другой: откройте актуальную.',INVALID_OPERATION:'Операция недоступна: проверьте выбранные записи и UID.',CONFLICT:'Состояние изменилось: обновите список.',INVALID_RESOLUTION:'Это действие недоступно для выбранного конфликта.',AUTHENTICATION_REQUIRED:'Сессия завершилась. Войдите снова.',INVALID_CREDENTIALS:'Не удалось войти. Проверьте имя и пароль.',FORBIDDEN:'Недостаточно прав для этого действия.',NOT_FOUND:'Объект не найден или недоступен.',REVISION_MISMATCH:'Карточка изменилась. Обновите данные.',RATE_LIMITED:'Слишком много запросов. Повторите немного позже.',CONTRACT_MISMATCH:'Версии интерфейса и API несовместимы. Обратитесь к администратору.',INVALID_RESPONSE:'Сервер вернул ответ неизвестного формата.',NETWORK_ERROR:'Нет связи с сервером. Проверьте соединение.',CAPABILITY_NOT_ENABLED:'Эта возможность пока недоступна.'};
export function errorMessage(error:unknown){return error instanceof ApiError?(messages[error.code]??'Не удалось выполнить запрос. Повторите позже.'):'Не удалось выполнить запрос. Повторите позже.'}
async function call<T>(path:string,name:string|undefined,init:RequestInit={}):Promise<T>{
 let response:Response;
 try{response=await fetch(path,{...init,credentials:'same-origin',cache:'no-store',signal:init.signal??AbortSignal.timeout(15000),headers:{Accept:'application/json',...(init.body?{'Content-Type':'application/json'}:{}),...init.headers}})}catch{throw new ApiError(0,'NETWORK_ERROR')}
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
 sourceRecords:(uid:string)=>call<SourceRecordPage>('/api/v1/assets/'+encodeURIComponent(uid)+'/source-records','SourceRecordPage'),
 mergeAssets:(csrf:string,body:{target_asset_uid:string;absorbed_asset_uid:string;target_version?:string})=>call<AssetOperation>('/api/v1/assets/merge','AssetOperation',{method:'POST',body:JSON.stringify(body),headers:{'X-CSRF-Token':csrf},signal:AbortSignal.timeout(130000)}),
 splitAsset:(uid:string,csrf:string,body:{source_record_keys:string[];target_asset_uid?:string;version?:string})=>call<AssetOperation>('/api/v1/assets/'+encodeURIComponent(uid)+'/split','AssetOperation',{method:'POST',body:JSON.stringify(body),headers:{'X-CSRF-Token':csrf},signal:AbortSignal.timeout(130000)}),
 assetCMDB:(uid:string)=>call<AssetCMDB>('/api/v1/assets/'+encodeURIComponent(uid)+'/cmdb','AssetCMDB'),
 setAssetClass:(uid:string,csrf:string,body:{asset_class:AssetClassName|null;revision:string})=>call<AssetCMDB>('/api/v1/assets/'+encodeURIComponent(uid)+'/classification','AssetCMDB',{method:'PATCH',body:JSON.stringify(body),headers:{'X-CSRF-Token':csrf}}),
 software:(uid:string,filter:string,cursor:string|null)=>call<SoftwarePage>('/api/v1/assets/'+encodeURIComponent(uid)+'/software?limit=100'+(filter?'&filter='+encodeURIComponent(filter):'')+(cursor?'&cursor='+encodeURIComponent(cursor):''),'SoftwarePage'),
 components:(uid:string)=>call<ComponentList>('/api/v1/assets/'+encodeURIComponent(uid)+'/components','ComponentList'),
 products:(q:string)=>call<ProductList>('/api/v1/software?q='+encodeURIComponent(q),'ProductList'),
 services:(cursor:string|null=null)=>call<ServicePage>('/api/v1/services?limit=50'+(cursor?'&cursor='+encodeURIComponent(cursor):''),'ServicePage'),
 service:(uid:string)=>call<ServiceDetail>('/api/v1/services/'+encodeURIComponent(uid),'ServiceDetail'),
 createService:(csrf:string,body:{name:string;description?:string;criticality?:string})=>call<ServiceDetail>('/api/v1/services','ServiceDetail',{method:'POST',body:JSON.stringify(body),headers:{'X-CSRF-Token':csrf}}),
 patchService:(uid:string,csrf:string,body:{revision:string;name?:string;description?:string;criticality?:string;retire?:boolean})=>call<ServiceDetail>('/api/v1/services/'+encodeURIComponent(uid),'ServiceDetail',{method:'PATCH',body:JSON.stringify(body),headers:{'X-CSRF-Token':csrf}}),
 createRelation:(csrf:string,body:{relation_type:string;from:CIEnd;to:CIEnd;note?:string})=>call<Relation>('/api/v1/relations','Relation',{method:'POST',body:JSON.stringify(body),headers:{'X-CSRF-Token':csrf}}),
 retireRelation:(id:string,csrf:string)=>call<Relation>('/api/v1/relations/'+encodeURIComponent(id),'Relation',{method:'DELETE',headers:{'X-CSRF-Token':csrf}}),
 webhooks:()=>call<WebhookList>('/api/v1/webhooks','WebhookList'),
 createWebhook:(csrf:string,body:{url:string;event_types:WebhookEventType[]})=>call<WebhookCreated>('/api/v1/webhooks','WebhookCreated',{method:'POST',body:JSON.stringify(body),headers:{'X-CSRF-Token':csrf}}),
 patchWebhook:(id:string,csrf:string,body:{revision:string;active?:boolean})=>call<WebhookSubscription>('/api/v1/webhooks/'+encodeURIComponent(id),'WebhookSubscription',{method:'PATCH',body:JSON.stringify(body),headers:{'X-CSRF-Token':csrf}}),
 webhookDeliveries:(id:string,state:''|'pending'|'delivered'|'dead')=>call<WebhookDeliveryPage>('/api/v1/webhooks/'+encodeURIComponent(id)+'/deliveries'+(state?'?state='+state:''),'WebhookDeliveryPage'),
 retryWebhook:(id:string,event:string,csrf:string)=>call<void>('/api/v1/webhooks/'+encodeURIComponent(id)+'/deliveries/'+encodeURIComponent(event)+'/retry',undefined,{method:'POST',headers:{'X-CSRF-Token':csrf}}),
 directorySync:()=>call<DirectorySyncStatus>('/api/v1/directory-sync','DirectorySyncStatus'),
 runDirectorySync:(csrf:string,mode:'full'|'auto')=>call<SyncRun>('/api/v1/directory-sync/run','SyncRun',{method:'POST',body:JSON.stringify({mode}),headers:{'X-CSRF-Token':csrf},signal:AbortSignal.timeout(300000)}),
 importCSV:(csrf:string,text:string,dry:boolean)=>call<CSVImportResult>('/api/v1/assets/import.csv?dry_run='+dry,'CSVImportResult',{method:'POST',body:text,headers:{'X-CSRF-Token':csrf,'Content-Type':'text/csv; charset=utf-8'},signal:AbortSignal.timeout(300000)}),
 subjects:(kind:''|'person'|'team'='',inactive=false)=>call<SubjectPage>('/api/v1/subjects?limit=200'+(kind?'&kind='+kind:'')+(inactive?'&include_inactive=true':''),'SubjectPage'),
 createSubject:(csrf:string,body:{kind:'person'|'team';name:string;contact:string;username?:string})=>call<SubjectResult>('/api/v1/subjects','SubjectResult',{method:'POST',body:JSON.stringify(body),headers:{'X-CSRF-Token':csrf}}),
 patchSubject:(id:string,csrf:string,body:{revision:string;name?:string;contact?:string;username?:string;deactivate?:boolean})=>call<SubjectResult>('/api/v1/subjects/'+encodeURIComponent(id),'SubjectResult',{method:'PATCH',body:JSON.stringify(body),headers:{'X-CSRF-Token':csrf}}),
 member:(team:string,person:string,csrf:string,add:boolean)=>call<Subject>('/api/v1/subjects/'+encodeURIComponent(team)+'/members/'+encodeURIComponent(person),'Subject',{method:add?'PUT':'DELETE',headers:{'X-CSRF-Token':csrf}}),
 assignments:(uid:string)=>call<AssetAssignments>('/api/v1/assets/'+encodeURIComponent(uid)+'/assignments','AssetAssignments'),
 assign:(uid:string,csrf:string,body:{role:RoleName;subject_id:string|null;note?:string;expected_version:string})=>call<AssetAssignments>('/api/v1/assets/'+encodeURIComponent(uid)+'/assignments','AssetAssignments',{method:'POST',body:JSON.stringify(body),headers:{'X-CSRF-Token':csrf}}),
 bulkAssign:(csrf:string,body:{role:RoleName;subject_id:string;note?:string;items:{asset_uid:string;expected_version:string}[]})=>call<BulkAssignResult>('/api/v1/assignments/bulk','BulkAssignResult',{method:'POST',body:JSON.stringify(body),headers:{'X-CSRF-Token':csrf}}),
 worklist:(scope:string,cursor:string|null=null)=>call<WorklistPage>('/api/v1/worklist?limit=100&scope='+encodeURIComponent(scope)+(cursor?'&cursor='+encodeURIComponent(cursor):''),'WorklistPage'),
 search:(q:string,filters:{os?:string;class?:string},cursor:string|null)=>call<SearchPage>('/api/v1/search?limit=20&q='+encodeURIComponent(q)+(filters.os?'&os='+encodeURIComponent(filters.os):'')+(filters.class?'&class='+encodeURIComponent(filters.class):'')+(cursor?'&cursor='+encodeURIComponent(cursor):''),'SearchPage'),
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
