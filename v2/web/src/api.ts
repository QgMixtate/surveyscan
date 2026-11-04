import validators from './generated/wire.cjs';
import type { components } from './generated/c03';

export type Asset=components['schemas']['Asset'];
export type AssetPage=components['schemas']['AssetPage'];
export type Source=components['schemas']['Source'];
export type SourcePage=components['schemas']['SourcePage'];
export type Session=components['schemas']['Session'];
export class ApiError extends Error {
 constructor(public status:number,public code:string,public requestId?:string){super(code)}
}
const messages:Record<string,string>={AUTHENTICATION_REQUIRED:'Сессия завершилась. Войдите снова.',INVALID_CREDENTIALS:'Не удалось войти. Проверьте имя и пароль.',FORBIDDEN:'Недостаточно прав для этого действия.',NOT_FOUND:'Объект не найден или недоступен.',REVISION_MISMATCH:'Карточка изменилась. Обновите данные.',RATE_LIMITED:'Слишком много запросов. Повторите немного позже.',CONTRACT_MISMATCH:'Версии интерфейса и API несовместимы. Обратитесь к администратору.',INVALID_RESPONSE:'Сервер вернул ответ неизвестного формата.',NETWORK_ERROR:'Нет связи с сервером. Проверьте соединение.',CAPABILITY_NOT_ENABLED:'Эта возможность пока недоступна.'};
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
 sources:(cursor:string|null=null)=>call<SourcePage>('/api/v1/sources?limit=50'+(cursor?'&cursor='+encodeURIComponent(cursor):''),'SourcePage')
};
export async function checkCompatibility(){
 try{
 const [manifest,contract]=await Promise.all([fetch('/version.json',{cache:'no-store'}),fetch('/contracts/openapi.json',{cache:'no-store'})]);
 if(!manifest.ok||!contract.ok)throw new Error();
 const version=await manifest.json() as {wire?:{major:number;minor:number};openapi_sha256?:string};const bytes=await contract.arrayBuffer();if(bytes.byteLength>1048576)throw new Error();
 const digest=await crypto.subtle.digest('SHA-256',bytes);const hash=Array.from(new Uint8Array(digest),n=>n.toString(16).padStart(2,'0')).join('');
 if(version.wire?.major!==1||version.wire?.minor!==0||version.openapi_sha256!==hash)throw new Error();
 }catch{throw new ApiError(0,'CONTRACT_MISMATCH')}
}
