import { readFileSync, writeFileSync, readdirSync, statSync, chmodSync } from 'node:fs';
import { createHash } from 'node:crypto';
const pkg=JSON.parse(readFileSync(new URL('../package.json', import.meta.url)));
const extension=readFileSync(new URL('../../contracts/c09.openapi.json',import.meta.url));
const contract=readFileSync(new URL('../../contracts/openapi.json', import.meta.url));
writeFileSync(new URL('../dist/version.json',import.meta.url),JSON.stringify({component:'surveyscan-web',version:pkg.version,api_contract:'C03+C09',c09_version:'1.0',c09_sha256:createHash('sha256').update(extension).digest('hex'),wire:{major:1,minor:0},openapi_sha256:createHash('sha256').update(contract).digest('hex'),runtime:'static; no Node or CDN'},null,2)+'\n');
function readable(dir){chmodSync(dir,0o755);for(const name of readdirSync(dir)){const path=dir+'/'+name;if(statSync(path).isDirectory())readable(path);else chmodSync(path,0o644)}}readable(new URL('../dist',import.meta.url).pathname);
