import { readFileSync, writeFileSync, readdirSync, statSync, chmodSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { execFileSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
const pkg=JSON.parse(readFileSync(new URL('../package.json', import.meta.url)));
const extension=readFileSync(new URL('../../contracts/c09.openapi.json',import.meta.url));
const contract=readFileSync(new URL('../../contracts/openapi.json', import.meta.url));
const cwd=new URL('..',import.meta.url);
const revision=execFileSync('git',['rev-parse','HEAD'],{cwd,encoding:'utf8'}).trim();
const source_dirty=execFileSync('git',['status','--porcelain','--untracked-files=normal'],{cwd,encoding:'utf8'}).trim() ? 'true':'false';
const profile=readFileSync(new URL('../../contracts/c12.openapi.json',import.meta.url));
writeFileSync(new URL('../dist/version.json',import.meta.url),JSON.stringify({component:'surveyscan-web',version:process.env.SURVEYSCAN_VERSION || pkg.version,revision,source_dirty,api_contract:'C03+C09+C12',c12_sha256:createHash('sha256').update(profile).digest('hex'),c09_version:'1.0',c09_sha256:createHash('sha256').update(extension).digest('hex'),wire:{major:1,minor:0},openapi_sha256:createHash('sha256').update(contract).digest('hex'),runtime:'static; no Node or CDN'},null,2)+'\n');
function readable(dir){chmodSync(dir,0o755);for(const name of readdirSync(dir)){const path=dir+'/'+name;if(statSync(path).isDirectory())readable(path);else chmodSync(path,0o644)}}readable(fileURLToPath(new URL('../dist',import.meta.url))); // не .pathname: на Windows он даёт /C:/…
