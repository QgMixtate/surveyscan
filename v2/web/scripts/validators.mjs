import {createRequire} from 'node:module';
import {readFileSync,writeFileSync} from 'node:fs';
const require=createRequire(import.meta.url);
const Ajv=require('ajv/dist/2020').default,addFormats=require('ajv-formats').default,standalone=require('ajv/dist/standalone').default;
const schema=JSON.parse(readFileSync(new URL('../../contracts/wire.schema.json',import.meta.url)));
const ajv=new Ajv({strict:false,allowUnionTypes:true,code:{source:true}});addFormats(ajv);ajv.addSchema(schema);
const names=['Session','Asset','AssetPage','SourcePage'];
const exports=Object.fromEntries(names.map(name=>[name,schema.$id+'#/$defs/'+name]));
writeFileSync(new URL('../src/generated/wire.cjs',import.meta.url),standalone(ajv,exports));
