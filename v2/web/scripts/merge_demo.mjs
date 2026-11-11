// C25.03 — слияние и разделение через Web UI на демо-стенде (живой центр, данные demo-сети). Не входит в CI-смок:
// меняет данные. Скриншоты — в каталог out.
import {readFileSync} from 'node:fs';
import {chromium,expect} from '@playwright/test';
const c=JSON.parse(readFileSync(process.argv[2]));const out=process.argv[3];
const browser=await chromium.launch({headless:true,...(process.env.SURVEYSCAN_CHROMIUM?{executablePath:process.env.SURVEYSCAN_CHROMIUM}:{})});const errors=[];
try{
 const ctx=await browser.newContext({viewport:{width:1440,height:900},deviceScaleFactor:2});const page=await ctx.newPage();page.on('pageerror',e=>errors.push(e.message));
 page.on('dialog',d=>void d.accept());
 const shot=async n=>{await page.waitForTimeout(400);await page.screenshot({path:`${out}/${n}.png`,fullPage:true})};
 await page.goto(c.origin);await page.getByLabel('Имя пользователя').fill(c.username);await page.getByLabel('Пароль',{exact:true}).fill(c.password);
 await page.getByRole('button',{name:'Войти в рабочее пространство'}).click();await expect(page.locator('.asset-link').first()).toBeVisible();
 const list=async()=>page.evaluate(async()=>(await (await fetch('/api/v1/assets?limit=200',{credentials:'same-origin'})).json()).items);
 const before=await list();const demo=before.filter(a=>(a.observed_hostname??'').startsWith('demo-')).sort((x,y)=>x.observed_hostname.localeCompare(y.observed_hostname));
 if(demo.length<2)throw new Error('need two demo assets');
 const [a,b]=demo;console.log('MERGE',b.observed_hostname,'->',a.observed_hostname);
 // слияние: карточка A, UID карточки B
 await page.locator('.asset-link',{hasText:a.observed_hostname}).first().click();const card=page.getByRole('dialog');await expect(card).toContainText('Сопоставление и слияние');
 await expect(card.locator('.source-record')).toHaveCount(1);
 await card.getByLabel('UID другой карточки').fill(b.asset_uid);await card.locator('.merge-field').scrollIntoViewIfNeeded();await shot('c25-01-merge-before');
 await card.getByRole('button',{name:'Присоединить карточку к этой'}).click();
 await expect(card.locator('.notice')).toContainText('Готово',{timeout:130000});await expect(card.locator('.source-record')).toHaveCount(2);
 await card.locator('.source-records').scrollIntoViewIfNeeded();await shot('c25-02-merged');
 const after=await list();if(after.some(x=>x.asset_uid===b.asset_uid)||after.length!==before.length-1)throw new Error('merged asset still listed');
 const alias=await page.evaluate(async uid=>{const r=await fetch('/api/v1/assets/'+uid,{credentials:'same-origin'});return {status:r.status,redirected:r.redirected,uid:(await r.json()).asset_uid}},b.asset_uid);
 if(alias.uid!==a.asset_uid)throw new Error('old UID does not lead to canonical: '+JSON.stringify(alias));console.log('ALIAS',JSON.stringify(alias));
 // разделение: запись B — в новый актив
 await card.locator('.source-record',{hasText:b.observed_hostname}).locator('input').check().catch(async()=>{await card.locator('.source-record').nth(1).locator('input').check()});
 await card.getByRole('button',{name:'Выделить в новый актив'}).click();
 await expect(card.locator('.notice')).toContainText('создан новый актив',{timeout:130000});
 await expect(card.locator('.source-record')).toHaveCount(1);
 const split=await list();const created=split.find(x=>!before.some(y=>y.asset_uid===x.asset_uid));
 if(!created||split.length!==before.length||split.some(x=>x.asset_uid===b.asset_uid))throw new Error('split must create a NEW asset UID');
 console.log('SPLIT new',created.asset_uid,'old merged',b.asset_uid,'hostname',created.observed_hostname);
 await card.locator('.source-records').scrollIntoViewIfNeeded();await shot('c25-03-split');
 await card.getByRole('button',{name:'Открыть новый актив'}).click();await expect(card).toContainText(created.asset_uid);await shot('c25-04-new-asset');
 if(errors.length)throw new Error('page errors: '+errors.join('; '));
 console.log('C25.03 UI OK');
}finally{await browser.close()}
