import {readFileSync} from 'node:fs';
import {chromium,expect} from '@playwright/test';
const c=JSON.parse(readFileSync(process.argv[2]));const out=process.argv[3];
const browser=await chromium.launch({headless:true,...(process.env.SURVEYSCAN_CHROMIUM?{executablePath:process.env.SURVEYSCAN_CHROMIUM}:{})});const errors=[];
try{
 const ctx=await browser.newContext({viewport:{width:1440,height:900},deviceScaleFactor:2});const page=await ctx.newPage();page.on('pageerror',e=>errors.push(e.message));
 const shot=async(n,full=true)=>{await page.waitForTimeout(500);await page.screenshot({path:`${out}/${n}.png`,fullPage:full})};
 await page.goto(c.origin);await expect(page.getByRole('heading',{name:'Вход в систему'})).toBeVisible();await shot('01-login');
 await page.getByLabel('Имя пользователя').fill(c.username);await page.getByLabel('Пароль',{exact:true}).fill(c.password);
 await page.getByRole('button',{name:'Войти в рабочее пространство'}).click();await expect(page.locator('.asset-link').first()).toBeVisible();await shot('02-registry');
 // карточка демо-сервера: разделы 1.2
 await page.locator('.asset-link',{hasText:'demo-app01'}).click();const card=page.getByRole('dialog');await expect(card).toBeVisible();
 for(const t of ['Сеть','Программное обеспечение'])await card.locator('details.inv12>summary',{hasText:t}).click();
 await expect(card.locator('.inv12-record').first()).toBeVisible();await card.locator('.inv12-record>summary').first().click();
 await card.locator('h3',{hasText:'Инвентаризация'}).scrollIntoViewIfNeeded();await shot('03-card-inventory12',false);
 await page.getByRole('button',{name:'Закрыть карточку'}).click();
 // карточка реального хоста песочницы (portable-аудит)
 await page.locator('.asset-link').filter({has:page.locator('strong',{hasText:/^vm$/})}).first().click();await expect(card).toBeVisible();await card.locator('details.inv12>summary',{hasText:'Маршруты и порты'}).click();await expect(card.locator('.inv12-record').first()).toBeVisible();
 await card.locator('h3',{hasText:'Инвентаризация'}).scrollIntoViewIfNeeded();await shot('04-card-real-host',false);await page.getByRole('button',{name:'Закрыть карточку'}).click();
 // схема сети
 await page.getByRole('button',{name:/Схема сети/}).click();await expect(page.locator('.topo-node').first()).toBeVisible();await shot('05-topology');
 await page.locator('.topo-node.router').first().click();await shot('06-topology-router');
 await page.getByLabel('Найти на схеме').fill('10.20.0.107');await page.locator('.topo-node',{hasText:'demo-ws-007'}).click();await shot('07-topology-conflict');
 if(errors.length)throw new Error('browser errors: '+errors.join('; '));
}finally{await browser.close()}
