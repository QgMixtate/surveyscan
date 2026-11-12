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
 await card.getByRole('tab',{name:'Инвентаризация 1.2',exact:true}).click();for(const t of ['Сеть','Программное обеспечение'])await card.locator('details.inv12>summary',{hasText:t}).click();
 await expect(card.locator('.inv12-record').first()).toBeVisible();await card.locator('.inv12-record>summary').first().click();
 await card.locator('h3',{hasText:'Инвентаризация'}).scrollIntoViewIfNeeded();await shot('03-card-inventory12',false);
 // C26: вкладки ПО и компоненты, класс актива на обзоре
 await card.getByRole('tab',{name:'ПО',exact:true}).click();await expect(card.locator('.mini-table tbody tr').first()).toBeVisible();await shot('03b-card-software',false);
 await card.getByRole('tab',{name:'Компоненты',exact:true}).click();await shot('03c-card-components',false);
 await card.getByRole('tab',{name:'Обзор',exact:true}).click();await expect(card.locator('.class-block')).toBeVisible();await shot('03d-card-overview',false);
 await page.getByRole('button',{name:'Закрыть карточку'}).click();
 // карточка реального хоста песочницы (portable-аудит)
 await page.locator('.asset-link').filter({has:page.locator('strong',{hasText:/^vm$/})}).first().click();await expect(card).toBeVisible();await card.getByRole('tab',{name:'Инвентаризация 1.2',exact:true}).click();await card.locator('details.inv12>summary',{hasText:'Маршруты и порты'}).click();await expect(card.locator('.inv12-record').first()).toBeVisible();
 await card.locator('h3',{hasText:'Инвентаризация'}).scrollIntoViewIfNeeded();await shot('04-card-real-host',false);await page.getByRole('button',{name:'Закрыть карточку'}).click();
 // схема сети
 await page.getByRole('button',{name:/Схема сети/}).click();await expect(page.locator('.topo-node').first()).toBeVisible();await shot('05-topology');
 await page.locator('.topo-node.router').first().click();await shot('06-topology-router');
 await page.getByLabel('Найти на схеме').fill('10.20.0.107');await page.locator('.topo-node',{hasText:'demo-ws-007'}).click();await shot('07-topology-conflict');
 // разбор конфликтов: демо-хост DEMO-WS-001. совпал по имени с demo-ws-001 только слабым признаком
 await page.getByRole('button',{name:/Разбор конфликтов/}).click();await expect(page.locator('.conflict').first()).toBeVisible();await shot('08-reconcile');
 // C26: сервис, его связь с активом и поиск ПО по реестру
 const app01=(await page.evaluate(async()=>(await (await fetch('/api/v1/assets?limit=200',{credentials:'same-origin'})).json()).items)).find(a=>a.observed_hostname==='demo-app01');
 page.on('dialog',d=>void d.accept());
 await page.getByRole('button',{name:/Сервисы/}).click();await page.getByLabel('Название нового сервиса').fill('1С Бухгалтерия');await page.getByLabel('Критичность').selectOption('high');await page.getByRole('button',{name:'Создать'}).click();
 await expect(page.locator('.service-card')).toBeVisible();await page.getByLabel('UID актива').fill(app01.asset_uid);await page.getByRole('button',{name:'Добавить',exact:true}).click();
 await expect(page.locator('.service-card .relations li')).toHaveCount(1);await shot('09-services');
 await page.getByRole('button',{name:/Поиск ПО/}).click();await page.getByLabel('Название ПО').fill('lib');await page.getByRole('button',{name:'Найти'}).click();await expect(page.locator('tbody tr').first()).toBeVisible();await shot('10-software-search');
 // C27: оргструктура, массовое назначение из «Не распределено», «На мне», вкладка «Ответственность»
 await page.getByRole('button',{name:/Оргструктура/}).click();await page.getByLabel('Имя',{exact:true}).fill('Иванов Иван');await page.getByLabel('Контакт').fill('ivanov@example.test');await page.getByLabel('Логин').fill(c.username);await page.locator('.org-form').getByRole('button',{name:'Добавить'}).click();
 await expect(page.locator('tbody tr',{hasText:'Иванов Иван'})).toBeVisible();
 await page.getByLabel('Вид').selectOption('team');await page.getByLabel('Имя',{exact:true}).fill('Группа серверов');await page.getByLabel('Контакт').fill('srv@example.test');await page.locator('.org-form').getByRole('button',{name:'Добавить'}).click();
 await expect(page.locator('tbody tr',{hasText:'Группа серверов'})).toBeVisible();await page.getByLabel('Команда',{exact:true}).selectOption({label:'Группа серверов'});await page.getByLabel('Человек',{exact:true}).selectOption({label:'Иванов Иван'});await page.getByRole('button',{name:'Включить'}).click();
 await expect(page.locator('tbody tr',{hasText:'Группа серверов'})).toContainText('Команда (1)');await shot('11-org');
 await page.getByRole('button',{name:/Мои задачи/}).click();await page.getByRole('tab',{name:'Не распределено'}).click();await expect(page.locator('tbody tr').first()).toBeVisible();
 const rows=page.locator('tbody tr input[type=checkbox]');await rows.nth(0).check();await rows.nth(1).check();await page.getByLabel('Назначить на').selectOption({label:'Иванов Иван'});await page.getByRole('button',{name:'Назначить выбранным'}).click();
 await expect(page.locator('.notice')).toContainText('Назначено: 2');await page.getByRole('tab',{name:'На мне'}).click();await expect(page.locator('tbody tr')).toHaveCount(2);await shot('12-worklist-mine');
 await page.locator('tbody .asset-link').first().click();await card.getByRole('tab',{name:'Ответственность',exact:true}).click();await expect(card).toContainText('Иванов Иван');await shot('13-card-owners',false);await page.getByRole('button',{name:'Закрыть карточку'}).click();
 // C29: полнотекстовый поиск (если демо запущено с SURVEYSCAN_SEARCH_BIN — режим fulltext)
 await page.getByRole('button',{name:/Поиск\s*00/}).click();await page.getByLabel('Запрос').fill('openssl');await page.getByRole('button',{name:'Найти',exact:true}).click();await expect(page.locator('.search-hit').first()).toBeVisible();await shot('14-search');
 // C31: синхронизация оргструктуры из каталога (демо — мок OpenLDAP, не AD) и обмен CSV
 await page.getByRole('button',{name:/Оргструктура/}).click();
 await page.locator('.sync-panel').waitFor();if(await page.getByText('Синхронизация с Active Directory').isVisible()){await page.getByRole('button',{name:'Синхронизировать сейчас'}).click();await expect(page.locator('.sync-panel')).toContainText('Последний прогон');await expect(page.locator('tbody tr',{hasText:'Мария Петрова'})).toContainText('AD');await expect(page.locator('tbody tr',{hasText:'Linux Admins'})).toContainText('Команда (2)');await shot('15-org-ad')}
 await page.getByRole('button',{name:/Реестр активов/}).click();await expect(page.locator('.csv-panel')).toBeVisible();
 const [download]=await Promise.all([page.waitForEvent('download'),page.getByRole('link',{name:/Выгрузить CSV/}).click()]);
 const exported=await (await import('node:fs/promises')).readFile(await download.path(),'utf8');const lines=exported.split('\r\n');
 const head=lines[1].split(';'),row=lines[2].split(';');row[head.indexOf('display_name')]='Сервер из Excel';row[head.indexOf('criticality')]='high';
 const edited=[lines[0],lines[1],row.join(';')].join('\r\n')+'\r\n';
 await page.locator('.csv-panel input[type=file]').setInputFiles({name:'assets.csv',mimeType:'text/csv',buffer:Buffer.from(edited)});
 await page.getByRole('button',{name:'Проверить'}).click();await expect(page.locator('.csv-panel')).toContainText('применится 1');await shot('16-csv-check');
 await page.getByRole('button',{name:'Применить'}).click();await expect(page.locator('.csv-panel .notice')).toContainText('Применено строк: 1');await expect(page.locator('tbody')).toContainText('Сервер из Excel');await shot('17-csv-applied');
 if(errors.length)throw new Error('browser errors: '+errors.join('; '));
}finally{await browser.close()}
