from pathlib import Path
import re, json, subprocess, hashlib, collections
from datetime import datetime, timezone
from docx import Document
from docx.shared import Inches, Pt, Cm, RGBColor
from docx.oxml import OxmlElement
from docx.oxml.ns import qn

import argparse
parser=argparse.ArgumentParser(description='Build the archived SurveyScan project report.')
parser.add_argument('--repo', type=Path, required=True, help='Checkout of the pinned source revision')
parser.add_argument('--output', type=Path, required=True, help='Separate output directory')
args=parser.parse_args()
ROOT=args.repo.resolve()
OUT=args.output.resolve()
OUT.mkdir(parents=True, exist_ok=True)
PLAN=json.loads((ROOT/'docs/plans/surveyscan-v2/plan.json').read_text())
SHA='5fe78c5f844e6d1768fa343cdb64ed18178c5d1b'
BASE='https://github.com/QgMixtate/surveyscan/blob/'+SHA+'/'
STAT={'done':'Завершено в принятом объёме','in_progress':'В работе','planned':'Запланировано'}
doc=Document()
sec=doc.sections[0];sec.page_height=Cm(29.7);sec.page_width=Cm(21)
sec.top_margin=Cm(1.8);sec.bottom_margin=Cm(1.8);sec.left_margin=Cm(2);sec.right_margin=Cm(1.6)
styles=doc.styles
for name in ['Normal','Body Text','List Bullet','List Number']:
 styles[name].font.name='Calibri';styles[name].font.size=Pt(10)
 styles[name].paragraph_format.space_after=Pt(5)
 styles[name].paragraph_format.line_spacing=1.08
for name,size,color in [('Title',30,'16324F'),('Heading 1',19,'16324F'),('Heading 2',14,'146C83'),('Heading 3',11,'16324F')]:
 styles[name].font.name='Calibri';styles[name].font.size=Pt(size);styles[name].font.color.rgb=RGBColor.from_string(color)
 styles[name].paragraph_format.space_before=Pt(12);styles[name].paragraph_format.space_after=Pt(6)
styles['Caption'].font.size=Pt(9)
for name in ['Heading 1','Heading 2','Heading 3']:styles[name].paragraph_format.keep_with_next=True
header=sec.header.paragraphs[0];header.text='SURVEYSCAN v2  |  Архитектура и состояние проекта  |  08.11.2026'
header.style='Caption'
footer=sec.footer.paragraphs[0];footer.alignment=2
footer.add_run('Проект 0.5 · снимок '+SHA[:7]+'  |  ')
fld=OxmlElement('w:fldSimple');fld.set(qn('w:instr'),'PAGE');footer._p.append(fld)

def p(s='',style=None):
 return doc.add_paragraph(clean(s),style)
def h(s,level=1):return doc.add_heading(s,level)
def clean(s):
 s=re.sub(r'!\[([^]]*)\]\([^)]*\)',r'\1',str(s))
 s=re.sub(r'\[([^]]+)\]\(([^)]+)\)',r'\1 (\2)',s)
 return s.replace('**','').replace('`','').replace('\x00','')
def bullet(s):return p(s,'List Bullet')
def table(headers,rows):
 t=doc.add_table(rows=1, cols=len(headers));t.style='Light Shading Accent 1'
 for c,x in zip(t.rows[0].cells,headers):c.text=clean(x)
 repeat=OxmlElement('w:tblHeader');t.rows[0]._tr.get_or_add_trPr().append(repeat)
 for row in rows:
  cells=t.add_row().cells
  for c,x in zip(cells,row):
   c.text=clean(x)
   for para in c.paragraphs:
    para.paragraph_format.space_after=Pt(3)
    for r in para.runs:r.font.size=Pt(8)
  pr=t.rows[-1]._tr.get_or_add_trPr();pr.append(OxmlElement('w:cantSplit'))
 p()
 return t
def link(label,url):
 para=doc.add_paragraph();para.add_run(label+' — ')
 rel=para.part.relate_to(url,'http://schemas.openxmlformats.org/officeDocument/2006/relationships/hyperlink',is_external=True)
 el=OxmlElement('w:hyperlink');el.set(qn('r:id'),rel)
 r=OxmlElement('w:r');pr=OxmlElement('w:rPr');c=OxmlElement('w:color');c.set(qn('w:val'),'146C83');pr.append(c);r.append(pr)
 text=OxmlElement('w:t');text.text=url;r.append(text);el.append(r);para._p.append(el)
def page():doc.add_page_break()
diagrams={}
def graph(key,title,nodes,edges,rank='TB'):
 lines=['digraph G {',f'rankdir={rank};', 'graph [bgcolor="white", pad="0.2", nodesep="0.3", ranksep="0.5", dpi=170];', 'node [shape=box, style="rounded,filled", fontname="DejaVu Sans", fontsize=11, margin="0.16,0.1"];','edge [fontname="DejaVu Sans",fontsize=9,color="#536878", arrowsize=0.7];']
 for keyn,label,state in nodes:
  color={'live':'#DDF1E4','partial':'#FFF0CC','target':'#E6ECF7','store':'#DFEFF7'}.get(state,'#E6ECF7')
  lines.append(f'"{keyn}" [label={json.dumps(label,ensure_ascii=False)},fillcolor="{color}"];')
 for edge in edges:
  a,b,label,*rest=edge;attr='style=dashed,' if rest and rest[0]=='dash' else ''
  lines.append(f'"{a}" -> "{b}" [{attr}label={json.dumps(label,ensure_ascii=False)}];')
 if key=='06-data':lines.append('ids -> own -> hist -> rel -> future [style=invis];')
 lines.append('}')
 dot=OUT/(key+'.dot');dot.write_text('\n'.join(lines))
 png=OUT/(key+'.png');subprocess.run(['dot','-Tpng',str(dot),'-o',str(png)],check=True)
 diagrams[key]=(png,title)
def image(key):
 from PIL import Image
 path,title=diagrams[key];im=Image.open(path);w,hh=im.size
 width=min(6.65,7.7*w/hh)
 doc.add_picture(str(path),width=Inches(width));p(title,'Caption')

graph('01-context','Схема 1. Целевая общая архитектура. Зелёный — принятая основа E1; жёлтый — частичная реализация; голубой — будущие возможности.',[
 ('browser','Браузер / отдельный Web UI','live'),('cli','CLI / внешние интеграции','live'),('edge','HTTPS / reverse proxy','live'),('api','Go API / auth / tenant scope','live'),('domain','Модули: Assets / Inventory / Sources\nResponsibility / History','live'),('worker','Workers / scheduler / outbox','live'),('pg','PostgreSQL\nреестр / наблюдения / jobs / outbox','store'),('bao','OpenBao\nPKI / Transit / секреты','live'),('collector','Постоянный site collector\nspool / relay','live'),('agent','Постоянные host agents\nLinux E1; Windows C15 — частично','partial'),('targets','Agentless SSH / WinRM / SNMP\nхосты и сетевые устройства','target'),('portable','Portable / offline-пакет','target'),('proj','Поиск / presence / топология','target'),('geo','HA / shard routing / geo DR','target')],
 [('browser','edge',''),('cli','edge','API'),('edge','api',''),('api','domain',''),('domain','pg','транзакции'),('worker','pg','jobs / checkpoints'),('domain','bao','scoped операции'),('agent','collector','исходящий HTTPS'),('collector','edge','подписанные наблюдения'),('collector','targets','разрешённый сбор','dash'),('portable','edge','импорт','dash'),('pg','proj','outbox','dash'),('pg','geo','E5','dash')])
graph('02-delivery','Схема 2. Постоянная доставка: удаление очереди только после проверенного центрального подтверждения.',[
 ('a','Агент: read-only сбор','live'),('as','Долговечный spool агента','live'),('c','Collector: проверка / spool','live'),('s','Центр: подпись / tenant / dedup','live'),('tx','Одна транзакция PostgreSQL\nнаблюдение + факты + история + outbox','store'),('ack','Подписанный CenterResult ACK','live'),('del','Проверка ACK и долговечное\nудаление подтверждённого пакета','live')],
 [('a','as','сохранить до отправки'),('as','c','повторы с backoff'),('c','s','origin сохранён'),('s','tx','применить'),('tx','ack','после commit'),('ack','c','relay без подмены'),('c','del','передать ACK агенту'),('as','as','перезапуск / обрыв: сохранить'),('s','s','повтор: без дублей')])
graph('03-discovery','Схема 3. Целевой discovery и доказательная топология — этапы C20–C22, ещё не приняты.',[
 ('active','ICMP / TCP / ARP / NDP','target'),('passive','ARP/NDP/FDB, DHCP/DNS\nAD / гипервизоры / импорт','target'),('e','Наблюдение + scope + время\nпокрытие + полнота + здоровье источника','target'),('id','Reconciliation / asset_uid / конфликты','target'),('pr','Presence: present / suspect\nmissing / unknown / reappeared','target'),('net','SNMPv3 / read-only SSH/API\nLLDP/CDP / VLAN / VRF / routes','target'),('top','L2/L3 связи\nevidence / confidence / возраст','target')],
 [('active','e',''),('passive','e',''),('e','id',''),('id','pr','пороги / TTL'),('net','top',''),('id','top','идентичность'),('e','top','подтверждение')])
graph('04-events','Схема 4. Событийная логика без внешней шины. Основа outbox принята; проекции расширяются по эпохам.',[
 ('cmd','Команда UI / CLI / collector','live'),('tx','Транзакция владельца модуля','live'),('state','Состояние / observations','store'),('ob','PostgreSQL outbox','store'),('d','Go dispatcher\nretry / checkpoints / dedup','live'),('fts','FTS-проекция / rebuild','target'),('top','Presence / topology','target'),('future','ЖЦ / склад / ITSM','target')],
 [('cmd','tx',''),('tx','state','атомарно'),('tx','ob','атомарно'),('ob','d','at least once'),('d','fts','C28–C29','dash'),('d','top','C21–C22','dash'),('d','future','волны 2–3','dash')])
graph('05-geo','Схема 5. Целевая геоархитектура E5. Размещение DR допустимо только в разрешённых регионах.',[
 ('route','Каталог tenant → shard\nhome / DR / residency / routing epoch','target'),('a','Шард A: primary, регион 1','target'),('b','Шард B: primary, регион 2','target'),('ar','DR A: разрешённый регион 2','target'),('br','DR B: разрешённый регион 1','target'),('ops','Fencing / failover / failback\nизмеренные RPO / RTO','target'),('all','Восстановить весь контур:\nPG, каталог, artifacts, OpenBao,\nkeys, outbox, dedup, index rebuild','target')],
 [('route','a','один writer'),('route','b','один writer'),('a','ar','репликация по RPO'),('b','br','репликация по RPO'),('ops','route','новый epoch'),('ops','all','проверяемая процедура')])
graph('06-data','Схема 6. Концептуальная модель данных. Это логические связи, а не точная физическая ER-диаграмма всех таблиц.',[
 ('tenant','Tenant / Site / сетевой контекст','live'),('asset','Asset: неизменный asset_uid','live'),('ids','Identifiers / aliases\nконфликты / merge / split','partial'),('source','Source: agent_id / collector_id\ngeneration / assignment / profile','live'),('rec','Source record → asset mapping','live'),('obs','Immutable observations\nsection status / origin / sequence','live'),('facts','Current facts + provenance\nотдельно от business fields','live'),('own','Responsibility assignments\nfallback team / интервалы','partial'),('hist','History / audit / outbox','live'),('rel','Relations / topology / CI / service','target'),('future','ЖЦ / stock / parts / ITSM\nссылки на общий asset_uid','target')],
 [('tenant','asset','1:N'),('tenant','source','1:N'),('asset','ids','1:N'),('source','rec','1:N'),('rec','asset','mapping'),('rec','obs','1:N'),('obs','facts','проекция'),('asset','facts','1:N'),('asset','own','во времени'),('asset','hist','история'),('asset','rel','связи','dash'),('asset','future','общая идентичность','dash')])
graph('07-trust','Схема 7. Доверие и подписанные профили C15. Проверка профиля реализована; Windows durable apply ещё нет.',[
 ('bao','OpenBao Transit\nнеэкспортируемый ключ центра','live'),('center','Центр: signed capabilities\nи inventory profile 1.2','live'),('collector','Collector: attested key\nнеизменный inner frame + outer signature','live'),('agent','Агент: pinned center key\nTLS peer + две подписи + nonce\ntenant / generation / expiry','live'),('limits','Пересечение лимитов трёх сторон\nзакрытый partial profile 12 секций','live'),('cache','Windows private state / host binding\nsigned cache / offline verify / apply','partial'),('progress','Applied progress центра\nsource-reported, не аттестация хоста','partial')],
 [('bao','center','подписать без fallback'),('center','collector','подписанный inner frame'),('collector','agent','mTLS + outer frame'),('agent','limits','проверка'),('limits','cache','нужна интеграция','dash'),('cache','progress','после durable commit','dash')])
graph('08-roadmap','Схема 8. Эпохи и продуктовые волны. W2 после C30 не обязана ждать физического geo DR.',[
 ('e0','E0 · C01–C03\nконтракты и базовая модель\nЗАВЕРШЕНО','live'),('e1','E1 · C04–C14\nпостоянный Linux SMB\nПРИНЯТ В ОГРАНИЧЕННОМ ПРОФИЛЕ','live'),('e2','E2 · C15–C24\nсбор / discovery / topology / portable\nC15.02 В РАБОТЕ','partial'),('e3','E3 · C25–C30\nреестр / ответственность / FTS / 100 active','target'),('e4','E4 · C31–C34\nинтеграции / миграция / пилот','target'),('e5','E5 · C35–C40\nреплики / pool / shards / geo DR','target'),('w2','Волна 2 · C41–C45\nЖЦ / склад / запчасти / движения','target'),('w3','Волна 3 · C46–C50\nITSM / каталог / SLA','target')],
 [('e0','e1',''),('e1','e2',''),('e2','e3',''),('e3','e4',''),('e4','e5',''),('e3','w2','по зависимостям'),('w2','w3','')])

p('SURVEYSCAN v2','Title')
p('Полное описание проекта\nАрхитектура · спецификация · план · выполненные и оставшиеся работы','Subtitle')
p('Состояние на 8 ноября 2026 года')
p('Репозиторий: QgMixtate/surveyscan\nВетка: codex/v2-c15-windows\nСнимок исходников: '+SHA)
p('Документ объединяет актуальный обзор реализации и полный комплект проектных материалов. Спецификация 0.5 остаётся проектом для согласования. Описание целевой функции не означает её готовность.')
table(['Ключевой показатель','Состояние'],[
 ('Учёт плана','50 пакетов / 200 подзадач; 57 завершены, 1 в работе, 142 запланированы'),
 ('Принятый объём','C01–C14: ограниченный Linux/amd64 E1; внутренний кандидат'),
 ('Текущий этап','C15.01 завершён как проектирование; C15.02 в работе'),
 ('Последний CI','4 success / 1 failure; Windows atomic_rename code=5'),
 ('Публикация','PR №4 и №5 открыты как draft; main не слит; официального релиза и production deployment нет')])
p('Подготовлено по исходникам, evidence и GitHub API. Секреты, ключи, raw inventory и приватные журналы в документ не включены. Код проекта и настройки среды при подготовке отчёта не изменялись.')
page();h('Навигация по документу')
for s in ['1. Что создаём и зачем','2. Требования и границы продукта','3. Общая архитектура','4. Непрерывный цикл и надёжная доставка','5. Данные, идентичность и ответственность','6. Безопасность и OpenBao','7. Discovery, presence и топология','8. События, поиск и масштабирование','9. Что уже сделано','10. Текущий C15 и незавершённые работы','11. Проверки, доказательства и ограничения','12. Полный маршрут этапов','13. Следующие действия и открытые решения','14. Источники и правила чтения статусов','Приложение А. Полная спецификация 0.5','Приложение Б. Полная архитектура 0.5 со схемами','Приложение В. Полный WBS: 50 пакетов / 200 подзадач','Приложение Г. Трассировка всех 19 замечаний пользователя','Приложение Д. Аналоги и основания решений']:p(s)
p('Заголовки доступны в области навигации Word. Ниже — автоматическое оглавление: для пересчёта номеров страниц в Word выделите его и нажмите F9.')
field=OxmlElement('w:fldSimple');field.set(qn('w:instr'),'TOC \\o "1-2" \\h \\z \\u');doc.add_paragraph()._p.append(field)

page();h('1. Что создаём и зачем')
p('Мы развиваем SurveyScan из инструмента разового обследования сети в постоянно работающую платформу инвентаризации и управления ИТ-активами. Центральная сущность — долгоживущий актив с неизменным asset_uid, техническими фактами, происхождением данных, ответственными и историей. Сканирование становится одним из источников наблюдений, а карточка продолжает существовать между обследованиями.')
p('Разработка идёт по пути SMB → enterprise: сначала полезный постоянный контур на одной платформе, затем расширение сбора и реестра, поиск и интеграции, после этого масштабирование и георезервирование. Отдельные продуктовые волны добавляют процессы жизненного цикла, склад и запчасти, затем ITSM. Календарь, трудозатраты и стоимость в текущем WBS не утверждены.')
h('1.1. От исходного v1 к целевому v2',2)
table(['Аспект','Наследуемый v1','Целевая платформа v2'],[
 ('Основная роль','Разовое обследование, nmap и сбор SSH/WinRM/SNMP, граф сети','Постоянный реестр и регулярное обновление из нескольких источников'),
 ('Стек','Python / FastAPI / React UMD; Go-коннектор','Go backend/agent/collector/CLI; PostgreSQL; отдельный React/TypeScript/Vite UI; OpenBao'),
 ('Данные','Материалы задачи и dashboard snapshot','Постоянные активы, immutable observations, проекции, история и outbox'),
 ('Миграция','v1 сохраняется в исходниках','C32: отдельный экспорт/импорт и проверка паритета; автоматический перенос не выполнен')])
p('Перенос старых модулей уязвимостей и конфигурационного аудита в v2 не включён автоматически. SurveyScan не объявляется EDR, системой патч-менеджмента, удалённого администрирования или сертифицированным СЗИ.')
h('2. Требования и границы продукта')
table(['Режим','Назначение','Жизненный цикл / состояние'],[
 ('Local / host agent','Минимальный сбор на одном управляемом хосте; исходящая передача collector','Постоянная служба; Linux E1 принят, Windows E2 в работе'),
 ('Site collector','Приём агентов, relay и долговечная доставка; далее remote discovery','Постоянная служба площадки; relay принят, широкие remote adapters ещё впереди'),
 ('Portable','Разовый аудит host/network/mixed без установленной службы','Пакет и offline-импорт: C23; ещё не принят'),
 ('Agentless','SSH/WinRM/SNMP/API с разрешённого collector','C17–C22; постоянный агент на каждом активе не обязателен')])
p('Позднее уточнение пользователя имеет приоритет: local и portable различаются эксплуатацией. Агент не сканирует всю сеть. Portable после окончания аудита не становится постоянным источником heartbeat. Общие контракты и SDK могут переиспользоваться без смешивания полномочий.')
p('Обязательные основы: OpenBao, сквозной ID, ответственность, CLI и открытый API, отдельный Web UI, событийность без внешней шины, независимые границы модулей. Георезервирование учтено в целевой архитектуре; физические шарды и регионы не блокируют первый SMB. Полнотекстовый движок Tantivy либо Bluge выбирается по PoC в C28.')
h('3. Общая архитектура');image('01-context')
p('Backend — модульный монолит Go с ownership данных. Для компактного запуска используется combined; проект предусматривает раздельные API и workers. Реальная многопроцессная приёмка и независимое масштабирование относятся к E5. Отдельный Web UI уже имеет собственную сборку и CI; same-origin размещение через reverse proxy упрощает эксплуатацию. Python и Node.js не требуются как runtime целевых Go-компонентов и статической SPA.')
table(['Контур','Ответственность'],[
 ('API / identity','Сессии и CLI, tenant scope, машинные identities, contracts и валидация'),
 ('Assets / reconciliation','asset_uid, source mappings, identifiers и конфликты'),
 ('Inventory','Наблюдения, статусы секций, факты с provenance; business fields отдельно'),
 ('Sources / collectors / jobs','Enrollment, generation, assignments, heartbeat, signed config и расписания'),
 ('Responsibility / history','Fallback-назначение, история; расширенная оргмодель позже'),
 ('Outbox / workers','Долговечные изменения, replay/checkpoints, фоновые операции'),
 ('Imports / artifacts','Проверка и хранение пакетов, digest, staging и backup'),
 ('Discovery / topology / search','Будущие evidence-проекции, presence, FTS; по этапам E2/E3')])
h('4. Непрерывный цикл и надёжная доставка');image('02-delivery')
for s in [
 'Агент выполняет периодический read-only сбор и отдельный heartbeat, использует jitter, контекстные лимиты и ограниченный дисковый spool. Неподтверждённые данные переживают перезапуск и обрыв.',
 'Collector проверяет источник и сохраняет исходное происхождение наблюдения. HTTP 202 или receipt коллектора означает приём в обработку, а не окончательное применение.',
 'Центр проверяет подписи, tenant/generation, назначение, версии и лимиты. Наблюдение, выбранные факты, история и outbox применяются согласованно; повторная доставка не создаёт повторные эффекты.',
 'Центральный подписанный результат возвращается через collector. Только проверенное подтверждение с долговечным удалением ранее ожидающего пакета считается реальным прогрессом доставки.',
 'Локальные очереди ограничены. Ошибки диска, отказы подписи, истёкший доступ и неизвестные статусы обрабатываются явно. Нельзя удалять данные по одному транспортному успеху.'
]:p(s)
p('В C15 сбор вынесен из serial actor: heartbeat, обновление доступа и доставка могут продолжаться. Счётчики, TLS, подписи и spool изменяются сериализованно. Для Windows провайдеры работают в ограниченных дочерних процессах; полный постоянный Windows runtime ещё не подключён.')
h('5. Данные, идентичность и ответственность');image('06-data')
p('asset_uid — канонический идентификатор актива во всех API/CLI, карточках, событиях и будущих процессах. Он не равен agent_id, collector_id или адресу IP. Переустановка, повторное enrollment, клон VM и перенос площадки требуют явных правил, а не бесшумного создания либо слияния активов.')
p('Неизвестная offline-запись первоначально имеет source_record_id и кандидаты идентичности. Центральное сопоставление возвращает mapping к asset_uid. Два автономных источника не обязаны заранее угадать один UUID одного физического устройства. Полные merge/split и aliases развиваются в C25.')
p('Наблюдения неизменяемы; текущая карточка — проекция. Для каждого факта нужны источник, время и правила приоритета. Неполная секция, отказ API или недоступный provider не доказывают удаление ранее известного факта. Ручные бизнес-поля не затираются инвентаризацией.')
p('С первой карточки существует fallback-команда tenant/site. Персональные роли owner, technical responsible и custodian, интервалы назначений, организационная структура и полные передачи — C27 и затем волна 2. Нельзя считать все эти процессы уже реализованными на основании базового назначения.')
p('Схема C15: 35 миграций (0000–0034), 48 принадлежащих модулям таблиц; 49 с migration ledger. Старые применённые SQL не переписываются. Новая схема требует синхронно обновлять backup/restore и upgrade-проверки. Это текущая физическая база, а не окончательная модель будущего ITSM.')
h('6. Безопасность и OpenBao');image('07-trust')
p('OpenBao выбран пользователем. В принятом контуре используются ограниченные PKI/KV/Transit операции, bootstrap/enrollment, renewal и отзыв машинных доступов. Приватный ключ центра в Transit не экспортируется. Отказ внешней подписи не подменяется локальным signer. Root-токен не является штатным доступом приложения.')
p('Для каждого API и фонового действия проверяется tenant scope; UUID не является разрешением. Секреты, private keys, raw inventory и пути/идентификаторы из закрытого состояния не должны попадать в публичные diagnostics, artifacts или отчёты. Наличие возможностей OpenBao не означает готовность всех будущих remote/offline/geo сценариев.')
p('В profile 1.2 разделены домены подписей запроса/ответа. Проверяются nonce, tenant, generation, назначенный collector, срок действия, TLS peer, подпись центра и внешняя подпись collector. Лимиты выбираются как пересечение трёх предложений. Заявленная platform Windows/amd64 и applied progress не являются аппаратной аттестацией.')
p('Защищённое Windows-состояние — текущая незавершённая работа: private DACL, root-relative file operations, запрет reparse/hardlinks и process lock уже проверены на Windows Server 2022 с повышенными правами. Atomic replace опубликован, но последняя конкурентная проверка падает. Модуль ещё не подключён к agent runtime, signed cache и host binding.')
h('7. Discovery, presence и топология');image('03-discovery')
table(['Понятие','Что показывает'],[
 ('Source health','Работает ли источник и доступен ли путь связи'),('Heartbeat','Когда источник выходил на связь'),('Inventory freshness','Насколько свежи технические наблюдения'),('Presence','Есть ли обоснованное подтверждение присутствия/исчезновения актива'),('Business lifecycle','Эксплуатация, хранение, ремонт, списание и другие управленческие процессы')])
p('Один неответивший протокол не означает исчезновение устройства. Для negative evidence нужны успешное покрытие scope, здоровый источник, TTL и пороги. Отказ collector или частичный scan не должен массово переводить активы в missing. Поздний offline-пакет не откатывает актуальную доступность автоматически.')
p('Топология строится по LLDP/CDP, интерфейсам, VLAN/VRF/LAG, маршрутам и другим evidence. FDB сама по себе не доказывает прямую физическую связь. Подтверждённые и предположительные связи различаются по достоверности и возрасту. Эти расширения входят в C19–C22; принятого широкого v2 покрытия сетевых устройств пока нет.')
h('8. События, поиск и масштабирование');image('04-events')
p('Используется PostgreSQL transactional outbox: изменение и событие записываются атомарно. Доставка обработчикам — at least once, с dedup/checkpoints/retry и replay. Это не обязательный event sourcing. Kafka, NATS и RabbitMQ сейчас не требуются. Проекции могут отставать, не блокируя авторитетную запись.')
p('Текущий базовый поиск PostgreSQL не выдаётся за готовый полнотекстовый движок. C28 сравнит Tantivy/Bluge на RU/EN корпусе, IP/FQDN/serial, ranking, facets, ACL, rebuild и сопровождении. Индекс — восстановимая проекция; tenant и актуальные права проверяются до выдачи результатов, snippets и counts. Multi-instance требует явного writer/readers ownership.')
image('05-geo')
p('Шардинг, SQL pool и HTTP-балансировщик решают разные задачи. В E5 каталог маршрутизирует tenant к shard/home/DR с routing epoch и residency. Базовое предложение — один writer на шард; active-active одного актива не обещается. Failover требует fencing, failback проверяется отдельно. UID не меняется при переносе и DR.')
p('Восстановление охватывает PostgreSQL, routing catalog, artifacts, OpenBao/ключи, dedup/outbox/checkpoints и индексы либо их rebuild. Backup сам по себе не равен geo HA. RPO/RTO и конкретные регионы должны быть согласованы и измерены; при ненулевом RPO нельзя обещать exactly once после аварии.')
h('9. Что уже сделано')
for pack in PLAN['packages'][:14]:
 h(pack['id']+'. '+pack['title'],2)
 for task in pack['tasks']:bullet(task['id']+' — '+task['name']+'. Результат: '+task['output']+'.')
p('C01–C03 приняты как проектирование и контракты, C04–C14 — в явно ограниченном Linux E1. Название C14 «выпуск» не означает официальный GitHub release: сформирован внутренний кандидат. Реализация находится в draft PR, main и production не обновлялись.')
h('10. Текущий C15 и незавершённые работы')
table(['Подзадача','Статус / фактический объём'],[
 ('C15.01','Завершено проектирование capabilities/прав; вся матрица платформ ещё не принята'),
 ('C15.02','В работе: native providers, contracts, relay/projection/profile core и private state; постоянный Windows agent ещё не принят'),
 ('C15.03','Не начата: SCM, install/start/stop, update и сохранение identity/spool'),
 ('C15.04','Не начата: итоговая проверка поддержанных Windows/прав, reboot и ресурсов')])
h('10.1. Что реализовано внутри C15.02',2)
for s in [
 'Read-only baseline из 12 секций: identity, OS, network, hardware, software, updates, services, users/groups, routes/ports, resources, protection и neighbors. Проверен на Windows Server 2022/elevated. Секции partial, complete=false; это не полный coverage всех ОС и прав.',
 'Изоляция каждого provider дочерним процессом: собственный бинарник с закрытым именем секции, 30 секунд на provider, bounded stdout, kill/wait и проверка схемы. Произвольный shell, PowerShell, remote target и произвольный WMI query не разрешаются этим контрактом.',
 'Отдельные observation/batch 1.2, opt-in по умолчанию false, typed facts, per-field provenance и tenant-scoped read API. Partial не означает deletion; C03/C09/C12 остаются совместимыми.',
 'Цепочка signed capabilities center→collector→agent и реальные mTLS/PG/Transit проверки. Origin и подпись исходного сообщения сохраняются; CenterResult ACK остаётся привязанным к исходному batch.',
 'Signed inventory profile 1.2: fixed policy windows-amd64-partial-baseline-v1, 12 секций, 30 секунд на provider и общий бюджет 420 секунд. Cadence берётся из общей Sources config; версия политики и common revision разделены.',
 'Migration 0034: отдельный offered/applied progress и Sources read API. FetchInventoryProfile12 проверяет и возвращает профиль/лимиты, но ещё не выполняет Windows persist/apply/ACK.',
 'Изолированный winstate: private DACL/root-relative bounded files/exclusive process lock. Базовый коммит c7e2f0a прошёл все пять workflow; модуль остаётся вне runtime.'
]:bullet(s)
h('10.2. Последний подтверждённый дефект',2)
p('Ветка и HEAD GitHub подтверждены 08.11.2026: '+SHA+'. Windows run 42309005102 завершился failure. Падает шаг Isolated Windows private DACL, reparse, bounded file and process lock primitives; TestAtomicReadersSeeWholeOldOrNewData, atomic_windows_test.go:149: concurrent replace … [atomic_rename code=5]. Это отказ операции rename, а точная причина ещё не установлена.')
p('Предыдущий сбой конкурентного чтения code=32 привёл к bounded read-only retry. Последний прогон не подтвердил готовность atomic replace: теперь зафиксирован code=5. Нельзя считать дефект закрытым или расширять write/rename retries по догадке. Остальные тесты базовых ACL, locks и process-crash в этом журнале прошли, но весь Windows workflow — failed.')
h('10.3. Что осталось до приёмки Windows',2)
for s in ['Разобрать и устранить native atomic rename failure с сохранением DACL/reparse/hardlink гарантий; повторить targeted native и все workflow на точном SHA.','Реализовать bounded orphan recovery и общие Windows privatefile/diskspool adapters.','Добавить host continuity / MachineGuid binding, обработку повторного enrollment и клонов.','Выполнить signed durable cache, offline verification, profile apply и applied reporting после durable commit.','Подключить постоянный Windows runtime к enrollment, collection, delivery, restart и recovery.','Завершить C15.03 SCM/install/update и C15.04: Windows 11/обычные права/реальный reboot/ресурсы/полнота заявленных providers.']:bullet(s)
h('11. Проверки, доказательства и ограничения')
table(['Точная ревизия / кампания','Результат','Граница доказательства'],[
 ('8560f57 · C14 actual soak','24 часа: 86400.914 с; 2740 samples; 1419 observations; 2 renewal; очереди опустели','Реальный Linux E1; не новый C15 soak и не production SLA'),
 ('39e401f · C14 candidate','Принят bounded Linux E1; auth regression; native systemd/update/reboot; backup/restore','Внутренний кандидат, не официальный release'),
 ('4ff977f · C15 profile core','Все 5 workflow success; PG60; C03 58 fixtures; center7 / relay11; две Linux VM по 9 проверок','Relay содержит synthetic enrolled agent; не Windows durable profile cache'),
 ('c7e2f0a · private-root base','Все 5 workflow success; native DACL/reparse/hardlinks/cross-process lock/redaction','Windows Server 2022/elevated; изолированный модуль, вне runtime'),
 ('5fe78c5 · текущий HEAD','V2/Web/Boot/Evidence success; Windows failure','Нельзя объявлять all green или C15.02 done')])
table(['Workflow текущего HEAD','Run ID','Итог'],[
 ('surveyscan-v2','42309004958','success'),('surveyscan-web','42309004983','success'),('surveyscan-boot','42309005065','success'),('surveyscan-acceptance-evidence','42309005140','success'),('surveyscan-c15-contract-preparation','42309005102','failure')])
p('Отдельные старые попытки этого HEAD имеют cancelled; они не подменяют приведённые завершённые прогоны. Исторические D06/D07 и C14 CLI503 не получают доказанную причину задним числом: приняты воспроизводимые исправления и повторные проверки, но причина исходных эпизодов остаётся не полностью подтверждённой.')
p('Не доказаны: production HA/geo DR, 100 одновременно активных пользователей, полная Windows compatibility/SCM/reboot/обычные права и сохранность при физическом отключении питания. Process crash и атомарная видимость имён не равны power-loss durability. Старый 24-часовой прогон завершён 6 ноября; нового временного запрета на продолжение работ нет.')
h('12. Полный маршрут этапов');image('08-roadmap')
table(['Эпоха','Пакеты','Назначение / состояние'],[
 ('E0','C01–C03','Основные решения, модель и контракты — завершено'),('E1','C04–C14','Постоянный Linux SMB — принят bounded profile'),('E2','C15–C24','Расширенный сбор, discovery, presence, topology, portable — C15 в работе'),('E3','C25–C30','Reconciliation, AM/CMDB, ответственность, FTS и нагрузка — план'),('E4','C31–C34','Интеграции, миграция v1, industrial delivery и пилот — план'),('E5','C35–C40','API/worker, SQL pool, shards, HA/geo DR — план'),('Волна 2','C41–C45','ЖЦ, склад, запчасти и физическая инвентаризация — план'),('Волна 3','C46–C50','ITSM: услуги, инциденты, requests, changes, SLA — план')])
table(['ID','Пакет','Эпоха','Готовность подзадач'],[(x['id'],x['title'],x['epoch'],str(sum(t['status']=='done' for t in x['tasks']))+'/4'+(' · в работе' if any(t['status']=='in_progress' for t in x['tasks']) else '')) for x in PLAN['packages']])
p('57/200 = 28,5% по количеству подзадач. Это не 28,5% трудозатрат, бюджета или срока: задачи имеют разную сложность. 14 пакетов приняты целиком; C15 принят частично. Полная детализация каждой подзадачи, зависимостей, результата, роли и критерия — приложение В.')
h('13. Следующие действия и открытые решения')
p('Первое действие после отчёта — продолжить C15.02 с native Windows atomic_rename code=5. После устранения и зелёного CI — безопасное состояние/кэш и постоянная передача, затем C15.03/04. Следующий пакет последовательного маршрута после C15 — C16, расширение Linux inventory/platform parity. Linux E1 уже работает, а C16 расширяет его до E2.')
p('C17–C19 добавят SSH, WinRM и SNMP, C20–C22 — discovery/presence/topology, C23 — portable, C24 — итоговую приёмку E2. Зависимости важнее механического порядка номеров. После C30 бизнес-волна 2 может развиваться без ожидания физического enterprise geo, если выполнены собственные prerequisites.')
table(['Решение / вход','Когда нужно'],[
 ('Windows/Linux/vendor matrix и разрешённые lab targets','До приёмки соответствующих C15–C24; тесты mock не заменяют совместимость'),
 ('Полная Asset/CI/component/service модель; merge/split','C25–C26; первоначальная трактовка «smdb» как CMDB остаётся рабочей'),
 ('Tantivy либо Bluge; RU/EN корпус и критерии','C28 перед реализацией C29'),
 ('100 active: данные, операции, think-time, hardware, SLO','C30; зарегистрированные пользователи не равны одновременно активным'),
 ('Integration access / exports v1 / ключи миграции','C31–C32'),
 ('Pilot scope, владельцы, окна и доступы','C34; production deploy отдельно'),
 ('Регионы, residency, RPO/RTO, fencing и DR capacity','C38–C39'),
 ('ЖЦ/склад и ITSM бизнес-процессы/права','C41/C46 перед реализацией волн')])
h('14. Источники и правила чтения статусов')
p('Актуальные AGENTS.md, docs/STATUS.md и docs/REQUESTS.md прочитаны через GitHub API; байты совпали с локальным checkout '+SHA[:7]+'. Ветка PR5, draft/base и пять итогов CI проверены отдельно. Main остаётся 73ced7e; PR4 открыт draft, не слит. Отчёт фиксирует состояние на 08.11.2026 и не изменяет проектные журналы.')
p('Источники содержат накопленные исторические записи. STATUS/handoff и C15-winstate-atomic.json ещё называют atomic native pending; GitHub уже показывает failure. Агрегат progress в plan.json отстаёт от tasks; число 57 пересчитано по task.status. C14-soak.json сохраняет исходную running запись, итог находится в C14-soak-result.json. В случае расхождения приоритет у финального evidence и результата конкретного SHA, а не у старого заголовка.')
for label,path in [('Правила продолжения','AGENTS.md'),('Текущий статус','docs/STATUS.md'),('Журнал запросов','docs/REQUESTS.md'),('Спецификация 0.5','docs/specifications/go-asset-management-v2.md'),('Архитектура','docs/architecture/go-target-architecture.md'),('WBS / источник 200 задач','docs/plans/surveyscan-v2/plan.json'),('C14 acceptance','docs/plans/surveyscan-v2/evidence/C14-acceptance.json'),('Финал actual soak','docs/plans/surveyscan-v2/evidence/C14-soak-result.json'),('C15 handoff','docs/plans/surveyscan-v2/handoffs/C15.md')]:link(label,BASE+path)
link('PR5','https://github.com/QgMixtate/surveyscan/pull/5')
link('Windows failure текущего HEAD','https://github.com/QgMixtate/surveyscan/actions/runs/42309005102')

def markdown(path,diagram_keys=None):
 lines=(ROOT/path).read_text().splitlines();i=0;di=0
 while i<len(lines):
  line=lines[i].strip()
  if line.startswith('```'):
   lang=line[3:];block=[];i+=1
   while i<len(lines) and not lines[i].strip().startswith('```'):block.append(lines[i]);i+=1
   if lang=='mermaid' and diagram_keys:
    image(diagram_keys[di]);di+=1
   else:
    para=p('\n'.join(block))
    for r in para.runs:r.font.name='Consolas';r.font.size=Pt(8)
   i+=1;continue
  if line.startswith('|'):
   rows=[]
   while i<len(lines) and lines[i].strip().startswith('|'):
    cells=[c.strip() for c in lines[i].strip().strip('|').split('|')]
    if not all(re.fullmatch(r':?-+:?',c) for c in cells):rows.append(cells)
    i+=1
   if rows:
    n=max(map(len,rows));table(rows[0]+['']*(n-len(rows[0])),[r+['']*(n-len(r)) for r in rows[1:]])
   continue
  m=re.match(r'^(#{1,5})\s+(.*)',line)
  if m:h(m.group(2),min(len(m.group(1))+1,3))
  elif re.match(r'^[-*]\s',line):bullet(line[2:])
  elif re.match(r'^\d+\.\s',line):p(line,'List Number')
  elif line:p(line)
  i+=1

page();h('Приложение А. Полная спецификация 0.5')
p('Исходный проект требований от 03.11.2026 приведён целиком с преобразованием разметки в Word. Статус — проект для согласования. Исторические «следующие задачи», открытые решения и запреты на старт в исходном документе относятся к моменту его подготовки; фактическое исполнение и последующая авторизация описаны в основном отчёте. Целевые требования будущих эпох не считаются выполненными.')
markdown('docs/specifications/go-asset-management-v2.md')
page();h('Приложение Б. Полная архитектура 0.5 со схемами')
p('Исходное описание приведено целиком. Пять Mermaid-схем переведены в изображения Word с сохранением логики потоков. Цветовое указание текущей готовности добавлено для отчёта. Старые утверждения о ещё не выбранном frontend и других решениях читаются вместе с актуальной частью отчёта: Web UI E1 уже реализован на React/TypeScript/Vite.')
markdown('docs/architecture/go-target-architecture.md',['01-context','02-delivery','03-discovery','04-events','05-geo'])
page();h('Приложение В. Полный WBS: 50 пакетов / 200 подзадач')
p('Источник — plan.json на '+SHA[:7]+'. Статусы пересчитаны по tasks. Каждый пакет содержит четыре подзадачи. Роль — зона ответственности, а не утверждённый штат. Длительности и стоимость не оценены. Критерий — ожидаемая проверка; наличие текста критерия не означает, что planned задача уже прошла её.')
for pack in PLAN['packages']:
 h(pack['id']+'. '+pack['title'],2)
 p('Эпоха: '+pack['epoch']+'. Зависимости пакета: '+(', '.join(pack.get('depends_on',[])) or 'нет')+'. Разделы спецификации: '+str(pack.get('spec_sections','—'))+'.')
 for task in pack['tasks']:
  h(task['id']+' — '+task['name'],3)
  p('Статус: '+STAT.get(task['status'],task['status'])+'. Группа: '+task.get('work_group','—')+'. Ответственная роль: '+task['owner']+'.')
  p('Вход / зависимости: '+(', '.join(task.get('depends_on',[])) or 'нет')+'.')
  p('Результат: '+task['output']+'.')
  p('Критерий проверки: '+task['verification']+'.')
  p('База будущей оценки: '+task.get('estimation_basis','—')+'.')
  if task.get('evidence'):p('Артефакты: '+'; '.join(task['evidence'])+'.')
  if task['id']=='C15.02':p('Уточнение 08.11.2026: native Windows CI на текущем HEAD failed, atomic_rename code=5. Модуль atomic state не принят и не подключён к runtime; общий статус остаётся in_progress.')
page();h('Приложение Г. Трассировка всех 19 замечаний пользователя')
p('Матрица связывает замечания с проектными требованиями и эпохами. «Учтено» означает отражено в требованиях. Фактическая готовность функций определяется разделами 9–11, а не наличием строки в матрице. Заключительный список открытых решений в исходной матрице исторический; часть закрыта E0/E1.')
markdown('docs/specifications/requirements-traceability-v0.5.md')
page();h('Приложение Д. Аналоги и основания решений')
p('Документальное исследование аналогов приведено с источниками и ограничениями. Это не пилот продуктов и не доказательство функционального паритета SurveyScan.')
markdown('docs/research/inventory-platform-analogues.md')
settings=doc.settings.element
update=OxmlElement('w:updateFields');update.set(qn('w:val'),'true');settings.append(update)
doc.core_properties.title='SurveyScan v2 — полное описание, архитектура и состояние проекта'
doc.core_properties.subject='Архитектура 0.5, план 50 пакетов / 200 задач, факт и оставшиеся работы на 08.11.2026'
doc.core_properties.author='SurveyScan project'
doc.core_properties.language='ru-RU'
dest=OUT/'SurveyScan_v2_Architecture_Specification_Status_2026-11-08.docx'
doc.save(dest)
counts=collections.Counter(t['status'] for x in PLAN['packages'] for t in x['tasks'])
manifest={'snapshot_date':'2026-11-08','source_revision':SHA,'task_counts':dict(counts),'document':dest.name,'docx_sha256':hashlib.sha256(dest.read_bytes()).hexdigest(),'diagrams':len(diagrams),'sources':{str(path.relative_to(ROOT)):hashlib.sha256(path.read_bytes()).hexdigest() for path in [ROOT/'docs/specifications/go-asset-management-v2.md',ROOT/'docs/architecture/go-target-architecture.md',ROOT/'docs/plans/surveyscan-v2/plan.json']},'latest_ci':{'success':[42309004958,42309004983,42309005065,42309005140],'failure':[42309005102]},'validation':'DOCX generated; structural/visual checks follow separately'}
(OUT/'manifest.json').write_text(json.dumps(manifest,ensure_ascii=False,indent=2))
print(json.dumps({'file':str(dest),'bytes':dest.stat().st_size,'paragraphs':len(doc.paragraphs),'tables':len(doc.tables),'inline_shapes':len(doc.inline_shapes),'tasks':dict(counts)},ensure_ascii=False))
