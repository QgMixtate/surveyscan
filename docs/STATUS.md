# Текущее состояние surveyscan

Обновлено: 6 ноября 2026. **C14 завершён в пределах Linux E1; 57/200 подзадач выполнены**,
включая проектирование C15.01. [Протокол приёмки](plans/surveyscan-v2/evidence/C14-acceptance.json).

Суточный прогон: 86400,914 с, 2740 измерений, 1419 наблюдений, два настоящих продления
сертификатов; очереди опустели, UID и отсутствие дублей сохранены. Это frozen source8560f57.
Исправление входа проверено отдельно на39e401f: бюджет5→8с, без изменения Argon2, лимитов
попыток и двух hashslots. При48%CPU прежний вариант давал503 после6464мс проверки пароля;
исправленный вернул201 за6336мс и создал ровно одну сессию, затем штатно отозванную тестом.
Блокировка БД по-прежнему возвращает ограниченный503 без создания сессии.

39e401f: все4 hosted workflows SUCCESS (v242183074129, native42183074101, Web42183074062,
evidence42183074089), две свежие VM9+9, локальный PG51 и точные артефакты кандидата Chromium16.
[Доказательства](plans/surveyscan-v2/evidence/C14-hosted-39.json). Причина конкретного старого
503 без backendtrace недоказуема; воспроизведённый класс исправлен, безопасная диагностика сохранена.
Виртуальный HPET отключён только в тестовой VM; исходный зависший запуск остался failed.

[Кандидат](plans/surveyscan-v2/evidence/C14-candidate-39.json):27 файлов, подпись/verify/staging
проверены, временный ключ удалён. Go39e401f и независимый Web8560f57. Это внутренний кандидат;
официальный GitHubRelease, слияние main и production deployment не выполнялись.
E1 source опубликован в [PR4](https://github.com/QgMixtate/surveyscan/pull/4).

**Следующая работа — C15.02**, worktree `/workspace/surveyscan-c15`, ветка codex/v2-c15-windows,
[PR5](https://github.com/QgMixtate/surveyscan/pull/5). C15.01done, C15.02partial: восемь native
секций проверены на WindowsServer2022 с elevatedtoken; четыре секции не реализованы. Новый
observation1.2 пока изолирован: signed delivery/storage/detail API, DACL/spool locks, host
continuity, SCM lifecycle, обычные права, Windows11 и настоящий reboot ещё не приняты.
Продолжать автоматически с этого пункта по R-020/R-022/R-023. Настройки среды не публиковать.

Архитектура0.5: OpenBao, отдельный Web, CLI/API, неизменяемый asset_uid, событийный outbox
без внешней шины. E1 — постоянный Linux цикл с identity/os/network; полная инвентаризация
и платформы расширяются в E2. Enterprise HA/geo/100users не являются подтверждённым SLA.

Текущий checkout — C15 worktree. Комбинированный981f4e7 (E1 auth8s + C15 baseline)
прошёл все5hosted workflows. C14final metadata получена изE1fa73e47, статусыplan/CSV57done
согласованы; C15 evidence использует локальныеpaths. Следующий код — локальные users/groups/SID.
