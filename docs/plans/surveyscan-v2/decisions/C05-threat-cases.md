# C05 — проверенные threat cases и границы

| Сценарий | Проверка | Результат |
|---|---|---|
| Два bootstrap одновременно | real PG, 2 goroutines, Argon2id | 1 success, 1 conflict; одна учётная запись |
| Нет/чужой Origin, missing/чужой session CSRF | HTTPS httptest + real PG | 403, mutation не вызывается |
| Изменение login body tenant/unknown property | HTTPS + strict JSON | 400, клиент не выбирает tenant |
| Viewer/operator/admin | real login и protected future routes | viewer write 403, operator source-admin 403 |
| X-Tenant-ID/X-User-ID подмена | анонимный и authenticated HTTP | 401 без credential; auth context сохраняет свой tenant |
| Чужой token UUID, другой tenant | реальный revoke API | generic 404, чужой credential не отозван |
| Cookie + bearer одновременно | реальный HTTP | 401, нет смешения полномочий |
| CLI write/escalation | scopes assets:read | write/source-read 403, только разрешённое чтение проходит gate |
| Token revoke/logout/expiry | real PG + HTTPS API | credential после отзыва/expiry не принимается |
| Несколько sessions и concurrent token issuance | real PG locks | две независимые sessions/tokens; logout одной не отзывает другую |
| Password reset | console service + real PG | старый пароль и старые credentials отвергнуты, новый пароль принят |
| Disable/role change против transaction | FOR SHARE + concurrent change | change ждёт commit; затем старый credential отвергнут |
| Worker с чужим tenant | Authorizer port внутри real transaction | forbidden |
| Общий rate limit двух экземпляров service | real invalid logins и shared PG | bounded attempts, 429 |
| Перезапуск Go server | скомпилированный бинарник, настоящий HTTP/PG | session сохраняется после остановки/старта процесса |
| HTTP без dev opt-in/с посторонним hostname | origin validation unit checks | startup rejected |

HTTPS integration использует httptest TLS server и Go cookie jar, не настоящий браузер.
Binary smoke использует явный loopback HTTP dev mode. Полный браузерный UI E2E — C09.
Тестовый пароль синтетический; live smoke генерирует временный private file и удаляет его.
Raw session/token/CSRF values не включаются в отчёты. Тестовые БД случайные, удаляются только
созданные самим прогоном; существующие v1/v2 данные не удаляются.

Не выполнены: production TLS proxy/PKI, machine auth/enrollment/renewal, OIDC/MFA,
100-user load/soak, действующие asset/job/artifact handlers и их бизнес-гонки.
Проверенные auth gates/ports не заменяют будущие проверки реальных доменных запросов.
GitHub hosted CI требует сетевого доступа api.github.com; local pass не означает hosted pass.
