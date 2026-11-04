# surveyscanctl — C12.01

Отдельный компилируемый human CLI, только HTTP API; без PostgreSQL/Bao/machine private keys.
Вывод JSON. Сценарии:

```
surveyscanctl login --server https://surveyscan.example.invalid --username operator --password-file /secure/password --context-file /secure/survey-context.json --ca-file /secure/server-ca.pem
surveyscanctl context show --context-file /secure/survey-context.json
surveyscanctl assets list --context-file /secure/survey-context.json --limit 50
surveyscanctl assets get --context-file /secure/survey-context.json --id UUID
surveyscanctl sources list --context-file /secure/survey-context.json
surveyscanctl sources status --context-file /secure/survey-context.json --id UUID
surveyscanctl status --context-file /secure/survey-context.json
surveyscanctl logout --context-file /secure/survey-context.json
surveyscanctl help
```

Login использует существующий session API C03, Origin и server-issued tenant/user; cookie+CSRF+expiry
сохраняются в context0600, пароль не сохраняется. Публикация файла через atomic hardlink не заменяет
существующий context; при неудачном сохранении CLI пытается завершить новую server session.
`context show` скрывает cookie/CSRF. Отдельные context files задают разные server/tenant sessions;
произвольный tenant/header аргумент не поддерживается. Bearer-token context пока не реализован.

HTTPS>=1.2 с проверкой hostname/system CA либо дополнительным --ca-file. Нет insecure/redirect fallback.
Только явный --dev-loopback-http для localhost/127.0.0.1/::1 допускает HTTP на dev-стенде.
Таймаут15s, response<=2MiB. Assets/sources возвращают одну страницу и next_cursor; следующая — через--cursor.
API ошибки печатают только HTTP code в JSON stderr, не произвольный error body/credentials.

Exit0 — success;2 — flags/private file/config;3 — auth/policy;4 — missing UUID;5 — network/TLS/timeout/
503/429;6 — прочие API ошибки. Logout отзывает server session с CSRF и удаляет context; при401 удаляет
уже недействующий context, при403/network error сохраняет его для повторной попытки.
Context не должен публиковаться/попадать в backup общего доступа. На shared host защищать каталог
и UID пользователя. Table output поддержан для resource commands (--output table), JSON остаётсяdefault. OS keychain/bearer-token contexts не реализованы.

scripts/cli_smoke.py: compiled CLI/real HTTPS/PG/auth/CSRF, two tenants/viewer, pagination и logout.
C12.02–04 добавили profiles get/set --id UUID --revision REV --profile-file JSON, diagnostics,
local-status --diagnostics-file PRIVATE; source profile panel виден в отдельном UI. JSONC03/C09 остаётся неизменным.
