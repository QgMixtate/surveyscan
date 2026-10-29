# surveyscan connector

Агент сбора на стороне заказчика (этап 4). Всегда дозванивается до центра сам
(pull-модель, только исходящие соединения) — у заказчика не открываются входящие
правила на фаерволе. Для изолированного контура — файловый обмен (офлайн-курьер).

Статическая сборка без внешних зависимостей: один бинарник заносится в закрытый контур.

## Сборка

```bash
CGO_ENABLED=0 go build -o surveyscan-connector .
# кросс-компиляция под цель заказчика:
GOOS=linux   GOARCH=amd64 CGO_ENABLED=0 go build -o surveyscan-connector-linux .
GOOS=windows GOARCH=amd64 CGO_ENABLED=0 go build -o surveyscan-connector.exe   .
```

## Режимы

```bash
# PULL: цикл дозвона до центра, забор задания, сбор, выгрузка результата
./surveyscan-connector -mode serve \
    -center https://center.aittask -token <ТОКЕН> \
    -raw /var/surveyscan/collected -interval 30s \
    -ca center-ca.pem -cert connector.pem -key connector.key   # mTLS (прод)

# ОФЛАЙН-КУРЬЕР (изолированный контур, без сети):
#  на центре:   GET /connector/jobs/{id}/bundle  -> job.json  (переносится в контур)
./surveyscan-connector -mode courier-run -job job.json -raw /var/surveyscan/collected -out result.json
#  result.json переносится обратно, на онлайн-стороне:
./surveyscan-connector -mode courier-import -center https://center.aittask -token <ТОКЕН> -result result.json
```

`-raw` — каталог уже снятых выгрузок коллекторов (`linux_collect.sh` / `windows_collect.ps1`
и отчёты сканеров). Коннектор передаёт их в центр; анализ (БДУ, фиды, конфигурации) идёт
на центре его базами знаний. mTLS (`-ca/-cert/-key`) — боевой режим аутентификации;
токен — минимальный вариант. Сами соединения всегда исходящие.
