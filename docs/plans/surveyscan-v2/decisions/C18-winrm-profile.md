# C18.01 — профиль безагентного WinRM-сбора Windows (проект + локальная реализация internal/remote/winrminv)

Статус: код и нормализация проверены на фикстурах и схеме наблюдения; **живая Windows по WinRM НЕ проверялась** (C18.04 не выполнена).

- **Транспорт.** Только HTTPS (по умолчанию 5986), сертификат цели проверяется по переданному CA (PEM, обязателен), `insecure`/HTTP/Basic-over-HTTP
  не поддерживаются. Аутентификация NTLM (`DOMAIN\user` или локальная УЗ), пароль — по алиасу из хранилища секретов, обнуляется после использования.
- **Команда.** Один фиксированный read-only сценарий PowerShell 5.1 (`winrminv.Script`): только `Get-CimInstance`/`Get-ItemProperty`; тест запрещает
  `Set-`/`Remove-`/`New-Item`/`Out-File`; закодированный размер ≤ 7800 символов (лимит cmd.exe ≈ 8191). Данные оператора в сценарий не подставляются.
- **Секции.** identity, os, network, hardware, software, services — `partial/REMOTE_WINRM_PARTIAL`; updates/protection/neighbors/users_groups/routes_ports/
  resources — `unsupported`; значения не выдумываются (placeholder-серийники, управляющие символы, неизвестные состояния → unknown/пропуск).
  Ошибка/таймаут/отмена → ошибка без частичной публикации; текст ответа цели в ошибки не попадает.
- **Доставка.** Как у SSH: `surveyscan-agent run-winrm12 --config agent.json --winrm-target target.json` на Linux-хосте коллектора — виртуальная агентская личность
  (grant с `inventory_platform=windows/amd64`, файл `prepare-windows.json` в vm_center). Вид источника на проводе пока `agent`.
- **Требования к цели (оператор).** HTTPS-listener WinRM с сертификатом, доверенным CA из конфига; УЗ в «Remote Management Users» + права на чтение WMI/реестра;
  firewall 5986 только с коллектора. Конфиг цели: host, port, user, password_file, ca_file, tls_server_name (0600, неизвестные поля запрещены).
- **План C18.04 (на ВМ Windows Server 2019 пользователя):** создать самоподписанный CA/сертификат и HTTPS-listener; `ssh-probe`-аналога пока нет — прогнать
  `run-winrm12`; негатив: неверный пароль, неверный CA, закрытый порт, УЗ без прав; проверить, что в журнале и результатах нет пароля.
