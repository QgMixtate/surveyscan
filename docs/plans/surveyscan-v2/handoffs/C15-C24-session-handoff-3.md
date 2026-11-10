# Передача сессии №3: C15–C24 — состояние на 2026-11-10 ~18:30 UTC

Ветка `claude/peaceful-goodall-a8u9sk`, журнал — docs/REQUESTS.md R-027. Счётчик 57/200 и статусы пакетов НЕ менялись.
Предыдущая передача: C15-C24-session-handoff-2.md (стенд, изменения цели, история).

## Сделано (R-027, всё — локально в песочнице, hosted CI заблокирован биллингом)
- C09: карточка актива перечисляет источники профиля 1.2 (45d657d).
- Тестовый CA smoke совместим с Python 3.13 strict X.509 (dd8ebb6): 7 ранее падавших smoke зелёные на 3.13.
- C23.03 HTTPS-загрузка portable: POST /api/v1/sources/{id}/portable-import + nginx location (507882d).

## Ждёт стенда / пользователя
1. **Утренний снимок суточного soak** (11.11 после 09:00 МСК; напоминание send_later в этой сессии на 09:05 МСК). Команды soak-end — R-026. Сравнить с базой 10:24 UTC и 16:58 UTC.
2. **Перезапуск центра стенда новой сборкой** (только ПОСЛЕ снимка): на Linux-ВМ `git pull`, `make build`, в tmux `center` Ctrl-C и запуск vm_center.py заново.
   Внимание: новая БД и CA — все четыре личности (Windows SurveyscanAgentVm, surveyscan-agent, surveyscan-ssh1, surveyscan-winrm2) регистрировать заново
   (prepare → grant → enroll, см. C15-vm-stand-runbook.md и R-026). Ожидание: в источниках поле acquisition = agent/ssh/winrm (по имени prepare-файла).
   HTTPS-загрузку portable на стенде проверить нельзя без человеческого API и учётной записи администратора у vm_center — сначала проверить, поднимает ли их харнесс.
3. **WinRM с правами WMI** (на DC, PowerShell от администратора домена; тестовая настройка — откатить после пилота):

        Add-ADGroupMember -Identity "Distributed COM Users" -Members scanwinrm
        $sid = (Get-ADUser scanwinrm).SID.Value
        $sec = Get-WmiObject -Namespace root/cimv2 -Class __SystemSecurity
        $sd = $sec.GetSecurityDescriptor().Descriptor
        $ace = (New-Object System.Management.ManagementClass Win32_ACE).CreateInstance()
        $tr = (New-Object System.Management.ManagementClass Win32_Trustee).CreateInstance(); $tr.SIDString = $sid
        $ace.AccessMask = 0x21   # Enable Account (0x1) + Remote Enable (0x20)
        $ace.AceFlags = 0x2      # наследовать на дочерние пространства
        $ace.AceType = 0; $ace.Trustee = $tr
        $sd.DACL += $ace.psobject.immediateBaseObject
        $sec.SetSecurityDescriptor($sd).ReturnValue   # 0 = успех

   Затем с Linux: `winrm-probe … exec-script` (как в R-026) — ожидание: os/cs/prod/bios/cpu/nics уже без PermissionDenied. Службы (Win32_Service) удалённому
   не-админу может дополнительно закрывать SDDL SCM (`sc.exe sdshow scmanager`) — фиксировать фактический результат, не расширять права заранее.
   Откат: Remove-ADGroupMember "Distributed COM Users" scanwinrm; удалить ACE с SID scanwinrm тем же __SystemSecurity.
4. **Решения пользователя:** приёмка C15.02 по V1–V4/V9 (исключения V5 обычные права, V6 Win10/11, V7 клон, откат); биллинг CI.

## Не проверено (честно)
PG17/Python 3.12/hosted CI для R-027; продление таймаутов сервера при загрузке на настоящем бинарнике; загрузка через nginx и большой пакет; UI/CLI-клиент загрузки;
upgrade_smoke/update_smoke в полном клоне. Дальше по плану: C25 (merge/split, в т.ч. отдельный актив WinRM1).
