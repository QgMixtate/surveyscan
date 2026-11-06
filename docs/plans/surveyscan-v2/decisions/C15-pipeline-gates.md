# C15.02 — следующие gates постоянной доставки

Native12baseline и worker проверки не завершают C15.02. До runtime enable: 

1. Согласовать observation1.2 и batch/ACK/profile versions отдельно. Старые C03 schemas
   immutable; новые signed payload/batch contracts добавляются рядом. Collector+center
   должны подтвердить поддержку и negotiated byte limits до первого send. Pending bytes
   нельзя пересобирать/переподписывать при downgrade.
2. Согласовать payload/batch/spool/admission limits: старый canonical observation64KiB,
   HTTP/batch1MiB, draftpayload/worker1MiB. Равныйpayload max не вмещается втотжеHTTPmax
   после envelope/signature. Нужны совместимые limits, не молчаливое усечение.
3. Реализовать проекцию новых records. Сейчас inventory.flatten() знает3sections и
   default игнорируетпрочие; нельзя просто разрешить1.2 и потерять hardware/software.
   Семантика record keys, duplicate/conflict, partial/complete и source ranking обязательна.
4. Обеспечить достоверное удаление ушедших facts в заявленном coverage. Все native baseline
   сейчас partial/complete=false; это не даёт права удалить отсутствующие ПО/пользователей.
   Provider scope/field availability и полное перечисление scope надо выразить явно.
5. Сохранить старый C09 asset/list/detail shape. Новые sections не должны сломать старый
   Web validator. Новый detail API/schema и пагинация длябольшихrecords добавляются отдельно.
6. Отделить долгуюcollection от heartbeat вscheduler; только короткаяserial actor операция
   меняет config/counters/spool/TLSstate. Запрет overlapping inventory и провайдерных утечек.
7. Только после real signed agent→collector→center→PG/projection/API + offline/replay/
   old-peer rejection/tenant/secret/partialcoverage checks закрывать C15.02. Windows DACL,
   hostcontinuity/processlock и SCM/reboot — C15.03/04, не доказаны native API CI.
