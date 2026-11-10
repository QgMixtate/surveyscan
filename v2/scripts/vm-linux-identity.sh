#!/usr/bin/env bash
# Стенд Linux-ВМ: регистрирует агентскую личность и запускает её systemd-службой. Запускать под root.
#   vm-linux-identity.sh agent                      — локальный агент run12 (юнит surveyscan-agent уже установлен)
#   vm-linux-identity.sh ssh NAME ADDR USER KEYFILE — личность для SSH-цели (юнит NAME, run-ssh12); KEYFILE — приватный ключ цели
# Нужны: запущенный vm_center.py (OUT=~/surveyscan/v2/.local/vm-center), собранные .dist/surveyscan-agent и .dist/ssh-probe,
# установленный /opt/surveyscan/current/bin/surveyscan-agent. Секреты в вывод не печатаются.
set -euo pipefail
OUT="${OUT:-$HOME/surveyscan/v2/.local/vm-center}"
BIN=/opt/surveyscan/current/bin/surveyscan-agent
PROBE="$(dirname "$OUT")/../.dist/ssh-probe"
kind="${1:-}"
case "$kind" in
  agent) NAME=surveyscan-agent; PREP="prepare-linux.json"; GRANT="grant-linux.json" ;;
  ssh)   NAME="${2:?NAME}"; ADDR="${3:?ADDR}"; TUSER="${4:?USER}"; KEYFILE="${5:?KEYFILE}"
         PREP="prepare-linux-$NAME.json"; GRANT="grant-linux-$NAME.json" ;;
  *) echo "usage: $0 agent | ssh NAME ADDR USER KEYFILE" >&2; exit 2 ;;
esac
CFG="/etc/$NAME"
install -d -m0755 "$CFG"
install -m0644 "$OUT/ca.pem" "$CFG/ca.pem"
python3 - "$OUT" "$CFG" "$NAME" <<'PY'
import json, sys
out, cfg, name = sys.argv[1:4]
c = json.load(open(out + '/agent-config.linux.json'))
c['ca_certificate_file'] = cfg + '/ca.pem'
c['state_directory'] = '/var/lib/' + name
path = cfg + ('/config.json' if name == 'surveyscan-agent' else '/agent.json')
json.dump(c, open(path, 'w'), indent=2)
print(path)
PY
if [ "$NAME" = surveyscan-agent ]; then CONF="$CFG/config.json"; else CONF="$CFG/agent.json"; fi
chmod 0600 "$CONF"
if [ "$kind" = ssh ]; then
  FP="$("$PROBE" fingerprint --addr "$ADDR")"; echo "target host key: $FP"
  install -m0600 "$KEYFILE" "$CFG/key"
  python3 - "$CFG" "$NAME" "$ADDR" "$TUSER" "$FP" <<'PY'
import json, sys
cfg, name, addr, user, fp = sys.argv[1:6]
json.dump({'addr': addr, 'user': user, 'host_key_sha256': fp,
           'private_key_file': f'/run/credentials/{name}.service/key'}, open(cfg + '/target.json', 'w'), indent=2)
PY
  chmod 0600 "$CFG/target.json"
  cat > "/etc/systemd/system/$NAME.service" <<UNIT
[Unit]
Description=SurveyScan SSH-collected target ($NAME)
Wants=network-online.target
After=network-online.target
StartLimitIntervalSec=120
StartLimitBurst=8
[Service]
Type=simple
User=surveyscan-agent
Group=surveyscan-agent
StateDirectory=$NAME
StateDirectoryMode=0700
LoadCredential=config:$CFG/agent.json
LoadCredential=target:$CFG/target.json
LoadCredential=key:$CFG/key
ExecStart=$BIN run-ssh12 --config %d/config --ssh-target %d/target
Restart=on-failure
RestartSec=10s
RestartPreventExitStatus=2
UMask=0077
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
PrivateDevices=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectControlGroups=yes
RestrictRealtime=yes
LockPersonality=yes
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX
[Install]
WantedBy=multi-user.target
UNIT
  systemctl daemon-reload
fi
systemctl stop "$NAME" 2>/dev/null || true
SR=(systemd-run --quiet --wait --pipe --collect -p User=surveyscan-agent -p "StateDirectory=$NAME" -p StateDirectoryMode=0700 -p UMask=0077)
TMP="$(mktemp /root/prepare.XXXXXX)"
"${SR[@]}" -p "LoadCredential=config:$CONF" sh -c "exec $BIN prepare --config \"\$CREDENTIALS_DIRECTORY/config\"" > "$TMP"
echo "prepare ok; private key markers: $(grep -c 'PRIVATE KEY' "$TMP" || true)"
rm -f "$OUT/$GRANT"
mv "$TMP" "$OUT/$PREP"
for _ in $(seq 1 30); do [ -s "$OUT/$GRANT" ] && break; sleep 2; done
[ -s "$OUT/$GRANT" ] || { echo "FAIL: grant $GRANT не появился (проверьте окно центра: tmux attach -t center)"; exit 1; }
"${SR[@]}" -p "LoadCredential=config:$CONF" -p "LoadCredential=grant:$OUT/$GRANT" \
  sh -c "exec $BIN enroll --config \"\$CREDENTIALS_DIRECTORY/config\" --grant-file \"\$CREDENTIALS_DIRECTORY/grant\""
systemctl enable --now "$NAME"
sleep 75
systemctl is-active "$NAME"
journalctl -u "$NAME" --no-pager -n 6 | cut -c1-170
