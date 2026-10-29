#!/bin/sh
# Коллектор сканера обследования для Linux (Astra Linux, РЕД ОС, Альт, Debian/RHEL-семейство).
# Только чтение: ничего не меняет на хосте. Запуск от root (или через sudo) даёт полный набор;
# без root часть секций будет пустой, ядро сканера это учитывает (результат «нет данных»).
#
#   sh linux_collect.sh > "$(hostname)".surv
#
# Формат вывода: секции, каждая начинается строкой @@@SURVEY:<имя>@@@ .

COLLECTOR_VERSION="0.1"
sec() { printf '\n@@@SURVEY:%s@@@\n' "$1"; }
have() { command -v "$1" >/dev/null 2>&1; }
run() { "$@" 2>/dev/null; }

sec meta
echo "collector=linux_collect.sh"
echo "version=$COLLECTOR_VERSION"
echo "collected_at=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
echo "uid=$(id -u)"

sec hostname
run hostname
run hostname -f

sec ip_addr
if have ip; then run ip -o addr show; else run ifconfig -a; fi

sec ip_link
if have ip; then run ip -o link show; fi

sec ip_route
if have ip; then run ip -o route show; elif have route; then run route -n; fi

sec resolv_conf
run cat /etc/resolv.conf

sec os_release
run cat /etc/os-release

sec astra_version
run cat /etc/astra_version
run cat /etc/astra/build_version

sec redhat_release
run cat /etc/redos-release
run cat /etc/altlinux-release
run cat /etc/redhat-release

sec uname
run uname -srmv

sec packages_dpkg
if have dpkg-query; then run dpkg-query -W -f='${Package}\t${Version}\t${Architecture}\t${db:Status-Abbrev}\n'; fi

sec packages_rpm
if have rpm; then run rpm -qa --qf '%{NAME}\t%{EPOCH}:%{VERSION}-%{RELEASE}\t%{ARCH}\t%{VENDOR}\n'; fi

sec sysctl
run sysctl -a

sec cmdline
run cat /proc/cmdline

sec sshd_effective
if have sshd; then run sshd -T; elif [ -x /usr/sbin/sshd ]; then run /usr/sbin/sshd -T; fi

sec sshd_config
run cat /etc/ssh/sshd_config
for f in /etc/ssh/sshd_config.d/*.conf; do [ -f "$f" ] && run cat "$f"; done

sec login_defs
run grep -Ev '^[[:space:]]*(#|$)' /etc/login.defs

sec pwquality
run grep -Ev '^[[:space:]]*(#|$)' /etc/security/pwquality.conf
for f in /etc/security/pwquality.conf.d/*.conf; do [ -f "$f" ] && run grep -Ev '^[[:space:]]*(#|$)' "$f"; done

sec faillock
run grep -Ev '^[[:space:]]*(#|$)' /etc/security/faillock.conf

sec pam
for f in /etc/pam.d/common-password /etc/pam.d/common-auth /etc/pam.d/system-auth /etc/pam.d/password-auth /etc/pam.d/su /etc/pam.d/sshd /etc/pam.d/login; do
  if [ -f "$f" ]; then echo "### $f"; run grep -Ev '^[[:space:]]*(#|$)' "$f"; fi
done

sec passwd
# Только имя, UID и оболочка — без хэшей и персональных полей
run awk -F: '{print $1":"$3":"$7}' /etc/passwd

sec shadow_empty
# Учётные записи с пустым паролем (только имена). Требует root.
if [ -r /etc/shadow ]; then run awk -F: '($2==""){print $1}' /etc/shadow; else echo "#noaccess"; fi

sec sudoers_nopasswd
if [ -r /etc/sudoers ]; then run grep -rhE '^[^#].*NOPASSWD' /etc/sudoers /etc/sudoers.d/; else echo "#noaccess"; fi

sec file_modes
for f in /etc/passwd /etc/shadow /etc/group /etc/gshadow /etc/sudoers /etc/ssh/sshd_config \
         /etc/crontab /etc/cron.d /etc/cron.daily /etc/cron.hourly /boot/grub/grub.cfg /boot/grub2/grub.cfg; do
  [ -e "$f" ] && run stat -c '%n|%a|%U|%G' "$f"
done

sec listening
if have ss; then run ss -H -tulpn; elif have netstat; then run netstat -tulpn; fi

sec connections
if have ss; then run ss -H -tnp state established; elif have netstat; then run netstat -tnp 2>/dev/null | grep ESTABLISHED; fi

sec services_enabled
if have systemctl; then run systemctl list-unit-files --type=service --state=enabled --no-legend --no-pager; fi

sec services_active
if have systemctl; then
  for s in auditd rsyslog syslog-ng systemd-journald chronyd chrony ntp ntpd systemd-timesyncd firewalld ufw nftables iptables \
           telnet.socket rsh.socket rlogin.socket vsftpd tftp.socket avahi-daemon cups snmpd kesl klnagent drweb-configd; do
    printf '%s=%s\n' "$s" "$(systemctl is-active "$s" 2>/dev/null)"
  done
fi

sec audit_rules
if have auditctl; then run auditctl -l; fi

sec mounts
run cat /proc/mounts

sec astra_security
# Режимы защиты Astra Linux SE (присутствуют только на Astra)
if have astra-mic-control; then echo "mic=$(astra-mic-control is-enabled 2>/dev/null)"; fi
if have astra-digsig-control; then echo "digsig=$(astra-digsig-control is-enabled 2>/dev/null)"; fi
if have astra-modeswitch; then echo "mode=$(astra-modeswitch get 2>/dev/null)"; fi
if have astra-ptrace-lock; then echo "ptrace_lock=$(astra-ptrace-lock is-enabled 2>/dev/null)"; fi
if have astra-sudo-control; then echo "sudo_control=$(astra-sudo-control is-enabled 2>/dev/null)"; fi
if have astra-console-lock; then echo "console_lock=$(astra-console-lock is-enabled 2>/dev/null)"; fi
if have astra-interpreters-lock; then echo "interpreters_lock=$(astra-interpreters-lock is-enabled 2>/dev/null)"; fi
if have astra-swapwiper-control; then echo "swapwiper=$(astra-swapwiper-control is-enabled 2>/dev/null)"; fi

sec end
echo ok
