#!/bin/sh
# Сбор версий ПО — ТОЛЬКО ЧТЕНИЕ: ничего не ставит, не меняет, сеть не сканирует, файлов на сервере НЕ оставляет.
# Вывод — в stdout. Удалённо: ssh user@IP 'sh -s' < version.sh > versions_IP.txt
echo "== host"; hostname; date; uname -a; cat /etc/os-release
echo "== packages"
if command -v dpkg-query >/dev/null 2>&1; then dpkg-query -W -f='${Package} ${Version} ${source:Package}\n'
elif command -v rpm >/dev/null 2>&1; then rpm -qa --qf '%{NAME} %{VERSION}-%{RELEASE} %{SOURCERPM}\n'; fi
echo "== services"; systemctl list-units --type=service --state=running --no-pager --no-legend 2>/dev/null
echo "== listening"; ss -tln 2>/dev/null
echo "== config"
for k in PermitRootLogin PasswordAuthentication PubkeyAuthentication X11Forwarding MaxAuthTries; do v=$(grep -hiE "^\s*$k\b" /etc/ssh/sshd_config.d/*.conf /etc/ssh/sshd_config 2>/dev/null | head -n1 | awk '{print $NF}'); echo "sshd_$k ${v:-default}"; done
[ -f /var/run/reboot-required ] && echo "reboot_required yes" || echo "reboot_required no"
echo "kernel_running $(uname -r)"
echo "uptime_days $(awk '{print int($1/86400)}' /proc/uptime)"
if command -v unattended-upgrade >/dev/null 2>&1; then echo "auto_updates unattended-upgrades"; elif systemctl is-enabled dnf-automatic.timer >/dev/null 2>&1; then echo "auto_updates dnf-automatic"; else echo "auto_updates none"; fi
echo "login_users $(awk -F: '$7 !~ /(nologin|false|sync|halt|shutdown)$/ {print $1}' /etc/passwd | tr '\n' ' ')"
echo "uid0_users $(awk -F: '$3==0 {print $1}' /etc/passwd | tr '\n' ' ')"
if command -v ufw >/dev/null 2>&1; then echo "firewall ufw"; elif command -v firewall-cmd >/dev/null 2>&1; then echo "firewall firewalld"; elif command -v nft >/dev/null 2>&1; then echo "firewall nftables"; else echo "firewall unknown"; fi
echo "== stack"
for c in "nginx -v" "apache2 -v" "httpd -v" "php -v" "mysql --version" "psql --version" "python3 --version" "node -v" "java -version" "openssl version"; do
  command -v ${c%% *} >/dev/null 2>&1 && { echo "-- $c"; $c 2>&1 | head -n 2; }
done
