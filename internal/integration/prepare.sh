#!/usr/bin/env bash
# Prepares a fresh Ubuntu VM like a ServerDog App server, minus the parts sites don't need, and installs the agent under test.
set -euo pipefail
export DEBIAN_FRONTEND=noninteractive

apt-get update -q
php_fpm="$(apt-cache search --names-only '^php[0-9.]+-fpm$' | awk '{print $1}' | sort -V | tail -n 1)"
# The mysql extension is one provisioning installs too; WordPress refuses to start without it.
apt-get install -y -q nginx "$php_fpm" "${php_fpm%-fpm}-mysql" nodejs git python3 cron redis-server memcached

id serverdog > /dev/null 2>&1 || useradd --create-home --shell /bin/bash serverdog
id git > /dev/null 2>&1 || useradd --create-home --shell /usr/bin/git-shell git
install -d -m 700 -o git -g git /home/git/.ssh
touch /home/git/.ssh/authorized_keys
chown git:git /home/git/.ssh/authorized_keys
chmod 600 /home/git/.ssh/authorized_keys
install -d -o git -g git /srv/git

# The Git server and the agent share 127.0.0.1, and the suite creates sites far faster than people do. OpenSSH 9.8+
# counts each ssh-keyscan connection as a connection without authentication and would soon refuse the address.
sshd_settings="$(sshd -T 2> /dev/null || true)"
if grep -q '^persourcepenalties ' <<< "$sshd_settings"; then
  echo 'PerSourcePenaltyExemptList 127.0.0.1/32,::1/128' > /etc/ssh/sshd_config.d/serverdog-vmtest.conf
  sshd -t
  systemctl restart ssh
fi

# The tests push into repositories owned by git while running as root.
git config --global --add safe.directory '*'

rm -f /etc/nginx/sites-enabled/default
cat > /etc/nginx/sites-available/000-catch-all << 'EOF'
server {
    listen 80 default_server;
    listen [::]:80 default_server;
    server_name _;
    return 444;
}
EOF
ln -sf /etc/nginx/sites-available/000-catch-all /etc/nginx/sites-enabled/000-catch-all
nginx -t
systemctl reload-or-restart nginx

# One database engine per release, so both kinds are tested: MariaDB on 24.04, PostgreSQL on 26.04.
. /etc/os-release
if [ "$VERSION_ID" = "24.04" ]; then
  apt-get install -y -q mariadb-server
else
  apt-get install -y -q postgresql
fi

# Pebble, Let's Encrypt's test server, stands in for the ACME API. It validates over port 80, and it resolves names
# through /etc/hosts like the agent does, so the tests point their domains at this VM there.
PEBBLE=v2.10.1
arch="$(dpkg --print-architecture)"
if ! /usr/local/bin/pebble -version 2>&1 | grep -q "$PEBBLE"; then
  work="$(mktemp -d)"
  curl -fsSL "https://github.com/letsencrypt/pebble/releases/download/$PEBBLE/pebble-linux-$arch.tar.gz" | tar -xz -C "$work"
  install -m 0755 "$work/pebble-linux-$arch/linux/$arch/pebble" /usr/local/bin/pebble
  curl -fsSL "https://github.com/letsencrypt/pebble/archive/refs/tags/$PEBBLE.tar.gz" | tar -xz -C "$work"
  rm -rf /opt/pebble
  install -d /opt/pebble
  cp -r "$work/pebble-${PEBBLE#v}/test" /opt/pebble/
  sed -i 's/"httpPort": [0-9]*/"httpPort": 80/' /opt/pebble/test/config/pebble-config.json
  rm -rf "$work"
fi

systemctl stop serverdog-pebble 2> /dev/null || true
systemctl reset-failed serverdog-pebble 2> /dev/null || true
systemd-run --unit serverdog-pebble --working-directory /opt/pebble \
  -E PEBBLE_VA_NOSLEEP=1 -E PEBBLE_WFE_NONCEREJECT=0 \
  /usr/local/bin/pebble -config test/config/pebble-config.json
for _ in $(seq 1 50); do
  curl -fsk https://localhost:14000/dir > /dev/null 2>&1 && break
  sleep 0.2
done
curl -fsk https://localhost:14000/dir > /dev/null

install -d -m 0755 /etc/serverdog
install -m 0644 /opt/pebble/test/certs/pebble.minica.pem /etc/serverdog/pebble-minica.pem
cat > /etc/serverdog/agent.json << 'EOF'
{"acmeDirectory": "https://localhost:14000/dir", "acmeCaBundle": "/etc/serverdog/pebble-minica.pem", "allowLoopbackDomains": true}
EOF

install -m 0755 /tmp/serverdog-agent /usr/local/bin/serverdog-agent
install -m 0644 /tmp/serverdog-agent.service /etc/systemd/system/serverdog-agent.service
systemctl daemon-reload
systemctl enable serverdog-agent
systemctl restart serverdog-agent

for _ in $(seq 1 50); do
  [ -S /run/serverdog/agent.sock ] && exit 0
  sleep 0.2
done
echo "The agent didn't open its socket." >&2
journalctl -u serverdog-agent --no-pager | tail -n 30 >&2
exit 1
