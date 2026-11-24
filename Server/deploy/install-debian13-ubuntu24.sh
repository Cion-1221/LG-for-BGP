#!/usr/bin/env bash
# Copyright (c) 2026 Alan <alan.xiao@cionsiu.com>
# ==============================================================================
# Automated Setup Script for Debian 13 (Trixie) / Ubuntu 24.04 LTS (Noble)+
# Architecture:
#   - MariaDB / MySQL (Relational Database for Users, Views, Settings, Logs)
#   - GoBGP / BIRD 2 / FRR (Read-Only Route Collector)
#   - LG-for-BGP Backend API (127.0.0.1:8080, running as dedicated `lg-bgp` user)
#   - Caddy 2 / Nginx serving Separated Frontend Static Files (/var/www/lg-for-bgp/ui/dist)
# ==============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
BUNDLE_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"

echo "[1/6] Installing MariaDB Server, Caddy, and OpenSSL on Debian 13 / Ubuntu 24.04+..."
apt-get update
apt-get install -y mariadb-server caddy curl tar openssl

systemctl enable --now mariadb

echo "[2/6] Initializing MySQL / MariaDB database and least-privilege schema..."
mysql -u root < "${SCRIPT_DIR}/sql/schema-mysql-mariadb.sql"

echo "[3/6] Creating dedicated non-root system user 'lg-bgp' and runtime directories..."
if ! id -u lg-bgp >/dev/null 2>&1; then
  useradd --system --no-create-home --shell /usr/sbin/nologin lg-bgp
fi
mkdir -p /opt/lg-for-bgp /var/lib/lg-for-bgp /var/log/lg-for-bgp /etc/lg-for-bgp

echo "[4/6] Deploying Separated Frontend UI to /var/www/lg-for-bgp/ui/dist..."
mkdir -p /var/www/lg-for-bgp/ui
if [ -d "${BUNDLE_DIR}/ui/dist" ]; then
  rm -rf /var/www/lg-for-bgp/ui/dist
  cp -r "${BUNDLE_DIR}/ui/dist" /var/www/lg-for-bgp/ui/
fi
chown -R www-data:www-data /var/www/lg-for-bgp

echo "[5/6] Deploying LG Backend binaries, /etc/lg-for-bgp/config.yaml, and systemd units..."
if [ -f "${BUNDLE_DIR}/lg-server" ]; then
  cp "${BUNDLE_DIR}/lg-server" /opt/lg-for-bgp/lg-server
  chmod 0755 /opt/lg-for-bgp/lg-server
fi
if [ -f "${BUNDLE_DIR}/lg-agent" ]; then
  cp "${BUNDLE_DIR}/lg-agent" /opt/lg-for-bgp/lg-agent
  chmod 0755 /opt/lg-for-bgp/lg-agent
fi

if [ ! -f /etc/lg-for-bgp/config.yaml ]; then
  cp "${SCRIPT_DIR}/config.yaml" /etc/lg-for-bgp/config.yaml
  RANDOM_JWT_SECRET="$(openssl rand -hex 32)"
  sed -i "s|ChangeMe_LG_For_BGP_JWT_Secret_Key_2026|${RANDOM_JWT_SECRET}|g" /etc/lg-for-bgp/config.yaml
fi

chown -R lg-bgp:lg-bgp /opt/lg-for-bgp /var/lib/lg-for-bgp /var/log/lg-for-bgp
chown root:lg-bgp /etc/lg-for-bgp/config.yaml
chmod 0640 /etc/lg-for-bgp/config.yaml

if [ -f "${SCRIPT_DIR}/systemd/lg-server.service" ]; then
  cp "${SCRIPT_DIR}/systemd/lg-server.service" /etc/systemd/system/lg-server.service
  systemctl daemon-reload
fi

echo "[6/6] Configuring Caddyfile (backing up any existing /etc/caddy/Caddyfile)..."
if [ -f /etc/caddy/Caddyfile ]; then
  BACKUP_TS="$(date +%Y%m%d%H%M%S)"
  cp /etc/caddy/Caddyfile "/etc/caddy/Caddyfile.bak.${BACKUP_TS}"
  echo "  -> Backed up existing Caddyfile to /etc/caddy/Caddyfile.bak.${BACKUP_TS}"
fi
cp "${SCRIPT_DIR}/webservers/Caddyfile" /etc/caddy/Caddyfile
systemctl reload caddy || systemctl restart caddy

echo "=============================================================================="
echo "Deployment Ready!"
echo " - Start & Enable Backend   : systemctl enable --now lg-server"
echo " - Public Looking Glass URL : http://<SERVER_IP>/"
echo " - Admin Console URL        : http://<SERVER_IP>/console"
echo "   (Customize admin_path & DB password via /etc/lg-for-bgp/config.yaml)"
echo "=============================================================================="
