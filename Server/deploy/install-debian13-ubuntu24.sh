#!/usr/bin/env bash
# ==============================================================================
# Automated Setup Script for Debian 13 (Trixie) / Ubuntu 24.04 LTS (Noble)+
# Architecture:
#   - MariaDB / MySQL (Relational Database for Users, Views, Settings, Logs)
#   - GoBGP (Read-Only Route Collector)
#   - LG-for-BGP Backend API (127.0.0.1:8080)
#   - Caddy 2 / Nginx serving Separated Frontend Static Files (/var/www/lg-for-bgp/ui/dist)
# ==============================================================================
set -euo pipefail

echo "[1/5] Installing MariaDB Server and Caddy on Debian 13 / Ubuntu 24.04+..."
apt-get update
apt-get install -y mariadb-server caddy curl tar

systemctl enable --now mariadb

echo "[2/5] Initializing MySQL / MariaDB database and schema..."
mysql -u root < "$(dirname "$0")/sql/schema-mysql-mariadb.sql"

echo "[3/5] Deploying Separated Frontend UI to /var/www/lg-for-bgp/ui/dist..."
mkdir -p /var/www/lg-for-bgp/ui
if [ -d "$(dirname "$0")/../ui/dist" ]; then
  cp -r "$(dirname "$0")/../ui/dist" /var/www/lg-for-bgp/ui/
fi
chown -R www-data:www-data /var/www/lg-for-bgp

echo "[4/5] Deploying LG Backend API binary and /etc/lg-for-bgp/config.yaml..."
mkdir -p /opt/lg-for-bgp /opt/lg-for-bgp/logs /etc/lg-for-bgp
if [ -f "$(dirname "$0")/../lg-server" ]; then
  cp "$(dirname "$0")/../lg-server" /opt/lg-for-bgp/lg-server
  chmod +x /opt/lg-for-bgp/lg-server
fi
if [ ! -f /etc/lg-for-bgp/config.yaml ]; then
  cp "$(dirname "$0")/config.yaml" /etc/lg-for-bgp/config.yaml
fi

echo "[5/5] Configuring Caddyfile..."
cp "$(dirname "$0")/webservers/Caddyfile" /etc/caddy/Caddyfile
systemctl reload caddy || systemctl restart caddy

echo "=============================================================================="
echo "Deployment Ready!"
echo " - Public Looking Glass URL : http://<SERVER_IP>/"
echo " - Admin Console URL        : http://<SERVER_IP>/console"
echo "   (Customize admin_path via /etc/lg-for-bgp/config.yaml)"
echo "=============================================================================="
