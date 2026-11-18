# LG-for-BGP — Multi-Instance / Multi-Engine BGP Looking Glass

> **Language**: **English (Default)** | [Chinese Documentation (README.zh-CN.md)](README.zh-CN.md)

An open-source, carrier-grade **BGP Looking Glass** supporting both **Single Global RIB** and **Multi-VRF / Multi-Instance** routing architectures across **GoBGP (Native gRPC)**, **BIRD 2**, and **FRRouting (FRR)**.

Built with a separated **Go Backend API (`Server/`)**, **React 18 + Vite 6 + TypeScript 5.7 Frontend (`UI/`)**, **MySQL 8.4+ / MariaDB 11.x Configuration & User Storage**, and **Caddy 2 / Nginx / Apache 2.4** integration for **Debian 13 (Trixie)** and **Ubuntu 24.04 LTS (Noble)+** (Linux-only deployment).

---

## 1. Core Architecture & Highlights

* **Dual Frontend Portals**:
  1. **User Looking Glass Portal (`/`)**: Opens directly into the BGP Looking Glass query interface for immediate IPv4/IPv6 Prefix, AS-Path, and BGP Community lookups, supporting single-table inspection or multi-table side-by-side comparison.
  2. **Administrator Configuration Console (`/<admin_path>`)**: Accessed via the path defined in `/etc/lg-for-bgp/config.yaml` (e.g., `admin_path: "/console"` or `admin_path: "/admin"`). Manages global access modes (`public` vs `auth_required`), VRF/RIB definitions, RR collector nodes, customer accounts (RBAC), and Community dictionaries.
* **In-Memory RR RIBs + MySQL / MariaDB Configuration Storage**:
  * **All BGP routes reside 100% in each RR's in-memory RIBs** (never stored in the SQL database).
  * **MySQL / MariaDB** stores only User Accounts (`lg_users`), VRF definitions (`lg_vrfs`), RR Node endpoints (`lg_rr_nodes`), System Settings (`lg_settings`), Community labels (`lg_communities`), and Audit Logs (`lg_audit_logs`).
* **Multi-Engine Support (`GoBGP` · `BIRD 2` · `FRR`)**:
  * **`type = gobgp`**: Queries GoBGP directly via **native gRPC (`github.com/osrg/gobgp/v3/api` `ListPath` RPC)** — zero CLI execution.
  * **`type = bird2`**: Queries BIRD 2 in-memory tables via restricted read-only control socket (`birdc -r`).
  * **`type = frr`**: Queries FRR BGP Views / Global RIB via structured JSON (`vtysh -c "show bgp ... json"`).
* **100% Untouched Original BGP Attributes**:
  * Preserves original eBGP `NEXT_HOP`, `AS_PATH`, `LOCAL_PREF`, `MED`, `Origin`, `RPKI Validation State`, and `BGP Communities` via read-only iBGP (`add-path` enabled, no `next-hop self`).

---

## 2. How to Configure `VRF Name` & `RR Collector Nodes` in Web Admin

### 2.1 VRF Routing Table Configuration (Single Global RIB vs. Multi-VRF)

In the Web Admin Console (**Section 2: VRF Routing Table Configuration**), each routing table entry has three core fields: **`Name`** (Frontend Display Name), **`VRF Name`** (Underlying RIB Table Name), and **`Type`** (`gobgp` / `bird2` / `frr`).

Depending on whether your RR has **only a single global table (no VRF)** or **multiple isolated VRF/RIB tables**, fill in `VRF Name` as follows:

| Scenario | What to fill in `VRF Name` | `Type = gobgp` (Native gRPC Behavior) | `Type = bird2` (BIRD 2 Behavior) | `Type = frr` (FRR Behavior) |
| :--- | :--- | :--- | :--- | :--- |
| **Scenario A: Single Global Table (No VRF)** | **Leave blank** or enter **`global`** (also accepts `default` / `master`) | Queries GoBGP Global RIB via gRPC (`TableType: TableType_GLOBAL, Name: ""`) | Queries BIRD 2 default global table (`master4` / `master6`: `show route for <target> all`) | Queries FRR default global BGP RIB (`show bgp ipv4/ipv6 unicast <target> json`) |
| **Scenario B: Multi-VRF / Multi-Instance** | Enter the exact VRF / Table / View name (e.g. **`LSYS-OPT`**, **`VRF-DIA`**, **`VRF-TRANSIT-A`**) | Queries the specified VRF RIB via gRPC (`TableType: TableType_VRF, Name: "<VRF Name>"`) | Queries the specified BIRD 2 table (`show route table '<VRF Name>' for <target> all`) | Queries the specified FRR BGP View (`show bgp view <VRF Name> ipv4/ipv6 unicast <target> json`) |

### 2.2 Route Reflector (RR) Collector Node Configuration (1 or Multiple RRs)

In the Web Admin Console (**Section 3: RR Collector Nodes**), **at least 1 active RR node must be configured and enabled** so the backend knows where to send GoBGP gRPC, BIRD 2, or FRR queries. You can configure **1 standalone RR** (`role = primary`) or **multiple RRs** (`role = primary` + `role = backup`) for automatic high-availability failover:

| RR Engine Type | What to fill in `Endpoint` | Backend Query Driver Behavior | One-Click Health Probe (`Test Connection`) |
| :--- | :--- | :--- | :--- |
| **`gobgp`** | GoBGP gRPC listen address `host:port` (e.g. **`127.0.0.1:50051`** or remote **`10.255.255.101:50051`**) | Connects to `Endpoint` over native gRPC (`apipb.NewGobgpApiClient` `ListPath` RPC) | Verifies TCP/gRPC socket reachability and measures latency (ms) |
| **`bird2`** | BIRD 2 control socket path (e.g. **`/run/bird/bird.ctl`** or **`local`**) | Executes `birdc -s <Endpoint> -r "show route ..."` | Verifies `birdc` binary and control socket path existence |
| **`frr`** | FRR vtysh socket directory (e.g. **`/run/frr`** or **`local`**) | Executes `vtysh --vty_socket <Endpoint> -c "show bgp ... json"` | Verifies `vtysh` binary and socket directory existence |

---

## 3. Backend YAML Configuration (`config.yaml`) & Daily Log Rotation

The backend reads `/etc/lg-for-bgp/config.yaml` (or `./config.yaml`):

```yaml
server:
  host: "127.0.0.1"
  port: 8080
  admin_path: "/console" # User-defined Admin Portal path (e.g. "/admin", "/console")
  trusted_proxies:
    - "127.0.0.1"
    - "::1"

database:
  host: "127.0.0.1"
  port: 3306
  user: "lg_user"
  password: "ChangeMe_StrongDBPass_2026!"
  dbname: "lg_for_bgp"
  max_open_conns: 25
  max_idle_conns: 5
  conn_max_lifetime_minutes: 30
  conn_max_idle_time_minutes: 5

jwt:
  secret: "ChangeMe_LG_For_BGP_JWT_Secret_Key_2026"
  refresh_token_days: 3

log:
  dir: "./logs"
  filename: "lg-server"
  max_age_days: 14
  max_backups: 14
  compress: true
  level: "info"
  format: "json"
  stdout: true
  access_log: true
```

* **Daily Log Naming & Retention Policy**:
  * **Current day's active log**: `<dir>/lg-server.log` (e.g., `logs/lg-server.log`).
  * **Previous days' rotated logs**: `<dir>/lg-server-YYYY-MM-DD.log` (or `lg-server-YYYY-MM-DD.log.gz` when `compress: true`).
  * **Automatic Pruning**: Rotated log files older than `max_age_days` (default `14` days) or exceeding `max_backups` (default `14` files) are automatically deleted.

---

## 4. Included Production Configuration Templates (`Server/deploy/`)

* **Router & RR Config Templates (All with Inbound Soft Reconfiguration / `Soft-In`, `Graceful Restart / LLGR`, & `Add-Path RX` Enabled)**:
  * `deploy/juniper-multi-instance-example.conf` — Juniper Junos `logical-systems` & `routing-instances` read-only iBGP (`add-path send`, `graceful-restart`, no `next-hop self`) to RR single Loopback IP.
  * `deploy/gobgpd-rr-example.conf` — GoBGP single Loopback + `[[vrfs]]` multi-RIB isolation + `graceful-restart` / `long-lived-graceful-restart` + per-neighbor `Adj-RIB-In` & `softresetin` policy configuration (`gobgp neighbor <peer> softresetin`).
  * `deploy/bird2-rr-example.conf` — BIRD 2 single Loopback + multi-table (`ipv4/ipv6 table`) + `graceful restart on;` / `long lived graceful restart on;` + `import table on;` (`soft-in` Adj-RIB-In retention for `birdc reload in <peer>`) + recursive next-hop resolution.
  * `deploy/frr-rr-example.conf` — FRRouting (FRR) single Loopback + `router bgp <ASN> view <VRF_NAME>` + `bgp graceful-restart` / `graceful-restart-helper` + `soft-reconfiguration inbound` for IPv4 & IPv6 (`vtysh -c "clear bgp view <VRF> * soft in"`).
* **Database & Web Server Templates (Debian 13 / Ubuntu 24.04+)**:
  * `deploy/sql/schema-mysql-mariadb.sql` — MySQL 8.4+ / MariaDB 11.x database schema.
  * `deploy/webservers/Caddyfile` — Caddy 2 configuration serving `UI/dist` and reverse-proxying `/api/*`.
  * `deploy/webservers/nginx.conf` — Nginx configuration serving `UI/dist` and reverse-proxying `/api/*`.
  * `deploy/webservers/apache-vhost.conf` — Apache 2.4 VirtualHost configuration.
  * `deploy/systemd-services-example.conf` — Native Linux `systemd` units for `gobgpd.service` and `lg-server.service`.
  * `deploy/install-debian13-ubuntu24.sh` — One-step setup script for Debian 13 (Trixie) & Ubuntu 24.04 LTS (Noble)+.

---

## 5. Quick Deployment on Debian 13 / Ubuntu 24.04+ (Linux Only)

```bash
# 1. Download and extract the release archive from GitHub Releases
tar -xzf lg-for-bgp-linux-amd64.tar.gz
cd lg-for-bgp-linux-amd64

# 2. Run the automated setup script (installs MariaDB & Caddy, initializes DB, deploys UI & Backend)
sudo bash deploy/install-debian13-ubuntu24.sh

# 3. Edit /etc/lg-for-bgp/config.yaml (set your admin_path and DB credentials) and start lg-server
sudo cp deploy/systemd-services-example.conf /etc/systemd/system/lg-server.service
sudo systemctl daemon-reload
sudo systemctl enable --now lg-server
```

* **User Looking Glass Portal**: `http://<server-ip>/`
* **Admin Console Portal**: `http://<server-ip>/console` (or whatever `admin_path` is set in `/etc/lg-for-bgp/config.yaml`; initial login: `admin` / `Admin@123456`).
