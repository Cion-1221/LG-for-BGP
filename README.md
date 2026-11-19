# LG-for-BGP — Multi-Instance / Multi-Engine BGP Looking Glass

> **Language**: **English (Default)** | [Chinese Documentation (README.zh-CN.md)](README.zh-CN.md)

An open-source, carrier-grade **BGP Looking Glass** supporting both **Single Global RIB** and **Multi-VRF / Multi-Instance** routing architectures across **GoBGP (Native gRPC)**, **BIRD 2**, and **FRRouting (FRR) / VyOS**.

Built with a separated **Go Backend API (`Server/`)**, **100% Offline-Bundled React 18 + Tailwind CSS v3 + Vite 6 + TypeScript 5.7 Frontend (`UI/`)**, **MySQL 8.4+ / MariaDB 11.x or Embedded SQLite3 Storage**, an optional **Lightweight Remote Collector Agent (`lg-agent`)** for remote BIRD 2 / FRR / VyOS routers, and **Caddy 2 / Nginx / Apache 2.4** integration for Linux (including **Debian 13 (Trixie)**, **Ubuntu 24.04 LTS (Noble)+**, and minimal router OSes such as **VyOS** via embedded SQLite).

---

## 1. Core Architecture & Highlights

* **Dual Frontend Portals (100% Offline-Ready)**:
  1. **User Looking Glass Portal (`/`)**: Opens directly into the BGP Looking Glass query interface for immediate IPv4/IPv6 Prefix, AS-Path, and BGP Community lookups, supporting strict per-PoP isolation, single-table inspection, or multi-table comparison. All Tailwind CSS assets are bundled at build time — zero external CDN or Google Fonts dependency.
  2. **Administrator Configuration Console (`/<admin_path>`)**: Accessed via the path defined in `/etc/lg-for-bgp/config.yaml` (e.g., `admin_path: "/console"` or `admin_path: "/admin"`). Manages global access modes (`public` vs `auth_required`), PoP groups, RR collector nodes, VRF-to-RR bindings, customer accounts (RBAC), Login Brute-Force Locks (manual unban), and Audit Logs.
* **Strict `VRF <-> RR <-> PoP` Topology & Isolation**:
  * **Each RR node binds to exactly 1 PoP** (`N:1`).
  * **Each VRF / Routing Table binds to 1 RR, multiple RRs, or All RRs** (`M:N`).
  * Queries for a PoP strictly target **only** enabled RRs inside that PoP that are bound to the requested VRF — never falling back across PoPs.
  * **Live iBGP Neighbor Session Summary (Admin Only)** queries live peer sessions per `(PoP, RR Node, Engine, VRF)` across GoBGP gRPC, BIRD 2, and FRR/lg-agent without ever borrowing peer stats across VRFs.
* **In-Memory RR RIBs + MySQL / MariaDB / SQLite Incremental Storage**:
  * **All BGP routes reside 100% in each RR's in-memory RIBs** (never stored in SQL).
  * **MySQL / MariaDB or Embedded SQLite3 (`modernc.org/sqlite`, `CGO_ENABLED=0`)** uses incremental single-entity SQL writes plus automatic `lg_audit_logs` retention pruning (`audit_retention_days` / `audit_max_rows`) and WAL checkpointing on graceful shutdown.
* **Multi-Engine Support (`GoBGP` · `BIRD 2` · `FRR / VyOS`) + Remote `lg-agent`**:
  * **`gobgp`**: Queries GoBGP directly via **native gRPC (`ListPath` & `ListPeer`)** — zero CLI execution.
  * **`bird2`**: Queries local `birdc -r` or a remote **`lg-agent`** over HTTP(S) for `prefix`, `aspath`, `community` (standard + large), and live BGP neighbor summaries.
  * **`frr`**: Queries local `vtysh` (supporting both FRR `view <vrf>` and VyOS `vrf <vrf>`) or a remote **`lg-agent`** over HTTP(S) for `prefix`, `aspath`, `community` (standard + large), and live BGP neighbor summaries.
* **Security & High-Concurrency Hardening**:
  * **`bcrypt` password hashing** (automatic transparent upgrade for legacy SHA-256 hashes on login).
  * **Login brute-force protection** (5 failed attempts within 15 min -> 15 min lockout per IP & username, with Admin Console manual unban).
  * **Bounded `TTLCache` & GC-swept `RateLimiter`** (prevents long-running memory growth), **`singleflight` query deduplication**, **per-PoP concurrency semaphore** for full-table scans (`aspath`/`community`), and **`SIGINT`/`SIGTERM` graceful shutdown**.

---

## 2. How to Configure `PoP Groups`, `RR Nodes`, and `VRF <-> RR Bindings`

### 2.1 Step 1 & Step 2: PoP Groups & RR Collector Nodes (Section 3)

Define your PoP groups first, then assign **1 or multiple RR nodes** (`role = primary` + `backup`) to each PoP (deleting a PoP is prevented while RRs remain assigned to it):

| RR Engine Type | What to fill in `Endpoint` | `lg-agent Token` | Backend Query & Probe Behavior |
| :--- | :--- | :--- | :--- |
| **`gobgp`** | GoBGP gRPC address `host:port` (e.g. `127.0.0.1:50051` or `10.255.255.101:50051`) | Leave blank | Native gRPC `ListPath` / `ListPeer`; TCP/gRPC latency probe |
| **`bird2`** | Local socket (e.g. `/run/bird/bird.ctl` or `local`) **OR** remote `lg-agent` URL (`http://10.0.0.2:9090`) | Optional Bearer token (for `lg-agent`) | Local `birdc -r` or authenticated HTTP `/agent/v1/*` calls |
| **`frr`** | Local socket dir (e.g. `/run/frr` or `local`) **OR** remote `lg-agent` URL (`http://10.0.0.2:9090`) | Optional Bearer token (for `lg-agent`) | Local `vtysh` (`view`/`vrf`) or authenticated HTTP `/agent/v1/*` calls |

### 2.2 Step 3: VRF / Routing Tables Bound to RRs (Section 2)

Each VRF entry supports binding to **1 RR**, **multiple RRs**, or **All RR Nodes**, and defaults `Engine Mode` to **`auto`** (follows each bound RR's engine automatically):

| Scenario | What to fill in `VRF Name` | `gobgp` (gRPC) | `bird2` (BIRD 2) | `frr` (FRR / VyOS) |
| :--- | :--- | :--- | :--- | :--- |
| **Single Global Table** | **Leave blank** or **`global`** (`default`/`master`) | `TableType_GLOBAL` | `master4` / `master6` | `show bgp ipv4/ipv6 unicast ... json` |
| **Multi-VRF / Multi-Instance** | Exact VRF / Table / View name (e.g. `VRF-CN-OPT`, `VRF-INTL`) | `TableType_VRF` (`Name: "<VRF>"`) | `table '<VRF>'` (`prefix`/`aspath`/`community`) | Auto-tries `view <VRF>` then `vrf <VRF>` |

### 2.3 Running `lg-agent` on Remote BIRD 2 / FRR / VyOS Routers

To query BIRD 2 or FRR/VyOS on a remote router without SSH, run the included `lg-agent` static binary on the router:

```bash
./lg-agent \
  -listen 0.0.0.0:9090 \
  -engine frr \
  -socket /run/frr \
  -token "ChangeMe_StrongAgentToken_2026"
```

Then in the Web Admin Console (**Section 3**), set the RR node's `Endpoint` to `http://<router-mgmt-ip>:9090` and paste the same Bearer token in `lg-agent Token`.

---

## 3. Backend YAML Configuration (`config.yaml`) & Log / Audit Retention

The backend reads `/etc/lg-for-bgp/config.yaml` (or `./config.yaml`):

```yaml
server:
  host: "127.0.0.1"
  port: 8080
  admin_path: "/console" # User-defined Admin Portal path (e.g. "/admin", "/console")
  allowed_origins: []    # Empty = same-origin / permissive; or set explicit origins e.g. ["https://lg.example.net"]
  trusted_proxies:
    - "127.0.0.1"
    - "::1"

database:
  # Supported: "mysql" (also accepts "mariadb") | "sqlite" (also accepts "sqlite3")
  driver: "mysql"

  # Used when driver is "sqlite" (zero external DB; ideal for VyOS / lightweight Linux)
  # Tip for VyOS: store at /config/user-data/lg-for-bgp/lg.db to survive image upgrades
  path: "./data/lg.db"

  # Used when driver is "mysql" / "mariadb"
  host: "127.0.0.1"
  port: 3306
  user: "lg_user"
  password: "ChangeMe_StrongDBPass_2026!"
  dbname: "lg_for_bgp"
  max_open_conns: 25
  max_idle_conns: 5
  conn_max_lifetime_minutes: 30
  conn_max_idle_time_minutes: 5

  # Automatic SQL audit log retention pruning (lg_audit_logs)
  audit_retention_days: 30
  audit_max_rows: 50000

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

---

## 4. Included Production Configuration Templates (`Server/deploy/`)

* **Router & RR Config Templates (`Soft-In`, `Graceful Restart / LLGR`, & `Add-Path RX`)**:
  * `deploy/juniper-multi-instance-example.conf`
  * `deploy/gobgpd-rr-example.conf`
  * `deploy/bird2-rr-example.conf`
  * `deploy/frr-rr-example.conf`
* **Database, Web Server & Systemd Templates (Debian 13 / Ubuntu 24.04+ / VyOS)**:
  * `deploy/sql/schema-mysql-mariadb.sql` & `deploy/sql/schema-sqlite.sql`
  * `deploy/webservers/Caddyfile`, `deploy/webservers/nginx.conf`, `deploy/webservers/apache-vhost.conf`
  * `deploy/systemd-services-example.conf` — `systemd` units for `gobgpd.service`, `lg-server.service`, and `lg-agent.service`.
  * `deploy/install-debian13-ubuntu24.sh` — One-step setup script for Debian 13 (Trixie) & Ubuntu 24.04 LTS (Noble)+.

---

## 5. Quick Deployment on Linux (Debian 13 / Ubuntu 24.04+ / VyOS)

```bash
# 1. Download and extract the release archive from GitHub Releases (includes lg-server, lg-agent, and offline UI/dist)
tar -xzf lg-for-bgp-linux-amd64.tar.gz
cd lg-for-bgp-linux-amd64

# 2. Run the automated setup script (Debian 13 / Ubuntu 24.04+) OR switch config.yaml to driver: "sqlite" for VyOS
sudo bash deploy/install-debian13-ubuntu24.sh

# 3. Edit /etc/lg-for-bgp/config.yaml (set admin_path, jwt.secret, DB credentials) and start lg-server
sudo systemctl enable --now lg-server
```

* **User Looking Glass Portal**: `http://<server-ip>/`
* **Admin Console Portal**: `http://<server-ip>/console` (depends on `admin_path` in `config.yaml`; initial login: `admin` / `Admin@123456`).
