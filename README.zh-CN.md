# LG-for-BGP — 多实例 / 多引擎 BGP Looking Glass 系统

> **语言 / Language**: [English (README.md)](README.md) | **简体中文**

开源、运营商级 **BGP Looking Glass** 路由查询与透视平台，同时支持 **单张全局路由表（Single Global RIB）** 与 **多路由实例隔离（Multi-VRF / Multi-Instance）** 架构，原生兼容 **GoBGP (Native gRPC)**、**BIRD 2** 与 **FRRouting (FRR) / VyOS** 三大路由反射器引擎。

本项目采用 **前后端分离架构**（后端 `Server/` 基于 Go 开发，前端 `UI/` 基于 100% 离线打包的 React 18 + Tailwind CSS v3 + Vite 6 + TypeScript 5.7 开发），支持 **MySQL 8.4+ / MariaDB 11.x** 与 **嵌入式 SQLite3** 双模式存储，附带面向远端 BIRD 2 / FRR / VyOS 节点的轻量级只读采集代理 **`lg-agent`**，适用于 **Debian 13 (Trixie)**、**Ubuntu 24.04 LTS (Noble)+** 及 **VyOS** 等精简路由器 Linux 平台。

---

## 1. 核心架构与特性亮点

* **前后端双入口分离设计（100% 离线可用）**：
  1. **用户 Looking Glass 查询入口 (`/`)**：打开首页即直接进入 BGP Looking Glass 路由查询中心，支持多 PoP 严格隔离查询、IPv4/IPv6 前缀最长掩码匹配、AS-Path 匹配、BGP Community 团体属性检索以及多表对比查询。所有 Tailwind CSS 样式均在构建阶段本地打包，零外部 CDN / Google Fonts 依赖。
  2. **管理员后台配置入口 (`/<admin_path>`)**：通过 `/etc/lg-for-bgp/config.yaml` 中自定义的 `admin_path` 路径访问（例如 `/console` 或 `/admin`），统一管理全局访问模式（公开模式 `public` vs 登录鉴权模式 `auth_required`）、PoP 分组、RR 采集节点、VRF 与 RR 绑定关系、客户账号权限（RBAC）、登录防爆破手动解封以及审计日志。
* **严格的 `VRF <-> RR <-> PoP` 拓扑绑定与隔离**：
  * **1 台 RR 节点严格绑定 1 个 PoP**（`N:1`），若某 PoP 下仍绑定有 RR 节点，将禁止误删该 PoP。
  * **1 个 VRF / 路由表支持绑定 1 台 RR、多台 RR 或全部 RR**（`M:N`），支持新建 / 修改 / 删除。
  * 在前台切换 PoP 时，系统**仅展示并查询当前 PoP 下已绑定该 VRF 的启用 RR**，绝不会跨 PoP 回退或串查其他 PoP 数据。
  * **Live iBGP Neighbor Session Summary（仅管理员）** 按 `(PoP, RR Node, Engine, VRF)` 维度跨 GoBGP gRPC / BIRD 2 / FRR 实时拉取 BGP 邻居状态，严格按 VRF 匹配，绝不跨 VRF 借用邻居数据。
* **RR 纯内存路由表 + MySQL / MariaDB / SQLite 增量持久化**：
  * **100% BGP 路由保存在各台 RR 的纯内存 RIB 中**（绝不写入 SQL 数据库）。
  * **MySQL / MariaDB 或内置纯 Go SQLite3 (`modernc.org/sqlite`, `CGO_ENABLED=0`)** 采用单实体增量写入（避免全表覆写锁库），内置 `lg_audit_logs` 定时留存清理（`audit_retention_days` / `audit_max_rows`）及优雅停机 SQLite WAL checkpoint。
* **多引擎全能力补齐 (`GoBGP` · `BIRD 2` · `FRR / VyOS`) + 远端 `lg-agent`**：
  * **`gobgp`**：通过 **GoBGP 原生 gRPC (`ListPath` / `ListPeer`)** 直接高速查询内存 RIB 与实时邻居状态。
  * **`bird2`**：支持本机 `birdc -r` 或远端 **`lg-agent`**（HTTP/HTTPS + Bearer Token），完整支持 `prefix`、`aspath`、`community`（标准 + Large Community）及实时 BGP 邻居摘要。
  * **`frr`**：支持本机 `vtysh`（自动兼容 FRR `view <vrf>` 与 VyOS `vrf <vrf>`）或远端 **`lg-agent`**，完整支持 `prefix`、`aspath`、`community`（标准 + Large Community）及实时 BGP 邻居摘要。
* **安全加固与高并发长周期稳定性**：
  * **密码哈希升级为 `bcrypt`**（历史旧版 SHA-256 哈希在用户登录成功时自动无感平滑升级为 bcrypt）。
  * **登录防爆破限流 + 后台手动解封**：15 分钟内连续失败 5 次自动锁定对应 IP 与用户名 15 分钟（返回 HTTP `429` + `Retry-After`），管理员可在后台 **Section 5: Security, Audit & Cache** 查看锁定列表并一键手动解封。
  * **长周期运行防泄漏 & 高并发保护**：`TTLCache` 上限淘汰（4096 条）+ 后台 GC 清理、`RateLimiter` 自动 GC 过期 IP、`singleflight` 并发查询去重、单 PoP 全表扫描（`aspath`/`community`）并发闸门（限 3 路）以及 `SIGINT`/`SIGTERM` 优雅停机。

---

## 2. Web 管理后台 `PoP`、`RR 节点` 与 `VRF <-> RR 绑定` 配置规范

### 2.1 Step 1 & Step 2：PoP 分组与 RR 路由反射器节点（Section 3）

先创建 PoP 分组，再为每个 PoP 添加 1 台或多台 RR 节点（`primary` + `backup` 主备自动切换）：

| RR 引擎类型 (`Engine Type`) | `Endpoint`（连接端点）填写规范 | `lg-agent Token` | 后端驱动实际调用与连通性探测 |
| :--- | :--- | :--- | :--- |
| **`gobgp`** | GoBGP gRPC 地址 `host:port`（如 `127.0.0.1:50051` 或远端 `10.255.255.101:50051`） | 留空即可 | 原生 gRPC `ListPath` / `ListPeer`；TCP 延迟探测 |
| **`bird2`** | 本机 socket 路径（如 `/run/bird/bird.ctl` / `local`）**或** 远端 `lg-agent` 地址（如 `http://10.0.0.2:9090`） | 远端 `lg-agent` Bearer Token（可选） | 本机 `birdc -r` 或远端 `/agent/v1/*` 鉴权接口 |
| **`frr`** | 本机 socket 目录（如 `/run/frr` / `local`）**或** 远端 `lg-agent` 地址（如 `http://10.0.0.2:9090`） | 远端 `lg-agent` Bearer Token（可选） | 本机 `vtysh`（`view`/`vrf`）或远端 `/agent/v1/*` 鉴权接口 |

### 2.2 Step 3：VRF / 路由表与 RR 绑定配置（Section 2）

在 **Section 2** 中为每张 VRF 路由表勾选绑定的 RR 节点（支持 **单个 RR**、**多个 RR** 或 **All RR Nodes**），`Engine Mode` 默认选择 **`auto`**（自动跟随所绑定 RR 的引擎类型）：

| 部署场景 | `VRF Name` 填写内容 | `gobgp` (gRPC) | `bird2` (BIRD 2) | `frr` (FRR / VyOS) |
| :--- | :--- | :--- | :--- | :--- |
| **场景 A：单全局表（无 VRF）** | **留空** 或 **`global`**（兼容 `default`/`master`） | `TableType_GLOBAL` | `master4` / `master6` | `show bgp ipv4/ipv6 unicast ... json` |
| **场景 B：多 VRF / 多实例** | 真实 VRF / 表名 / View 名（如 `VRF-CN-OPT`、`VRF-INTL`） | `TableType_VRF` (`Name: "<VRF>"`) | `table '<VRF>'`（支持 prefix/aspath/community） | 自动尝试 `view <VRF>` 与 `vrf <VRF>` |

### 2.3 在远端 BIRD 2 / FRR / VyOS 节点部署轻量代理 `lg-agent`

当 `lg-server` 与 BIRD 2 / FRR / VyOS 不在同一台主机时，可在远端路由器运行发行包中附带的静态单文件 **`lg-agent`**：

```bash
./lg-agent \
  -listen 0.0.0.0:9090 \
  -engine frr \
  -socket /run/frr \
  -token "ChangeMe_StrongAgentToken_2026"
```

随后在 Web 管理后台 **Section 3** 中将该 RR 的 `Endpoint` 填为 `http://<远端管理IP>:9090`，并在 `lg-agent Token` 填入相同 Token 即可（支持 `Test Connection` 在线探活与 `Refresh Peers` 邻居实时拉取）。

---

## 3. 后端 YAML 配置文件 (`config.yaml`) 与留存清理策略

后端默认读取 `/etc/lg-for-bgp/config.yaml`（或当前目录 `./config.yaml`）：

```yaml
server:
  host: "127.0.0.1"
  port: 8080
  admin_path: "/console" # 自定义管理员后台访问路径（如 "/admin", "/console"）
  allowed_origins: []    # 留空默认允许；生产跨域可显式指定白名单如 ["https://lg.example.net"]
  trusted_proxies:
    - "127.0.0.1"
    - "::1"

database:
  # 支持的数据库驱动："mysql"（兼容 "mariadb"）或 "sqlite"（兼容 "sqlite3"）
  driver: "mysql"

  # 当 driver 为 "sqlite" 时使用（零外部数据库依赖，适合 VyOS / 精简 Linux 路由器）
  # VyOS 建议路径：/config/user-data/lg-for-bgp/lg.db（系统镜像升级后自动保留）
  path: "./data/lg.db"

  # 当 driver 为 "mysql" / "mariadb" 时使用
  host: "127.0.0.1"
  port: 3306
  user: "lg_user"
  password: "ChangeMe_StrongDBPass_2026!"
  dbname: "lg_for_bgp"
  max_open_conns: 25
  max_idle_conns: 5
  conn_max_lifetime_minutes: 30
  conn_max_idle_time_minutes: 5

  # 审计日志数据库自动留存清理（lg_audit_logs）
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

## 4. 随附生产环境配置模板 (`Server/deploy/`)

* **核心路由器与 RR 采集节点模板（均启用 `Soft-In`、`Graceful Restart / LLGR` 与 `Add-Path RX`）**：
  * `deploy/juniper-multi-instance-example.conf`
  * `deploy/gobgpd-rr-example.conf`
  * `deploy/bird2-rr-example.conf`
  * `deploy/frr-rr-example.conf`
* **数据库、Web 服务器与 Systemd 模板 (Debian 13 / Ubuntu 24.04+ / VyOS)**：
  * `deploy/sql/schema-mysql-mariadb.sql` & `deploy/sql/schema-sqlite.sql`
  * `deploy/webservers/Caddyfile`、`deploy/webservers/nginx.conf`、`deploy/webservers/apache-vhost.conf`
  * `deploy/systemd-services-example.conf` — 包含 `gobgpd.service`、`lg-server.service` 与 `lg-agent.service` 守护进程单元。
  * `deploy/install-debian13-ubuntu24.sh` — Debian 13 (Trixie) & Ubuntu 24.04 LTS (Noble)+ 一键安装脚本。

---

## 5. 快速部署指南（Linux：Debian 13 / Ubuntu 24.04+ / VyOS）

```bash
# 1. 从 GitHub Releases 下载对应架构发行包（内含 lg-server、lg-agent 与离线 UI/dist）
tar -xzf lg-for-bgp-linux-amd64.tar.gz
cd lg-for-bgp-linux-amd64

# 2. Debian 13 / Ubuntu 24.04+ 可执行一键部署；VyOS 可将 config.yaml 中 database.driver 改为 "sqlite" 直接运行
sudo bash deploy/install-debian13-ubuntu24.sh

# 3. 编辑 /etc/lg-for-bgp/config.yaml（配置 admin_path、jwt.secret 与数据库）并启动服务
sudo systemctl enable --now lg-server
```

* **用户 Looking Glass 查询前台**：`http://<服务器IP>/`
* **管理员后台控制台**：`http://<服务器IP>/console`（取决于 `config.yaml` 的 `admin_path`；初始账号：`admin` / `Admin@123456`）。
