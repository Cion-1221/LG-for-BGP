# LG-for-BGP — 多实例 / 多引擎 BGP Looking Glass 系统

> **语言 / Language**: [English (README.md)](README.md) | **简体中文**

开源、运营商级 **BGP Looking Glass** 路由查询与透视平台，同时支持 **单张全局路由表（Single Global RIB）** 与 **多路由实例隔离（Multi-VRF / Multi-Instance）** 架构，原生兼容 **GoBGP (Native gRPC)**、**BIRD 2** 与 **FRRouting (FRR)** 三大路由反射器引擎。

本项目采用 **前后端分离架构**（后端 `Server/` 基于 Go 开发，前端 `UI/` 基于 React 18 + Vite 6 + TypeScript 5.7 开发），配合 **MySQL 8.4+ / MariaDB 11.x** 存储系统配置与账号权限，并针对 **Debian 13 (Trixie)** 与 **Ubuntu 24.04 LTS (Noble)+** 提供完整的 **Caddy 2 / Nginx / Apache 2.4** 生产级部署模板（仅支持 Linux 部署）。

---

## 1. 核心架构与特性亮点

* **前后端双入口分离设计**：
  1. **用户 Looking Glass 查询入口 (`/`)**：打开首页即直接进入 BGP Looking Glass 路由查询中心，支持 IPv4/IPv6 前缀最长掩码匹配、AS-Path 正则匹配、BGP Community 团体属性检索，以及单表全路径透视或多表并排对比（Side-by-Side Diff）。
  2. **管理员后台配置入口 (`/<admin_path>`)**：通过后端配置文件 `/etc/lg-for-bgp/config.yaml` 中自定义的 `admin_path` 路径访问（例如 `admin_path: "/console"` 或 `admin_path: "/admin"`），统一管理全局访问模式（公开模式 `public` vs 登录鉴权模式 `auth_required`）、VRF/RIB 路由表映射、RR 采集节点、客户账号权限（RBAC）以及 BGP Community 语义字典。
* **RR 纯内存路由表 + MySQL / MariaDB 账号与配置持久化**：
  * **100% BGP 路由保存在各台 RR 的纯内存 RIB 中**（不写入 SQL 数据库，避免海量 BGP 路由对磁盘与数据库造成性能瓶颈）。
  * **MySQL / MariaDB** 仅存储用户账号 (`lg_users`)、VRF 路由表定义 (`lg_vrfs`)、RR 节点连接信息 (`lg_rr_nodes`)、系统参数 (`lg_settings`)、Community 字典 (`lg_communities`) 及审计日志 (`lg_audit_logs`)。
* **多引擎原生支持 (`GoBGP` · `BIRD 2` · `FRR`)**：
  * **`type = gobgp`**：通过 **GoBGP 原生 gRPC 接口 (`github.com/osrg/gobgp/v3/api` `ListPath` RPC)** 直接高速查询内存 RIB，零命令行子进程开销。
  * **`type = bird2`**：通过只读控制套接字 (`birdc -r`) 查询 BIRD 2 内存路由表。
  * **`type = frr`**：通过结构化 JSON 接口 (`vtysh -c "show bgp ... json"`) 查询 FRR BGP Views 或全局表。
* **100% 保留原始 BGP 路由属性**：
  * 通过只读 iBGP 反射会话（开启 `add-path`，不配置 `next-hop self`），完整保留核心路由器上最真实的 eBGP `NEXT_HOP`、`AS_PATH`、`LOCAL_PREF`、`MED`、`Origin`、`RPKI 校验状态` 与 `BGP Communities`。

---

## 2. Web 管理后台 `VRF Name` 与 `RR 采集节点` 配置规范

### 2.1 VRF 路由表配置（单全局表 vs 多 VRF 隔离）

在管理后台（**Section 2: VRF Routing Table Configuration**）新增或编辑路由表时，包含三个核心字段：**`Name`**（前端展示名称）、**`VRF Name`**（底层查询表名）以及 **`Type`**（`gobgp` / `bird2` / `frr`）。

针对 **只有一张全局表（没有 VRF）** 或 **存在多张独立 VRF/RIB 路由表** 的不同部署场景，`VRF Name` 的填写方式如下：

| 部署场景 | `VRF Name` 填写内容 | `Type = gobgp` (原生 gRPC 行为) | `Type = bird2` (BIRD 2 行为) | `Type = frr` (FRR 行为) |
| :--- | :--- | :--- | :--- | :--- |
| **场景 A：仅单张全局表（无 VRF）** | **直接留空（不填）** 或填写 **`global`**（也兼容 `default` / `master`） | 通过 gRPC 查询 GoBGP 全局表 (`TableType: TableType_GLOBAL, Name: ""`) | 查询 BIRD 2 默认主表 (`master4` / `master6`: `show route for <target> all`) | 查询 FRR 默认全局 BGP 表 (`show bgp ipv4/ipv6 unicast <target> json`) |
| **场景 B：多 VRF / 多实例隔离模式** | 填写 RR 中配置的真实表名 / 实例名（如 **`LSYS-OPT`**、**`VRF-DIA`**、**`VRF-TRANSIT-A`**） | 通过 gRPC 查询指定 VRF 内存表 (`TableType: TableType_VRF, Name: "<VRF Name>"`) | 查询 BIRD 2 指定路由表 (`show route table '<VRF Name>' for <target> all`) | 查询 FRR 指定 BGP View (`show bgp view <VRF Name> ipv4/ipv6 unicast <target> json`) |

### 2.2 RR 路由反射器节点配置（支持配置 1 台或多台 RR 主备自动切换）

在管理后台（**Section 3: RR Collector Nodes**）中，**必须至少配置并启用 1 台 RR 节点**，后端才能正确调用 GoBGP gRPC、BIRD 2 或 FRR 执行路由查询。系统支持配置 **单台独立 RR (`role = primary`)** 或 **多台主备 RR (`primary` + `backup`)**（当处于 `Auto` 模式时，优先查询匹配引擎类型的 Primary RR，若 Primary 不可达则自动无缝切换至 Backup RR）：

| RR 引擎类型 (`Engine Type`) | `Endpoint`（连接端点）填写规范 | 后端驱动实际调用方式 | 在线连通性探测 (`Test Connection`) |
| :--- | :--- | :--- | :--- |
| **`gobgp`** | GoBGP gRPC 监听地址 `host:port`（如本机 **`127.0.0.1:50051`** 或远端 RR **`10.255.255.101:50051`**） | 通过原生 gRPC 连接该 `Endpoint` 并调用 `ListPath` RPC | 探测 TCP/gRPC 端口连通性并返回毫秒级延迟 |
| **`bird2`** | BIRD 2 控制套接字路径（如 **`/run/bird/bird.ctl`** 或 **`local`**） | 调用 `birdc -s <Endpoint> -r "show route ..."` | 检查 `birdc` 客户端与控制套接字文件是否存在 |
| **`frr`** | FRR vtysh 套接字目录（如 **`/run/frr`** 或 **`local`**） | 调用 `vtysh --vty_socket <Endpoint> -c "show bgp ... json"` | 检查 `vtysh` 客户端与套接字目录是否存在 |

---

## 3. 后端 YAML 配置文件 (`config.yaml`) 与按天日志轮转

后端默认读取 `/etc/lg-for-bgp/config.yaml`（或当前工作目录下的 `./config.yaml`）：

```yaml
server:
  host: "127.0.0.1"
  port: 8080
  admin_path: "/console" # 自定义管理员后台访问路径（如 "/admin", "/console"）
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

* **按天日志轮转与自动清理策略**：
  * **当天活动日志**：固定命名为 `<dir>/lg-server.log`（例如 `logs/lg-server.log`）。
  * **历史归档日志**：跨午夜或服务重启归档时，自动按实际日期重命名为 `<dir>/lg-server-YYYY-MM-DD.log`（当 `compress: true` 时自动压缩为 `lg-server-YYYY-MM-DD.log.gz`）。
  * **自动过期清理**：自动扫描并删除超过 `max_age_days`（默认 `14` 天）或超出 `max_backups`（默认 `14` 份）的历史归档日志。

---

## 4. 随附生产环境配置模板 (`Server/deploy/`)

* **核心路由器与 RR 采集节点配置模板（均默认启用 `Soft-In` 入向软重配、`Graceful Restart / LLGR` 优雅重启与 `Add-Path RX`）**：
  * `deploy/juniper-multi-instance-example.conf` — Juniper Junos `logical-systems` 与 `routing-instances` 向单 Loopback RR 反射只读 iBGP 路由配置（启用 `add-path send`、`graceful-restart`，不改写 `next-hop`）。
  * `deploy/gobgpd-rr-example.conf` — GoBGP 单 Loopback + `[[vrfs]]` 多表内存隔离 + `graceful-restart` / `long-lived-graceful-restart` 优雅重启 + 邻居级 `Adj-RIB-In` 与 `softresetin` 软重配支持（`gobgp neighbor <peer> softresetin`）。
  * `deploy/bird2-rr-example.conf` — BIRD 2 单 Loopback + 多路由表 (`ipv4/ipv6 table`) + `graceful restart on;` / `long lived graceful restart on;` 优雅重启 + `import table on;`（开启 `soft-in` 入向路由表留存，支持 `birdc reload in <peer>`）+ 递归下一跳解析。
  * `deploy/frr-rr-example.conf` — FRRouting (FRR) 单 Loopback + `router bgp <ASN> view <VRF_NAME>` + `bgp graceful-restart` / `graceful-restart-helper` 优雅重启 + IPv4/IPv6 双栈 `soft-reconfiguration inbound`（支持 `vtysh -c "clear bgp view <VRF> * soft in"`）。
* **数据库与 Web 服务器部署模板 (Debian 13 / Ubuntu 24.04+)**：
  * `deploy/sql/schema-mysql-mariadb.sql` — MySQL 8.4+ / MariaDB 11.x 数据库建表与初始化脚本（与 `config.yaml` 默认数据库名/用户名一致）。
  * `deploy/webservers/Caddyfile` — Caddy 2 静态前端托管与 `/api/*` 反向代理配置。
  * `deploy/webservers/nginx.conf` — Nginx 静态前端托管与 `/api/*` 反向代理配置。
  * `deploy/webservers/apache-vhost.conf` — Apache 2.4 VirtualHost 配置文件。
  * `deploy/systemd-services-example.conf` — Linux `systemd` 守护进程单元文件 (`gobgpd.service` 与 `lg-server.service`)。
  * `deploy/install-debian13-ubuntu24.sh` — Debian 13 (Trixie) 与 Ubuntu 24.04 LTS (Noble)+ 一键安装部署脚本。

---

## 5. 快速部署指南（仅支持 Linux：Debian 13 / Ubuntu 24.04+）

```bash
# 1. 从 GitHub Releases 下载并解压对应架构的 Linux 发行包
tar -xzf lg-for-bgp-linux-amd64.tar.gz
cd lg-for-bgp-linux-amd64

# 2. 执行自动化部署脚本（自动安装 MariaDB 与 Caddy、初始化数据库、部署前后端文件）
sudo bash deploy/install-debian13-ubuntu24.sh

# 3. 编辑 /etc/lg-for-bgp/config.yaml（按需修改 admin_path 与数据库密码）并启动服务
sudo cp deploy/systemd-services-example.conf /etc/systemd/system/lg-server.service
sudo systemctl daemon-reload
sudo systemctl enable --now lg-server
```

* **用户 Looking Glass 查询前台**：`http://<服务器IP>/`
* **管理员后台控制台**：`http://<服务器IP>/console`（取决于 `/etc/lg-for-bgp/config.yaml` 中的 `admin_path` 配置；初始管理员账号：`admin` / `Admin@123456`）。
