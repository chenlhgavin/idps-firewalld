# idps-firewalld

`idps-firewalld` 是 IDPS 防火墙与流量统计常驻进程，负责把 `idps-client` 的规则同步、eBPF 数据面、事件富化、流量聚合、本地持久化和上报重试串成一个完整闭环。

当前实现支持两类 server 规则：

- `firewall(fun=1)`：应用/程序联网策略与五元组访问控制
- `traffic(fun=4)`：流量上报周期

当前实现同时支持两种数据面模式：

- `mock`
- `ebpf`

`mock` 主要用于本地单元测试和无特权环境。`ebpf` 模式使用 Aya tc classifier，挂载 ingress/egress 程序并通过 map 与 userspace 交换规则、事件和统计。

## 目录结构

- `src/main.rs`
  daemon 入口，支持 `health` 和 `statistics` 只读命令。
- `src/runtime`
  常驻生命周期、重连、规则切换、窗口聚合、outbox 上传。
- `src/rule`
  `firewall(fun=1)` / `traffic(fun=4)` 归一化和版本管理。
- `src/dataplane`
  userspace 数据面抽象、Aya backend、wire map 结构和事件解码。
- `src/event`
  事实事件到业务事件的分类与归并。
- `src/identity`
  包名、uid、`/proc/<pid>/cmdline`、接口名等身份富化逻辑。
- `src/persistence`
  SQLite schema、窗口状态、事件表和 outbox。
- `src/reporter`
  本地 payload 到 `SecurityEvent` 的编码。
- `src/ops`
  `health` / `statistics` 诊断视图。
- `ebpf/`
  tc ingress/egress eBPF 程序和共享 map 定义。
- `migrations/`
  SQLite 初始化 schema。
- `scripts/ebpf-smoke.sh`
  eBPF 冒烟脚本。

## 运行方式

默认配置从环境变量读取，核心项如下：

- `IDPS_FIREWALLD_CONFIG`
  `idps-client` runtime 配置文件，默认 `/etc/idd/idps.yaml`
- `IDPS_FIREWALLD_DB`
  SQLite 路径，默认 `/data/idd/firewalld.sqlite3`
- `IDPS_FIREWALLD_DATAPLANE`
  `mock` 或 `ebpf`
- `IDPS_FIREWALLD_EBPF_OBJECT`
  eBPF object 路径
- `IDPS_FIREWALLD_ATTACH_IFACES`
  `ebpf` 模式下要挂载的网卡列表，逗号分隔
- `IDPS_FIREWALLD_ANDROID_PACKAGES_LIST`
  Android `packages.list` 路径，默认 `/data/system/packages.list`

只读命令：

- `cargo run -- health`
- `cargo run -- statistics`

## 常用命令

项目内 `Makefile` 已封装了常见命令：

- `make build`
- `make test`
- `make lint`
- `make check`
- `make build-ebpf`
- `make check-ebpf`
- `make smoke-ebpf`

如果直接调用 Cargo，工作区要求使用 Rust 1.93：

```bash
rustup run 1.93.0 cargo test
rustup run 1.93.0 cargo test --features ebpf
```

## 当前能力摘要

- 规则同步与快照恢复
- 应用/程序联网策略
- 五元组规则匹配
- `LP` / `LD` / `NLD` 区分语义
- ingress 事件二次归类
- `pid/tgid/uid/comm` 归属传递
- `/proc/<pid>/cmdline` userspace 富化
- 按应用 `wifi/mobile` 流量聚合
- 全局流量窗口聚合
- SQLite 本地恢复与 outbox 重试
- `health` / `statistics` 观测接口

## 设计文档

与本项目直接相关的设计文档位于：

- `../idps-docs/firewall/design/ebpf-rust-design.md`
- `../idps-docs/firewall/design/firewall-conclude.md`
- `../idps-docs/firewall/design/traffic-conclude.md`

实现或调整业务语义时，应优先核对这三份文档，再核对 `idps-base` 中的协议和 `idps-client` 集成接口。
