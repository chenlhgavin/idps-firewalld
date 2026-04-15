# CLAUDE.md

## What This Repo Is

`idps-firewalld` is the firewall and traffic-monitor daemon for the IDPS workspace.

It consumes synchronized rules from `idps-client`, applies them to either:

- a mock dataplane, or
- an Aya tc eBPF dataplane,

then turns dataplane facts into persisted and reportable business data.

## Mental Model

Think of the system as six layers:

1. `idps/client`
   connect, register, subscribe/load rules, upload reports
2. `rule`
   parse `firewall(fun=1)` / `traffic(fun=4)` into normalized internal models
3. `dataplane`
   encode normalized rules into wire structs and read back counters/events
4. `event` + `identity`
   enrich facts with app/process/interface context and classify ingress behavior
5. `traffic`
   aggregate per-app and global windows
6. `persistence` + `reporter`
   store local state, build outbox payloads, retry uploads

## Important Entry Points

- `src/main.rs`
  daemon entry, `health`, `statistics`
- `src/runtime/mod.rs`
  the main orchestrator; most cross-cutting behavior ends up here
- `src/dataplane/maps.rs`
  userspace copy of eBPF wire layout; changes here usually require matching eBPF changes
- `ebpf/src/maps.rs`
  kernel-side copy of the same ABI
- `src/reporter/mod.rs`
  the place where local business data is translated into `SecurityEvent`

## Current Behavior That Matters

- App/program policy rules can now carry interface scope.
- Tuple actions distinguish:
  - `allow`
  - `alert`
  - `LP`
  - `LD`
  - `NLD`
- Fact events and app traffic samples propagate:
  - `pid`
  - `tgid`
  - `uid`
  - `comm`
- Userspace may enrich app identity from `/proc/<pid>/cmdline`.
- Traffic aggregation is reported as:
  - per-app `wifi/mobile`
  - global ingress/egress bytes and packets

## When Editing

- If you change any wire struct used by eBPF, update both copies:
  - `src/dataplane/maps.rs`
  - `ebpf/src/maps.rs`
- If you change event semantics, inspect:
  - `src/event/classify.rs`
  - `src/event/pipeline.rs`
  - `src/reporter/mod.rs`
  - `src/runtime/mod.rs`
- If you change traffic aggregation or identity attribution, inspect:
  - `src/traffic/aggregate.rs`
  - `src/identity/*`
  - `src/runtime/mod.rs`
- If you change persistence shape or recovery behavior, inspect:
  - `src/persistence/schema.rs`
  - `src/persistence/db.rs`
  - `migrations/0001_init.sql`

## Verification

Minimum:

```bash
rustup run 1.93.0 cargo test
```

If eBPF ABI, Aya backend, or shared structs changed:

```bash
rustup run 1.93.0 cargo test --features ebpf
```

If Rust source changed significantly:

```bash
rustup run 1.93.0 cargo fmt --check
```

## Non-Goals By Default

- Do not reintroduce legacy `/proc/iddnf` or `ioctl` surface compatibility unless explicitly requested.
- Do not edit `target/` or other generated artifacts.
- Do not assume Android-only runtime details unless the specific code path already does so.
