# AGENTS.md

## Scope

- Applies to `idps-firewalld/` and all subdirectories unless a deeper `AGENTS.md` is added later.

## Project Purpose

- `idps-firewalld` is a standalone Rust daemon for firewall enforcement, traffic aggregation, and report delivery.
- It bridges:
  - `idps-client` rule sync / registration / event reporting
  - eBPF tc dataplane
  - local SQLite persistence
  - userspace identity enrichment and traffic aggregation

## Preferred Workflow

- For firewalld-only work, prefer the local `Makefile`.
- Common local entrypoints:
  - `make build`
  - `make test`
  - `make lint`
  - `make check`
  - `make build-ebpf`
  - `make check-ebpf`
- If you invoke Cargo directly, use the workspace toolchain explicitly:
  - `rustup run 1.93.0 cargo test`
  - `rustup run 1.93.0 cargo test --features ebpf`

## Module Map

- `src/runtime`: lifecycle, reconnect, polling, window close, outbox upload
- `src/rule`: normalization and active ruleset management
- `src/dataplane`: userspace/backend abstraction and wire map definitions
- `src/event`: fact-event classification and business-event assembly
- `src/identity`: package map, `/proc` enrichment, interface classification
- `src/persistence`: SQLite schema and storage primitives
- `src/reporter`: `ReportPayload` to `SecurityEvent`
- `src/ops`: health and statistics diagnostics
- `ebpf/`: tc ingress/egress programs and shared structs

## Boundaries

- Do not hand-edit generated or transient outputs:
  - `target/`
  - `ebpf/target/`
- Keep userspace/kernel shared struct layouts in sync:
  - `src/dataplane/maps.rs`
  - `ebpf/src/maps.rs`
- When changing event or traffic semantics, update tests in the same area.
- When changing rule normalization or wire encoding, verify both:
  - default test suite
  - `--features ebpf`

## Done Criteria

- For Rust-only changes, run at least:
  - `rustup run 1.93.0 cargo test`
- If shared userspace/eBPF structs or Aya backend behavior changes, also run:
  - `rustup run 1.93.0 cargo test --features ebpf`
- If formatting-sensitive Rust files change, also run:
  - `rustup run 1.93.0 cargo fmt --check`

## Implementation Notes

- `mock` dataplane is the default development path; do not assume eBPF is available.
- `ebpf` mode requires valid attach interfaces and a built object file.
- Identity enrichment is userspace-driven; do not add legacy `/proc/iddnf` or `ioctl` compatibility unless the task explicitly requires it.
- Traffic reporting currently exposes:
  - per-app `wifi/mobile` summaries
  - global ingress/egress byte and packet windows

## References

- `README.md` in this directory for operator/developer overview
- `CLAUDE.md` in this directory for AI-oriented project context
- `../idps-docs/firewall/design/ebpf-rust-design.md`
- `../idps-docs/firewall/design/firewall-conclude.md`
- `../idps-docs/firewall/design/traffic-conclude.md`
