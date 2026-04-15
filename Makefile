.PHONY: build build-android release release-android build-minimal \
       test lint fmt fmt-check check run run-debug doc clean \
       build-ebpf check-ebpf smoke-ebpf

BPF_TARGET ?= bpfel-unknown-none
BPF_TOOLCHAIN ?= nightly
EBPF_MANIFEST := ebpf/Cargo.toml
EBPF_TARGET_DIR := $(abspath target)
EBPF_OBJECT := target/$(BPF_TARGET)/release/idps-firewalld-ebpf

build:
	cargo build --all-features

build-android:
	cargo build --all-features --target aarch64-linux-android

release:
	cargo build --release

release-android:
	cargo build --release --target aarch64-linux-android

build-minimal:
	cargo build --no-default-features

test:
	cargo test --all-features

check-ebpf-userspace:
	cargo test --features ebpf --all-features

lint:
	cargo clippy --all-features -- -D warnings

fmt:
	cargo +nightly fmt

fmt-check:
	cargo +nightly fmt --check

check: fmt lint test

build-ebpf:
	@if ! rustup component list --toolchain $(BPF_TOOLCHAIN) --installed | grep -qx 'rust-src'; then \
		echo "missing rust-src for toolchain $(BPF_TOOLCHAIN)"; \
		echo "run: rustup component add rust-src --toolchain $(BPF_TOOLCHAIN)"; \
		exit 1; \
	fi
	@if ! command -v bpf-linker >/dev/null 2>&1; then \
		echo "missing bpf-linker in PATH"; \
		echo "run: cargo install bpf-linker"; \
		exit 1; \
	fi
	CARGO_TARGET_DIR=$(EBPF_TARGET_DIR) cargo +$(BPF_TOOLCHAIN) build -Z build-std=core --release --manifest-path $(EBPF_MANIFEST) --target $(BPF_TARGET)

check-ebpf: build-ebpf check-ebpf-userspace

test-ebpf-compile:
	cargo test --test ebpf_compile

smoke-ebpf:
	./scripts/ebpf-smoke.sh

run:
	cargo run

run-debug:
	RUST_LOG=debug cargo run

doc:
	cargo doc --all-features --no-deps --open

clean:
	cargo clean
