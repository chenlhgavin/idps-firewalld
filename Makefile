.PHONY: build build-android release release-android build-minimal \
       test lint fmt fmt-check check run run-debug doc clean

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

lint:
	cargo clippy --all-features -- -D warnings

fmt:
	cargo +nightly fmt

fmt-check:
	cargo +nightly fmt --check

check: fmt lint test

run:
	cargo run

run-debug:
	RUST_LOG=debug cargo run

doc:
	cargo doc --all-features --no-deps --open

clean:
	cargo clean
