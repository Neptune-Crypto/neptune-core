.PHONY: clean help stats bench all install run test build doc check format bench-no-run pretty-log ensure-clang

prog :=neptune-core

# Passive dependency-checker. Informs and exits.
check-clang:
	@if ! command -v clang > /dev/null || ! command -v clang++ > /dev/null ; then \
		echo "Error: Required dependencies (clang, clang++) are missing."; \
		exit 1; \
	else \
		echo "Non-rust dependencies clang, clang++ are installed; good."; \
	fi

# Active dependency-installer.
# Check for clang/clang++ and:
#  - if present, continue;
#  - if absent on Debian/Ubuntu, install and continue;
#  - if absent and not on Debian/Ubuntu, exit.
ensure-clang:
	@if ! command -v clang > /dev/null || ! command -v clang++ > /dev/null > /dev/null 2>&1; then \
		if [ -f /etc/debian_version ]; then \
			echo "Missing dependencies (clang, clang++, or libstdc++-14-dev). System identified as Ubuntu/Debian."; \
			echo "Running: sudo apt-get update && sudo apt-get install -y clang libstdc++-14-dev"; \
			sudo apt-get update && sudo apt-get install -y clang libstdc++-14-dev || { echo "Failed to install clang / C++."; exit 1; }; \
		else \
			echo "Error: clang, clang++ are required, along with C++14 (e.g., libstdc++14-dev)."; \
			echo "This system is not Ubuntu/Debian. Please install these dependencies manually to proceed."; \
			exit 1; \
		fi \
	fi

# Tests that require proofs that are expensive to create
expensive-proofs:
	CARGO_TARGET_DIR=./makefile-target-opt-level3 RUSTFLAGS="-C opt-level=3 -C debug-assertions=no -Z threads=180 --cfg=tokio_unstable" cargo t can_verify_transaction_ -- --nocapture --test-threads=1

build: ensure-clang
	$(info RUSTFLAGS is $(RUSTFLAGS))
	cargo build $(release)
	rustup check
	@echo "Update with \`rustup install stable\` if needed."

doc:
	cargo doc --no-deps
	xdg-open "target/doc/neptune-core/index.html"

check: check-clang
	cargo check

ctags:
	# Do `cargo install rusty-tags`
	# See https://github.com/dan-t/rusty-tags
	rusty-tags vi

format:
	cargo fmt --all -- --check

happy: clippy format
	RUSTDOCFLAGS="-D warnings" cargo doc --no-deps --workspace --document-private-items
	cargo test --doc

install: ensure-clang
	cargo install --force --locked --path neptune-core/
	cargo install --force --locked --path neptune-core-cli/
	cargo install --force --locked --path neptune-dashboard/

install-linux: install
	@echo "\n\nPlease run:\n./scripts/linux/install-bash-completions.sh\nto install bash-completions for Neptune-core's CLI."

clippy:
	cargo clippy --all-targets -- -D warnings

# Get a stack trace upon kernel panic (may slow down implementation)
run: export RUST_BACKTRACE = 1
run: ensure-clang
	$(info RUSTFLAGS is $(RUSTFLAGS))
	cargo run

# Get a stack trace upon kernel panic (may slow down implementation)
test: export RUST_BACKTRACE = 1
test: ensure-clang
	$(info RUSTFLAGS is $(RUSTFLAGS))
	cargo nextest r
	cargo test --doc

bench: ensure-clang
	$(info RUSTFLAGS is $(RUSTFLAGS))
	cargo bench

bench-no-run: ensure-clang
	$(info RUSTFLAGS is $(RUSTFLAGS))
	cargo bench --no-run

all: clippy format build test bench-no-run

help:
	@echo "usage: make [debug=1]"

restart: ensure-clang
	@rm -rf ~/.local/share/neptune-integration-test

clear-incremental:
	@rm -rf target/debug/incremental
	@rm -rf target/release/incremental
	@rm -rf "$CARGO_TARGET_DIR/debug/incremental"

clean:
	@echo "      ._.  ██    ██  ███  ██ ██ █████    ████ ██    █████  ███  ██  ██"
	@echo "    c/-|   ███  ███ ██ ██ ████  ██      ██    ██    ██    ██ ██ ███ ██"
	@echo "   c/--|   ████████ █████ ███   ███     ██    ██    ███   █████ ██████"
	@echo "   /  /|   ██ ██ ██ ██ ██ ████  ██      ██    ██    ██    ██ ██ ██ ███"
	@echo " mmm ' '   ██    ██ ██ ██ ██ ██ █████    ████ █████ █████ ██ ██ ██  ██"
	@rm -rf target
	cargo clean

stats:
	git shortlog --numbered --summary --all --email # --committer

pretty-log:
	git log --pretty=" %C(brightblack)%>(16)%ch  %C(auto,green)%>(11)%cN %C(brightmagenta)%G? %C(blue)%h %C(auto)%d %<|(118,trunc)%s%C(reset)" --date=relative --topo-order -n 52 --reverse
