.PHONY: clean help stats bench all install run test build doc check format bench-no-run pretty-log

prog :=neptune-core

debug ?=

$(info debug is $(debug))
# Treat all warnings as errors
# export RUSTFLAGS = -Dwarnings

ifdef debug
  release :=
  target :=debug
  extension :=-debug
else
  release :=--release
  target :=release
  extension :=
endif

build:
	$(info RUSTFLAGS is $(RUSTFLAGS))
	cargo build $(release)
	rustup check
	@echo "Update with \`rustup install stable\` if needed."

doc:
	cargo doc --no-deps
	xdg-open "target/doc/neptune-core/index.html"

check:
	cargo check

ctags:
	# Do `cargo install rusty-tags`
	# See https://github.com/dan-t/rusty-tags
	rusty-tags vi

format:
	cargo fmt --all --check

install-linux:
	cargo install --path .
	@echo "\n\nPlease run:\n./scripts/linux/install-bash-completions.sh\nto install bash-completions for Neptune-core's CLI."

lint:
	cargo clippy --all-targets

# Get a stack trace upon kernel panic (may slow down implementation)
run: export RUST_BACKTRACE = 1
run:
	$(info RUSTFLAGS is $(RUSTFLAGS))
	cargo run

# Get a stack trace upon kernel panic (may slow down implementation)
test: export RUST_BACKTRACE = 1
test:
	$(info RUSTFLAGS is $(RUSTFLAGS))
	cargo test -- --test-threads=1

bench:
	$(info RUSTFLAGS is $(RUSTFLAGS))
	cargo bench

bench-no-run:
	$(info RUSTFLAGS is $(RUSTFLAGS))
	cargo bench --no-run

all: lint format build test bench-no-run

help:
	@echo "usage: make [debug=1]"

restart:
	@rm -rf ~/.local/share/neptune-integration-test

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
