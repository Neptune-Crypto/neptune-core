
prog :=neptune-core

debug ?=

$(info debug is $(debug))
# Treat all warnings as errors
export RUSTFLAGS = -Dwarnings

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

format:
	cargo fmt

install:
	cp target/$(target)/$(prog) ~/bin/$(prog)$(extension)

lint:
	cargo clippy

# Get a stack trace upon kernel panic (may slow down implementation)
run: export RUST_BACKTRACE = 1
run:
	$(info RUSTFLAGS is $(RUSTFLAGS))
	cargo run

# Get a stack trace upon kernel panic (may slow down implementation)
test: export RUST_BACKTRACE = 1
test:
	$(info RUSTFLAGS is $(RUSTFLAGS))
	cargo test

bench:
	$(info RUSTFLAGS is $(RUSTFLAGS))
	cargo bench
bench-no-run:
	$(info RUSTFLAGS is $(RUSTFLAGS))
	cargo bench --no-run

all: lint build test bench-no-run

help:
	@echo "usage: make [debug=1]"

clean:
	@rm -rf target
