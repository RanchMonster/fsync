run:
   cargo run

release:
   cargo run --release

build: 
   cargo build

test:
   cargo test

check:
   cargo check

dep-tree:
   cargo tree

clippy:
   cargo clippy --fix --all-targets
   cargo check --all-targets
   cargo fmt --all
   cargo test

