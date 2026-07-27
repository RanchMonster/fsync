run:
   cargo run

release:
   cargo run --release

build: 
   cargo build

test:
   cargo test -- --test-threads=1

check:
   cargo check

dep-tree:
   cargo tree

fmt: 
   cargo fmt
