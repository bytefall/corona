## About

Corona is an echomail processor / netmail tracker for FidoNet Technology Network (FTN).

## Features

- SQLite mail storage - use the power of SQL
- self-contained - no external dependencies needed

## Build the project

### Requirements

1. Rust
	- Install [Rust](https://www.rust-lang.org/tools/install).
	- Install nightly toolchain: `rustup toolchain install nightly`

### Compile

Execute `cargo +nightly build` to compile in *debug* mode or `cargo +nightly build --release` for *release* mode.
