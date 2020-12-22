# Suricata WASM module: TLS parser

## Build

Prerequisites:

- rust (`rustup target add wasm32-unknown-unknown`)
- [wasm-pack](https://rustwasm.github.io/wasm-pack/installer/) (optional)

`wasm-pack` is not mandatory, but it produces smaller WASM files (using tools like `wasm-opt` and `wasm-gc`).

Build (using only rust toolchain)

```
cargo  +nightly build --target wasm32-unknown-unknown --release
```

Built file is `target/wasm32-unknown-unknown/release/wasm_tls_parser.wasm`

Build (using `wasm-pack`):

```
wasm-pack build --release
```

Built file is `pkg/wasm_tls_parser_bg.wasm`

## Installation

Copy the built file to suricata WASM modules directory.
