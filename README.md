# kzg-rs with OpenVM

## Quickstart

```bash
RUST_MIN_STACK=8388608 cargo test --release --package kzg-rs-openvm-tests --lib -- --show-output --test-threads=2
```

## Crates

### kzg-rs

Fork of [kzg-rs](https://github.com/succinctlabs/kzg-rs) that swaps out components for `verify_kzg_proof` with OpenVM equivalents.

## Test Crates

## tests/openvm/programs/verify_kzg

Guest program for running `verify_kzg_proof` with inputs from the host.

## tests/openvm/tests

Test harness for handling the test vectors as well as building and running the guest program.
