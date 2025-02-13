# OpenVM KZG

## Quickstart

To run guest tests with OpenVM proving, run:

```bash
cargo test --release --package openvm-kzg-tests --lib -- --show-output
```

This runs many tests, so it will take a while to complete. To speed up the tests, run:

```bash
OPENVM_FAST_TEST=1 cargo test --release --package openvm-kzg-tests --lib -- --show-output
```

## Crates

### `openvm-kzg`

This is a fork of [kzg-rs](https://github.com/succinctlabs/kzg-rs) that replaces `verify_kzg_proof` with an implementation using OpenVM intrinsic functions from the modular arithmetic, complex field extension, elliptic curve cryptography, and optimal Ate pairing VM extensions.

## Test Crates

### tests/programs/verify_kzg

Guest program for running `verify_kzg_proof` with inputs from the host.

### tests

Test harness for handling the test vectors as well as building and running the guest program.
