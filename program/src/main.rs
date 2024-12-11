#![no_std]
#![no_main]

extern crate alloc;

use axvm::io::read;
use axvm_pairing_guest::{bls12_381::Bls12_381, pairing::PairingCheck};
use kzg_rs::PairingInputs;

axvm::entry!(main);

axvm_algebra_moduli_setup::moduli_init! {
    "0x1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab",
    "0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001"
}

axvm_algebra_complex_macros::complex_init! {
    Fp2 { mod_idx = 0 },
}

pub fn main() {
    setup_0();
    setup_all_complex_extensions();

    let io: PairingInputs = read();

    assert!(Bls12_381::pairing_check(&[-io.p0, io.q0], &[io.p1, io.q1]).is_ok())
}
