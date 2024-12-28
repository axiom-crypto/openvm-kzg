#![no_std]
#![no_main]

extern crate alloc;

use kzg_rs::{get_kzg_settings, KzgInputs, KzgProof};
use openvm::io::read;
use openvm_pairing_guest::bls12_381::Fp as Bls12_381Fp;

openvm::entry!(main);

openvm_algebra_moduli_setup::moduli_init! {
    "0x1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab",
    "0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001"
}

openvm_algebra_complex_macros::complex_init! {
    Bls12_381Fp2 { mod_idx = 0 },
}

openvm_ecc_sw_setup::sw_init! {
    Bls12_381Fp,
}

pub fn main() {
    setup_0();
    setup_all_complex_extensions();
    setup_all_curves();

    // Get const trusted setup from disk
    let kzg_settings = get_kzg_settings();

    let io: KzgInputs = read();

    let res = KzgProof::verify_kzg_proof(
        &io.commitment_bytes,
        &io.z_bytes,
        &io.y_bytes,
        &io.proof_bytes,
        &kzg_settings,
    )
    .unwrap();
    assert!(res);
}
