#![no_std]
#![no_main]

extern crate alloc;

use axvm::io::read;
use bls12_381::{G1Affine, G2Affine, Scalar};
use kzg_rs::{get_kzg_settings, KzgInputs, KzgProof, KzgSettings};

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

    let kzg_settings = get_kzg_settings();

    // let kzg_settings = unsafe {
    //     KzgSettings {
    //         roots_of_unity: core::mem::transmute::<&[Scalar], &'static [Scalar]>(&[Scalar::one()]),
    //         g1_points: core::mem::transmute::<&[G1Affine], &'static [G1Affine]>(&[
    //             G1Affine::generator(),
    //         ]),
    //         g2_points: core::mem::transmute::<&[G2Affine], &'static [G2Affine]>(&[
    //             G2Affine::generator(),
    //         ]),
    //     }
    // };

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
