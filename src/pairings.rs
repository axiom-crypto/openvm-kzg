use axvm_ecc_guest::{algebra::IntMod, AffinePoint};
use axvm_pairing_guest::{
    bls12_381::{Bls12_381, Fp, Fp2},
    pairing::PairingCheck,
};
use bls12_381::{G1Affine, G2Affine};

/// Verifies the pairing of two G1 and two G2 points are equivalent using the multi-miller loop
pub fn pairings_verify(a1: G1Affine, a2: G2Affine, b1: G1Affine, b2: G2Affine) -> bool {
    // Convert to AffinePoint
    let p0 = g1_affine_to_affine_point(a1);
    let q0 = g2_affine_to_affine_point(a2);
    let p1 = g1_affine_to_affine_point(b1);
    let q1 = g2_affine_to_affine_point(b2);
    Bls12_381::pairing_check(&[p0, p1], &[q0, q1]).is_ok()
}

pub fn g1_affine_to_affine_point(a: G1Affine) -> AffinePoint<Fp> {
    let a_bytes = a.to_uncompressed();
    let x = Fp::from_be_bytes(&a_bytes[0..48]);
    let y = Fp::from_be_bytes(&a_bytes[48..96]);
    AffinePoint::<Fp>::new(x, y)
}

pub fn g2_affine_to_affine_point(a: G2Affine) -> AffinePoint<Fp2> {
    let a_bytes = a.to_uncompressed();
    let x = Fp2 {
        c0: Fp::from_be_bytes(&a_bytes[0..48]),
        c1: Fp::from_be_bytes(&a_bytes[48..96]),
    };
    let y = Fp2 {
        c0: Fp::from_be_bytes(&a_bytes[96..144]),
        c1: Fp::from_be_bytes(&a_bytes[144..192]),
    };
    AffinePoint::<Fp2>::new(x, y)
}
