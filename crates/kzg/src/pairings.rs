#[cfg(not(target_os = "zkvm"))]
use bls12_381::{G1Affine, G2Affine};
#[cfg(target_os = "zkvm")]
use {
    openvm_ecc_guest::{algebra::IntMod, AffinePoint},
    openvm_pairing_guest::bls12_381::{Fp, Fp2},
};

/// Verifies the pairing of two G1 and two G2 points are equivalent using the multi-miller loop
#[cfg(target_os = "zkvm")]
pub fn pairings_verify(
    p0: AffinePoint<Fp>,
    p1: AffinePoint<Fp2>,
    q0: AffinePoint<Fp>,
    q1: AffinePoint<Fp2>,
) -> bool {
    use openvm_pairing_guest::{bls12_381::Bls12_381, pairing::PairingCheck};

    // Check that input points are on the curve
    assert!(g1_affine_is_on_curve(&p0));
    assert!(g2_affine_is_on_curve(&p1));
    assert!(g1_affine_is_on_curve(&q0));
    assert!(g2_affine_is_on_curve(&q1));

    Bls12_381::pairing_check(&[-p0, q0], &[p1, q1]).is_ok()
}

#[cfg(not(target_os = "zkvm"))]
pub fn pairings_verify(a1: G1Affine, a2: G2Affine, b1: G1Affine, b2: G2Affine) -> bool {
    // This is run during the build process
    use bls12_381::{multi_miller_loop, G2Prepared, Gt};
    multi_miller_loop(&[(&-a1, &G2Prepared::from(a2)), (&b1, &G2Prepared::from(b2))])
        .final_exponentiation()
        == Gt::identity()
}

#[cfg(target_os = "zkvm")]
pub fn g1_affine_is_on_curve(p: &AffinePoint<Fp>) -> bool {
    if p.is_infinity() {
        return true;
    }
    let x = &p.x;
    let y = &p.y;
    // y^2 - x^3 ?= 4
    let x_3 = x * x * x;
    let y_2 = y * y;
    let four = Fp::from_u32(4);
    y_2 - x_3 == four
}

#[cfg(target_os = "zkvm")]
pub fn g2_affine_is_on_curve(p: &AffinePoint<Fp2>) -> bool {
    if p.is_infinity() {
        return true;
    }
    let x = &p.x;
    let y = &p.y;
    // y^2 - x^3 ?= 4(u + 1)
    let x_3 = x * x * x;
    let y_2 = y * y;
    let four = Fp2::new(Fp::from_u32(4), Fp::from_u32(4));
    y_2 - x_3 == four
}
