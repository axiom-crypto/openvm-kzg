use axvm_ecc_guest::AffinePoint;
use axvm_pairing_guest::{
    bls12_381::{Bls12_381, Fp, Fp2, Scalar},
    pairing::PairingCheck,
};

type G1Affine = AffinePoint<Fp>;
type G2Affine = AffinePoint<Fp2>;

/// Verifies the pairing of two G1 and two G2 points are equivalent using the multi-miller loop
pub fn pairings_verify(a1: G1Affine, a2: G2Affine, b1: G1Affine, b2: G2Affine) -> bool {
    let p0 = AffinePoint::new(a1.x, a1.y);
    let q0 = AffinePoint::new(a2.x, a2.y);
    let p1 = AffinePoint::new(b1.x, b1.y);
    let q1 = AffinePoint::new(b2.x, b2.y);
    match Bls12_381::pairing_check(&[p0, p1], &[q0, q1]) {
        Ok(_) => true,
        Err(_) => false,
    }
}
