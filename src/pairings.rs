use axvm_ecc_guest::{algebra::IntMod, AffinePoint};
use axvm_pairing_guest::bls12_381::{Fp, Fp2};
use bls12_381::{G1Affine, G2Affine};

/// Verifies the pairing of two G1 and two G2 points are equivalent using the multi-miller loop
pub fn pairings_verify(a1: G1Affine, a2: G2Affine, b1: G1Affine, b2: G2Affine) -> bool {
    #[cfg(feature = "program-test")]
    {
        use axvm_pairing_guest::{bls12_381::Bls12_381, pairing::PairingCheck};
        // Convert to AffinePoint
        let p0 = g1_affine_to_affine_point(a1);
        let p1 = g2_affine_to_affine_point(a2);
        let q0 = g1_affine_to_affine_point(b1);
        let q1 = g2_affine_to_affine_point(b2);

        // Check that input points are on the curve
        assert!(g1_affine_is_on_curve(&p0));
        assert!(g2_affine_is_on_curve(&p1));
        assert!(g1_affine_is_on_curve(&q0));
        assert!(g2_affine_is_on_curve(&q1));

        Bls12_381::pairing_check(&[-p0, q0], &[p1, q1]).is_ok()
    }
    #[cfg(not(feature = "program-test"))]
    {
        // This is run during the build process
        use bls12_381::{multi_miller_loop, G2Prepared, Gt};
        multi_miller_loop(&[(&-a1, &G2Prepared::from(a2)), (&b1, &G2Prepared::from(b2))])
            .final_exponentiation()
            == Gt::identity()
    }
}

pub fn g1_affine_to_affine_point(a: G1Affine) -> AffinePoint<Fp> {
    if a.is_identity().into() {
        return AffinePoint::<Fp>::new(<Fp as IntMod>::ZERO, <Fp as IntMod>::ZERO);
    }
    let a_bytes = a.to_uncompressed();
    let x = Fp::from_be_bytes(&a_bytes[0..48]);
    let y = Fp::from_be_bytes(&a_bytes[48..96]);
    AffinePoint::<Fp>::new(x, y)
}

pub fn g2_affine_to_affine_point(a: G2Affine) -> AffinePoint<Fp2> {
    if a.is_identity().into() {
        return AffinePoint::<Fp2>::new(Fp2::ZERO, Fp2::ZERO);
    }
    let a_bytes = a.to_uncompressed();
    let x = Fp2 {
        c0: Fp::from_be_bytes(&a_bytes[48..96]),
        c1: Fp::from_be_bytes(&a_bytes[0..48]),
    };
    let y = Fp2 {
        c0: Fp::from_be_bytes(&a_bytes[144..192]),
        c1: Fp::from_be_bytes(&a_bytes[96..144]),
    };
    AffinePoint::<Fp2>::new(x, y)
}

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
