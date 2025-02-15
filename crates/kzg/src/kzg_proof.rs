use crate::dtypes::*;
use crate::enums::KzgError;
use crate::types::KzgSettings;

use alloc::{string::ToString, vec::Vec};
use bls12_381::{G2Affine, Scalar};

#[cfg(not(target_os = "zkvm"))]
use bls12_381::G1Affine;
#[cfg(target_os = "zkvm")]
use openvm_ecc_guest::weierstrass::FromCompressed;
use {
    core::hint::black_box,
    hex_literal::hex,
    openvm_algebra_guest::field::FieldExtension,
    openvm_algebra_guest::IntMod,
    openvm_ecc_guest::{
        weierstrass::{CachedMulTable, IntrinsicCurve, WeierstrassPoint},
        AffinePoint, CyclicGroup, Group,
    },
    openvm_pairing_guest::bls12_381::{
        Bls12_381 as Bls12_381_G1, Fp, Fp2, G1Affine as Bls12_381G1Affine,
        G2Affine as Bls12_381G2Affine, Scalar as Bls12_381Scalar,
    },
};

const G2_AFFINE_GENERATOR: Bls12_381G2Affine = Bls12_381G2Affine::new(
    Fp2::new(
        Fp::from_const_bytes(hex!("B8BD21C1C85680D4EFBB05A82603AC0B77D1E37A640B51B4023B40FAD47AE4C65110C52D27050826910A8FF0B2A24A02")),
        Fp::from_const_bytes(hex!("7E2B045D057DACE5575D941312F14C3349507FDCBB61DAB51AB62099D0D06B59654F2788A0D3AC7D609F7152602BE013"))
    ),
    Fp2::new(
        Fp::from_const_bytes(hex!("0128B808865493E189A2AC3BCCC93A922CD16051699A426DA7D3BD8CAA9BFDAD1A352EDAC6CDC98C116E7D7227D5E50C")),
        Fp::from_const_bytes(hex!("BE795FF05F07A9AAA11DEC5C270D373FAB992E57AB927426AF63A7857E283ECB998BC22BB0D2AC32CC34A72EA0C40606"))
    )
);

pub struct KzgProof {}

impl KzgProof {
    /// This function asserts that the KZG proof is valid. It will panic if the proof is not valid.
    ///
    /// **WARNING:** a dishonest host of the VM may cause this function to panic even on valid inputs,
    /// so this function cannot be used to prove that the KZG proof is definitely invalid.
    ///
    /// Therefore this function should only be used in cases where successful guest program execution requires
    /// the KZG proof to be valid.
    pub fn assert_kzg_proof(
        commitment_bytes: &Bytes48,
        z_bytes: &Bytes32,
        y_bytes: &Bytes32,
        proof_bytes: &Bytes48,
        kzg_settings: &KzgSettings,
    ) {
        // Check that the scalar is valid
        let z = Bls12_381Scalar::from_be_bytes(z_bytes.as_slice());
        let y = Bls12_381Scalar::from_be_bytes(y_bytes.as_slice());
        // Small optimization: this is a way to check both z, y are less than the modulus
        let _ = black_box(z == y);
        #[cfg(not(target_os = "zkvm"))]
        {
            // On host: check z, y are less than the modulus. (On guest this is done by iseqmod above)
            safe_scalar_affine_from_bytes(z_bytes).unwrap();
            safe_scalar_affine_from_bytes(y_bytes).unwrap();
        }

        let commitment = safe_g1_affine_from_bytes(commitment_bytes).unwrap();
        let proof = safe_g1_affine_from_bytes(proof_bytes).unwrap();

        let openvm_kzg_g2_point = to_openvm_g2_affine(kzg_settings.g2_points[1]);

        // Used for CachedMulTable implementation of msm for Bls12_381_G2.
        #[allow(non_camel_case_types)]
        struct Bls12_381_G2;
        impl IntrinsicCurve for Bls12_381_G2 {
            type Scalar = Bls12_381Scalar; // order of the generator is prime
            type Point = Bls12_381G2Affine;

            fn msm(coeffs: &[Self::Scalar], bases: &[Self::Point]) -> Self::Point {
                openvm_ecc_guest::msm(coeffs, bases)
            }
        }

        // We use the fact that g2_affine_generator has prime order.
        let table = CachedMulTable::<Bls12_381_G2>::new_with_prime_order(&[G2_AFFINE_GENERATOR], 4);
        let g2_z = table.windowed_mul(&[z]);

        let x_minus_z = openvm_kzg_g2_point - g2_z;

        // We use the fact that Bls12_381G1Affine::GENERATOR has prime order.
        let table = CachedMulTable::<Bls12_381_G1>::new_with_prime_order(
            &[Bls12_381G1Affine::GENERATOR],
            4,
        );
        let g1_y = table.windowed_mul(&[y]);

        let p_minus_y = commitment - g1_y;

        let p0 = {
            let (x, y) = p_minus_y.into_coords();
            AffinePoint::<Fp>::new(x, y)
        };
        let q0 = {
            let (x, y) = proof.into_coords();
            AffinePoint::<Fp>::new(x, y)
        };

        // p0 = p_minus_y;
        // p1 = g2_affine_generator;
        // q0 = proof;
        // q1 = x_minus_z;
        assert_pairing_equality(p0, G2_AFFINE_GENERATOR.clone().into(), q0, x_minus_z.into())
    }
}

/// Verifies the pairing of two G1 and two G2 points are equivalent using the multi-miller loop.
/// If this function succeeds without panicking, then the two pairings are equal.
///
/// **However** a dishonest host of the VM may cause this function to panic even on valid inputs,
/// so this function cannot be used to prove that two pairings are unequal.
///
/// Therefore this function should only be used in cases where successful guest program execution requires
/// the two pairings to be equal.
///
/// # Panics
/// - If the inputs are not valid points on the curve.
/// - If the two pairings are not equal.
pub fn assert_pairing_equality(
    p0: AffinePoint<Fp>,
    p1: AffinePoint<Fp2>,
    q0: AffinePoint<Fp>,
    q1: AffinePoint<Fp2>,
) {
    use openvm_pairing_guest::{bls12_381::Bls12_381, pairing::PairingCheck};

    // Check that input points are on the curve
    assert!(g1_affine_is_on_curve(&p0));
    assert!(g2_affine_is_on_curve(&p1));
    assert!(g1_affine_is_on_curve(&q0));
    assert!(g2_affine_is_on_curve(&q1));

    Bls12_381::pairing_check(&[-p0, q0], &[p1, q1]).unwrap();
}

pub fn g1_affine_is_on_curve(p: &AffinePoint<Fp>) -> bool {
    if p.is_infinity() {
        return true;
    }
    let x = &p.x;
    let y = &p.y;
    // y^2 == x^3 + 4
    y * y - x * x * x - Fp::from_u8(4) == Fp::ZERO
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

// Conversion functions:

/// Assumes that G2Affine is a point on the curve in the correct subgroup.
fn to_openvm_g2_affine(g2: G2Affine) -> Bls12_381G2Affine {
    if g2.is_identity().unwrap_u8() != 0 {
        return <Bls12_381G2Affine as Group>::IDENTITY;
    }
    let g2_bytes = g2.to_uncompressed();
    let x_c1: [u8; 48] = g2_bytes[0..48].try_into().unwrap();
    let x_c0: [u8; 48] = g2_bytes[48..96].try_into().unwrap();
    let y_c1: [u8; 48] = g2_bytes[96..144].try_into().unwrap();
    let y_c0: [u8; 48] = g2_bytes[144..192].try_into().unwrap();

    let ox = Fp2::from_coeffs([Fp::from_be_bytes(&x_c0), Fp::from_be_bytes(&x_c1)]);
    let oy = Fp2::from_coeffs([Fp::from_be_bytes(&y_c0), Fp::from_be_bytes(&y_c1)]);
    Bls12_381G2Affine::from_xy_unchecked(ox, oy)
}

/// Returns true if the field element is lexicographically larger than its negation.
///
/// The input `y` does not need to be reduced modulo the modulus.
pub fn is_lex_largest(y: &Fp) -> bool {
    let neg_y = -y.clone();
    // This is a way to assert canonical representation of y and -y simultaneously using iseqmod
    let _ = black_box(y == &neg_y);
    y.to_be_bytes() > neg_y.to_be_bytes()
}

// hint_decompress is currently not implemented on host because of the need to do a sqrt
#[cfg(target_os = "zkvm")]
pub fn safe_g1_affine_from_bytes(bytes: &Bytes48) -> Result<Bls12_381G1Affine, KzgError> {
    let mut x_bytes = [0u8; 48];
    x_bytes.copy_from_slice(&bytes.0[0..48]);

    let compression_flag_set = ((x_bytes[0] >> 7) & 1) != 0;
    let infinity_flag_set = ((x_bytes[0] >> 6) & 1) != 0;
    let sort_flag_set = ((x_bytes[0] >> 5) & 1) != 0;

    // Mask away the flag bits
    x_bytes[0] &= 0b0001_1111;
    let x = Fp::from_be_bytes(&x_bytes);

    if infinity_flag_set && compression_flag_set && !sort_flag_set && x == Fp::ZERO {
        return Ok(<Bls12_381G1Affine as Group>::IDENTITY);
    }

    // Note that we are hinting decompress and getting the y-coord pos/neg using lexicographical ordering, so
    // the value for rec_id does not matter and we can pass in either 0 or 1.
    let y = Bls12_381G1Affine::hint_decompress(&x, &0u8);
    let y = if is_lex_largest(&y) ^ sort_flag_set {
        -y
    } else {
        y
    };

    Bls12_381G1Affine::from_xy(x, y).ok_or(KzgError::BadArgs(
        "Failed to parse G1Affine from bytes".to_string(),
    ))
}

/// Assumes that G1Affine is a point on the curve in the correct subgroup.
#[cfg(not(target_os = "zkvm"))]
fn to_openvm_g1_affine(g1: G1Affine) -> Bls12_381G1Affine {
    if g1.is_identity().unwrap_u8() != 0 {
        return <Bls12_381G1Affine as Group>::IDENTITY;
    }
    let g1_bytes = g1.to_uncompressed();
    let x = Fp::from_be_bytes(&g1_bytes[0..48]);
    let y = Fp::from_be_bytes(&g1_bytes[48..96]);
    Bls12_381G1Affine::from_xy_unchecked(x, y)
}

#[cfg(not(target_os = "zkvm"))]
pub fn safe_g1_affine_from_bytes(bytes: &Bytes48) -> Result<Bls12_381G1Affine, KzgError> {
    let g1 = G1Affine::from_compressed(&bytes.0);
    if g1.is_none().into() {
        return Err(KzgError::BadArgs(
            "Failed to parse G1Affine from bytes".to_string(),
        ));
    }
    Ok(to_openvm_g1_affine(g1.unwrap()))
}

pub fn safe_scalar_affine_from_bytes(bytes: &Bytes32) -> Result<Scalar, KzgError> {
    let lendian: [u8; 32] = bytes
        .as_slice()
        .iter()
        .rev()
        .copied()
        .collect::<Vec<u8>>()
        .try_into()
        .unwrap();

    let scalar = Scalar::from_bytes(&lendian);
    if scalar.is_none().into() {
        return Err(KzgError::BadArgs(
            "Failed to parse G1Affine from bytes".to_string(),
        ));
    }
    Ok(scalar.unwrap())
}

#[cfg(test)]
pub mod tests {
    use std::panic::catch_unwind;

    use super::*;
    use crate::{
        test_files::VERIFY_KZG_PROOF_TESTS,
        test_utils::{Input, Test},
    };

    // This is a test on host
    #[test]
    pub fn test_verify_kzg_proof() {
        let kzg_settings = KzgSettings::load_trusted_setup_file().unwrap();

        for (test_file, data) in &VERIFY_KZG_PROOF_TESTS {
            let test: Test<Input> = serde_yaml::from_str(data).unwrap();
            let (Ok(commitment), Ok(z), Ok(y), Ok(proof)) = (
                test.input.get_commitment(),
                test.input.get_z(),
                test.input.get_y(),
                test.input.get_proof(),
            ) else {
                assert!(test.get_output().is_none());
                continue;
            };

            let result = catch_unwind(|| {
                KzgProof::assert_kzg_proof(&commitment, &z, &y, &proof, &kzg_settings)
            });
            // We assume an honest host, so panic implies result is false
            let result = result.is_ok();
            println!("test: {test_file}: {result}");
            assert_eq!(result, test.get_output().unwrap_or(false));
        }
    }
}
