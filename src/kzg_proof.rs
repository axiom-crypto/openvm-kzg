use core::num::NonZeroUsize;
use core::ops::Mul;

use crate::enums::KzgError;
use crate::pairings::g2_affine_to_affine_point;
#[cfg(not(feature = "guest-program"))]
use crate::pairings::pairings_verify_host;
use crate::types::KzgSettings;
use crate::{
    dtypes::*, BYTES_PER_BLOB, BYTES_PER_COMMITMENT, BYTES_PER_FIELD_ELEMENT, BYTES_PER_PROOF,
    CHALLENGE_INPUT_SIZE, DOMAIN_STR_LENGTH, FIAT_SHAMIR_PROTOCOL_DOMAIN, MODULUS,
    NUM_FIELD_ELEMENTS_PER_BLOB, RANDOM_CHALLENGE_KZG_BATCH_DOMAIN,
};

use alloc::{string::ToString, vec::Vec};
use bls12_381::{G1Affine, G1Projective, G2Affine, G2Projective, Scalar};
use ff::derive::sbb;
use hex_literal::hex;
use openvm_algebra_guest::field::FieldExtension;
use openvm_algebra_guest::{DivUnsafe, IntMod};
use openvm_ecc_guest::weierstrass::{FromCompressed, IntrinsicCurve, WeierstrassPoint};
use openvm_ecc_guest::{msm, AffinePoint, CyclicGroup, Group};
use openvm_pairing_guest::bls12_381::{
    Fp, Fp2, G1Affine as Bls12_381G1Affine, G2Affine as Bls12_381G2Affine,
    Scalar as Bls12_381Scalar,
};
use sha2::{Digest, Sha256};

pub fn to_openvm_g2_affine(g2: G2Affine) -> Bls12_381G2Affine {
    let x = g2.x;
    let y = g2.y;
    let ox = Fp2::from_coeffs([
        Fp::from_be_bytes(&x.c0.to_bytes()),
        Fp::from_be_bytes(&x.c1.to_bytes()),
    ]);
    let oy = Fp2::from_coeffs([
        Fp::from_be_bytes(&y.c0.to_bytes()),
        Fp::from_be_bytes(&y.c1.to_bytes()),
    ]);
    Bls12_381G2Affine::from_xy(ox, oy).unwrap()
}

/// Returns true if the field element is lexicographically larger than its negation.
pub fn is_lex_largest(y: Fp) -> bool {
    let modulus = Fp::from_le_bytes(&Fp::MODULUS);
    let half_modulus = modulus.div_unsafe(Fp::from_u32(2));
    // Use subtraction and sign check instead of direct comparison
    let diff = y - half_modulus;
    // Check if difference is positive by checking if negation would be smaller
    let neg_diff = -diff.clone();
    diff.to_be_bytes() > neg_diff.to_be_bytes()
}

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
    let y = if is_lex_largest(y.clone()) ^ sort_flag_set {
        -y
    } else {
        y
    };

    Ok(Bls12_381G1Affine::from_xy(x, y).unwrap())
}

pub fn safe_scalar_affine_from_bytes(bytes: &Bytes32) -> Result<Scalar, KzgError> {
    let lendian: [u8; 32] = Into::<[u8; 32]>::into(bytes.clone())
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

/// Return the Fiat-Shamir challenge required to verify `blob` and `commitment`.
fn compute_challenge(blob: &Blob, commitment: &G1Affine) -> Result<Scalar, KzgError> {
    let mut bytes = [0_u8; CHALLENGE_INPUT_SIZE];
    let mut offset = 0_usize;
    // Copy domain separator
    bytes[offset..DOMAIN_STR_LENGTH].copy_from_slice(FIAT_SHAMIR_PROTOCOL_DOMAIN.as_bytes());
    offset += DOMAIN_STR_LENGTH;
    // Copy polynomial degree (16-bytes, big-endian)
    bytes[offset..offset + 8].copy_from_slice(&0_u64.to_be_bytes());
    offset += 8;
    bytes[offset..offset + 8].copy_from_slice(&(NUM_FIELD_ELEMENTS_PER_BLOB as u64).to_be_bytes());
    offset += 8;
    // Copy blob
    bytes[offset..offset + BYTES_PER_BLOB].copy_from_slice(blob.as_slice());
    offset += BYTES_PER_BLOB;
    // Copy commitment
    bytes[offset..offset + BYTES_PER_COMMITMENT].copy_from_slice(&commitment.to_compressed());
    offset += BYTES_PER_COMMITMENT;
    /* Make sure we wrote the entire buffer */
    if offset != CHALLENGE_INPUT_SIZE {
        return Err(KzgError::InvalidBytesLength(format!(
            "The challenge should be {} length, but was {}",
            CHALLENGE_INPUT_SIZE, offset,
        )));
    }
    let evaluation: [u8; 32] = Sha256::digest(bytes).into();
    Ok(scalar_from_bytes_unchecked(evaluation))
}

pub fn scalar_from_bytes_unchecked(bytes: [u8; 32]) -> Scalar {
    scalar_from_u64_array_unchecked([
        u64::from_be_bytes(<[u8; 8]>::try_from(&bytes[0..8]).unwrap()),
        u64::from_be_bytes(<[u8; 8]>::try_from(&bytes[8..16]).unwrap()),
        u64::from_be_bytes(<[u8; 8]>::try_from(&bytes[16..24]).unwrap()),
        u64::from_be_bytes(<[u8; 8]>::try_from(&bytes[24..32]).unwrap()),
    ])
}

pub fn scalar_from_u64_array_unchecked(array: [u64; 4]) -> Scalar {
    // Try to subtract the modulus
    let (_, borrow) = sbb(array[0], MODULUS[0], 0);
    let (_, borrow) = sbb(array[1], MODULUS[1], borrow);
    let (_, borrow) = sbb(array[2], MODULUS[2], borrow);
    let (_, _borrow) = sbb(array[3], MODULUS[3], borrow);

    Scalar::from_raw([array[3], array[2], array[1], array[0]])
}

/// Evaluates a polynomial in evaluation form at a given point
pub fn evaluate_polynomial_in_evaluation_form(
    polynomial: Vec<Scalar>,
    x: Scalar,
    kzg_settings: &KzgSettings,
) -> Result<Scalar, KzgError> {
    if polynomial.len() != NUM_FIELD_ELEMENTS_PER_BLOB {
        return Err(KzgError::InvalidBytesLength(
            "The polynomial length is incorrect".to_string(),
        ));
    }

    let mut inverses_in = vec![Scalar::default(); NUM_FIELD_ELEMENTS_PER_BLOB];
    let mut inverses = vec![Scalar::default(); NUM_FIELD_ELEMENTS_PER_BLOB];
    let roots_of_unity = kzg_settings.roots_of_unity;
    for i in 0..NUM_FIELD_ELEMENTS_PER_BLOB {
        if x == roots_of_unity[i] {
            return Ok(polynomial[i]);
        }
        inverses_in[i] = x - roots_of_unity[i];
    }

    batch_inversion(
        &mut inverses,
        &inverses_in,
        NonZeroUsize::new(NUM_FIELD_ELEMENTS_PER_BLOB).unwrap(),
    )?;

    let mut out = Scalar::zero();

    for i in 0..NUM_FIELD_ELEMENTS_PER_BLOB {
        out += (inverses[i] * roots_of_unity[i]) * polynomial[i];
    }

    out *= Scalar::from(NUM_FIELD_ELEMENTS_PER_BLOB as u64)
        .invert()
        .unwrap();
    out *= x.pow(&[NUM_FIELD_ELEMENTS_PER_BLOB as u64, 0, 0, 0]) - Scalar::one();

    Ok(out)
}

/// Montgomery batch inversion in a finite field
/// Given a list of elements \( x_1, x_2, \dots, x_n \) from a finite field \( F \), Montgomery batch inversion computes the inverses \( x_1^{-1}, x_2^{-1}, \dots, x_n^{-1} \) as follows:
///
/// Let's consider three elements \( a \), \( b \), and \( c \) in a finite field \( F \). The steps are as follows:
///
/// 1. **Product Accumulation**:
///     \[
///     P = a \times b \times c
///     \]
///
/// 2. **Single Inversion**:
///     \[
///     P^{-1} = \text{inverse}(P)
///     \]
///
/// 3. **Backward Substitution**:
///     - \( a^{-1} = P^{-1} \times (b \times c) \)
///     - \( b^{-1} = P^{-1} \times (a \times c) \)
///     - \( c^{-1} = P^{-1} \times (a \times b) \)
///
fn batch_inversion(out: &mut [Scalar], a: &[Scalar], len: NonZeroUsize) -> Result<(), KzgError> {
    if a == out {
        return Err(KzgError::BadArgs(
            "Destination is the same as source".to_string(),
        ));
    }

    // Compute the product of all the elements:
    //
    // \[
    // P = x_1 \times x_2 \times \dots \times x_n
    // \]

    let mut accumulator = Scalar::one();

    for i in 0..len.into() {
        out[i] = accumulator;
        accumulator = accumulator.mul(&a[i]);
    }

    if accumulator == Scalar::zero() {
        return Err(KzgError::BadArgs("Zero input".to_string()));
    }

    // Compute the inverse of the product \( P \):
    //
    // \[
    // P^{-1} = \text{inverse}(P)
    // \]
    accumulator = accumulator.invert().unwrap();

    // Compute the inverse of each element \( x_i^{-1} \) by using the precomputed product and its inverse:
    //
    // \[
    // x_i^{-1} = P^{-1} \times \left(\prod_{j \neq i} x_j \right)
    // \]
    for i in (0..len.into()).rev() {
        out[i] *= accumulator;
        accumulator *= a[i];
    }

    Ok(())
}

// fn verify_kzg_proof_impl(
//     commitment: G1Affine,
//     z: Scalar,
//     y: Scalar,
//     proof: G1Affine,
//     kzg_settings: &KzgSettings,
// ) -> Result<bool, KzgError> {
//     let x = G2Projective::generator() * z;
//     let x_minus_z = kzg_settings.g2_points[1] - x;

//     let y = G1Projective::generator() * y;
//     let p_minus_y = commitment - y;

//     // Verify: P - y = Q * (X - z)
//     Ok(pairings_verify_host(
//         p_minus_y.into(),
//         G2Projective::generator().into(),
//         proof,
//         x_minus_z.into(),
//     ))
// }

// fn validate_batched_input(commitment: &[G1Affine], proofs: &[G1Affine]) -> Result<(), KzgError> {
//     // Check if any commitment is invalid (not on curve or identity)
//     let invalid_commitment = commitment.iter().any(|commitment| {
//         !bool::from(commitment.is_identity()) && !bool::from(commitment.is_on_curve())
//     });

//     // Check if any proof is invalid (not on curve or identity)
//     let invalid_proof = proofs
//         .iter()
//         .any(|proof| !bool::from(proof.is_identity()) && !bool::from(proof.is_on_curve()));

//     // Return error if any invalid commitment is found
//     if invalid_commitment {
//         return Err(KzgError::BadArgs("Invalid commitment".to_string()));
//     }
//     // Return error if any invalid proof is found
//     if invalid_proof {
//         return Err(KzgError::BadArgs("Invalid proof".to_string()));
//     }

//     Ok(()) // Return Ok if all commitments and proofs are valid
// }

// fn compute_challenges_and_evaluate_polynomial(
//     blobs: Vec<Blob>,
//     commitment: &[G1Affine],
//     kzg_settings: &KzgSettings,
// ) -> Result<(Vec<Scalar>, Vec<Scalar>), KzgError> {
//     // Initialize vectors to store evaluation challenges and polynomial evaluations
//     let mut evaluation_challenges = Vec::with_capacity(blobs.len());
//     let mut ys = Vec::with_capacity(blobs.len());

//     // Iterate over each blob to compute its polynomial evaluation
//     for i in 0..blobs.len() {
//         // Convert the blob to its polynomial representation
//         let polynomial = blobs[i].as_polynomial()?;
//         // Compute the Fiat-Shamir challenge for the current blob and its commitment
//         let evaluation_challenge = compute_challenge(&blobs[i], &commitment[i])?;
//         // Evaluate the polynomial at the computed challenge
//         let y =
//             evaluate_polynomial_in_evaluation_form(polynomial, evaluation_challenge, kzg_settings)?;

//         // Store the evaluation challenge and the polynomial evaluation
//         evaluation_challenges.push(evaluation_challenge);
//         ys.push(y);
//     }

//     // Return the vectors of evaluation challenges and polynomial evaluations
//     Ok((evaluation_challenges, ys))
// }

pub fn compute_powers(base: &Scalar, num_powers: usize) -> Vec<Scalar> {
    let mut powers = vec![Scalar::default(); num_powers];
    if num_powers == 0 {
        return powers;
    }
    powers[0] = Scalar::one();
    for i in 1..num_powers {
        powers[i] = powers[i - 1].mul(base);
    }
    powers
}

fn compute_r_powers(
    commitment: &[G1Affine],
    zs: &[Scalar],
    ys: &[Scalar],
    proofs: &[G1Affine],
) -> Result<Vec<Scalar>, KzgError> {
    let n = commitment.len();
    let input_size =
        32 + n * (BYTES_PER_COMMITMENT + 2 * BYTES_PER_FIELD_ELEMENT + BYTES_PER_PROOF);

    let mut bytes: Vec<u8> = vec![0; input_size];

    // Copy domain separator
    bytes[..16].copy_from_slice(RANDOM_CHALLENGE_KZG_BATCH_DOMAIN.as_bytes());

    bytes[16..24].copy_from_slice(&(NUM_FIELD_ELEMENTS_PER_BLOB as u64).to_be_bytes());

    let mut n_bytes = n.to_be_bytes().to_vec();
    n_bytes.resize(8, 0);
    bytes[24..32].copy_from_slice(&n_bytes);

    let mut offset = 32;

    for i in 0..n {
        // Copy commitment
        let v = commitment[i].to_compressed();
        bytes[offset..(v.len() + offset)].copy_from_slice(&v[..]);
        offset += BYTES_PER_COMMITMENT;

        // Copy evaluation challenge
        let v = zs[i].to_bytes();
        bytes[offset..(v.len() + offset)].copy_from_slice(&v[..]);
        offset += BYTES_PER_FIELD_ELEMENT;

        // Copy polynomial's evaluation value
        let v = ys[i].to_bytes();
        bytes[offset..(v.len() + offset)].copy_from_slice(&v[..]);
        offset += BYTES_PER_FIELD_ELEMENT;

        // Copy proof
        let v = proofs[i].to_compressed();
        bytes[offset..(v.len() + offset)].copy_from_slice(&v[..]);
        offset += BYTES_PER_PROOF;
    }

    // Make sure we wrote the entire buffer
    if offset != input_size {
        return Err(KzgError::InvalidBytesLength(
            "Error while copying commitments".to_string(),
        ));
    }

    // Now let's create the challenge!
    let evaluation: [u8; 32] = Sha256::digest(bytes).into();
    let r = scalar_from_bytes_unchecked(evaluation);

    Ok(compute_powers(&r, n))
}

pub struct KzgProof {}

impl KzgProof {
    pub fn verify_kzg_proof(
        commitment_bytes: &Bytes48,
        z_bytes: &Bytes32,
        y_bytes: &Bytes32,
        proof_bytes: &Bytes48,
        kzg_settings: &KzgSettings,
    ) -> Result<bool, KzgError> {
        let z = Bls12_381Scalar::from_be_bytes(z_bytes.as_slice());
        let y = Bls12_381Scalar::from_be_bytes(y_bytes.as_slice());
        // let z = match safe_scalar_affine_from_bytes(z_bytes) {
        //     Ok(z) => z,
        //     Err(e) => {
        //         return Err(e);
        //     }
        // };
        // let y = match safe_scalar_affine_from_bytes(y_bytes) {
        //     Ok(y) => y,
        //     Err(e) => {
        //         return Err(e);
        //     }
        // };
        let commitment = match safe_g1_affine_from_bytes(commitment_bytes) {
            Ok(g1) => g1,
            Err(e) => {
                return Err(e);
            }
        };
        let proof = match safe_g1_affine_from_bytes(proof_bytes) {
            Ok(g1) => g1,
            Err(e) => {
                return Err(e);
            }
        };

        let g2_affine_generator_pt = AffinePoint::new(
            Fp2::from_coeffs([
                Fp::from_be_bytes(&hex!("024aa2b2f08f0a91260805272dc51051c6e47ad4fa403b02b4510b647ae3d1770bac0326a805bbefd48056c8c121bdb8")),
                Fp::from_be_bytes(&hex!("13e02b6052719f607dacd3a088274f65596bd0d09920b61ab5da61bbdc7f5049334cf11213945d57e5ac7d055d042b7e"))
            ]),
            Fp2::from_coeffs([
                Fp::from_be_bytes(&hex!("0ce5d527727d6e118cc9cdc6da2e351aadfd9baa8cbdd3a76d429a695160d12c923ac9cc3baca289e193548608b82801")),
                Fp::from_be_bytes(&hex!("0606c4a02ea734cc32acd2b02bc28b99cb3e287e85a763af267492ab572e99ab3f370d275cec1da1aaa9075ff05f79be"))
            ])
        );

        let g2_affine_generator = Bls12_381G2Affine::from_xy(
            g2_affine_generator_pt.x.clone(),
            g2_affine_generator_pt.y.clone(),
        )
        .unwrap();

        let openvm_kzg_g2_point = to_openvm_g2_affine(kzg_settings.g2_points[1]);

        // let g2_x = G2Affine::mul() msm(&[z], &[g2_affine_generator]);
        let g2_x = g2_affine_generator;
        let x_minus_z = openvm_kzg_g2_point - g2_x;

        // let g1_y = msm(&[y], &[Bls12_381G1Affine::GENERATOR]);
        let g1_y = Bls12_381G1Affine::GENERATOR;
        let p_minus_y = commitment - g1_y;

        let p0 = AffinePoint::<Fp>::new(p_minus_y.x, p_minus_y.y);
        let q0 = AffinePoint::<Fp>::new(proof.x, proof.y);

        let x_minus_z_pt = AffinePoint::<Fp2>::new(
            Fp2::from_coeffs([x_minus_z.x().c0.clone(), x_minus_z.x().c1.clone()]),
            Fp2::from_coeffs([x_minus_z.y().c0.clone(), x_minus_z.y().c1.clone()]),
        );

        // let p0 = p_minus_y;
        // let p1 = g2_affine_generator;
        // let q0 = proof;
        // let q1 = x_minus_z;
        Ok(crate::pairings_verify(
            p0,
            g2_affine_generator_pt,
            q0,
            x_minus_z_pt,
        ))
        // Ok(true)
    }

    pub fn verify_kzg_proof_batch(
        commitments: &[G1Affine],
        zs: &[Scalar],
        ys: &[Scalar],
        proofs: &[G1Affine],
        kzg_settings: &KzgSettings,
    ) -> Result<bool, KzgError> {
        Ok(true)
        // let n = commitments.len();

        // // Initialize vectors to store intermediate values
        // let mut c_minus_y: Vec<G1Projective> = Vec::with_capacity(n);
        // let mut r_times_z: Vec<Scalar> = Vec::with_capacity(n);

        // // Compute r powers
        // let r_powers = compute_r_powers(commitments, zs, ys, proofs)?;

        // // let proof_lincomb = msm_variable_base(&r_powers, &proofs);

        // // Convert proofs to G1Projective
        // let proofs = proofs.iter().map(Into::into).collect::<Vec<_>>();

        // // Compute proof linear combination
        // let proof_lincomb = G1Projective::msm_variable_base(&proofs, &r_powers);

        // // Compute c_minus_y and r_times_z
        // for i in 0..n {
        //     let ys_encrypted = G1Affine::generator() * ys[i];
        //     c_minus_y.push(commitments[i] - ys_encrypted);
        //     r_times_z.push(r_powers[i] * zs[i]);
        // }

        // // Compute proof_z_lincomb and c_minus_y_lincomb
        // let proof_z_lincomb = G1Projective::msm_variable_base(&proofs, &r_times_z);
        // let c_minus_y_lincomb = G1Projective::msm_variable_base(&c_minus_y, &r_powers);

        // // Compute rhs_g1
        // let rhs_g1 = c_minus_y_lincomb + proof_z_lincomb;

        // // Verify the pairing equation
        // let result = pairings_verify_host(
        //     proof_lincomb.into(),
        //     kzg_settings.g2_points[1],
        //     rhs_g1.into(),
        //     G2Affine::generator(),
        // );

        // Ok(result)
    }

    pub fn verify_blob_kzg_proof(
        blob: Blob,
        commitment_bytes: &Bytes48,
        proof_bytes: &Bytes48,
        kzg_settings: &KzgSettings,
    ) -> Result<bool, KzgError> {
        Ok(true)
        // // Convert commitment bytes to G1Affine
        // let commitment = safe_g1_affine_from_bytes(commitment_bytes)?;

        // // Convert blob to polynomial
        // let polynomial = blob.as_polynomial()?;

        // // Convert proof bytes to G1Affine
        // let proof = safe_g1_affine_from_bytes(proof_bytes)?;

        // // Compute the evaluation challenge for the blob and commitment
        // let evaluation_challenge = compute_challenge(&blob, &commitment)?;

        // // Evaluate the polynomial in evaluation form
        // let y =
        //     evaluate_polynomial_in_evaluation_form(polynomial, evaluation_challenge, kzg_settings)?;

        // // Verify the KZG proof
        // verify_kzg_proof_impl(commitment, evaluation_challenge, y, proof, kzg_settings)
    }

    pub fn verify_blob_kzg_proof_batch(
        blobs: Vec<Blob>,
        commitments_bytes: Vec<Bytes48>,
        proofs_bytes: Vec<Bytes48>,
        kzg_settings: &KzgSettings,
    ) -> Result<bool, KzgError> {
        Ok(true)
        // if blobs.is_empty() {
        //     return Ok(true);
        // }

        // if blobs.len() == 1 {
        //     return Self::verify_blob_kzg_proof(
        //         blobs[0].clone(),
        //         &commitments_bytes[0],
        //         &proofs_bytes[0],
        //         kzg_settings,
        //     );
        // }

        // if blobs.len() != commitments_bytes.len() {
        //     return Err(KzgError::InvalidBytesLength(
        //         "Invalid commitments length".to_string(),
        //     ));
        // }

        // if blobs.len() != proofs_bytes.len() {
        //     return Err(KzgError::InvalidBytesLength(
        //         "Invalid proofs length".to_string(),
        //     ));
        // }

        // let commitments = commitments_bytes
        //     .iter()
        //     .map(safe_g1_affine_from_bytes)
        //     .collect::<Result<Vec<_>, _>>()?;

        // let proofs = proofs_bytes
        //     .iter()
        //     .map(safe_g1_affine_from_bytes)
        //     .collect::<Result<Vec<_>, _>>()?;

        // validate_batched_input(&commitments, &proofs)?;

        // let (evaluation_challenges, ys) =
        //     compute_challenges_and_evaluate_polynomial(blobs, &commitments, kzg_settings)?;

        // Self::verify_kzg_proof_batch(
        //     &commitments,
        //     &evaluation_challenges,
        //     &ys,
        //     &proofs,
        //     kzg_settings,
        // )
    }
}

#[cfg(test)]
pub mod tests {
    use std::path::PathBuf;

    use super::*;
    use crate::{
        test_files::{
            VERIFY_BLOB_KZG_PROOF_BATCH_TESTS, VERIFY_BLOB_KZG_PROOF_TESTS, VERIFY_KZG_PROOF_TESTS,
        },
        test_utils::{FromHex, Input, Test},
    };
    use serde::Deserialize;

    // type F = BabyBear;

    #[test]
    pub fn test_verify_kzg_proof() {
        let kzg_settings = KzgSettings::load_trusted_setup_file().unwrap();
        let test_files = VERIFY_KZG_PROOF_TESTS;

        for (_test_file, data) in test_files {
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

            let result = KzgProof::verify_kzg_proof(&commitment, &z, &y, &proof, &kzg_settings);
            match result {
                Ok(result) => {
                    assert_eq!(result, test.get_output().unwrap_or(false));
                }
                Err(_) => {
                    assert!(test.get_output().is_none());
                }
            }
        }
    }

    #[derive(Debug, Deserialize)]
    pub struct BlobInput<'a> {
        blob: &'a str,
        commitment: &'a str,
        proof: &'a str,
    }

    impl BlobInput<'_> {
        pub fn get_blob(&self) -> Result<Blob, KzgError> {
            Blob::from_hex(self.blob)
        }

        pub fn get_commitment(&self) -> Result<Bytes48, KzgError> {
            Bytes48::from_hex(self.commitment)
        }

        pub fn get_proof(&self) -> Result<Bytes48, KzgError> {
            Bytes48::from_hex(self.proof)
        }
    }

    #[test]
    pub fn test_verify_blob_kzg_proof() {
        let kzg_settings = KzgSettings::load_trusted_setup_file().unwrap();
        let test_files = VERIFY_BLOB_KZG_PROOF_TESTS;

        for (_test_file, data) in test_files {
            let test: Test<BlobInput> = serde_yaml::from_str(data).unwrap();
            let (Ok(blob), Ok(commitment), Ok(proof)) = (
                test.input.get_blob(),
                test.input.get_commitment(),
                test.input.get_proof(),
            ) else {
                assert!(test.get_output().is_none());
                continue;
            };

            let result = KzgProof::verify_blob_kzg_proof(blob, &commitment, &proof, &kzg_settings);
            match result {
                Ok(result) => {
                    assert_eq!(result, test.get_output().unwrap_or(false));
                }
                Err(_) => {
                    assert!(test.get_output().is_none());
                }
            }
        }
    }

    #[derive(Debug, Deserialize)]
    struct BlobBatchInput<'a> {
        #[serde(borrow)]
        blob: &'a str,
        #[serde(borrow)]
        commitment: &'a str,
        #[serde(borrow)]
        proof: &'a str,
    }

    impl<'a> BlobBatchInput<'a> {
        pub fn get_blobs(&self) -> Result<Blob, KzgError> {
            Blob::from_hex(self.blob)
        }

        pub fn get_commitments(&self) -> Result<Bytes48, KzgError> {
            Bytes48::from_hex(self.commitment)
        }

        pub fn get_proofs(&self) -> Result<Bytes48, KzgError> {
            Bytes48::from_hex(self.proof)
        }
    }

    #[test]
    pub fn test_verify_blob_kzg_proof_batch() {
        let test_files = VERIFY_BLOB_KZG_PROOF_BATCH_TESTS;
        let kzg_settings = KzgSettings::load_trusted_setup_file().unwrap();

        for (_test_file, data) in test_files {
            let test: Test<BlobBatchInput> = serde_yaml::from_str(data).unwrap();
            let (Ok(blobs), Ok(commitments), Ok(proofs)) = (
                test.input.get_blobs(),
                test.input.get_commitments(),
                test.input.get_proofs(),
            ) else {
                assert!(test.get_output().is_none());
                continue;
            };

            let result = KzgProof::verify_blob_kzg_proof_batch(
                vec![blobs],
                vec![commitments],
                vec![proofs],
                &kzg_settings,
            );
            match result {
                Ok(result) => {
                    assert_eq!(result, test.get_output().unwrap_or(false));
                }
                Err(_) => {
                    assert!(test.get_output().is_none());
                }
            }
        }
    }

    // #[test]
    // pub fn test_compute_challenge() {
    //     let data = include_str!("../tests/verify_blob_kzg_proof/verify_blob_kzg_proof_case_correct_proof_fb324bc819407148/data.yaml");

    //     let test: Test<BlobInput> = serde_yaml::from_str(data).unwrap();
    //     let blob = test.input.get_blob().unwrap();
    //     let commitment = safe_g1_affine_from_bytes(&test.input.get_commitment().unwrap()).unwrap();

    //     let evaluation_challenge = compute_challenge(&blob, &commitment).unwrap();

    //     assert_eq!(
    //         format!("{evaluation_challenge}"),
    //         "0x4f00eef944a21cb9f3ac3390702621e4bbf1198767c43c0fb9c8e9923bfbb31a"
    //     )
    // }

    // #[test]
    // pub fn test_evaluate_polynomial_in_evaluation_form() {
    //     let data = include_str!("../tests/verify_blob_kzg_proof/verify_blob_kzg_proof_case_correct_proof_19b3f3f8c98ea31e/data.yaml");

    //     let test: Test<BlobInput> = serde_yaml::from_str(data).unwrap();
    //     let kzg_settings = KzgSettings::load_trusted_setup_file().unwrap();
    //     let blob = test.input.get_blob().unwrap();
    //     let polynomial = blob.as_polynomial().unwrap();

    //     let evaluation_challenge = scalar_from_bytes_unchecked(
    //         Bytes32::from_hex("0x637c904d316955b7282f980433d5cd9f40d0533c45d0a233c009bc7fe28b92e3")
    //             .unwrap()
    //             .into(),
    //     );

    //     let y =
    //         evaluate_polynomial_in_evaluation_form(polynomial, evaluation_challenge, &kzg_settings)
    //             .unwrap();

    //     assert_eq!(
    //         format!("{y}"),
    //         "0x1bdfc5da40334b9c51220e8cbea1679c20a7f32dd3d7f3c463149bb4b41a7d18"
    //     );
    // }
}
