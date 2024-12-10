#![no_std]
#![no_main]

extern crate alloc;

use axvm::io::read;
use bls12_381::{G1Affine, G2Affine, Scalar};
use kzg_rs::{Bytes32, Bytes48, KzgProof, KzgSettings};

axvm::entry!(main);

axvm_algebra_moduli_setup::moduli_init! {
    "0x1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab",
    "0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001"
}

axvm_algebra_complex_macros::complex_init! {
    Fp2 { mod_idx = 0 },
}

/// Inputs to the KZG proof verification
#[derive(serde::Deserialize)]
struct KzgInputs {
    #[serde(deserialize_with = "deserialize_u8_48")]
    commitment_bytes: Bytes48,
    #[serde(deserialize_with = "deserialize_u8_32")]
    z_bytes: Bytes32,
    #[serde(deserialize_with = "deserialize_u8_32")]
    y_bytes: Bytes32,
    #[serde(deserialize_with = "deserialize_u8_48")]
    proof_bytes: Bytes48,
    // #[serde(deserialize_with = "deserialize_kzg_settings")]
    // kzg_settings: KzgSettings,
}

pub fn main() {
    setup_0();
    setup_all_complex_extensions();

    let io: KzgInputs = read();

    // SAFETY: We know these values will be valid for the duration of their use,
    // even though they're not actually 'static
    let kzg_settings = unsafe {
        KzgSettings {
            roots_of_unity: core::mem::transmute::<&[Scalar], &'static [Scalar]>(&[Scalar::one()]),
            g1_points: core::mem::transmute::<&[G1Affine], &'static [G1Affine]>(&[
                G1Affine::generator(),
            ]),
            g2_points: core::mem::transmute::<&[G2Affine], &'static [G2Affine]>(&[
                G2Affine::generator(),
            ]),
        }
    };

    let res = KzgProof::verify_kzg_proof(
        &io.commitment_bytes,
        &io.z_bytes,
        &io.y_bytes,
        &io.proof_bytes,
        &kzg_settings,
    );

    assert!(res.is_ok());
    assert!(res.unwrap());
}

fn deserialize_u8_48<'de, D>(deserializer: D) -> Result<Bytes48, D::Error>
where
    D: serde::Deserializer<'de>,
{
    struct ArrayVisitor;

    impl<'de> serde::de::Visitor<'de> for ArrayVisitor {
        type Value = [u8; 48];

        fn expecting(&self, formatter: &mut core::fmt::Formatter) -> core::fmt::Result {
            formatter.write_str("an array of 48 bytes")
        }

        fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
        where
            A: serde::de::SeqAccess<'de>,
        {
            let mut array = [0u8; 48];
            for i in 0..48 {
                array[i] = seq
                    .next_element()?
                    .ok_or_else(|| serde::de::Error::invalid_length(i, &self))?;
            }
            Ok(array)
        }
    }

    deserializer
        .deserialize_tuple(48, ArrayVisitor)
        .map(|arr| Bytes48::from_slice(&arr).unwrap())
}

fn deserialize_u8_32<'de, D>(deserializer: D) -> Result<Bytes32, D::Error>
where
    D: serde::Deserializer<'de>,
{
    struct ArrayVisitor;

    impl<'de> serde::de::Visitor<'de> for ArrayVisitor {
        type Value = [u8; 32];

        fn expecting(&self, formatter: &mut core::fmt::Formatter) -> core::fmt::Result {
            formatter.write_str("an array of 32 bytes")
        }

        fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
        where
            A: serde::de::SeqAccess<'de>,
        {
            let mut array = [0u8; 32];
            for i in 0..32 {
                array[i] = seq
                    .next_element()?
                    .ok_or_else(|| serde::de::Error::invalid_length(i, &self))?;
            }
            Ok(array)
        }
    }

    deserializer
        .deserialize_tuple(32, ArrayVisitor)
        .map(|arr| Bytes32::from_slice(&arr).unwrap())
}

// Temp deserializer to get things working
// fn deserialize_kzg_settings<'de, D>(deserializer: D) -> Result<KzgSettings, D::Error>
// where
//     D: serde::Deserializer<'de>,
// {
//     let s = [Scalar::one()];
//     let g1 = [G1Affine::generator()];
//     let g2 = [G2Affine::generator()];

//     Ok(KzgSettings {
//         roots_of_unity: &s.clone(),
//         g1_points: &g1.clone(),
//         g2_points: &g2.clone(),
//     })
// }
