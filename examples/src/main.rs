#![cfg_attr(not(feature = "std"), no_main)]
#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

use spin::Once;

use axvm::io::read;
use bls12_381::{G1Affine, G2Affine, Scalar};
use kzg_rs::{Bytes32, Bytes48, KzgProof, KzgSettings};

axvm::entry!(main);

/// Inputs to the KZG proof verification
#[derive(serde_derive::Deserialize)]
struct KzgInputs {
    #[serde(deserialize_with = "deserialize_u8_48")]
    commitment_bytes: Bytes48,
    #[serde(deserialize_with = "deserialize_u8_32")]
    z_bytes: Bytes32,
    #[serde(deserialize_with = "deserialize_u8_32")]
    y_bytes: Bytes32,
    #[serde(deserialize_with = "deserialize_u8_48")]
    proof_bytes: Bytes48,
    #[serde(deserialize_with = "deserialize_kzg_settings")]
    kzg_settings: KzgSettings,
}

pub fn main() {
    let io: KzgInputs = read();

    let res = KzgProof::verify_kzg_proof(
        &io.commitment_bytes,
        &io.z_bytes,
        &io.y_bytes,
        &io.proof_bytes,
        &io.kzg_settings,
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
fn deserialize_kzg_settings<'de, D>(deserializer: D) -> Result<KzgSettings, D::Error>
where
    D: serde::Deserializer<'de>,
{
    static ROOTS: Once<[Scalar; 1]> = Once::new();
    static G1: Once<[G1Affine; 1]> = Once::new();
    static G2: Once<[G2Affine; 1]> = Once::new();

    Ok(KzgSettings {
        roots_of_unity: ROOTS.call_once(|| [Scalar::one()]),
        g1_points: G1.call_once(|| [G1Affine::generator()]),
        g2_points: G2.call_once(|| [G2Affine::generator()]),
    })
}
