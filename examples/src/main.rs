#![cfg_attr(not(feature = "std"), no_main)]
#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

use alloc::vec::Vec;
use axvm::io::read;
use kzg_rs::{KzgProof, KzgSettings};

axvm::entry!(main);

/// Inputs to the KZG proof verification
#[derive(serde_derive::Deserialize)]
struct KzgInputs {
    #[serde(deserialize_with = "deserialize_u8_48")]
    commitment_bytes: [u8; 48],
    z_bytes: [u8; 32],
    y_bytes: [u8; 32],
    #[serde(deserialize_with = "deserialize_u8_48")]
    proof_bytes: [u8; 48],
    // kzg_settings: KzgSettings,
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

fn deserialize_u8_48<'de, D>(deserializer: D) -> Result<[u8; 48], D::Error>
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

    deserializer.deserialize_tuple(48, ArrayVisitor)
}
