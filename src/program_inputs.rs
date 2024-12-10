use serde::{Deserialize, Serialize};

use crate::{Bytes32, Bytes48};
use serde_big_array::BigArray;

/// Inputs to the KZG proof verification
#[derive(Deserialize, Serialize)]
pub struct KzgInputs {
    pub commitment_bytes: Bytes48,
    pub z_bytes: Bytes32,
    pub y_bytes: Bytes32,
    pub proof_bytes: Bytes48,
    // #[serde(deserialize_with = "deserialize_kzg_settings")]
    // pub kzg_settings: KzgSettings,
}

// fn deserialize_u8_48<'de, D>(deserializer: D) -> Result<Bytes48, D::Error>
// where
//     D: serde::de::Deserializer<'de>,
// {
//     struct ArrayVisitor;

//     impl<'de> serde::de::Visitor<'de> for ArrayVisitor {
//         type Value = [u8; 48];

//         fn expecting(&self, formatter: &mut core::fmt::Formatter) -> core::fmt::Result {
//             formatter.write_str("an array of 48 bytes")
//         }

//         fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
//         where
//             A: serde::de::SeqAccess<'de>,
//         {
//             let mut array = [0u8; 48];
//             for i in 0..48 {
//                 array[i] = seq
//                     .next_element()?
//                     .ok_or_else(|| serde::de::Error::invalid_length(i, &self))?;
//             }
//             Ok(array)
//         }
//     }

//     deserializer
//         .deserialize_tuple(48, ArrayVisitor)
//         .map(|arr| Bytes48::from_slice(&arr).unwrap())
// }

// fn deserialize_u8_32<'de, D>(deserializer: D) -> Result<Bytes32, D::Error>
// where
//     D: serde::de::Deserializer<'de>,
// {
//     struct ArrayVisitor;

//     impl<'de> serde::de::Visitor<'de> for ArrayVisitor {
//         type Value = [u8; 32];

//         fn expecting(&self, formatter: &mut core::fmt::Formatter) -> core::fmt::Result {
//             formatter.write_str("an array of 32 bytes")
//         }

//         fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
//         where
//             A: serde::de::SeqAccess<'de>,
//         {
//             let mut array = [0u8; 32];
//             for i in 0..32 {
//                 array[i] = seq
//                     .next_element()?
//                     .ok_or_else(|| serde::de::Error::invalid_length(i, &self))?;
//             }
//             Ok(array)
//         }
//     }

//     deserializer
//         .deserialize_tuple(32, ArrayVisitor)
//         .map(|arr| Bytes32::from_slice(&arr).unwrap())
// }

// Temp deserializer to get things working
// fn deserialize_kzg_settings<'de, D>(deserializer: D) -> Result<KzgSettings, D::Error>
// where
//     D: Deserializer<'de>,
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

// Implement Serialize and Deserialize for Bytes48
impl Serialize for Bytes48 {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        // Get the underlying array and serialize it
        BigArray::serialize(&self.0, serializer)
    }
}

impl<'de> Deserialize<'de> for Bytes48 {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        // Deserialize into a temporary array
        let arr = <[u8; 48] as BigArray<u8>>::deserialize(deserializer)?;
        // Convert the array to Bytes48
        Ok(Bytes48::from_slice(&arr).unwrap())
    }
}

impl Serialize for Bytes32 {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        Serialize::serialize(&self.0, serializer)
    }
}

impl<'de> Deserialize<'de> for Bytes32 {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        Ok(Bytes32::from_slice(&<[u8; 32] as BigArray<u8>>::deserialize(deserializer)?).unwrap())
    }
}
