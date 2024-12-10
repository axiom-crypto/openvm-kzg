use core::hash::{Hash, Hasher};

use alloc::{boxed::Box, sync::Arc, vec::Vec};
use bls12_381::{G1Affine, G2Affine, Scalar};
use serde::{ser::SerializeSeq, Deserialize, Serialize};

#[cfg(not(feature = "program-test"))]
use crate::get_kzg_settings;
use crate::{Bytes32, Bytes48, KzgError, NUM_G1_POINTS, NUM_G2_POINTS, NUM_ROOTS_OF_UNITY};
use serde_big_array::BigArray;
use spin::Once;

/// Inputs to the KZG proof verification
#[derive(Clone, Deserialize, Serialize)]
pub struct KzgInputs {
    pub commitment_bytes: Bytes48,
    pub z_bytes: Bytes32,
    pub y_bytes: Bytes32,
    pub proof_bytes: Bytes48,
    #[serde(
        serialize_with = "serialize_kzg_settings",
        deserialize_with = "deserialize_kzg_settings"
    )]
    pub kzg_settings: KzgSettingsInput,
}

/// Copy of KzgSettings struct as Vecs
#[derive(Debug, Clone)]
pub struct KzgSettingsInput {
    pub roots_of_unity: Vec<Scalar>,
    pub g1_points: Vec<G1Affine>,
    pub g2_points: Vec<G2Affine>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[repr(C, align(4))]
pub struct KzgSettings {
    pub roots_of_unity: &'static [Scalar],
    pub g1_points: &'static [G1Affine],
    pub g2_points: &'static [G2Affine],
}

#[derive(Debug, Clone, Default, Eq)]
pub enum EnvKzgSettings {
    #[default]
    Default,
    Custom(Arc<KzgSettings>),
}

impl PartialEq for EnvKzgSettings {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::Default, Self::Default) => true,
            (Self::Custom(a), Self::Custom(b)) => Arc::ptr_eq(a, b),
            _ => false,
        }
    }
}

impl Hash for EnvKzgSettings {
    fn hash<H: Hasher>(&self, state: &mut H) {
        core::mem::discriminant(self).hash(state);
        match self {
            Self::Default => {}
            Self::Custom(settings) => Arc::as_ptr(settings).hash(state),
        }
    }
}

#[cfg(not(feature = "program-test"))]
impl EnvKzgSettings {
    pub fn get(&self) -> &KzgSettings {
        match self {
            Self::Default => {
                static DEFAULT: Once<KzgSettings> = Once::new();
                DEFAULT.call_once(|| {
                    KzgSettings::load_trusted_setup_file()
                        .expect("failed to load default trusted setup")
                })
            }
            Self::Custom(settings) => settings,
        }
    }
}

#[cfg(not(feature = "program-test"))]
impl KzgSettings {
    pub fn load_trusted_setup_file() -> Result<Self, KzgError> {
        Ok(get_kzg_settings())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KzgSettingsOwned {
    pub roots_of_unity: [Scalar; NUM_ROOTS_OF_UNITY],
    pub g1_points: [G1Affine; NUM_G1_POINTS],
    pub g2_points: [G2Affine; NUM_G2_POINTS],
}

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

// # KzgSettingsInput
fn serialize_kzg_settings<S>(
    kzg_settings: &KzgSettingsInput,
    serializer: S,
) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    let mut seq = serializer.serialize_seq(Some(3))?;

    // Serialize each scalar individually
    let roots_bytes: Vec<[u8; 32]> = kzg_settings
        .roots_of_unity
        .iter()
        .map(|x| x.to_bytes())
        .collect();
    seq.serialize_element(&roots_bytes)?;

    // Serialize G1/G2 points with infinity flags
    let g1_bytes = kzg_settings
        .g1_points
        .iter()
        .map(|x| x.to_uncompressed())
        .flat_map(|arr| arr.into_iter())
        .collect::<Vec<_>>();
    seq.serialize_element(&g1_bytes)?;

    let g2_bytes = kzg_settings
        .g2_points
        .iter()
        .map(|x| x.to_uncompressed())
        .flat_map(|arr| arr.into_iter())
        .collect::<Vec<_>>();
    seq.serialize_element(&g2_bytes)?;

    seq.end()
}

fn deserialize_kzg_settings<'de, D>(deserializer: D) -> Result<KzgSettingsInput, D::Error>
where
    D: serde::Deserializer<'de>,
{
    use core::convert::TryInto;
    struct KzgVisitor;

    impl<'de> serde::de::Visitor<'de> for KzgVisitor {
        type Value = KzgSettingsInput;

        fn expecting(&self, formatter: &mut core::fmt::Formatter) -> core::fmt::Result {
            formatter.write_str("sequence of 3 elements for KzgSettings")
        }

        fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
        where
            A: serde::de::SeqAccess<'de>,
        {
            use serde::de::Error;

            // Deserialize roots_of_unity
            let roots: Vec<[u8; 32]> = seq
                .next_element()?
                .ok_or_else(|| Error::invalid_length(0, &self))?;
            let roots_of_unity = roots
                .iter()
                .map(|bytes| Scalar::from_bytes(bytes).unwrap())
                .collect();

            // Deserialize g1_points with infinity flag
            let g1_bytes: Vec<u8> = seq
                .next_element()?
                .ok_or_else(|| Error::invalid_length(1, &self))?;
            let g1_points = g1_bytes
                .chunks(96) // 96 bytes for point + 1 byte for infinity flag
                .map(|chunk| G1Affine::from_uncompressed(chunk.try_into().unwrap()).unwrap())
                .collect();

            // Deserialize g2_points with infinity flag
            let g2_bytes: Vec<u8> = seq
                .next_element()?
                .ok_or_else(|| Error::invalid_length(2, &self))?;
            let g2_points = g2_bytes
                .chunks(192) // 192 bytes for point + 1 byte for infinity flag
                .map(|chunk| G2Affine::from_uncompressed(chunk.try_into().unwrap()).unwrap())
                .collect();

            Ok(KzgSettingsInput {
                roots_of_unity,
                g1_points,
                g2_points,
            })
        }
    }

    deserializer.deserialize_seq(KzgVisitor)
}

// fn serialize_kzg_settings<S>(
//     kzg_settings: &KzgSettingsOwned,
//     serializer: S,
// ) -> Result<S::Ok, S::Error>
// where
//     S: serde::Serializer,
// {
//     let mut seq = serializer.serialize_seq(Some(3))?;

//     // Serialize roots_of_unity
//     let roots_of_unity = kzg_settings
//         .roots_of_unity
//         .iter()
//         .map(|x| x.to_bytes())
//         .collect::<Vec<[u8; 32]>>();
//     seq.serialize_element(&roots_of_unity)?;

//     // Serialize g1_points as raw bytes
//     let g1_bytes: Vec<u8> = kzg_settings
//         .g1_points
//         .iter()
//         .flat_map(|x| x.to_uncompressed().to_vec())
//         .collect();
//     seq.serialize_element(&g1_bytes)?;

//     // Serialize g2_points as raw bytes
//     let g2_bytes: Vec<u8> = kzg_settings
//         .g2_points
//         .iter()
//         .flat_map(|x| x.to_uncompressed().to_vec())
//         .collect();
//     seq.serialize_element(&g2_bytes)?;

//     seq.end()
// }

// # KzgSettingsOwned
// fn serialize_kzg_settings<S>(
//     kzg_settings: &KzgSettingsOwned,
//     serializer: S,
// ) -> Result<S::Ok, S::Error>
// where
//     S: serde::Serializer,
// {
//     let mut seq = serializer.serialize_seq(Some(3))?;

//     // Serialize each scalar individually to avoid large array serialization
//     let roots_bytes: Vec<[u8; 32]> = kzg_settings
//         .roots_of_unity
//         .iter()
//         .map(|x| x.to_bytes())
//         .collect();
//     seq.serialize_element(&roots_bytes)?;

//     // Same for G1/G2 points
//     let g1_bytes = kzg_settings
//         .g1_points
//         .iter()
//         .flat_map(|x| {
//             let mut v = x.to_uncompressed().to_vec();
//             v.push(x.is_identity().unwrap_u8());
//             v
//         })
//         .collect::<Vec<_>>();
//     seq.serialize_element(&g1_bytes)?;

//     let g2_bytes = kzg_settings
//         .g2_points
//         .iter()
//         .flat_map(|x| {
//             let mut v = x.to_uncompressed().to_vec();
//             v.push(x.is_identity().unwrap_u8());
//             v
//         })
//         .collect::<Vec<_>>();
//     seq.serialize_element(&g2_bytes)?;

//     seq.end()
// }

// fn deserialize_kzg_settings<'de, D>(deserializer: D) -> Result<KzgSettingsOwned, D::Error>
// where
//     D: serde::Deserializer<'de>,
// {
//     use core::convert::TryInto;
//     struct KzgVisitor;

//     impl<'de> serde::de::Visitor<'de> for KzgVisitor {
//         type Value = KzgSettingsOwned;

//         fn expecting(&self, formatter: &mut core::fmt::Formatter) -> core::fmt::Result {
//             formatter.write_str("sequence of 3 elements for KzgSettings")
//         }

//         fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
//         where
//             A: serde::de::SeqAccess<'de>,
//         {
//             use serde::de::Error;

//             // Deserialize roots_of_unity (unchanged)
//             let roots: Vec<[u8; 32]> = seq
//                 .next_element()?
//                 .ok_or_else(|| Error::invalid_length(0, &self))?;
//             let roots_of_unity = roots
//                 .iter()
//                 .map(|bytes| Scalar::from_bytes(bytes).unwrap())
//                 .collect::<Vec<_>>();

//             // Deserialize g1_points with infinity flag
//             let g1_bytes: Vec<u8> = seq
//                 .next_element()?
//                 .ok_or_else(|| Error::invalid_length(1, &self))?;
//             let g1_points = g1_bytes
//                 .chunks(97) // 96 bytes for point + 1 byte for infinity flag
//                 .map(|chunk| {
//                     let (point_bytes, infinity_flag) = chunk.split_at(96);
//                     let point =
//                         G1Affine::from_uncompressed(point_bytes.try_into().unwrap()).unwrap();
//                     if infinity_flag[0] == 1 {
//                         G1Affine::identity()
//                     } else {
//                         point
//                     }
//                 })
//                 .collect::<Vec<_>>();

//             // Deserialize g2_points with infinity flag
//             let g2_bytes: Vec<u8> = seq
//                 .next_element()?
//                 .ok_or_else(|| Error::invalid_length(2, &self))?;
//             let g2_points = g2_bytes
//                 .chunks(193) // 192 bytes for point + 1 byte for infinity flag
//                 .map(|chunk| {
//                     let (point_bytes, infinity_flag) = chunk.split_at(192);
//                     let point =
//                         G2Affine::from_uncompressed(point_bytes.try_into().unwrap()).unwrap();
//                     if infinity_flag[0] == 1 {
//                         G2Affine::identity()
//                     } else {
//                         point
//                     }
//                 })
//                 .collect::<Vec<_>>();

//             Ok(KzgSettingsOwned {
//                 roots_of_unity: roots_of_unity.try_into().unwrap(),
//                 g1_points: g1_points.try_into().unwrap(),
//                 g2_points: g2_points.try_into().unwrap(),
//             })
//         }
//     }

//     deserializer.deserialize_seq(KzgVisitor)
// }

// fn deserialize_kzg_settings<'de, D>(deserializer: D) -> Result<KzgSettingsOwned, D::Error>
// where
//     D: serde::Deserializer<'de>,
// {
//     use core::convert::TryInto;
//     use serde::de::SeqAccess;

//     struct KzgVisitor;

//     impl<'de> serde::de::Visitor<'de> for KzgVisitor {
//         type Value = KzgSettingsOwned;

//         fn expecting(&self, formatter: &mut core::fmt::Formatter) -> core::fmt::Result {
//             formatter.write_str("sequence of 3 elements for KzgSettings")
//         }

//         fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
//         where
//             A: SeqAccess<'de>,
//         {
//             use serde::de::Error;

//             // Deserialize roots_of_unity
//             let roots: Vec<[u8; 32]> = seq
//                 .next_element()?
//                 .ok_or_else(|| Error::invalid_length(0, &self))?;
//             let roots_of_unity = roots
//                 .iter()
//                 .map(|bytes| Scalar::from_bytes(bytes).unwrap())
//                 .collect::<Vec<_>>();

//             // Deserialize g1_points
//             let g1_bytes: Vec<u8> = seq
//                 .next_element()?
//                 .ok_or_else(|| Error::invalid_length(1, &self))?;
//             let g1_points = g1_bytes
//                 .chunks(96)
//                 .map(|chunk| G1Affine::from_uncompressed(chunk.try_into().unwrap()).unwrap())
//                 .collect::<Vec<_>>();

//             // Deserialize g2_points
//             let g2_bytes: Vec<u8> = seq
//                 .next_element()?
//                 .ok_or_else(|| Error::invalid_length(2, &self))?;
//             let g2_points = g2_bytes
//                 .chunks(192)
//                 .map(|chunk| G2Affine::from_uncompressed(chunk.try_into().unwrap()).unwrap())
//                 .collect::<Vec<_>>();

//             Ok(KzgSettingsOwned {
//                 roots_of_unity,
//                 g1_points,
//                 g2_points,
//             })
//         }
//     }

//     deserializer.deserialize_seq(KzgVisitor)
// }

// fn serialize_kzg_settings<S>(kzg_settings: &KzgSettings, serializer: S) -> Result<S::Ok, S::Error>
// where
//     S: serde::Serializer,
// {
//     // let mut seq = serializer.serialize_seq(Some(3))?;

//     let roots_of_unity = kzg_settings
//         .roots_of_unity
//         .iter()
//         .flat_map(|x| x.to_bytes())
//         .collect::<Vec<_>>();
//     // seq.serialize_element(&roots_of_unity).unwrap();
//     serializer.serialize_bytes(&roots_of_unity).unwrap();

//     let g1_points = kzg_settings
//         .g1_points
//         .iter()
//         .flat_map(|x| x.to_uncompressed())
//         .collect::<Vec<_>>();
//     // Serialize the length first
//     // seq.serialize_element(&g1_points.len())?;
//     // // Then serialize each array individually using BigArray
//     // for point in g1_points {
//     BigArray::serialize(&g1_points, serializer)?;
//     // }

//     let g2_points = kzg_settings
//         .g2_points
//         .iter()
//         .map(|x| x.to_uncompressed())
//         .collect::<Vec<_>>();
//     seq.serialize_element(&g2_points).unwrap();

//     seq.end()
// }

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
