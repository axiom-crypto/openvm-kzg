use crate::get_kzg_settings;
use crate::{Bytes32, Bytes48, KzgError};
use bls12_381::{G1Affine, G2Affine, Scalar};
use serde::{Deserialize, Serialize};
use serde_big_array::BigArray;
#[cfg(not(target_os = "zkvm"))]
use {
    crate::{NUM_G1_POINTS, NUM_G2_POINTS, NUM_ROOTS_OF_UNITY},
    alloc::sync::Arc,
    core::hash::{Hash, Hasher},
    openvm_ecc_guest::AffinePoint,
    openvm_pairing_guest::bls12_381::{Fp, Fp2},
    spin::Once,
};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg(not(target_os = "zkvm"))]
pub struct PairingInputs {
    pub p0: AffinePoint<Fp>,
    pub p1: AffinePoint<Fp2>,
    pub q0: AffinePoint<Fp>,
    pub q1: AffinePoint<Fp2>,
}

/// Inputs to pass to the VM for KZG proof verification
/// Excludes `KzgSettings`, which is read from disk by the VM
#[derive(Clone, Deserialize, Serialize)]
pub struct KzgInputs {
    pub commitment_bytes: Bytes48,
    pub z_bytes: Bytes32,
    pub y_bytes: Bytes32,
    pub proof_bytes: Bytes48,
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

#[derive(Debug, Clone, PartialEq, Eq)]
#[repr(C, align(4))]
pub struct KzgSettings {
    pub roots_of_unity: &'static [Scalar],
    pub g1_points: &'static [G1Affine],
    pub g2_points: &'static [G2Affine],
}

#[derive(Debug, Clone, Default, Eq)]
#[cfg(not(target_os = "zkvm"))]
pub enum EnvKzgSettings {
    #[default]
    Default,
    Custom(Arc<KzgSettings>),
}

#[cfg(not(target_os = "zkvm"))]
impl PartialEq for EnvKzgSettings {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::Default, Self::Default) => true,
            (Self::Custom(a), Self::Custom(b)) => Arc::ptr_eq(a, b),
            _ => false,
        }
    }
}

#[cfg(not(target_os = "zkvm"))]
impl Hash for EnvKzgSettings {
    fn hash<H: Hasher>(&self, state: &mut H) {
        core::mem::discriminant(self).hash(state);
        match self {
            Self::Default => {}
            Self::Custom(settings) => Arc::as_ptr(settings).hash(state),
        }
    }
}

#[cfg(not(target_os = "zkvm"))]
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

impl KzgSettings {
    pub fn load_trusted_setup_file() -> Result<Self, KzgError> {
        Ok(get_kzg_settings())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg(not(target_os = "zkvm"))]
pub struct KzgSettingsOwned {
    pub roots_of_unity: [Scalar; NUM_ROOTS_OF_UNITY],
    pub g1_points: [G1Affine; NUM_G1_POINTS],
    pub g2_points: [G2Affine; NUM_G2_POINTS],
}
