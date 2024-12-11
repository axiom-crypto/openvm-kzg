use core::hash::{Hash, Hasher};

use alloc::sync::Arc;
use axvm_ecc_guest::AffinePoint;
use axvm_pairing_guest::bls12_381::{Fp, Fp2};
use bls12_381::{G1Affine, G2Affine, Scalar};
use serde::{Deserialize, Serialize};

#[cfg(not(feature = "program-test"))]
use crate::get_kzg_settings;
use crate::{Bytes32, Bytes48, KzgError, NUM_G1_POINTS, NUM_G2_POINTS, NUM_ROOTS_OF_UNITY};
use spin::Once;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PairingInputs {
    pub p0: AffinePoint<Fp>,
    pub p1: AffinePoint<Fp2>,
    pub q0: AffinePoint<Fp>,
    pub q1: AffinePoint<Fp2>,
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
