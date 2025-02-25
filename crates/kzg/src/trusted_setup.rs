use crate::{types::KzgSettings, NUM_G1_POINTS, NUM_G2_POINTS, NUM_ROOTS_OF_UNITY};

use bls12_381::{G1Affine, G2Affine, Scalar};
use core::{mem::transmute, slice};
use spin::Once;

pub fn get_roots_of_unity() -> &'static [Scalar] {
    static ROOTS_OF_UNITY: Once<&'static [Scalar]> = Once::new();
    ROOTS_OF_UNITY.call_once(|| {
        let bytes = include_bytes!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../assets/trusted_setup/roots_of_unity.bin"
        ));
        unsafe { transmute(slice::from_raw_parts(bytes.as_ptr(), NUM_ROOTS_OF_UNITY)) }
    })
}

pub fn get_g1_points() -> &'static [G1Affine] {
    static G1_POINTS: Once<&'static [G1Affine]> = Once::new();
    G1_POINTS.call_once(|| {
        let bytes = include_bytes!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../assets/trusted_setup/g1.bin"
        ));
        unsafe { transmute(slice::from_raw_parts(bytes.as_ptr(), NUM_G1_POINTS)) }
    })
}

pub fn get_g2_points() -> &'static [G2Affine] {
    static G2_POINTS: Once<&'static [G2Affine]> = Once::new();
    G2_POINTS.call_once(|| {
        let bytes = include_bytes!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../assets/trusted_setup/g2.bin"
        ));
        unsafe { transmute(slice::from_raw_parts(bytes.as_ptr(), NUM_G2_POINTS)) }
    })
}

pub fn get_kzg_settings() -> KzgSettings {
    KzgSettings {
        roots_of_unity: get_roots_of_unity(),
        g1_points: get_g1_points(),
        g2_points: get_g2_points(),
    }
}
