use crate::{types::KzgSettings, NUM_G1_POINTS, NUM_G2_POINTS, NUM_ROOTS_OF_UNITY};

use bls12_381::{G1Affine, G2Affine, Scalar};
use core::slice;
use spin::Once;

// Newtype to force alignment. We over-align to 16 bytes.
#[repr(align(16))]
struct Aligned<T>(T);

pub fn get_roots_of_unity() -> &'static [Scalar] {
    static ROOTS_OF_UNITY: Once<&'static [Scalar]> = Once::new();
    ROOTS_OF_UNITY.call_once(|| {
        static ALIGNED_BYTES: Aligned<&[u8]> = Aligned(include_bytes!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../assets/trusted_setup/roots_of_unity.bin"
        )));
        // The minimum alignment required is 4
        assert!(ALIGNED_BYTES.0.as_ptr() as usize % 4 == 0);
        unsafe {
            slice::from_raw_parts::<Scalar>(
                ALIGNED_BYTES.0.as_ptr() as *const Scalar,
                NUM_ROOTS_OF_UNITY,
            )
        }
    })
}

pub fn get_g1_points() -> &'static [G1Affine] {
    static G1_POINTS: Once<&'static [G1Affine]> = Once::new();
    G1_POINTS.call_once(|| {
        static ALIGNED_BYTES: Aligned<&[u8]> = Aligned(include_bytes!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../assets/trusted_setup/g1.bin"
        )));
        // The minimum alignment required is 4
        assert!(ALIGNED_BYTES.0.as_ptr() as usize % 4 == 0);
        unsafe {
            slice::from_raw_parts::<G1Affine>(
                ALIGNED_BYTES.0.as_ptr() as *const G1Affine,
                NUM_G1_POINTS,
            )
        }
    })
}

pub fn get_g2_points() -> &'static [G2Affine] {
    static G2_POINTS: Once<&'static [G2Affine]> = Once::new();
    G2_POINTS.call_once(|| {
        static ALIGNED_BYTES: Aligned<&[u8]> = Aligned(include_bytes!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../assets/trusted_setup/g2.bin"
        )));
        // The minimum alignment required is 4
        assert!(ALIGNED_BYTES.0.as_ptr() as usize % 4 == 0);
        unsafe {
            slice::from_raw_parts::<G2Affine>(
                ALIGNED_BYTES.0.as_ptr() as *const G2Affine,
                NUM_G2_POINTS,
            )
        }
    })
}

pub fn get_kzg_settings() -> KzgSettings {
    KzgSettings {
        roots_of_unity: get_roots_of_unity(),
        g1_points: get_g1_points(),
        g2_points: get_g2_points(),
    }
}
