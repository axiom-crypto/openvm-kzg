use axvm_ecc_guest::algebra::{DivUnsafe, IntMod};
use axvm_ecc_guest::AffinePoint;
use axvm_pairing_guest::bls12_381::{Fp, Fp2, Scalar};

use crate::utils::convert_u64_le_arr_to_bytes_be;
use crate::Bytes48;

pub type G1Affine = AffinePoint<Fp>;
pub type G2Affine = AffinePoint<Fp2>;

pub fn g1_affine_generator() -> G1Affine {
    G1Affine {
        x: Fp::from_be_bytes(&convert_u64_le_arr_to_bytes_be(&[
            0x5cb3_8790_fd53_0c16,
            0x7817_fc67_9976_fff5,
            0x154f_95c7_143b_a1c1,
            0xf0ae_6acd_f3d0_e747,
            0xedce_6ecc_21db_f440,
            0x1201_7741_9e0b_fb75,
        ])),
        y: Fp::from_be_bytes(&convert_u64_le_arr_to_bytes_be(&[
            0xbaac_93d5_0ce7_2271,
            0x8c22_631a_7918_fd8e,
            0xdd59_5f13_5707_25ce,
            0x51ac_5829_5040_5194,
            0x0e1c_8c3f_ad00_59c0,
            0x0bbc_3efc_5008_a26a,
        ])),
    }
}

pub fn g1_affine_from_compressed(bytes: &Bytes48) -> Option<G1Affine> {
    todo!()
}

pub fn g1_affine_to_compressed(point: &G1Affine) -> Bytes48 {
    todo!()
}

pub fn g1_affine_is_on_curve(point: &G1Affine) -> bool {
    todo!()
}

pub fn g1_affine_sub(a: &G1Affine, b: &G1Affine) -> G1Affine {
    todo!()
}

pub fn g1_affine_scalar_sub(a: &G1Affine, b: Scalar) -> G1Affine {
    todo!()
}

pub fn g1_affine_scalar_mul(a: &G1Affine, b: Scalar) -> G1Affine {
    todo!()
}

pub fn g2_affine_generator() -> G2Affine {
    G2Affine {
        x: Fp2 {
            c0: Fp::from_be_bytes(&convert_u64_le_arr_to_bytes_be(&[
                0xf5f2_8fa2_0294_0a10,
                0xb3f5_fb26_87b4_961a,
                0xa1a8_93b5_3e2a_e580,
                0x9894_999d_1a3c_aee9,
                0x6f67_b763_1863_366b,
                0x0581_9192_4350_bcd7,
            ])),
            c1: Fp::from_be_bytes(&convert_u64_le_arr_to_bytes_be(&[
                0xa5a9_c075_9e23_f606,
                0xaaa0_c59d_bccd_60c3,
                0x3bb1_7e18_e286_7806,
                0x1b1a_b6cc_8541_b367,
                0xc2b6_ed0e_f215_8547,
                0x1192_2a09_7360_edf3,
            ])),
        },
        y: Fp2 {
            c0: Fp::from_be_bytes(&convert_u64_le_arr_to_bytes_be(&[
                0x4c73_0af8_6049_4c4a,
                0x597c_fa1f_5e36_9c5a,
                0xe7e6_856c_aa0a_635a,
                0xbbef_b5e9_6e0d_495f,
                0x07d3_a975_f0ef_25a2,
                0x0083_fd8e_7e80_dae5,
            ])),
            c1: Fp::from_be_bytes(&convert_u64_le_arr_to_bytes_be(&[
                0xadc0_fc92_df64_b05d,
                0x18aa_270a_2b14_61dc,
                0x86ad_ac6a_3be4_eba0,
                0x7949_5c4e_c93d_a33a,
                0xe717_5850_a43c_caed,
                0x0b2b_c2a1_63de_1bf2,
            ])),
        },
    }
}

pub fn g2_affine_sub(a: &G2Affine, b: &G2Affine) -> G2Affine {
    todo!()
}

pub fn g2_affine_scalar_sub(a: &G2Affine, b: Scalar) -> G2Affine {
    todo!()
}

pub fn g2_affine_scalar_mul(a: &G2Affine, b: Scalar) -> G2Affine {
    todo!()
}
