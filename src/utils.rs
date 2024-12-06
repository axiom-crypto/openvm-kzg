pub(crate) fn convert_u64_le_arr_to_bytes_be(arr: &[u64]) -> [u8; 48] {
    let mut bytes = [0u8; 48];
    for (i, &num) in arr.iter().rev().enumerate() {
        bytes[i * 8..(i + 1) * 8].copy_from_slice(&num.to_be_bytes());
    }
    bytes
}

#[test]
fn test_convert_g1_affine_points() {
    let x: [u64; 6] = [
        0x5cb3_8790_fd53_0c16,
        0x7817_fc67_9976_fff5,
        0x154f_95c7_143b_a1c1,
        0xf0ae_6acd_f3d0_e747,
        0xedce_6ecc_21db_f440,
        0x1201_7741_9e0b_fb75,
    ];
    let y: [u64; 6] = [
        0xbaac_93d5_0ce7_2271,
        0x8c22_631a_7918_fd8e,
        0xdd59_5f13_5707_25ce,
        0x51ac_5829_5040_5194,
        0x0e1c_8c3f_ad00_59c0,
        0x0bbc_3efc_5008_a26a,
    ];
    let bytes = convert_u64_le_arr_to_bytes_be(&x);
    println!("{:?}", bytes);
}
