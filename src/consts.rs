pub const BYTES_PER_G1_POINT: usize = 48;
pub const BYTES_PER_G2_POINT: usize = 96;
pub const BYTES_PER_FIELD_ELEMENT: usize = 32;
pub const NUM_G1_POINTS: usize = 4096;
pub const NUM_G2_POINTS: usize = 65;
pub const NUM_ROOTS_OF_UNITY: usize = 4096;
pub const NUM_FIELD_ELEMENTS_PER_BLOB: usize = 4096;
pub const BYTES_PER_BLOB: usize = NUM_FIELD_ELEMENTS_PER_BLOB * BYTES_PER_FIELD_ELEMENT;
pub const BYTES_PER_COMMITMENT: usize = 48;
pub const BYTES_PER_PROOF: usize = 48;
pub const DOMAIN_STR_LENGTH: usize = 16;
pub const CHALLENGE_INPUT_SIZE: usize =
    DOMAIN_STR_LENGTH + 16 + BYTES_PER_BLOB + BYTES_PER_COMMITMENT;
pub const FIAT_SHAMIR_PROTOCOL_DOMAIN: &str = "FSBLOBVERIFY_V1_";
pub const RANDOM_CHALLENGE_KZG_BATCH_DOMAIN: &str = "RCKZGBATCH___V1_";

pub const SCALE2_ROOT_OF_UNITY: [[u64; 4]; 32] = [
    [
        0x0000000000000001,
        0x0000000000000000,
        0x0000000000000000,
        0x0000000000000000,
    ],
    [
        0xffffffff00000000,
        0x53bda402fffe5bfe,
        0x3339d80809a1d805,
        0x73eda753299d7d48,
    ],
    [
        0x0001000000000000,
        0xec03000276030000,
        0x8d51ccce760304d0,
        0x0000000000000000,
    ],
    [
        0x7228fd3397743f7a,
        0xb38b21c28713b700,
        0x8c0625cd70d77ce2,
        0x345766f603fa66e7,
    ],
    [
        0x53ea61d87742bcce,
        0x17beb312f20b6f76,
        0xdd1c0af834cec32c,
        0x20b1ce9140267af9,
    ],
    [
        0x360c60997369df4e,
        0xbf6e88fb4c38fb8a,
        0xb4bcd40e22f55448,
        0x50e0903a157988ba,
    ],
    [
        0x8140d032f0a9ee53,
        0x2d967f4be2f95155,
        0x14a1e27164d8fdbd,
        0x45af6345ec055e4d,
    ],
    [
        0x5130c2c1660125be,
        0x98d0caac87f5713c,
        0xb7c68b4d7fdd60d0,
        0x6898111413588742,
    ],
    [
        0x4935bd2f817f694b,
        0x0a0865a899e8deff,
        0x6b368121ac0cf4ad,
        0x4f9b4098e2e9f12e,
    ],
    [
        0x4541b8ff2ee0434e,
        0xd697168a3a6000fe,
        0x39feec240d80689f,
        0x095166525526a654,
    ],
    [
        0x3c28d666a5c2d854,
        0xea437f9626fc085e,
        0x8f4de02c0f776af3,
        0x325db5c3debf77a1,
    ],
    [
        0x4a838b5d59cd79e5,
        0x55ea6811be9c622d,
        0x09f1ca610a08f166,
        0x6d031f1b5c49c834,
    ],
    [
        0xe206da11a5d36306,
        0x0ad1347b378fbf96,
        0xfc3e8acfe0f8245f,
        0x564c0a11a0f704f4,
    ],
    [
        0x6fdd00bfc78c8967,
        0x146b58bc434906ac,
        0x2ccddea2972e89ed,
        0x485d512737b1da3d,
    ],
    [
        0x034d2ff22a5ad9e1,
        0xae4622f6a9152435,
        0xdc86b01c0d477fa6,
        0x56624634b500a166,
    ],
    [
        0xfbd047e11279bb6e,
        0xc8d5f51db3f32699,
        0x483405417a0cbe39,
        0x3291357ee558b50d,
    ],
    [
        0xd7118f85cd96b8ad,
        0x67a665ae1fcadc91,
        0x88f39a78f1aeb578,
        0x2155379d12180caa,
    ],
    [
        0x08692405f3b70f10,
        0xcd7f2bd6d0711b7d,
        0x473a2eef772c33d6,
        0x224262332d8acbf4,
    ],
    [
        0x6f421a7d8ef674fb,
        0xbb97a3bf30ce40fd,
        0x652f717ae1c34bb0,
        0x2d3056a530794f01,
    ],
    [
        0x194e8c62ecb38d9d,
        0xad8e16e84419c750,
        0xdf625e80d0adef90,
        0x520e587a724a6955,
    ],
    [
        0xfece7e0e39898d4b,
        0x2f69e02d265e09d9,
        0xa57a6e07cb98de4a,
        0x03e1c54bcb947035,
    ],
    [
        0xcd3979122d3ea03a,
        0x46b3105f04db5844,
        0xc70d0874b0691d4e,
        0x47c8b5817018af4f,
    ],
    [
        0xc6e7a6ffb08e3363,
        0xe08fec7c86389bee,
        0xf2d38f10fbb8d1bb,
        0x0abe6a5e5abcaa32,
    ],
    [
        0x5616c57de0ec9eae,
        0xc631ffb2585a72db,
        0x5121af06a3b51e3c,
        0x73560252aa0655b2,
    ],
    [
        0x92cf4deb77bd779c,
        0x72cf6a8029b7d7bc,
        0x6e0bcd91ee762730,
        0x291cf6d68823e687,
    ],
    [
        0xce32ef844e11a51e,
        0xc0ba12bb3da64ca5,
        0x0454dc1edc61a1a3,
        0x019fe632fd328739,
    ],
    [
        0x531a11a0d2d75182,
        0x02c8118402867ddc,
        0x116168bffbedc11d,
        0x0a0a77a3b1980c0d,
    ],
    [
        0xe2d0a7869f0319ed,
        0xb94f1101b1d7a628,
        0xece8ea224f31d25d,
        0x23397a9300f8f98b,
    ],
    [
        0xd7b688830a4f2089,
        0x6558e9e3f6ac7b41,
        0x99e276b571905a7d,
        0x52dd465e2f094256,
    ],
    [
        0x474650359d8e211b,
        0x84d37b826214abc6,
        0x8da40c1ef2bb4598,
        0x0c83ea7744bf1bee,
    ],
    [
        0x694341f608c9dd56,
        0xed3a181fabb30adc,
        0x1339a815da8b398f,
        0x2c6d4e4511657e1e,
    ],
    [
        0x63e7cb4906ffc93f,
        0xf070bb00e28a193d,
        0xad1715b02e5713b5,
        0x4b5371495990693f,
    ],
];

/// Constant representing the modulus
/// q = 0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001
pub const MODULUS: [u64; 4] = [
    0xffff_ffff_0000_0001,
    0x53bd_a402_fffe_5bfe,
    0x3339_d808_09a1_d805,
    0x73ed_a753_299d_7d48,
];

// Tests
pub const VERIFY_KZG_PROOF_TESTS: [(&str, &str); 122] = [
    (
        "verify_kzg_proof_case_correct_proof_02e696ada7d4631d",
        include_str!("../tests/verify_kzg_proof/verify_kzg_proof_case_correct_proof_02e696ada7d4631d/data.yaml"),
    ),
    (
        "verify_kzg_proof_case_correct_proof_05c1f3685f3393f0",
        include_str!("../tests/verify_kzg_proof/verify_kzg_proof_case_correct_proof_05c1f3685f3393f0/data.yaml"),
    ),
    (
        "verify_kzg_proof_case_correct_proof_08f9e2f1cb3d39db",
        include_str!("../tests/verify_kzg_proof/verify_kzg_proof_case_correct_proof_08f9e2f1cb3d39db/data.yaml"),
    ),
    (
        "verify_kzg_proof_case_correct_proof_0cf79b17cb5f4ea2",
        include_str!("../tests/verify_kzg_proof/verify_kzg_proof_case_correct_proof_0cf79b17cb5f4ea2/data.yaml"),
    ),
    (
        "verify_kzg_proof_case_correct_proof_177b58dc7a46b08f",
        include_str!("../tests/verify_kzg_proof/verify_kzg_proof_case_correct_proof_177b58dc7a46b08f/data.yaml"),
    ),
    (
        "verify_kzg_proof_case_correct_proof_1ce8e4f69d5df899",
        include_str!("../tests/verify_kzg_proof/verify_kzg_proof_case_correct_proof_1ce8e4f69d5df899/data.yaml"),
    ),
    (
        "verify_kzg_proof_case_correct_proof_26b753dec0560daa",
        include_str!("../tests/verify_kzg_proof/verify_kzg_proof_case_correct_proof_26b753dec0560daa/data.yaml"),
    ),
    (
        "verify_kzg_proof_case_correct_proof_2b76dc9e3abf42f3",
        include_str!("../tests/verify_kzg_proof/verify_kzg_proof_case_correct_proof_2b76dc9e3abf42f3/data.yaml"),
    ),
    (
        "verify_kzg_proof_case_correct_proof_31ebd010e6098750",
        include_str!("../tests/verify_kzg_proof/verify_kzg_proof_case_correct_proof_31ebd010e6098750/data.yaml"),
    ),
    (
        "verify_kzg_proof_case_correct_proof_3208425794224c3f",
        include_str!("../tests/verify_kzg_proof/verify_kzg_proof_case_correct_proof_3208425794224c3f/data.yaml"),
    ),
    (
        "verify_kzg_proof_case_correct_proof_36817bfd67de97a8",
        include_str!("../tests/verify_kzg_proof/verify_kzg_proof_case_correct_proof_36817bfd67de97a8/data.yaml"),
    ),
    (
        "verify_kzg_proof_case_correct_proof_392169c16a2e5ef6",
        include_str!("../tests/verify_kzg_proof/verify_kzg_proof_case_correct_proof_392169c16a2e5ef6/data.yaml"),
    ),
    (
        "verify_kzg_proof_case_correct_proof_395cf6d697d1a743",
        include_str!("../tests/verify_kzg_proof/verify_kzg_proof_case_correct_proof_395cf6d697d1a743/data.yaml"),
    ),
    (
        "verify_kzg_proof_case_correct_proof_3ac8dc31e9aa6a70",
        include_str!("../tests/verify_kzg_proof/verify_kzg_proof_case_correct_proof_3ac8dc31e9aa6a70/data.yaml"),
    ),
    (
        "verify_kzg_proof_case_correct_proof_3c1e8b38219e3e12",
        include_str!("../tests/verify_kzg_proof/verify_kzg_proof_case_correct_proof_3c1e8b38219e3e12/data.yaml"),
    ),
    (
        "verify_kzg_proof_case_correct_proof_3c87ec986c2656c2",
        include_str!("../tests/verify_kzg_proof/verify_kzg_proof_case_correct_proof_3c87ec986c2656c2/data.yaml"),
    ),
    (
        "verify_kzg_proof_case_correct_proof_3cd183d0bab85fb7",
        include_str!("../tests/verify_kzg_proof/verify_kzg_proof_case_correct_proof_3cd183d0bab85fb7/data.yaml"),
    ),
    (
        "verify_kzg_proof_case_correct_proof_420f2a187ce77035",
        include_str!("../tests/verify_kzg_proof/verify_kzg_proof_case_correct_proof_420f2a187ce77035/data.yaml"),
    ),
    (
        "verify_kzg_proof_case_correct_proof_444b73ff54a19b44",
        include_str!("../tests/verify_kzg_proof/verify_kzg_proof_case_correct_proof_444b73ff54a19b44/data.yaml"),
    ),
    (
        "verify_kzg_proof_case_correct_proof_53a9bdf4f75196da",
        include_str!("../tests/verify_kzg_proof/verify_kzg_proof_case_correct_proof_53a9bdf4f75196da/data.yaml"),
    ),
    (
        "verify_kzg_proof_case_correct_proof_585454b31673dd62",
        include_str!("../tests/verify_kzg_proof/verify_kzg_proof_case_correct_proof_585454b31673dd62/data.yaml"),
    ),
    (
        "verify_kzg_proof_case_correct_proof_7db4f140a955dd1a",
        include_str!("../tests/verify_kzg_proof/verify_kzg_proof_case_correct_proof_7db4f140a955dd1a/data.yaml"),
    ),
    (
        "verify_kzg_proof_case_correct_proof_83e53423a2dd93fe",
        include_str!("../tests/verify_kzg_proof/verify_kzg_proof_case_correct_proof_83e53423a2dd93fe/data.yaml"),
    ),
    (
        "verify_kzg_proof_case_correct_proof_9b24f8997145435c",
        include_str!("../tests/verify_kzg_proof/verify_kzg_proof_case_correct_proof_9b24f8997145435c/data.yaml"),
    ),
    (
        "verify_kzg_proof_case_correct_proof_9b754afb690c47e1",
        include_str!("../tests/verify_kzg_proof/verify_kzg_proof_case_correct_proof_9b754afb690c47e1/data.yaml"),
    ),
    (
        "verify_kzg_proof_case_correct_proof_a0be66af9a97ea52",
        include_str!("../tests/verify_kzg_proof/verify_kzg_proof_case_correct_proof_a0be66af9a97ea52/data.yaml"),
    ),
    (
        "verify_kzg_proof_case_correct_proof_af669445747d2585",
        include_str!("../tests/verify_kzg_proof/verify_kzg_proof_case_correct_proof_af669445747d2585/data.yaml"),
    ),
    (
        "verify_kzg_proof_case_correct_proof_af8b75f664ed7d43",
        include_str!("../tests/verify_kzg_proof/verify_kzg_proof_case_correct_proof_af8b75f664ed7d43/data.yaml"),
    ),
    (
        "verify_kzg_proof_case_correct_proof_b6cb6698327d9835",
        include_str!("../tests/verify_kzg_proof/verify_kzg_proof_case_correct_proof_b6cb6698327d9835/data.yaml"),
    ),
    (
        "verify_kzg_proof_case_correct_proof_b6ec3736f9ff2c62",
        include_str!("../tests/verify_kzg_proof/verify_kzg_proof_case_correct_proof_b6ec3736f9ff2c62/data.yaml"),
    ),
    (
        "verify_kzg_proof_case_correct_proof_becf2e1641bbd4e6",
        include_str!("../tests/verify_kzg_proof/verify_kzg_proof_case_correct_proof_becf2e1641bbd4e6/data.yaml"),
    ),
    (
        "verify_kzg_proof_case_correct_proof_c3d4322ec17fe7cd",
        include_str!("../tests/verify_kzg_proof/verify_kzg_proof_case_correct_proof_c3d4322ec17fe7cd/data.yaml"),
    ),
    (
        "verify_kzg_proof_case_correct_proof_c5e1490d672d026d",
        include_str!("../tests/verify_kzg_proof/verify_kzg_proof_case_correct_proof_c5e1490d672d026d/data.yaml"),
    ),
    (
        "verify_kzg_proof_case_correct_proof_cae5d3491190b777",
        include_str!("../tests/verify_kzg_proof/verify_kzg_proof_case_correct_proof_cae5d3491190b777/data.yaml"),
    ),
    (
        "verify_kzg_proof_case_correct_proof_d0992bc0387790a4",
        include_str!("../tests/verify_kzg_proof/verify_kzg_proof_case_correct_proof_d0992bc0387790a4/data.yaml"),
    ),
    (
        "verify_kzg_proof_case_correct_proof_d736268229bd87ec",
        include_str!("../tests/verify_kzg_proof/verify_kzg_proof_case_correct_proof_d736268229bd87ec/data.yaml"),
    ),
    (
        "verify_kzg_proof_case_correct_proof_e68d7111a2364a49",
        include_str!("../tests/verify_kzg_proof/verify_kzg_proof_case_correct_proof_e68d7111a2364a49/data.yaml"),
    ),
    (
        "verify_kzg_proof_case_correct_proof_ed6b180ec759bcf6",
        include_str!("../tests/verify_kzg_proof/verify_kzg_proof_case_correct_proof_ed6b180ec759bcf6/data.yaml"),
    ),
    (
        "verify_kzg_proof_case_correct_proof_f0ed3dc11cdeb130",
        include_str!("../tests/verify_kzg_proof/verify_kzg_proof_case_correct_proof_f0ed3dc11cdeb130/data.yaml"),
    ),
    (
        "verify_kzg_proof_case_correct_proof_f47eb9fc139f6bfd",
        include_str!("../tests/verify_kzg_proof/verify_kzg_proof_case_correct_proof_f47eb9fc139f6bfd/data.yaml"),
    ),
    (
        "verify_kzg_proof_case_correct_proof_f7f44e1e864aa967",
        include_str!("../tests/verify_kzg_proof/verify_kzg_proof_case_correct_proof_f7f44e1e864aa967/data.yaml"),
    ),
    (
        "verify_kzg_proof_case_correct_proof_ffa6e97b97146517",
        include_str!("../tests/verify_kzg_proof/verify_kzg_proof_case_correct_proof_ffa6e97b97146517/data.yaml"),
    ),
    (
        "verify_kzg_proof_case_correct_proof_point_at_infinity_for_twos_poly_05c1f3685f3393f0",
        include_str!("../tests/verify_kzg_proof/verify_kzg_proof_case_correct_proof_point_at_infinity_for_twos_poly_05c1f3685f3393f0/data.yaml"),
    ),
    (
        "verify_kzg_proof_case_correct_proof_point_at_infinity_for_twos_poly_177b58dc7a46b08f",
        include_str!("../tests/verify_kzg_proof/verify_kzg_proof_case_correct_proof_point_at_infinity_for_twos_poly_177b58dc7a46b08f/data.yaml"),
    ),
    (
        "verify_kzg_proof_case_correct_proof_point_at_infinity_for_twos_poly_2b76dc9e3abf42f3",
        include_str!("../tests/verify_kzg_proof/verify_kzg_proof_case_correct_proof_point_at_infinity_for_twos_poly_2b76dc9e3abf42f3/data.yaml"),
    ),
    (
        "verify_kzg_proof_case_correct_proof_point_at_infinity_for_twos_poly_395cf6d697d1a743",
        include_str!("../tests/verify_kzg_proof/verify_kzg_proof_case_correct_proof_point_at_infinity_for_twos_poly_395cf6d697d1a743/data.yaml"),
    ),
    (
        "verify_kzg_proof_case_correct_proof_point_at_infinity_for_twos_poly_585454b31673dd62",
        include_str!("../tests/verify_kzg_proof/verify_kzg_proof_case_correct_proof_point_at_infinity_for_twos_poly_585454b31673dd62/data.yaml"),
    ),
    (
        "verify_kzg_proof_case_correct_proof_point_at_infinity_for_twos_poly_a0be66af9a97ea52",
        include_str!("../tests/verify_kzg_proof/verify_kzg_proof_case_correct_proof_point_at_infinity_for_twos_poly_a0be66af9a97ea52/data.yaml"),
    ),
    (
        "verify_kzg_proof_case_correct_proof_point_at_infinity_for_zero_poly_02e696ada7d4631d",
        include_str!("../tests/verify_kzg_proof/verify_kzg_proof_case_correct_proof_point_at_infinity_for_zero_poly_02e696ada7d4631d/data.yaml"),
    ),
    (
        "verify_kzg_proof_case_correct_proof_point_at_infinity_for_zero_poly_0cf79b17cb5f4ea2",
        include_str!("../tests/verify_kzg_proof/verify_kzg_proof_case_correct_proof_point_at_infinity_for_zero_poly_0cf79b17cb5f4ea2/data.yaml"),
    ),
    (
        "verify_kzg_proof_case_correct_proof_point_at_infinity_for_zero_poly_3208425794224c3f",
        include_str!("../tests/verify_kzg_proof/verify_kzg_proof_case_correct_proof_point_at_infinity_for_zero_poly_3208425794224c3f/data.yaml"),
    ),
    (
        "verify_kzg_proof_case_correct_proof_point_at_infinity_for_zero_poly_3ac8dc31e9aa6a70",
        include_str!("../tests/verify_kzg_proof/verify_kzg_proof_case_correct_proof_point_at_infinity_for_zero_poly_3ac8dc31e9aa6a70/data.yaml"),
    ),
    (
        "verify_kzg_proof_case_correct_proof_point_at_infinity_for_zero_poly_c3d4322ec17fe7cd",
        include_str!("../tests/verify_kzg_proof/verify_kzg_proof_case_correct_proof_point_at_infinity_for_zero_poly_c3d4322ec17fe7cd/data.yaml"),
    ),
    (
        "verify_kzg_proof_case_correct_proof_point_at_infinity_for_zero_poly_ffa6e97b97146517",
        include_str!("../tests/verify_kzg_proof/verify_kzg_proof_case_correct_proof_point_at_infinity_for_zero_poly_ffa6e97b97146517/data.yaml"),
    ),
    (
        "verify_kzg_proof_case_incorrect_proof_02e696ada7d4631d",
        include_str!("../tests/verify_kzg_proof/verify_kzg_proof_case_incorrect_proof_02e696ada7d4631d/data.yaml"),
    ),
    (
        "verify_kzg_proof_case_incorrect_proof_05c1f3685f3393f0",
        include_str!("../tests/verify_kzg_proof/verify_kzg_proof_case_incorrect_proof_05c1f3685f3393f0/data.yaml"),
    ),
    (
        "verify_kzg_proof_case_incorrect_proof_08f9e2f1cb3d39db",
        include_str!("../tests/verify_kzg_proof/verify_kzg_proof_case_incorrect_proof_08f9e2f1cb3d39db/data.yaml"),
    ),
    (
        "verify_kzg_proof_case_incorrect_proof_0cf79b17cb5f4ea2",
        include_str!("../tests/verify_kzg_proof/verify_kzg_proof_case_incorrect_proof_0cf79b17cb5f4ea2/data.yaml"),
    ),
    (
        "verify_kzg_proof_case_incorrect_proof_177b58dc7a46b08f",
        include_str!("../tests/verify_kzg_proof/verify_kzg_proof_case_incorrect_proof_177b58dc7a46b08f/data.yaml"),
    ),
    (
        "verify_kzg_proof_case_incorrect_proof_1ce8e4f69d5df899",
        include_str!("../tests/verify_kzg_proof/verify_kzg_proof_case_incorrect_proof_1ce8e4f69d5df899/data.yaml"),
    ),
    (
        "verify_kzg_proof_case_incorrect_proof_26b753dec0560daa",
        include_str!("../tests/verify_kzg_proof/verify_kzg_proof_case_incorrect_proof_26b753dec0560daa/data.yaml"),
    ),
    (
        "verify_kzg_proof_case_incorrect_proof_2b76dc9e3abf42f3",
        include_str!("../tests/verify_kzg_proof/verify_kzg_proof_case_incorrect_proof_2b76dc9e3abf42f3/data.yaml"),
    ),
    (
        "verify_kzg_proof_case_incorrect_proof_31ebd010e6098750",
        include_str!("../tests/verify_kzg_proof/verify_kzg_proof_case_incorrect_proof_31ebd010e6098750/data.yaml"),
    ),
    (
        "verify_kzg_proof_case_incorrect_proof_3208425794224c3f",
        include_str!("../tests/verify_kzg_proof/verify_kzg_proof_case_incorrect_proof_3208425794224c3f/data.yaml"),
    ),
    (
        "verify_kzg_proof_case_incorrect_proof_36817bfd67de97a8",
        include_str!("../tests/verify_kzg_proof/verify_kzg_proof_case_incorrect_proof_36817bfd67de97a8/data.yaml"),
    ),
    (
        "verify_kzg_proof_case_incorrect_proof_392169c16a2e5ef6",
        include_str!("../tests/verify_kzg_proof/verify_kzg_proof_case_incorrect_proof_392169c16a2e5ef6/data.yaml"),
    ),
    (
        "verify_kzg_proof_case_incorrect_proof_395cf6d697d1a743",
        include_str!("../tests/verify_kzg_proof/verify_kzg_proof_case_incorrect_proof_395cf6d697d1a743/data.yaml"),
    ),
    (
        "verify_kzg_proof_case_incorrect_proof_3ac8dc31e9aa6a70",
        include_str!("../tests/verify_kzg_proof/verify_kzg_proof_case_incorrect_proof_3ac8dc31e9aa6a70/data.yaml"),
    ),
    (
        "verify_kzg_proof_case_incorrect_proof_3c1e8b38219e3e12",
        include_str!("../tests/verify_kzg_proof/verify_kzg_proof_case_incorrect_proof_3c1e8b38219e3e12/data.yaml"),
    ),
    (
        "verify_kzg_proof_case_incorrect_proof_3c87ec986c2656c2",
        include_str!("../tests/verify_kzg_proof/verify_kzg_proof_case_incorrect_proof_3c87ec986c2656c2/data.yaml"),
    ),
    (
        "verify_kzg_proof_case_incorrect_proof_3cd183d0bab85fb7",
        include_str!("../tests/verify_kzg_proof/verify_kzg_proof_case_incorrect_proof_3cd183d0bab85fb7/data.yaml"),
    ),
    (
        "verify_kzg_proof_case_incorrect_proof_420f2a187ce77035",
        include_str!("../tests/verify_kzg_proof/verify_kzg_proof_case_incorrect_proof_420f2a187ce77035/data.yaml"),
    ),
    (
        "verify_kzg_proof_case_incorrect_proof_444b73ff54a19b44",
        include_str!("../tests/verify_kzg_proof/verify_kzg_proof_case_incorrect_proof_444b73ff54a19b44/data.yaml"),
    ),
    (
        "verify_kzg_proof_case_incorrect_proof_53a9bdf4f75196da",
        include_str!("../tests/verify_kzg_proof/verify_kzg_proof_case_incorrect_proof_53a9bdf4f75196da/data.yaml"),
    ),
    (
        "verify_kzg_proof_case_incorrect_proof_585454b31673dd62",
        include_str!("../tests/verify_kzg_proof/verify_kzg_proof_case_incorrect_proof_585454b31673dd62/data.yaml"),
    ),
    (
        "verify_kzg_proof_case_incorrect_proof_7db4f140a955dd1a",
        include_str!("../tests/verify_kzg_proof/verify_kzg_proof_case_incorrect_proof_7db4f140a955dd1a/data.yaml"),
    ),
    (
        "verify_kzg_proof_case_incorrect_proof_83e53423a2dd93fe",
        include_str!("../tests/verify_kzg_proof/verify_kzg_proof_case_incorrect_proof_83e53423a2dd93fe/data.yaml"),
    ),
    (
        "verify_kzg_proof_case_incorrect_proof_9b24f8997145435c",
        include_str!("../tests/verify_kzg_proof/verify_kzg_proof_case_incorrect_proof_9b24f8997145435c/data.yaml"),
    ),
    (
        "verify_kzg_proof_case_incorrect_proof_9b754afb690c47e1",
        include_str!("../tests/verify_kzg_proof/verify_kzg_proof_case_incorrect_proof_9b754afb690c47e1/data.yaml"),
    ),
    (
        "verify_kzg_proof_case_incorrect_proof_a0be66af9a97ea52",
        include_str!("../tests/verify_kzg_proof/verify_kzg_proof_case_incorrect_proof_a0be66af9a97ea52/data.yaml"),
    ),
    (
        "verify_kzg_proof_case_incorrect_proof_af669445747d2585",
        include_str!("../tests/verify_kzg_proof/verify_kzg_proof_case_incorrect_proof_af669445747d2585/data.yaml"),
    ),
    (
        "verify_kzg_proof_case_incorrect_proof_af8b75f664ed7d43",
        include_str!("../tests/verify_kzg_proof/verify_kzg_proof_case_incorrect_proof_af8b75f664ed7d43/data.yaml"),
    ),
    (
        "verify_kzg_proof_case_incorrect_proof_b6cb6698327d9835",
        include_str!("../tests/verify_kzg_proof/verify_kzg_proof_case_incorrect_proof_b6cb6698327d9835/data.yaml"),
    ),
    (
        "verify_kzg_proof_case_incorrect_proof_b6ec3736f9ff2c62",
        include_str!("../tests/verify_kzg_proof/verify_kzg_proof_case_incorrect_proof_b6ec3736f9ff2c62/data.yaml"),
    ),
    (
        "verify_kzg_proof_case_incorrect_proof_becf2e1641bbd4e6",
        include_str!("../tests/verify_kzg_proof/verify_kzg_proof_case_incorrect_proof_becf2e1641bbd4e6/data.yaml"),
    ),
    (
        "verify_kzg_proof_case_incorrect_proof_c3d4322ec17fe7cd",
        include_str!("../tests/verify_kzg_proof/verify_kzg_proof_case_incorrect_proof_c3d4322ec17fe7cd/data.yaml"),
    ),
    (
        "verify_kzg_proof_case_incorrect_proof_c5e1490d672d026d",
        include_str!("../tests/verify_kzg_proof/verify_kzg_proof_case_incorrect_proof_c5e1490d672d026d/data.yaml"),
    ),
    (
        "verify_kzg_proof_case_incorrect_proof_cae5d3491190b777",
        include_str!("../tests/verify_kzg_proof/verify_kzg_proof_case_incorrect_proof_cae5d3491190b777/data.yaml"),
    ),
    (
        "verify_kzg_proof_case_incorrect_proof_d0992bc0387790a4",
        include_str!("../tests/verify_kzg_proof/verify_kzg_proof_case_incorrect_proof_d0992bc0387790a4/data.yaml"),
    ),
    (
        "verify_kzg_proof_case_incorrect_proof_d736268229bd87ec",
        include_str!("../tests/verify_kzg_proof/verify_kzg_proof_case_incorrect_proof_d736268229bd87ec/data.yaml"),
    ),
    (
        "verify_kzg_proof_case_incorrect_proof_e68d7111a2364a49",
        include_str!("../tests/verify_kzg_proof/verify_kzg_proof_case_incorrect_proof_e68d7111a2364a49/data.yaml"),
    ),
    (
        "verify_kzg_proof_case_incorrect_proof_ed6b180ec759bcf6",
        include_str!("../tests/verify_kzg_proof/verify_kzg_proof_case_incorrect_proof_ed6b180ec759bcf6/data.yaml"),
    ),
    (
        "verify_kzg_proof_case_incorrect_proof_f0ed3dc11cdeb130",
        include_str!("../tests/verify_kzg_proof/verify_kzg_proof_case_incorrect_proof_f0ed3dc11cdeb130/data.yaml"),
    ),
    (
        "verify_kzg_proof_case_incorrect_proof_f47eb9fc139f6bfd",
        include_str!("../tests/verify_kzg_proof/verify_kzg_proof_case_incorrect_proof_f47eb9fc139f6bfd/data.yaml"),
    ),
    (
        "verify_kzg_proof_case_incorrect_proof_f7f44e1e864aa967",
        include_str!("../tests/verify_kzg_proof/verify_kzg_proof_case_incorrect_proof_f7f44e1e864aa967/data.yaml"),
    ),
    (
        "verify_kzg_proof_case_incorrect_proof_ffa6e97b97146517",
        include_str!("../tests/verify_kzg_proof/verify_kzg_proof_case_incorrect_proof_ffa6e97b97146517/data.yaml"),
    ),
    (
        "verify_kzg_proof_case_incorrect_proof_point_at_infinity_392169c16a2e5ef6",
        include_str!("../tests/verify_kzg_proof/verify_kzg_proof_case_incorrect_proof_point_at_infinity_392169c16a2e5ef6/data.yaml"),
    ),
    (
        "verify_kzg_proof_case_incorrect_proof_point_at_infinity_3c1e8b38219e3e12",
        include_str!("../tests/verify_kzg_proof/verify_kzg_proof_case_incorrect_proof_point_at_infinity_3c1e8b38219e3e12/data.yaml"),
    ),
    (
        "verify_kzg_proof_case_incorrect_proof_point_at_infinity_3c87ec986c2656c2",
        include_str!("../tests/verify_kzg_proof/verify_kzg_proof_case_incorrect_proof_point_at_infinity_3c87ec986c2656c2/data.yaml"),
    ),
    (
        "verify_kzg_proof_case_incorrect_proof_point_at_infinity_420f2a187ce77035",
        include_str!("../tests/verify_kzg_proof/verify_kzg_proof_case_incorrect_proof_point_at_infinity_420f2a187ce77035/data.yaml"),
    ),
    (
        "verify_kzg_proof_case_incorrect_proof_point_at_infinity_83e53423a2dd93fe",
        include_str!("../tests/verify_kzg_proof/verify_kzg_proof_case_incorrect_proof_point_at_infinity_83e53423a2dd93fe/data.yaml"),
    ),
    (
        "verify_kzg_proof_case_incorrect_proof_point_at_infinity_ed6b180ec759bcf6",
        include_str!("../tests/verify_kzg_proof/verify_kzg_proof_case_incorrect_proof_point_at_infinity_ed6b180ec759bcf6/data.yaml"),
    ),
    (
        "verify_kzg_proof_case_invalid_commitment_1b44e341d56c757d",
        include_str!("../tests/verify_kzg_proof/verify_kzg_proof_case_invalid_commitment_1b44e341d56c757d/data.yaml"),
    ),
    (
        "verify_kzg_proof_case_invalid_commitment_32afa9561a4b3b91",
        include_str!("../tests/verify_kzg_proof/verify_kzg_proof_case_invalid_commitment_32afa9561a4b3b91/data.yaml"),
    ),
    (
        "verify_kzg_proof_case_invalid_commitment_3e55802a5ed3c757",
        include_str!("../tests/verify_kzg_proof/verify_kzg_proof_case_invalid_commitment_3e55802a5ed3c757/data.yaml"),
    ),
    (
        "verify_kzg_proof_case_invalid_commitment_e9d3e9ec16fbc15f",
        include_str!("../tests/verify_kzg_proof/verify_kzg_proof_case_invalid_commitment_e9d3e9ec16fbc15f/data.yaml"),
    ),
    (
        "verify_kzg_proof_case_invalid_proof_1b44e341d56c757d",
        include_str!("../tests/verify_kzg_proof/verify_kzg_proof_case_invalid_proof_1b44e341d56c757d/data.yaml"),
    ),
    (
        "verify_kzg_proof_case_invalid_proof_32afa9561a4b3b91",
        include_str!("../tests/verify_kzg_proof/verify_kzg_proof_case_invalid_proof_32afa9561a4b3b91/data.yaml"),
    ),
    (
        "verify_kzg_proof_case_invalid_proof_3e55802a5ed3c757",
        include_str!("../tests/verify_kzg_proof/verify_kzg_proof_case_invalid_proof_3e55802a5ed3c757/data.yaml"),
    ),
    (
        "verify_kzg_proof_case_invalid_proof_e9d3e9ec16fbc15f",
        include_str!("../tests/verify_kzg_proof/verify_kzg_proof_case_invalid_proof_e9d3e9ec16fbc15f/data.yaml"),
    ),
    (
        "verify_kzg_proof_case_invalid_y_35d08d612aad2197",
        include_str!("../tests/verify_kzg_proof/verify_kzg_proof_case_invalid_y_35d08d612aad2197/data.yaml"),
    ),
    (
        "verify_kzg_proof_case_invalid_y_4aa6def8c35c9097",
        include_str!("../tests/verify_kzg_proof/verify_kzg_proof_case_invalid_y_4aa6def8c35c9097/data.yaml"),
    ),
    (
        "verify_kzg_proof_case_invalid_y_4e51cef08a61606f",
        include_str!("../tests/verify_kzg_proof/verify_kzg_proof_case_invalid_y_4e51cef08a61606f/data.yaml"),
    ),
    (
        "verify_kzg_proof_case_invalid_y_64b9ff2b8f7dddee",
        include_str!("../tests/verify_kzg_proof/verify_kzg_proof_case_invalid_y_64b9ff2b8f7dddee/data.yaml"),
    ),
    (
        "verify_kzg_proof_case_invalid_y_b358a2e763727b70",
        include_str!("../tests/verify_kzg_proof/verify_kzg_proof_case_invalid_y_b358a2e763727b70/data.yaml"),
    ),
    (
        "verify_kzg_proof_case_invalid_y_eb0601fec84cc5e9",
        include_str!("../tests/verify_kzg_proof/verify_kzg_proof_case_invalid_y_eb0601fec84cc5e9/data.yaml"),
    ),
    (
        "verify_kzg_proof_case_invalid_z_35d08d612aad2197",
        include_str!("../tests/verify_kzg_proof/verify_kzg_proof_case_invalid_z_35d08d612aad2197/data.yaml"),
    ),
    (
        "verify_kzg_proof_case_invalid_z_4aa6def8c35c9097",
        include_str!("../tests/verify_kzg_proof/verify_kzg_proof_case_invalid_z_4aa6def8c35c9097/data.yaml"),
    ),
    (
        "verify_kzg_proof_case_invalid_z_4e51cef08a61606f",
        include_str!("../tests/verify_kzg_proof/verify_kzg_proof_case_invalid_z_4e51cef08a61606f/data.yaml"),
    ),
    (
        "verify_kzg_proof_case_invalid_z_64b9ff2b8f7dddee",
        include_str!("../tests/verify_kzg_proof/verify_kzg_proof_case_invalid_z_64b9ff2b8f7dddee/data.yaml"),
    ),
    (
        "verify_kzg_proof_case_invalid_z_b358a2e763727b70",
        include_str!("../tests/verify_kzg_proof/verify_kzg_proof_case_invalid_z_b358a2e763727b70/data.yaml"),
    ),
    (
        "verify_kzg_proof_case_invalid_z_eb0601fec84cc5e9",
        include_str!("../tests/verify_kzg_proof/verify_kzg_proof_case_invalid_z_eb0601fec84cc5e9/data.yaml"),
    ),
];

// pub const VERIFY_BLOB_KZG_PROOF_BATCH_TESTS: [(&str, &str); 27] = [
pub const VERIFY_BLOB_KZG_PROOF_BATCH_TESTS: [(&str, &str); 1] = [
    // (
    //     "verify_blob_kzg_proof_case_correct_proof_0951cfd9ab47a8d3",
    //     include_str!("../tests/verify_blob_kzg_proof/verify_blob_kzg_proof_case_correct_proof_0951cfd9ab47a8d3/data.yaml"),
    // ),
    // (
    //     "verify_blob_kzg_proof_case_correct_proof_19b3f3f8c98ea31e",
    //     include_str!("../tests/verify_blob_kzg_proof/verify_blob_kzg_proof_case_correct_proof_19b3f3f8c98ea31e/data.yaml"),
    // ),
    // (
    //     "verify_blob_kzg_proof_case_correct_proof_84d8089232bc23a8",
    //     include_str!("../tests/verify_blob_kzg_proof/verify_blob_kzg_proof_case_correct_proof_84d8089232bc23a8/data.yaml"),
    // ),
    // (
    //     "verify_blob_kzg_proof_case_correct_proof_a87a4e636e0f58fb",
    //     include_str!("../tests/verify_blob_kzg_proof/verify_blob_kzg_proof_case_correct_proof_a87a4e636e0f58fb/data.yaml"),
    // ),
    // (
    //     "verify_blob_kzg_proof_case_correct_proof_c40b9b515df8721b",
    //     include_str!("../tests/verify_blob_kzg_proof/verify_blob_kzg_proof_case_correct_proof_c40b9b515df8721b/data.yaml"),
    // ),
    (
        "verify_blob_kzg_proof_case_correct_proof_cdb3e6d49eb12307",
        include_str!("../tests/verify_blob_kzg_proof/verify_blob_kzg_proof_case_correct_proof_cdb3e6d49eb12307/data.yaml"),
    ),
    // (
    //     "verify_blob_kzg_proof_case_correct_proof_fb324bc819407148",
    //     include_str!("../tests/verify_blob_kzg_proof/verify_blob_kzg_proof_case_correct_proof_fb324bc819407148/data.yaml"),
    // ),
//     (
//         "verify_blob_kzg_proof_case_incorrect_proof_0951cfd9ab47a8d3",
//         include_str!(
//             "../tests/verify_blob_kzg_proof/verify_blob_kzg_proof_case_incorrect_proof_0951cfd9ab47a8d3/data.yaml"
//         ),
//     ),
//     (
//         "verify_blob_kzg_proof_case_incorrect_proof_19b3f3f8c98ea31e",
//         include_str!(
//             "../tests/verify_blob_kzg_proof/verify_blob_kzg_proof_case_incorrect_proof_19b3f3f8c98ea31e/data.yaml"
//         ),
//     ),
//     (
//         "verify_blob_kzg_proof_case_incorrect_proof_84d8089232bc23a8",
//         include_str!(
//             "../tests/verify_blob_kzg_proof/verify_blob_kzg_proof_case_incorrect_proof_84d8089232bc23a8/data.yaml"
//         ),
//     ),
//     (
//         "verify_blob_kzg_proof_case_incorrect_proof_a87a4e636e0f58fb",
//         include_str!(
//             "../tests/verify_blob_kzg_proof/verify_blob_kzg_proof_case_incorrect_proof_a87a4e636e0f58fb/data.yaml"
//         ),
//     ),
//     (
//         "verify_blob_kzg_proof_case_incorrect_proof_c40b9b515df8721b",
//         include_str!(
//             "../tests/verify_blob_kzg_proof/verify_blob_kzg_proof_case_incorrect_proof_c40b9b515df8721b/data.yaml"
//         ),
//     ),
//     (
//         "verify_blob_kzg_proof_case_incorrect_proof_cdb3e6d49eb12307",
//         include_str!(
//             "../tests/verify_blob_kzg_proof/verify_blob_kzg_proof_case_incorrect_proof_cdb3e6d49eb12307/data.yaml"
//         ),
//     ),
//     (
//         "verify_blob_kzg_proof_case_incorrect_proof_fb324bc819407148",
//         include_str!(
//             "../tests/verify_blob_kzg_proof/verify_blob_kzg_proof_case_incorrect_proof_fb324bc819407148/data.yaml"
//         ),
//     ),
//     (
//         "verify_blob_kzg_proof_case_incorrect_proof_point_at_infinity",
//         include_str!(
//             "../tests/verify_blob_kzg_proof/verify_blob_kzg_proof_case_incorrect_proof_point_at_infinity/data.yaml"
//         ),
//     ),
//     (
//         "verify_blob_kzg_proof_case_invalid_blob_59d64ff6b4648fad",
//         include_str!("../tests/verify_blob_kzg_proof/verify_blob_kzg_proof_case_invalid_blob_59d64ff6b4648fad/data.yaml"),
//     ),
//     (
//         "verify_blob_kzg_proof_case_invalid_blob_635fb2de5b0dc429",
//         include_str!("../tests/verify_blob_kzg_proof/verify_blob_kzg_proof_case_invalid_blob_635fb2de5b0dc429/data.yaml"),
//     ),
//     (
//         "verify_blob_kzg_proof_case_invalid_blob_a3b9ff28507767f8",
//         include_str!("../tests/verify_blob_kzg_proof/verify_blob_kzg_proof_case_invalid_blob_a3b9ff28507767f8/data.yaml"),
//     ),
//     (
//         "verify_blob_kzg_proof_case_invalid_blob_d3afbd98123a3434",
//         include_str!("../tests/verify_blob_kzg_proof/verify_blob_kzg_proof_case_invalid_blob_d3afbd98123a3434/data.yaml"),
//     ),
//     (
//         "verify_blob_kzg_proof_case_invalid_commitment_1a68c47b68148e78",
//         include_str!(
//             "../tests/verify_blob_kzg_proof/verify_blob_kzg_proof_case_invalid_commitment_1a68c47b68148e78/data.yaml"
//         ),
//     ),
//     (
//         "verify_blob_kzg_proof_case_invalid_commitment_24b932fb4dec5b2d",
//         include_str!(
//             "../tests/verify_blob_kzg_proof/verify_blob_kzg_proof_case_invalid_commitment_24b932fb4dec5b2d/data.yaml"
//         ),
//     ),
//     (
//         "verify_blob_kzg_proof_case_invalid_commitment_3a6eb616efae0627",
//         include_str!(
//             "../tests/verify_blob_kzg_proof/verify_blob_kzg_proof_case_invalid_commitment_3a6eb616efae0627/data.yaml"
//         ),
//     ),
//     (
//         "verify_blob_kzg_proof_case_invalid_commitment_d070689c3e15444c",
//         include_str!(
//             "../tests/verify_blob_kzg_proof/verify_blob_kzg_proof_case_invalid_commitment_d070689c3e15444c/data.yaml"
//         ),
//     ),
//     (
//         "verify_blob_kzg_proof_case_invalid_proof_1a68c47b68148e78",
//         include_str!("../tests/verify_blob_kzg_proof/verify_blob_kzg_proof_case_invalid_proof_1a68c47b68148e78/data.yaml"),
//     ),
//     (
//         "verify_blob_kzg_proof_case_invalid_proof_24b932fb4dec5b2d",
//         include_str!("../tests/verify_blob_kzg_proof/verify_blob_kzg_proof_case_invalid_proof_24b932fb4dec5b2d/data.yaml"),
//     ),
//     (
//         "verify_blob_kzg_proof_case_invalid_proof_3a6eb616efae0627",
//         include_str!("../tests/verify_blob_kzg_proof/verify_blob_kzg_proof_case_invalid_proof_3a6eb616efae0627/data.yaml"),
//     ),
//     (
//         "verify_blob_kzg_proof_case_invalid_proof_d070689c3e15444c",
//         include_str!("../tests/verify_blob_kzg_proof/verify_blob_kzg_proof_case_invalid_proof_d070689c3e15444c/data.yaml"),
//     ),
];

pub const VERIFY_BLOB_KZG_PROOF_TESTS: [(&str, &str); 29] = [
    (
        "verify_blob_kzg_proof_case_correct_proof_0951cfd9ab47a8d3",
        include_str!("../tests/verify_blob_kzg_proof/verify_blob_kzg_proof_case_correct_proof_0951cfd9ab47a8d3/data.yaml"),
    ),
    (
        "verify_blob_kzg_proof_case_correct_proof_19b3f3f8c98ea31e",
        include_str!("../tests/verify_blob_kzg_proof/verify_blob_kzg_proof_case_correct_proof_19b3f3f8c98ea31e/data.yaml"),
    ),
    (
        "verify_blob_kzg_proof_case_correct_proof_84d8089232bc23a8",
        include_str!("../tests/verify_blob_kzg_proof/verify_blob_kzg_proof_case_correct_proof_84d8089232bc23a8/data.yaml"),
    ),
    (
        "verify_blob_kzg_proof_case_correct_proof_a87a4e636e0f58fb",
        include_str!("../tests/verify_blob_kzg_proof/verify_blob_kzg_proof_case_correct_proof_a87a4e636e0f58fb/data.yaml"),
    ),
    (
        "verify_blob_kzg_proof_case_correct_proof_c40b9b515df8721b",
        include_str!("../tests/verify_blob_kzg_proof/verify_blob_kzg_proof_case_correct_proof_c40b9b515df8721b/data.yaml"),
    ),
    (
        "verify_blob_kzg_proof_case_correct_proof_cdb3e6d49eb12307",
        include_str!("../tests/verify_blob_kzg_proof/verify_blob_kzg_proof_case_correct_proof_cdb3e6d49eb12307/data.yaml"),
    ),
    (
        "verify_blob_kzg_proof_case_correct_proof_fb324bc819407148",
        include_str!("../tests/verify_blob_kzg_proof/verify_blob_kzg_proof_case_correct_proof_fb324bc819407148/data.yaml"),
    ),
    (
        "verify_blob_kzg_proof_case_correct_proof_point_at_infinity_for_twos_poly",
        include_str!("../tests/verify_blob_kzg_proof/verify_blob_kzg_proof_case_correct_proof_point_at_infinity_for_twos_poly/data.yaml"),
    ),
    (
        "verify_blob_kzg_proof_case_correct_proof_point_at_infinity_for_zero_poly",
        include_str!("../tests/verify_blob_kzg_proof/verify_blob_kzg_proof_case_correct_proof_point_at_infinity_for_zero_poly/data.yaml"),
    ),
    (
        "verify_blob_kzg_proof_case_incorrect_proof_0951cfd9ab47a8d3",
        include_str!("../tests/verify_blob_kzg_proof/verify_blob_kzg_proof_case_incorrect_proof_0951cfd9ab47a8d3/data.yaml"),
    ),
    (
        "verify_blob_kzg_proof_case_incorrect_proof_19b3f3f8c98ea31e",
        include_str!("../tests/verify_blob_kzg_proof/verify_blob_kzg_proof_case_incorrect_proof_19b3f3f8c98ea31e/data.yaml"),
    ),
    (
        "verify_blob_kzg_proof_case_incorrect_proof_84d8089232bc23a8",
        include_str!("../tests/verify_blob_kzg_proof/verify_blob_kzg_proof_case_incorrect_proof_84d8089232bc23a8/data.yaml"),
    ),
    (
        "verify_blob_kzg_proof_case_incorrect_proof_a87a4e636e0f58fb",
        include_str!("../tests/verify_blob_kzg_proof/verify_blob_kzg_proof_case_incorrect_proof_a87a4e636e0f58fb/data.yaml"),
    ),
    (
        "verify_blob_kzg_proof_case_incorrect_proof_c40b9b515df8721b",
        include_str!("../tests/verify_blob_kzg_proof/verify_blob_kzg_proof_case_incorrect_proof_c40b9b515df8721b/data.yaml"),
    ),
    (
        "verify_blob_kzg_proof_case_incorrect_proof_cdb3e6d49eb12307",
        include_str!("../tests/verify_blob_kzg_proof/verify_blob_kzg_proof_case_incorrect_proof_cdb3e6d49eb12307/data.yaml"),
    ),
    (
        "verify_blob_kzg_proof_case_incorrect_proof_fb324bc819407148",
        include_str!("../tests/verify_blob_kzg_proof/verify_blob_kzg_proof_case_incorrect_proof_fb324bc819407148/data.yaml"),
    ),
    (
        "verify_blob_kzg_proof_case_incorrect_proof_point_at_infinity",
        include_str!("../tests/verify_blob_kzg_proof/verify_blob_kzg_proof_case_incorrect_proof_point_at_infinity/data.yaml"),
    ),
    (
        "verify_blob_kzg_proof_case_invalid_blob_59d64ff6b4648fad",
        include_str!("../tests/verify_blob_kzg_proof/verify_blob_kzg_proof_case_invalid_blob_59d64ff6b4648fad/data.yaml"),
    ),
    (
        "verify_blob_kzg_proof_case_invalid_blob_635fb2de5b0dc429",
        include_str!("../tests/verify_blob_kzg_proof/verify_blob_kzg_proof_case_invalid_blob_635fb2de5b0dc429/data.yaml"),
    ),
    (
        "verify_blob_kzg_proof_case_invalid_blob_a3b9ff28507767f8",
        include_str!("../tests/verify_blob_kzg_proof/verify_blob_kzg_proof_case_invalid_blob_a3b9ff28507767f8/data.yaml"),
    ),
    (
        "verify_blob_kzg_proof_case_invalid_blob_d3afbd98123a3434",
        include_str!("../tests/verify_blob_kzg_proof/verify_blob_kzg_proof_case_invalid_blob_d3afbd98123a3434/data.yaml"),
    ),
    (
        "verify_blob_kzg_proof_case_invalid_commitment_1a68c47b68148e78",
        include_str!("../tests/verify_blob_kzg_proof/verify_blob_kzg_proof_case_invalid_commitment_1a68c47b68148e78/data.yaml"),
    ),
    (
        "verify_blob_kzg_proof_case_invalid_commitment_24b932fb4dec5b2d",
        include_str!("../tests/verify_blob_kzg_proof/verify_blob_kzg_proof_case_invalid_commitment_24b932fb4dec5b2d/data.yaml"),
    ),
    (
        "verify_blob_kzg_proof_case_invalid_commitment_3a6eb616efae0627",
        include_str!("../tests/verify_blob_kzg_proof/verify_blob_kzg_proof_case_invalid_commitment_3a6eb616efae0627/data.yaml"),
    ),
    (
        "verify_blob_kzg_proof_case_invalid_commitment_d070689c3e15444c",
        include_str!("../tests/verify_blob_kzg_proof/verify_blob_kzg_proof_case_invalid_commitment_d070689c3e15444c/data.yaml"),
    ),
    (
        "verify_blob_kzg_proof_case_invalid_proof_1a68c47b68148e78",
        include_str!("../tests/verify_blob_kzg_proof/verify_blob_kzg_proof_case_invalid_proof_1a68c47b68148e78/data.yaml"),
    ),
    (
        "verify_blob_kzg_proof_case_invalid_proof_24b932fb4dec5b2d",
        include_str!("../tests/verify_blob_kzg_proof/verify_blob_kzg_proof_case_invalid_proof_24b932fb4dec5b2d/data.yaml"),
    ),
    (
        "verify_blob_kzg_proof_case_invalid_proof_3a6eb616efae0627",
        include_str!("../tests/verify_blob_kzg_proof/verify_blob_kzg_proof_case_invalid_proof_3a6eb616efae0627/data.yaml"),
    ),
    (
        "verify_blob_kzg_proof_case_invalid_proof_d070689c3e15444c",
        include_str!("../tests/verify_blob_kzg_proof/verify_blob_kzg_proof_case_invalid_proof_d070689c3e15444c/data.yaml"),
    ),
];
