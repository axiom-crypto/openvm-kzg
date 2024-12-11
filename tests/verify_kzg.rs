use std::path::PathBuf;

use ax_stark_sdk::ax_stark_backend::p3_field::AbstractField;
use ax_stark_sdk::p3_baby_bear::BabyBear;
use axvm_algebra_circuit::{Fp2Extension, ModularExtension};
use axvm_algebra_transpiler::{Fp2TranspilerExtension, ModularTranspilerExtension};
use axvm_build::{GuestOptions, TargetFilter};
use axvm_circuit::arch::SystemConfig;
use axvm_circuit::utils::new_air_test_with_min_segments;
use axvm_ecc_circuit::WeierstrassExtension;
use axvm_pairing_circuit::{PairingCurve, PairingExtension, Rv32PairingConfig};
use axvm_pairing_guest::bls12_381::BLS12_381_MODULUS;
use axvm_pairing_transpiler::PairingTranspilerExtension;
use axvm_rv32im_circuit::Rv32IConfig;
use axvm_rv32im_transpiler::{
    Rv32ITranspilerExtension, Rv32IoTranspilerExtension, Rv32MTranspilerExtension,
};
use axvm_sdk::config::SdkVmConfig;
use axvm_sdk::Sdk;
use axvm_transpiler::transpiler::Transpiler;
use kzg_rs::pairings::{
    g1_affine_is_on_curve, g1_affine_to_affine_point, g2_affine_is_on_curve,
    g2_affine_to_affine_point,
};
use kzg_rs::test_files::{
    ONLY_VALID_KZG_PROOF_TESTS, SINGLE_VALID_KZG_PROOF_TEST, VERIFY_KZG_PROOF_TESTS,
};
use kzg_rs::test_utils::{Input, Test};
use kzg_rs::types::{KzgInputs, KzgSettings, KzgSettingsInput, KzgSettingsOwned};
use kzg_rs::{KzgProof, PairingInputs};
use serde_yaml::from_str;

type F = BabyBear;

#[test]
fn test_verify_kzg_proof() {
    let sdk = Sdk;
    let guest_opts = GuestOptions::default()
        // .with_options(vec!["--release"]);
        // .with_features(vec!["zkvm"])
        ;
    let mut pkg_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).to_path_buf();
    pkg_dir.push("program");
    let verify_kzg = sdk
        .build(guest_opts.clone(), &pkg_dir, &TargetFilter::default())
        .unwrap();
    let transpiler = Transpiler::<F>::default()
        .with_extension(Rv32ITranspilerExtension)
        .with_extension(Rv32MTranspilerExtension)
        .with_extension(Rv32IoTranspilerExtension)
        .with_extension(PairingTranspilerExtension)
        .with_extension(ModularTranspilerExtension)
        .with_extension(Fp2TranspilerExtension);
    let exe = sdk.transpile(verify_kzg, transpiler).unwrap();

    // Config
    let config = Rv32PairingConfig {
        system: SystemConfig::default().with_continuations(),
        base: Default::default(),
        mul: Default::default(),
        io: Default::default(),
        modular: ModularExtension::new(vec![BLS12_381_MODULUS.clone()]),
        fp2: Fp2Extension::new(vec![BLS12_381_MODULUS.clone()]),
        weierstrass: WeierstrassExtension::new(vec![]),
        pairing: PairingExtension::new(vec![PairingCurve::Bls12_381]),
    };
    // let config = SdkVmConfig::builder()
    //     .system(
    //         SystemConfig::default()
    //             .with_max_segment_len(200)
    //             .with_continuations()
    //             .with_public_values(16),
    //     )
    //     .native(Default::default())
    //     .rv32i(Default::default())
    //     .io(Default::default())
    //     .pairing(PairingExtension::new(vec![PairingCurve::Bls12_381]))
    //     .modular(ModularExtension::new(vec![BLS12_381_MODULUS.clone()]))
    //     .fp2(Fp2Extension::new(vec![BLS12_381_MODULUS.clone()]))
    //     // .weierstrass(WeierstrassExtension::new(vec![]))
    //     .build();

    // Get inputs from disk
    let kzg_settings = KzgSettings::load_trusted_setup_file().unwrap();

    #[allow(clippy::iter_cloned_collect)]
    let kzg_settings_input = KzgSettingsInput {
        // Use controlled copying that respects align(4) in KzgSettings struct
        roots_of_unity: kzg_settings.roots_of_unity.iter().copied().collect(),
        g1_points: kzg_settings.g1_points.iter().copied().collect(),
        g2_points: kzg_settings.g2_points.iter().copied().collect(),
    };

    // let kzg_settings_owned = KzgSettingsOwned {
    //     roots_of_unity: kzg_settings.roots_of_unity.try_into().unwrap(),
    //     g1_points: kzg_settings.g1_points.try_into().unwrap(),
    //     g2_points: kzg_settings.g2_points.try_into().unwrap(),
    // };

    let test_files = SINGLE_VALID_KZG_PROOF_TEST;

    for (_test_file, data) in test_files {
        println!("Running test: {}", _test_file);
        let test: Test<Input> = from_str(data).unwrap();
        let (Ok(commitment), Ok(z), Ok(y), Ok(proof)) = (
            test.input.get_commitment(),
            test.input.get_z(),
            test.input.get_y(),
            test.input.get_proof(),
        ) else {
            assert!(test.get_output().is_none());
            continue;
        };

        // Handle i/o
        let (a1, a2, b1, b2) =
            KzgProof::calculate_pairing_points(&commitment, &z, &y, &proof, &kzg_settings).unwrap();

        let p0 = g1_affine_to_affine_point(a1);
        let p1 = g2_affine_to_affine_point(a2);
        let q0 = g1_affine_to_affine_point(b1);
        let q1 = g2_affine_to_affine_point(b2);

        // Check that input points are on the curve
        assert!(g1_affine_is_on_curve(&p0));
        assert!(g2_affine_is_on_curve(&p1));
        assert!(g1_affine_is_on_curve(&q0));
        assert!(g2_affine_is_on_curve(&q1));

        let io = bincode::serialize(&PairingInputs { p0, p1, q0, q1 }).unwrap();

        // let io = KzgInputs {
        //     commitment_bytes: commitment,
        //     z_bytes: z,
        //     y_bytes: y,
        //     proof_bytes: proof,
        //     kzg_settings: kzg_settings_input.clone(),
        // };
        // let io = bincode::serialize(&io).unwrap();
        let io = io
            .iter()
            .map(|&x| AbstractField::from_canonical_u8(x))
            .collect::<Vec<_>>();

        new_air_test_with_min_segments(config.clone(), exe.clone(), vec![io], 1, false);
    }
}
