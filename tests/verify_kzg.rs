use std::path::PathBuf;

use ax_stark_sdk::p3_baby_bear::BabyBear;
use axvm_algebra_transpiler::{Fp2TranspilerExtension, ModularTranspilerExtension};
use axvm_build::GuestOptions;
use axvm_circuit::arch::SystemConfig;
use axvm_circuit::utils::new_air_test_with_min_segments;
use axvm_pairing_guest::bls12_381::BLS12_381_MODULUS;
use axvm_pairing_transpiler::PairingTranspilerExtension;
use axvm_rv32im_circuit::Rv32IConfig;
use axvm_rv32im_transpiler::{
    Rv32ITranspilerExtension, Rv32IoTranspilerExtension, Rv32MTranspilerExtension,
};
use axvm_sdk::Sdk;
use axvm_transpiler::transpiler::Transpiler;
#[cfg(feature = "test-utils")]
use kzg_rs::test_files::VERIFY_KZG_PROOF_TESTS;
#[cfg(feature = "test-utils")]
use kzg_rs::test_utils::{Input, Test};
use kzg_rs::KzgSettings;

type F = BabyBear;

#[test]
fn test_verify_kzg_proof() {
    let sdk = Sdk;
    let guest_opts = GuestOptions::default()
        // .with_options(vec!["--release"]);
        // .with_features(vec!["zkvm"])
        ;
    let mut pkg_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).to_path_buf();
    pkg_dir.push("examples");
    let verify_kzg = sdk.build(guest_opts.clone(), &pkg_dir).unwrap();
    let transpiler = Transpiler::<F>::default()
        .with_extension(Rv32ITranspilerExtension)
        .with_extension(Rv32MTranspilerExtension)
        .with_extension(Rv32IoTranspilerExtension)
        .with_extension(PairingTranspilerExtension)
        .with_extension(ModularTranspilerExtension)
        .with_extension(Fp2TranspilerExtension);
    let exe = sdk.transpile(verify_kzg, transpiler).unwrap();

    // Config

    // let primes = [BLS12_381_MODULUS.clone()];
    // let config = Rv32PairingConfig {
    //     system: SystemConfig::default().with_continuations(),
    //     base: Default::default(),
    //     mul: Default::default(),
    //     io: Default::default(),
    //     modular: ModularExtension::new(primes.to_vec()),
    //     fp2: Fp2Extension::new(primes.to_vec()),
    //     weierstrass: WeierstrassExtension::new(vec![]),
    //     pairing: PairingExtension::new(vec![PairingCurve::Bls12_381]),
    // };
    let config = Rv32IConfig::default();

    // Get inputs from disk
    let kzg_settings = KzgSettings::load_trusted_setup_file().unwrap();
    let test_files = VERIFY_KZG_PROOF_TESTS;

    for (_test_file, data) in test_files {
        println!("Running test: {}", _test_file);
        let test: Test<Input> = serde_yaml::from_str(data).unwrap();
        let (Ok(commitment), Ok(z), Ok(y), Ok(proof)) = (
            test.input.get_commitment(),
            test.input.get_z(),
            test.input.get_y(),
            test.input.get_proof(),
        ) else {
            assert!(test.get_output().is_none());
            continue;
        };

        new_air_test_with_min_segments(config.clone(), exe.clone(), vec![], 1, false);
    }
}
