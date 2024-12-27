use std::path::PathBuf;
use std::sync::Arc;

use kzg_rs::test_files::{
    ONLY_VALID_KZG_PROOF_TESTS, SINGLE_VALID_KZG_PROOF_TEST, VERIFY_KZG_PROOF_TESTS,
};
use kzg_rs::test_utils::{Input, Test};
use kzg_rs::KzgInputs;
use openvm_algebra_circuit::{Fp2Extension, ModularExtension};
use openvm_build::{GuestOptions, TargetFilter};
use openvm_circuit::openvm_stark_sdk::config::FriParameters;
use openvm_pairing_circuit::{PairingCurve, PairingExtension};
use openvm_pairing_guest::bls12_381::{BLS12_381_MODULUS, BLS12_381_ORDER};
use openvm_sdk::config::{AppConfig, SdkVmConfig};
use openvm_sdk::{Sdk, StdIn};
use serde_yaml::from_str;

#[test]
fn test_verify_kzg_proof() {
    let sdk = Sdk;

    let vm_config = SdkVmConfig::builder()
        .system(Default::default())
        .rv32i(Default::default())
        .rv32m(Default::default())
        .io(Default::default())
        .keccak(Default::default())
        .modular(ModularExtension::new(vec![BLS12_381_MODULUS.clone()]))
        // .ecc(WeierstrassExtension::new(vec![BLS12_381_MODULUS.clone()]))
        .fp2(Fp2Extension::new(vec![BLS12_381_MODULUS.clone()]))
        .pairing(PairingExtension::new(vec![PairingCurve::Bls12_381]))
        .build();

    let guest_opts = GuestOptions::default().with_features(["guest-program"]);
    let target_filter = Some(TargetFilter {
        name: "verify-kzg-program".to_string(),
        kind: "bin".to_string(),
    });
    let mut pkg_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).to_path_buf();
    pkg_dir.push("programs");

    let elf = sdk
        .build(guest_opts, pkg_dir.clone(), &target_filter)
        .unwrap();

    // Transpile the ELF into a VmExe
    let exe = sdk.transpile(elf, vm_config.transpiler()).unwrap();

    // Set App Config
    let app_log_blowup = 2;
    let app_fri_params = FriParameters::standard_with_100_bits_conjectured_security(app_log_blowup);
    let app_config = AppConfig::new(app_fri_params, vm_config);

    // Get inputs from disk
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

        let input = KzgInputs {
            commitment_bytes: commitment,
            z_bytes: z,
            y_bytes: y,
            proof_bytes: proof,
        };
        let mut io = StdIn::default();
        io.write(&input);

        println!("Committing app exe");
        let app_committed_exe = sdk.commit_app_exe(app_fri_params, exe.clone()).unwrap();

        println!("Generating app proving key");
        let app_pk = Arc::new(sdk.app_keygen(app_config.clone()).unwrap());

        println!("Generating app proof");
        let app_vk = app_pk.get_vk();
        let proof = sdk
            .generate_app_proof(app_pk.clone(), app_committed_exe.clone(), io.clone())
            .unwrap();

        println!("Verifying app proof");
        sdk.verify_app_proof(&app_vk, &proof).unwrap();

        println!("App proof verified!");
    }
}
