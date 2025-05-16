use std::path::PathBuf;

use openvm_build::{GuestOptions, TargetFilter};
use openvm_circuit::{
    arch::instructions::exe::VmExe, openvm_stark_sdk::config::setup_tracing,
    utils::air_test_with_min_segments,
};
use openvm_kzg::test_files::{
    ONLY_INVALID_KZG_PROOF_TESTS, ONLY_VALID_KZG_PROOF_TESTS, SINGLE_VALID_KZG_PROOF_TEST,
};
use openvm_kzg::{
    test_utils::{Input, Test},
    KzgInputs,
};
use openvm_sdk::{
    config::{AppConfig, SdkVmConfig},
    Sdk, StdIn,
};
use openvm_stark_sdk::p3_baby_bear::BabyBear;
use serde_yaml::from_str;

type F = BabyBear;

#[test]
fn test_single_valid_verify_kzg() {
    let (_, data) = SINGLE_VALID_KZG_PROOF_TEST[0];
    run_test_from_yaml_str(data);
}

#[test]
fn test_multiple_valid_verify_kzg() {
    for (test_file, data) in ONLY_VALID_KZG_PROOF_TESTS {
        println!("Running test: {}", test_file);
        run_test_from_yaml_str(data);
    }
}

#[test]
fn test_single_invalid_verify_kzg() {
    let (test_file, data) = ONLY_INVALID_KZG_PROOF_TESTS[0];
    let result = std::panic::catch_unwind(|| run_test_from_yaml_str(data));
    assert!(result.is_err(), "Test {} should have panicked", test_file);
}

#[ignore = "takes too long"]
#[test]
fn test_multiple_invalid_verify_kzg() {
    for (test_file, data) in ONLY_INVALID_KZG_PROOF_TESTS {
        println!("Running test: {}", test_file);
        let result = std::panic::catch_unwind(|| run_test_from_yaml_str(data));
        assert!(result.is_err(), "Test {} should have panicked", test_file);
    }
}

pub fn run_test_from_yaml_str(data: &str) {
    let test: Test<Input> = from_str(data).unwrap();
    let (Ok(commitment), Ok(z), Ok(y), Ok(proof)) = (
        test.input.get_commitment(),
        test.input.get_z(),
        test.input.get_y(),
        test.input.get_proof(),
    ) else {
        panic!("Invalid test inputs");
    };

    let input = KzgInputs {
        commitment_bytes: commitment,
        z_bytes: z,
        y_bytes: y,
        proof_bytes: proof,
    };

    run_guest_program(input);
}

pub fn run_guest_program(input: KzgInputs) {
    setup_tracing();
    let sdk = Sdk::new();
    let (exe, vm_config) = setup_test(&sdk);

    let mut io = StdIn::default();
    io.write(&input);

    air_test_with_min_segments(vm_config, exe, io, 1);
}

fn setup_test(sdk: &Sdk) -> (VmExe<F>, SdkVmConfig) {
    let app_config: AppConfig<SdkVmConfig> =
        toml::from_str(include_str!("programs/verify_kzg/openvm.toml")).unwrap();
    let vm_config = app_config.app_vm_config;

    let guest_opts = GuestOptions::default();
    let target_filter = Some(TargetFilter {
        name: "verify-kzg-program".to_string(),
        kind: "bin".to_string(),
    });
    let mut pkg_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    pkg_dir.push("tests");
    pkg_dir.push("programs");
    pkg_dir.push("verify_kzg");

    let elf = sdk
        .build(guest_opts, &vm_config, &pkg_dir, &target_filter, None)
        .unwrap();

    // Transpile the ELF into a VmExe
    let exe = sdk.transpile(elf, vm_config.transpiler()).unwrap();
    (exe, vm_config)
}
