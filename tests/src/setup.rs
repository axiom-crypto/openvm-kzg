use std::path::PathBuf;

use openvm_build::{GuestOptions, TargetFilter};
use openvm_circuit::{
    arch::instructions::exe::VmExe, openvm_stark_sdk::config::setup_tracing,
    utils::air_test_with_min_segments,
};
use openvm_sdk::{
    config::{AppConfig, SdkVmConfig},
    Sdk, StdIn,
};
use openvm_stark_sdk::p3_baby_bear::BabyBear;

use crate::KzgInputs;

type F = BabyBear;

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
        toml::from_str(include_str!("../programs/verify_kzg/openvm.toml")).unwrap();
    let vm_config = app_config.app_vm_config;

    let guest_opts = GuestOptions::default();
    let target_filter = Some(TargetFilter {
        name: "verify-kzg-program".to_string(),
        kind: "bin".to_string(),
    });
    let mut pkg_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    pkg_dir.push("programs");
    pkg_dir.push("verify_kzg");

    let elf = sdk
        .build(guest_opts, &vm_config, &pkg_dir, &target_filter, None)
        .unwrap();

    // Transpile the ELF into a VmExe
    let exe = sdk.transpile(elf, vm_config.transpiler()).unwrap();
    (exe, vm_config)
}
