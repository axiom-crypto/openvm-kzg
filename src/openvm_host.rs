use std::{path::PathBuf, sync::Arc};

use openvm_algebra_circuit::{Fp2Extension, ModularExtension};
use openvm_build::{GuestOptions, TargetFilter};
use openvm_circuit::{arch::instructions::exe::VmExe, openvm_stark_sdk::config::FriParameters};
use openvm_pairing_circuit::{PairingCurve, PairingExtension};
use openvm_pairing_guest::bls12_381::BLS12_381_MODULUS;
use openvm_sdk::{
    config::{AppConfig, SdkVmConfig},
    Sdk, StdIn,
};
use openvm_stark_sdk::p3_baby_bear::BabyBear;

use crate::KzgInputs;

type F = BabyBear;

pub fn run_guest_program(input: KzgInputs) {
    let sdk = Sdk;
    let (exe, vm_config) = setup_test(&sdk);

    let mut io = StdIn::default();
    io.write(&input);

    // 5. Run the program
    let output = sdk
        .execute(exe.clone(), vm_config.clone(), io.clone())
        .unwrap();
    println!("public values output: {:?}", output);

    // 6. Set app configuration
    let app_log_blowup = 2;
    let app_fri_params = FriParameters::standard_with_100_bits_conjectured_security(app_log_blowup);
    let app_config = AppConfig::new(app_fri_params, vm_config);

    // 7. Commit the exe
    println!("Committing app exe");
    let app_committed_exe = sdk.commit_app_exe(app_fri_params, exe).unwrap();

    // 8. Generate an AppProvingKey
    println!("Generating app proving key");
    let app_pk = Arc::new(sdk.app_keygen(app_config).unwrap());

    // 9. Generate a proof
    println!("Generating app proof");
    let proof = sdk
        .generate_app_proof(app_pk.clone(), app_committed_exe.clone(), io.clone())
        .unwrap();

    // 10. Verify your program
    println!("Verifying app proof");
    let app_vk = app_pk.get_vk();
    sdk.verify_app_proof(&app_vk, &proof).unwrap();

    println!("App proof verified!");
}

fn setup_test(sdk: &Sdk) -> (VmExe<F>, SdkVmConfig) {
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
    (exe, vm_config)
}
