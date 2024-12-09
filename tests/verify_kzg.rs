use std::path::PathBuf;

use ax_stark_sdk::p3_baby_bear::BabyBear;
use axvm_algebra_transpiler::{Fp2TranspilerExtension, ModularTranspilerExtension};
use axvm_build::GuestOptions;
use axvm_pairing_transpiler::PairingTranspilerExtension;
use axvm_rv32im_transpiler::{
    Rv32ITranspilerExtension, Rv32IoTranspilerExtension, Rv32MTranspilerExtension,
};
use axvm_sdk::Sdk;
use axvm_transpiler::transpiler::Transpiler;

type F = BabyBear;

#[test]
fn test_verify_kzg_proof() {
    let sdk = Sdk;
    let guest_opts = GuestOptions::default()
        // .with_options(["--example", "verify_kzg"])
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
    let _exe = sdk.transpile(verify_kzg, transpiler).unwrap();
}
