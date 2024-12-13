use std::path::PathBuf;

use kzg_rs::test_files::{
    ONLY_VALID_KZG_PROOF_TESTS, SINGLE_VALID_KZG_PROOF_TEST, VERIFY_KZG_PROOF_TESTS,
};
use kzg_rs::test_utils::{Input, Test};
use kzg_rs::KzgInputs;
use num_bigint_dig::BigUint;
use num_traits::{FromPrimitive, Zero};
use openvm_algebra_circuit::{Fp2Extension, ModularExtension};
use openvm_algebra_transpiler::{Fp2TranspilerExtension, ModularTranspilerExtension};
use openvm_build::{GuestOptions, TargetFilter};
use openvm_circuit::arch::SystemConfig;
use openvm_circuit::utils::new_air_test_with_min_segments;
use openvm_ecc_circuit::{CurveConfig, WeierstrassExtension};
use openvm_ecc_transpiler::EccTranspilerExtension;
use openvm_pairing_circuit::{PairingCurve, PairingExtension, Rv32PairingConfig};
use openvm_pairing_guest::bls12_381::{BLS12_381_MODULUS, BLS12_381_ORDER};
use openvm_pairing_transpiler::PairingTranspilerExtension;
use openvm_rv32im_transpiler::{
    Rv32ITranspilerExtension, Rv32IoTranspilerExtension, Rv32MTranspilerExtension,
};
use openvm_sdk::Sdk;
use openvm_stark_sdk::openvm_stark_backend::p3_field::AbstractField;
use openvm_stark_sdk::p3_baby_bear::BabyBear;
use openvm_transpiler::transpiler::Transpiler;
use serde_yaml::from_str;

type F = BabyBear;

#[test]
fn test_verify_kzg_proof() {
    let sdk = Sdk;
    let guest_opts = GuestOptions::default();
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
        .with_extension(EccTranspilerExtension)
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
        weierstrass: WeierstrassExtension::new(vec![CurveConfig {
            modulus: BLS12_381_MODULUS.clone(),
            scalar: BLS12_381_ORDER.clone(),
            a: BigUint::zero(),
            b: BigUint::from_u8(4u8).unwrap(),
        }]),
        pairing: PairingExtension::new(vec![PairingCurve::Bls12_381]),
    };

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

        let io = KzgInputs {
            commitment_bytes: commitment,
            z_bytes: z,
            y_bytes: y,
            proof_bytes: proof,
        };

        let io = openvm::serde::to_vec(&io).unwrap();
        let io = io
            .into_iter()
            .flat_map(|w| w.to_le_bytes())
            .map(F::from_canonical_u8)
            .collect();

        new_air_test_with_min_segments(config.clone(), exe.clone(), vec![io], 1, false);
    }
}
