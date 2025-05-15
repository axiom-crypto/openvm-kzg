use openvm_kzg::{
    test_utils::{Input, Test},
    KzgInputs,
};
use serde_yaml::from_str;
use setup::run_guest_program;

pub mod setup;

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

#[cfg(test)]
mod tests {
    use openvm_kzg::test_files::{
        ONLY_INVALID_KZG_PROOF_TESTS, ONLY_VALID_KZG_PROOF_TESTS, SINGLE_VALID_KZG_PROOF_TEST,
    };

    use crate::run_test_from_yaml_str;

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

    #[ignore]
    #[test]
    fn test_multiple_invalid_verify_kzg() {
        for (test_file, data) in ONLY_INVALID_KZG_PROOF_TESTS {
            println!("Running test: {}", test_file);
            let result = std::panic::catch_unwind(|| run_test_from_yaml_str(data));
            assert!(result.is_err(), "Test {} should have panicked", test_file);
        }
    }
}
