use kzg_rs::{
    run_guest_program,
    test_files::SINGLE_VALID_KZG_PROOF_TEST,
    test_utils::{Input, Test},
    KzgInputs,
};
use serde_yaml::from_str;

pub fn main() {
    let (_, data) = SINGLE_VALID_KZG_PROOF_TEST[0];
    let test: Test<Input> = from_str(data).unwrap();
    let (Ok(commitment), Ok(z), Ok(y), Ok(proof)) = (
        test.input.get_commitment(),
        test.input.get_z(),
        test.input.get_y(),
        test.input.get_proof(),
    ) else {
        panic!("Unable to get test data");
    };

    let input = KzgInputs {
        commitment_bytes: commitment,
        z_bytes: z,
        y_bytes: y,
        proof_bytes: proof,
    };

    run_guest_program(input);
}
