#![cfg_attr(not(feature = "std"), no_main)]
#![cfg_attr(not(feature = "std"), no_std)]

axvm::entry!(main);
use crate::kzg_proof::KzgProof;

pub fn main() {
    KzgProof::verify_kzg_proof(commitment, z, y, proof, kzg_settings)
}
