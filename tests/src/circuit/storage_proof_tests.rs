use plonky2::plonk::proof::ProofWithPublicInputs;
use std::panic;
use wormhole_circuit::{
    circuit::{CircuitFragment, C, D, F},
    storage_proof::{StorageProof, StorageProofTargets},
};

use test_helpers::storage_proof::{
    default_root_hash, default_storage_proof, DEFAULT_FUNDING_AMOUNT,
};

#[cfg(test)]
fn run_test(storage_proof: &StorageProof) -> anyhow::Result<ProofWithPublicInputs<F, C, D>> {
    let (mut builder, mut pw) = crate::circuit_helpers::setup_test_builder_and_witness(false);
    let targets = StorageProofTargets::new(&mut builder);
    StorageProof::circuit(&targets, &mut builder);

    storage_proof.fill_targets(&mut pw, targets).unwrap();
    crate::circuit_helpers::build_and_prove_test(builder, pw)
}

#[test]
fn build_and_verify_proof() {
    let storage_proof = StorageProof::new(
        &default_storage_proof(),
        default_root_hash(),
        DEFAULT_FUNDING_AMOUNT,
    );
    run_test(&storage_proof).unwrap();
}

#[test]
#[should_panic(expected = "set twice with different values")]
fn invalid_root_hash_fails() {
    let mut proof = StorageProof::new(
        &default_storage_proof(),
        default_root_hash(),
        DEFAULT_FUNDING_AMOUNT,
    );
    proof.root_hash = [0u8; 32];
    run_test(&proof).unwrap();
}

#[test]
#[should_panic(expected = "set twice with different values")]
fn tampered_proof_fails() {
    let mut tampered_proof = default_storage_proof();

    // Flip the first byte in the first node hash.
    tampered_proof[0].1[0] ^= 0xFF;
    let proof = StorageProof::new(&tampered_proof, default_root_hash(), DEFAULT_FUNDING_AMOUNT);

    run_test(&proof).unwrap();
}

#[ignore = "performance"]
#[test]
fn fuzz_tampered_proof() {
    const FUZZ_ITERATIONS: usize = 1000;

    // Number of fuzzing iterations
    let mut panic_count = 0;

    for i in 0..FUZZ_ITERATIONS {
        // Clone the original storage proof
        let mut tampered_proof = default_storage_proof();

        // Randomly select a node in the proof to tamper
        let node_index = rand::random_range(0..tampered_proof.len());

        // Randomly select a byte to flip
        let byte_index = rand::random_range(0..tampered_proof[node_index].1.len());

        // Flip random bits in the selected byte (e.g., XOR with a random value)
        tampered_proof[node_index].1[byte_index] ^= rand::random_range(1..=255);

        // Create the proof and inputs
        let proof = StorageProof::new(&tampered_proof, default_root_hash(), DEFAULT_FUNDING_AMOUNT);

        // Catch panic from run_test
        let result = panic::catch_unwind(|| {
            run_test(&proof).unwrap();
        });

        if result.is_err() {
            panic_count += 1;
        } else {
            // Optionally log cases where tampering didn't cause a panic
            println!("Iteration {i}: No panic occurred for tampered proof");
        }
    }

    assert_eq!(
        panic_count, FUZZ_ITERATIONS,
        "Only {panic_count} out of {FUZZ_ITERATIONS} iterations panicked",
    );
}
