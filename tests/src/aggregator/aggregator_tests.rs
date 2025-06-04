#![cfg(test)]
use wormhole_aggregator::{aggregator::WormholeProofAggregator, DEFAULT_NUM_PROOFS_TO_AGGREGATE};
use wormhole_circuit::inputs::CircuitInputs;
use wormhole_prover::WormholeProver;

use crate::aggregator::circuit_config;
use test_helpers::storage_proof::TestInputs;

#[test]
fn push_proof_to_buffer() {
    // Create a proof.
    let prover = WormholeProver::new(circuit_config());
    let inputs = CircuitInputs::test_inputs();
    let proof = prover.commit(&inputs).unwrap().prove().unwrap();

    let mut aggregator =
        WormholeProofAggregator::<{ DEFAULT_NUM_PROOFS_TO_AGGREGATE }>::new(circuit_config());
    aggregator.push_proof(proof).unwrap();

    let proofs_buffer = aggregator.proofs_buffer.unwrap();
    assert_eq!(proofs_buffer.len(), 1);
}

#[test]
fn push_proof_to_full_buffer() {
    // Create a proof.
    let prover = WormholeProver::new(circuit_config());
    let inputs = CircuitInputs::test_inputs();
    let proof = prover.commit(&inputs).unwrap().prove().unwrap();

    let mut aggregator =
        WormholeProofAggregator::<{ DEFAULT_NUM_PROOFS_TO_AGGREGATE }>::new(circuit_config());

    // Fill up the proof buffer.
    for _ in 0..DEFAULT_NUM_PROOFS_TO_AGGREGATE {
        aggregator.push_proof(proof.clone()).unwrap();
    }

    let result = aggregator.push_proof(proof.clone());
    assert!(result.is_err());

    let proofs_buffer = aggregator.proofs_buffer.unwrap();
    assert_eq!(proofs_buffer.len(), DEFAULT_NUM_PROOFS_TO_AGGREGATE);
}

#[test]
fn aggregate_single_proof() {
    // Create a proof.
    let prover = WormholeProver::new(circuit_config());
    let inputs = CircuitInputs::test_inputs();
    let proof = prover.commit(&inputs).unwrap().prove().unwrap();

    let mut aggregator =
        WormholeProofAggregator::<{ DEFAULT_NUM_PROOFS_TO_AGGREGATE }>::new(circuit_config());
    aggregator.push_proof(proof).unwrap();

    aggregator.aggregate().unwrap();
    aggregator.prove().unwrap();
}
