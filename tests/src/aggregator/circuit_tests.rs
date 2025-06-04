#![cfg(test)]
use crate::aggregator::circuit_config;
use crate::circuit_helpers::{build_and_prove_test, setup_test_builder_and_witness};
use test_helpers::storage_proof::TestInputs;
use wormhole_aggregator::circuit::{WormholeProofAggregatorInner, WormholeProofAggregatorTargets};
use wormhole_aggregator::MAX_NUM_PROOFS_TO_AGGREGATE;
use wormhole_circuit::circuit::{CircuitFragment, C, D, F};
use wormhole_circuit::inputs::CircuitInputs;
use wormhole_prover::WormholeProver;
use wormhole_verifier::ProofWithPublicInputs;

fn run_test(
    proofs: Vec<ProofWithPublicInputs<F, C, D>>,
) -> anyhow::Result<plonky2::plonk::proof::ProofWithPublicInputs<F, C, D>> {
    let (mut builder, mut pw) = setup_test_builder_and_witness(false);
    let targets = WormholeProofAggregatorTargets::new(&mut builder, circuit_config());
    WormholeProofAggregatorInner::circuit(&targets, &mut builder);

    let mut aggregator = WormholeProofAggregatorInner::new(circuit_config());
    aggregator.set_proofs(proofs)?;
    aggregator.fill_targets(&mut pw, targets)?;
    build_and_prove_test(builder, pw)
}

#[test]
fn build_and_verify_proof() {
    // Create proofs.
    let mut proofs = Vec::with_capacity(MAX_NUM_PROOFS_TO_AGGREGATE);
    for _ in 0..MAX_NUM_PROOFS_TO_AGGREGATE {
        let prover = WormholeProver::new(circuit_config());
        let inputs = CircuitInputs::test_inputs();
        let proof = prover.commit(&inputs).unwrap().prove().unwrap();
        proofs.push(proof);
    }
    run_test(proofs).unwrap();
}

#[test]
fn few_proofs_pass() {
    // Create proofs.
    let mut proofs = Vec::with_capacity(MAX_NUM_PROOFS_TO_AGGREGATE);
    for _ in 0..(MAX_NUM_PROOFS_TO_AGGREGATE / 2) {
        let prover = WormholeProver::new(circuit_config());
        let inputs = CircuitInputs::test_inputs();
        let proof = prover.commit(&inputs).unwrap().prove().unwrap();
        proofs.push(proof);
    }

    run_test(proofs).unwrap();
}
