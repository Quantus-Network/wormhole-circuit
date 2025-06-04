use std::time::Duration;

use criterion::{criterion_group, criterion_main, Criterion};
use plonky2::plonk::circuit_data::{CircuitConfig, CommonCircuitData};
use wormhole_aggregator::{aggregator::WormholeProofAggregator, MAX_NUM_PROOFS_TO_AGGREGATE};
use wormhole_circuit::circuit::{C, D, F};
use wormhole_verifier::ProofWithPublicInputs;

const MEASUREMENT_TIME_S: u64 = 100;
const DUMMY_PROOF_BYTES: &[u8] = include_bytes!("../data/dummy_proof_zk.bin");

fn deserialize_proofs(
    common_data: &CommonCircuitData<F, D>,
) -> [ProofWithPublicInputs<F, C, D>; MAX_NUM_PROOFS_TO_AGGREGATE] {
    let proof = ProofWithPublicInputs::from_bytes(DUMMY_PROOF_BYTES.to_vec(), common_data).unwrap();
    std::array::from_fn(|_| proof.clone())
}

// TODO: Add function to only bench circuit.
fn aggregate_proofs_benchmark(c: &mut Criterion) {
    c.bench_function("aggregator_aggregate_proofs", |b| {
        b.iter(|| {
            let config = CircuitConfig::standard_recursion_zk_config();
            let mut aggregator = WormholeProofAggregator::new(config);

            let proofs = deserialize_proofs(&aggregator.inner.inner_verifier.circuit_data.common);

            for proof in proofs.clone() {
                aggregator.push_proof(proof).unwrap();
            }

            aggregator.aggregate().unwrap();
            aggregator.prove().unwrap();
        });
    });
}

criterion_group!(
    name = benches;
    config = Criterion::default()
        .measurement_time(Duration::from_secs(MEASUREMENT_TIME_S))
        .sample_size(10);
    targets = aggregate_proofs_benchmark
);
criterion_main!(benches);
