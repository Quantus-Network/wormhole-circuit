use anyhow::bail;
use plonky2::{
    iop::witness::{PartialWitness, WitnessWrite},
    plonk::{
        circuit_builder::CircuitBuilder,
        circuit_data::{CircuitConfig, CommonCircuitData, VerifierCircuitTarget},
        proof::ProofWithPublicInputsTarget,
    },
};
use wormhole_circuit::circuit::{CircuitFragment, C, D, F};
use wormhole_verifier::{ProofWithPublicInputs, WormholeVerifier};

use crate::MAX_NUM_PROOFS_TO_AGGREGATE;

#[cfg(not(feature = "no_zk"))]
const DUMMY_PROOF_BYTES: &[u8] = include_bytes!("../data/dummy_proof_zk.bin");
#[cfg(feature = "no_zk")]
const DUMMY_PROOF_BYTES: &[u8] = include_bytes!("../data/dummy_proof.bin");

#[derive(Debug, Clone)]
pub struct WormholeProofAggregatorTargets {
    verifier_data: VerifierCircuitTarget,
    proofs: [ProofWithPublicInputsTarget<D>; MAX_NUM_PROOFS_TO_AGGREGATE],
    // HACK: This allows us to only create `circuit_data` once.
    circuit_data: CommonCircuitData<F, D>,
}

impl WormholeProofAggregatorTargets {
    pub fn new(builder: &mut CircuitBuilder<F, D>, config: CircuitConfig) -> Self {
        let circuit_data = WormholeVerifier::new(config, None).circuit_data.common;
        let verifier_data =
            builder.add_virtual_verifier_data(circuit_data.fri_params.config.cap_height);

        // Setup targets for proofs.
        let mut proofs = Vec::with_capacity(MAX_NUM_PROOFS_TO_AGGREGATE);
        for _ in 0..MAX_NUM_PROOFS_TO_AGGREGATE {
            proofs.push(builder.add_virtual_proof_with_pis(&circuit_data));
        }

        let proofs: [ProofWithPublicInputsTarget<D>; MAX_NUM_PROOFS_TO_AGGREGATE] =
            std::array::from_fn(|_| builder.add_virtual_proof_with_pis(&circuit_data));

        Self {
            verifier_data,
            proofs,
            circuit_data,
        }
    }
}

pub struct WormholeProofAggregatorInner {
    pub inner_verifier: WormholeVerifier,
    num_proofs: usize,
    proofs: Vec<ProofWithPublicInputs<F, C, D>>,
}

impl WormholeProofAggregatorInner {
    pub fn new(config: CircuitConfig) -> Self {
        let inner_verifier = WormholeVerifier::new(config, None);
        Self {
            inner_verifier,
            num_proofs: 0,
            proofs: Vec::with_capacity(MAX_NUM_PROOFS_TO_AGGREGATE),
        }
    }

    pub fn set_proofs(
        &mut self,
        proofs: Vec<ProofWithPublicInputs<F, C, D>>,
    ) -> anyhow::Result<()> {
        let num_proofs = proofs.len();

        if num_proofs > MAX_NUM_PROOFS_TO_AGGREGATE {
            bail!("proofs to aggregate was more than the maximum allowed")
        }

        // Move proof data from the aggregater, to be used the circuit.
        self.num_proofs = num_proofs;
        self.proofs = proofs;

        let dummy_proof = ProofWithPublicInputs::from_bytes(
            DUMMY_PROOF_BYTES.to_vec(),
            &self.inner_verifier.circuit_data.common,
        )?;
        for _ in 0..(MAX_NUM_PROOFS_TO_AGGREGATE - num_proofs) {
            self.proofs.push(dummy_proof.clone());
        }

        Ok(())
    }
}

impl CircuitFragment for WormholeProofAggregatorInner {
    type Targets = WormholeProofAggregatorTargets;

    fn circuit(
        Self::Targets {
            verifier_data,
            proofs,
            circuit_data,
        }: &Self::Targets,
        builder: &mut CircuitBuilder<F, D>,
    ) {
        // Verify each aggregated proof separately.
        for proof in proofs {
            builder.verify_proof::<C>(proof, verifier_data, circuit_data);
        }
    }

    fn fill_targets(
        &self,
        pw: &mut PartialWitness<F>,
        targets: Self::Targets,
    ) -> anyhow::Result<()> {
        for (proof_target, proof) in targets.proofs.iter().zip(self.proofs.iter()) {
            pw.set_proof_with_pis_target(proof_target, proof)?;
        }

        pw.set_verifier_data_target(
            &targets.verifier_data,
            &self.inner_verifier.circuit_data.verifier_only,
        )
    }
}
