use anyhow::bail;
use plonky2::{
    iop::witness::PartialWitness,
    plonk::{
        circuit_builder::CircuitBuilder,
        circuit_data::{CircuitConfig, CircuitData},
    },
};
use wormhole_circuit::circuit::{CircuitFragment, C, D, F};
use wormhole_verifier::ProofWithPublicInputs;

use crate::{
    circuit::{WormholeProofAggregatorInner, WormholeProofAggregatorTargets},
    MAX_NUM_PROOFS_TO_AGGREGATE,
};

/// A circuit that aggregates proofs from the Wormhole circuit.
pub struct WormholeProofAggregator {
    pub inner: WormholeProofAggregatorInner,
    pub circuit_data: CircuitData<F, C, D>,
    partial_witness: PartialWitness<F>,
    targets: WormholeProofAggregatorTargets,
    pub proofs_buffer: Option<Vec<ProofWithPublicInputs<F, C, D>>>,
}

impl Default for WormholeProofAggregator {
    fn default() -> Self {
        let config = CircuitConfig::standard_recursion_zk_config();
        Self::new(config)
    }
}

impl WormholeProofAggregator {
    pub fn new(config: CircuitConfig) -> Self {
        let inner = WormholeProofAggregatorInner::new(config.clone());
        let mut builder = CircuitBuilder::<F, D>::new(config.clone());

        // Setup targets.
        let targets = WormholeProofAggregatorTargets::new(&mut builder, config);

        // Setup circuits.
        WormholeProofAggregatorInner::circuit(&targets, &mut builder);
        let circuit_data = builder.build();
        let partial_witness = PartialWitness::new();
        let proofs_buffer = Some(Vec::with_capacity(MAX_NUM_PROOFS_TO_AGGREGATE));

        Self {
            inner,
            circuit_data,
            partial_witness,
            targets,
            proofs_buffer,
        }
    }

    pub fn push_proof(&mut self, proof: ProofWithPublicInputs<F, C, D>) -> anyhow::Result<()> {
        if let Some(proofs_buffer) = self.proofs_buffer.as_mut() {
            if proofs_buffer.len() >= MAX_NUM_PROOFS_TO_AGGREGATE {
                bail!("tried to add proof when proof buffer is full")
            }
            proofs_buffer.push(proof);
        } else {
            self.proofs_buffer = Some(vec![proof]);
        }

        Ok(())
    }

    pub fn aggregate(&mut self) -> anyhow::Result<()> {
        let Some(proofs) = self.proofs_buffer.take() else {
            bail!("there are no proofs to aggregate")
        };

        self.inner.set_proofs(proofs)?;
        self.inner
            .fill_targets(&mut self.partial_witness, self.targets.clone())?;

        Ok(())
    }

    /// Prove the circuit with commited values. It's necessary to call [`WormholeProofAggregator::aggregate`]
    /// before running this function.
    ///
    /// # Errors
    ///
    /// Returns an error if the prover has not commited to any inputs.
    pub fn prove(self) -> anyhow::Result<ProofWithPublicInputs<F, C, D>> {
        self.circuit_data.prove(self.partial_witness)
    }
}
