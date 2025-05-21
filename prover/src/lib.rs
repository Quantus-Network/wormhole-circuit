//! Prover logic for the Wormhole circuit.
//!
//! This module provides the [`WormholeProver`] type, which allows committing inputs to the circuit
//! and generating a zero-knowledge proof using those inputs.
//!
//! The typical usage flow involves:
//! 1. Initializing the prover (e.g., via [`WormholeProver::default`] or [`WormholeProver::new`]).
//! 2. Creating user inputs with [`CircuitInputs`].
//! 3. Committing user inputs using [`WormholeProver::commit`].
//! 4. Generating a proof using [`WormholeProver::prove`].
//!
//! # Example
//!
//! ```
//! use wormhole_circuit::inputs::CircuitInputs;
//! use wormhole_prover::WormholeProver;
//!
//! # fn main() -> anyhow::Result<()> {
//! # let inputs = CircuitInputs::default();
//! let prover = WormholeProver::new();
//! let proof = prover.commit(&inputs)?.prove()?;
//! # Ok(())
//! # }
//! ```
use anyhow::bail;
use plonky2::{
    iop::witness::PartialWitness,
    plonk::{circuit_data::ProverCircuitData, proof::ProofWithPublicInputs},
};

use wormhole_circuit::circuit::{WormholeCircuit, C, D, F};
use wormhole_circuit::{
    amounts::Amounts,
    circuit::{CircuitFragment, CircuitTargets},
    exit_account::ExitAccount,
    inputs::CircuitInputs,
    nullifier::Nullifier,
    storage_proof::StorageProof,
    unspendable_account::UnspendableAccount,
};

#[derive(Debug)]
pub struct WormholeProver {
    pub circuit_data: ProverCircuitData<F, C, D>,
    partial_witness: PartialWitness<F>,
    targets: Option<CircuitTargets>,
}

impl Default for WormholeProver {
    fn default() -> Self {
        let wormhole_circuit = WormholeCircuit::new();
        let partial_witness = PartialWitness::new();

        let targets = Some(wormhole_circuit.targets());
        let circuit_data = wormhole_circuit.build_prover();

        Self {
            circuit_data,
            partial_witness,
            targets,
        }
    }
}

impl WormholeProver {
    /// Creates a new [`WormholeProver`].
    pub fn new() -> Self {
        Self::default()
    }

    /// Commits the provided [`CircuitInputs`] to the circuit by filling relevant targets.
    ///
    /// # Errors
    ///
    /// Returns an error if the prover has already commited to inputs previously.
    pub fn commit(mut self, circuit_inputs: &CircuitInputs) -> anyhow::Result<Self> {
        let Some(targets) = self.targets.take() else {
            bail!("prover has already commited to inputs");
        };

        let amounts = Amounts::from(circuit_inputs);
        let nullifier = Nullifier::from(circuit_inputs);
        let unspendable_account = UnspendableAccount::from(circuit_inputs);
        let storage_proof = StorageProof::from(circuit_inputs);
        let exit_account = ExitAccount::from(circuit_inputs);

        amounts.fill_targets(&mut self.partial_witness, targets.amounts)?;
        nullifier.fill_targets(&mut self.partial_witness, targets.nullifier)?;
        unspendable_account.fill_targets(&mut self.partial_witness, targets.unspendable_account)?;
        storage_proof.fill_targets(&mut self.partial_witness, targets.storage_proof)?;
        exit_account.fill_targets(&mut self.partial_witness, targets.exit_account)?;

        Ok(self)
    }

    /// Prove the circuit with commited values. It's necessary to call [`WormholeProver::commit`]
    /// before running this function.
    ///
    /// # Errors
    ///
    /// Returns an error if the prover has not commited to any inputs.
    pub fn prove(self) -> anyhow::Result<ProofWithPublicInputs<F, C, D>> {
        if self.targets.is_some() {
            bail!("prover has not commited to any inputs")
        }
        self.circuit_data.prove(self.partial_witness)
    }
}

#[cfg(test)]
mod tests {
    use super::WormholeProver;
    use wormhole_circuit::inputs::CircuitInputs;

    #[test]
    #[cfg(feature = "testing")]
    fn commit_and_prove() {
        let prover = WormholeProver::new();
        let inputs = CircuitInputs::default();
        prover.commit(&inputs).unwrap().prove().unwrap();
    }

    #[test]
    #[ignore = "debug"]
    #[cfg(feature = "testing")]
    fn get_public_inputs() {
        let prover = WormholeProver::new();
        let inputs = CircuitInputs::default();
        let proof = prover.commit(&inputs).unwrap().prove().unwrap();
        let public_inputs = proof.public_inputs;
        println!("{:?}", public_inputs);
    }

    #[test]
    #[cfg(feature = "testing")]
    fn proof_can_be_deserialized() {
        use wormhole_circuit::inputs::PublicCircuitInputs;

        let prover = WormholeProver::new();
        let inputs = CircuitInputs::default();
        let proof = prover.commit(&inputs).unwrap().prove().unwrap();
        let public_inputs = PublicCircuitInputs::try_from(proof).unwrap();
        println!("{:?}", public_inputs);
    }
}
