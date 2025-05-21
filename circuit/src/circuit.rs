//! Wormhole Circuit.
//!
//! This module defines the zero-knowledge circuit for the Wormhole protocol.
use crate::amounts::{Amounts, AmountsTargets};
use crate::exit_account::{ExitAccount, ExitAccountTargets};
use crate::nullifier::{Nullifier, NullifierTargets};
use crate::storage_proof::{StorageProof, StorageProofTargets};
use crate::unspendable_account::{UnspendableAccount, UnspendableAccountTargets};
use plonky2::field::goldilocks_field::GoldilocksField;
use plonky2::plonk::circuit_data::CircuitData;
use plonky2::{
    iop::witness::PartialWitness,
    plonk::{
        circuit_builder::CircuitBuilder,
        circuit_data::{CircuitConfig, ProverCircuitData, VerifierCircuitData},
        config::PoseidonGoldilocksConfig,
    },
};

// Plonky2 setup parameters.
pub const D: usize = 2; // D=2 provides 100-bits of security
pub type C = PoseidonGoldilocksConfig;
pub type F = GoldilocksField;

pub trait CircuitFragment {
    /// The targets that the circuit operates on. These are constrained in the circuit definition
    /// and filled with [`Self::fill_targets`].
    type Targets;

    /// Builds a circuit with the operating wires being provided by `Self::Targets`.
    fn circuit(targets: &Self::Targets, builder: &mut CircuitBuilder<F, D>);

    /// Fills the targets in the partial witness with the provided inputs.
    fn fill_targets(
        &self,
        pw: &mut PartialWitness<F>,
        targets: Self::Targets,
    ) -> anyhow::Result<()>;
}

#[derive(Debug, Clone)]
pub struct CircuitTargets {
    pub amounts: AmountsTargets,
    pub nullifier: NullifierTargets,
    pub unspendable_account: UnspendableAccountTargets,
    pub storage_proof: StorageProofTargets,
    pub exit_account: ExitAccountTargets,
}

impl CircuitTargets {
    pub fn new(builder: &mut CircuitBuilder<F, D>) -> Self {
        Self {
            amounts: AmountsTargets::new(builder),
            nullifier: NullifierTargets::new(builder),
            unspendable_account: UnspendableAccountTargets::new(builder),
            storage_proof: StorageProofTargets::new(builder),
            exit_account: ExitAccountTargets::new(builder),
        }
    }
}

pub struct WormholeCircuit {
    builder: CircuitBuilder<F, D>,
    targets: CircuitTargets,
}

impl Default for WormholeCircuit {
    fn default() -> Self {
        let config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<F, D>::new(config);

        // Setup targets.
        let targets = CircuitTargets::new(&mut builder);

        // Setup circuits.
        Amounts::circuit(&targets.amounts, &mut builder);
        Nullifier::circuit(&targets.nullifier, &mut builder);
        UnspendableAccount::circuit(&targets.unspendable_account, &mut builder);
        StorageProof::circuit(&targets.storage_proof, &mut builder);
        ExitAccount::circuit(&targets.exit_account, &mut builder);

        Self { builder, targets }
    }
}

impl WormholeCircuit {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn targets(&self) -> CircuitTargets {
        self.targets.clone()
    }

    pub fn build_circuit(self) -> CircuitData<F, C, D> {
        self.builder.build()
    }

    pub fn build_prover(self) -> ProverCircuitData<F, C, D> {
        self.builder.build_prover()
    }

    pub fn build_verifier(self) -> VerifierCircuitData<F, C, D> {
        self.builder.build_verifier()
    }
}

#[cfg(any(test, feature = "testing"))]
pub mod tests {
    use plonky2::plonk::proof::ProofWithPublicInputs;

    use super::*;

    /// Convenince function for initializing a test circuit environment.
    pub fn setup_test_builder_and_witness() -> (CircuitBuilder<F, D>, PartialWitness<F>) {
        let config = CircuitConfig::standard_recursion_config();
        let builder = CircuitBuilder::<F, D>::new(config);
        let pw = PartialWitness::new();

        (builder, pw)
    }

    /// Convenince function for building and verifying a test function. The circuit is assumed to
    /// have been setup prior to calling this function.
    pub fn build_and_prove_test(
        builder: CircuitBuilder<F, D>,
        pw: PartialWitness<F>,
    ) -> anyhow::Result<ProofWithPublicInputs<F, C, D>> {
        let data = builder.build::<C>();
        data.prove(pw)
    }

    #[test]
    fn field_hash_codec() {
        use crate::{codec::FieldElementCodec, util::FieldHash};
        use plonky2::field::types::Field;

        let nullifier = FieldHash([
            F::from_noncanonical_u64(1),
            F::from_noncanonical_u64(2),
            F::from_noncanonical_u64(3),
            F::from_noncanonical_u64(4),
        ]);

        // Encode the account as field elements and compare.
        let field_elements = nullifier.to_field_elements();
        assert_eq!(field_elements.len(), 4);
        assert_eq!(field_elements[0], F::from_noncanonical_u64(1));
        assert_eq!(field_elements[1], F::from_noncanonical_u64(2));
        assert_eq!(field_elements[2], F::from_noncanonical_u64(3));
        assert_eq!(field_elements[3], F::from_noncanonical_u64(4));

        let field_elements_array = field_elements.try_into().unwrap();

        // Decode the field elements back into an UnspendableAccount
        let recovered_nullifier = FieldHash::from_field_elements(field_elements_array);
        assert_eq!(nullifier, recovered_nullifier);
    }
}
