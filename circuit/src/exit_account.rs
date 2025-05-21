use crate::circuit::{CircuitFragment, D};
use crate::codec::ByteCodec;
use crate::inputs::CircuitInputs;
use crate::util::{FieldHash, HASH_NUM_FELTS};
use crate::{circuit::F, codec::FieldElementCodec};
use plonky2::{
    hash::hash_types::HashOutTarget,
    iop::witness::{PartialWitness, WitnessWrite},
    plonk::circuit_builder::CircuitBuilder,
};

#[derive(Debug, Default, Eq, PartialEq, Clone, Copy)]
pub struct ExitAccount(FieldHash);

impl ExitAccount {
    pub fn new(address: [u8; 32]) -> Self {
        let address = FieldHash::from_bytes(address);
        Self(address)
    }
}

impl From<&CircuitInputs> for ExitAccount {
    fn from(inputs: &CircuitInputs) -> Self {
        Self::new(inputs.public.exit_account)
    }
}

impl FieldElementCodec<{ HASH_NUM_FELTS }> for ExitAccount {
    fn to_field_elements(&self) -> Vec<F> {
        self.0.to_vec()
    }

    fn from_field_elements(elements: [F; HASH_NUM_FELTS]) -> Self {
        Self(FieldHash(elements))
    }
}

#[derive(Debug, Clone, Copy)]
pub struct ExitAccountTargets {
    pub address: HashOutTarget,
}

impl ExitAccountTargets {
    pub fn new(builder: &mut CircuitBuilder<F, D>) -> Self {
        Self {
            address: builder.add_virtual_hash_public_input(),
        }
    }
}

impl CircuitFragment for ExitAccount {
    type Targets = ExitAccountTargets;

    /// Builds a dummy circuit to include the exit account as a public input.
    fn circuit(Self::Targets { address: _ }: &Self::Targets, _builder: &mut CircuitBuilder<F, D>) {}

    fn fill_targets(
        &self,
        pw: &mut PartialWitness<F>,
        targets: Self::Targets,
    ) -> anyhow::Result<()> {
        let hash = *self.0;
        pw.set_hash_target(targets.address, hash.into())
    }
}

#[cfg(test)]
mod tests {
    use crate::circuit::{
        tests::{build_and_prove_test, setup_test_builder_and_witness},
        C,
    };
    use plonky2::field::types::{Field, Field64};

    use super::*;
    use plonky2::plonk::proof::ProofWithPublicInputs;

    fn run_test(exit_account: &ExitAccount) -> anyhow::Result<ProofWithPublicInputs<F, C, D>> {
        let (mut builder, mut pw) = setup_test_builder_and_witness();
        let targets = ExitAccountTargets::new(&mut builder);
        ExitAccount::circuit(&targets, &mut builder);

        exit_account.fill_targets(&mut pw, targets).unwrap();
        build_and_prove_test(builder, pw)
    }

    #[test]
    fn run_circuit() {
        let exit_account = ExitAccount::default();
        run_test(&exit_account).unwrap();
    }

    #[test]
    fn test_exit_account_round_trip() -> anyhow::Result<()> {
        let exit_account = ExitAccount::new([42u8; 32]);
        let elements = exit_account.to_field_elements();
        assert_eq!(elements.len(), 4, "Expected 4 field elements");
        let elements_array = elements.try_into().unwrap();
        let decoded = ExitAccount::from_field_elements(elements_array);
        assert_eq!(exit_account, decoded, "Round-trip failed");
        Ok(())
    }

    #[test]
    fn test_exit_account_zero_address() -> anyhow::Result<()> {
        let exit_account = ExitAccount::new([0u8; 32]);
        let elements = exit_account.to_field_elements();
        assert_eq!(elements.len(), 4, "Expected 4 field elements");
        assert_eq!(
            elements,
            vec![F::ZERO; 4],
            "Zero address should encode to zero elements"
        );
        let elements_array = elements.try_into().unwrap();
        let decoded = ExitAccount::from_field_elements(elements_array);
        assert_eq!(exit_account, decoded, "Zero address round-trip failed");
        Ok(())
    }

    #[test]
    fn test_exit_account_max_address() -> anyhow::Result<()> {
        let exit_account = ExitAccount::new([255u8; 32]);
        let elements = exit_account.to_field_elements();
        assert_eq!(elements.len(), 4, "Expected 4 field elements");
        // Each element should be u64::MAX (0xFFFFFFFFFFFFFFFF)
        let expected_value = F::from_noncanonical_u64(u64::MAX);
        assert_eq!(
            elements,
            vec![expected_value; 4],
            "Max address encoding incorrect"
        );
        let elements_array = elements.try_into().unwrap();
        let decoded = ExitAccount::from_field_elements(elements_array);
        assert_eq!(exit_account, decoded, "Max address round-trip failed");
        Ok(())
    }

    #[test]
    fn test_exit_account_specific_address() -> anyhow::Result<()> {
        let mut address = [0u8; 32];
        address[0] = 1;
        address[31] = 255; // Non-zero first and last bytes
        let exit_account = ExitAccount::new(address);
        let elements = exit_account.to_field_elements();
        assert_eq!(elements.len(), 4, "Expected 4 field elements");
        // First element: 0x0000000000000001 (little-endian)
        // Last element: 0xFF00000000000000
        let expected_first = F::from_canonical_u64(1);
        let expected_last = F::from_canonical_u64((255u64 << 56) % F::ORDER);
        assert_eq!(elements[0], expected_first, "First element incorrect");
        assert_eq!(elements[3], expected_last, "Last element incorrect");
        let elements_array = elements.try_into().unwrap();
        let decoded = ExitAccount::from_field_elements(elements_array);
        assert_eq!(exit_account, decoded, "Specific address round-trip failed");
        Ok(())
    }
}
