use plonky2::{
    field::types::Field,
    iop::{
        target::Target,
        witness::{PartialWitness, WitnessWrite},
    },
    plonk::circuit_builder::CircuitBuilder,
};

use crate::circuit::{CircuitFragment, D, F};
use crate::inputs::CircuitInputs;

#[derive(Debug, Default, PartialEq, Eq)]
pub struct Amounts {
    /// The amount that a wormhole deposit adress was funded with
    pub funding_tx_amount: F,
    /// Amount to be given to exit account
    pub exit_amount: F,
    /// Amount to be given to miner
    pub fee_amount: F,
}

impl Amounts {
    pub fn new(funding_tx_amount: u64, exit_amount: u64, fee_amount: u64) -> Self {
        Self {
            funding_tx_amount: F::from_noncanonical_u64(funding_tx_amount),
            exit_amount: F::from_noncanonical_u64(exit_amount),
            fee_amount: F::from_noncanonical_u64(fee_amount),
        }
    }
}

impl From<&CircuitInputs> for Amounts {
    fn from(inputs: &CircuitInputs) -> Self {
        Self::new(
            inputs.public.funding_tx_amount,
            inputs.public.exit_amount,
            inputs.public.fee_amount,
        )
    }
}

#[derive(Debug, Clone, Copy)]
pub struct AmountsTargets {
    pub funding_tx_amount: Target,
    pub exit_amount: Target,
    pub fee_amount: Target,
}

impl AmountsTargets {
    pub fn new(builder: &mut CircuitBuilder<F, D>) -> Self {
        Self {
            funding_tx_amount: builder.add_virtual_public_input(),
            exit_amount: builder.add_virtual_public_input(),
            fee_amount: builder.add_virtual_public_input(),
        }
    }
}

impl CircuitFragment for Amounts {
    type Targets = AmountsTargets;

    /// Builds a circuit that asserts `funding_tx_amount = exit_amount + fee_amount`.
    fn circuit(
        &Self::Targets {
            funding_tx_amount,
            exit_amount,
            fee_amount,
        }: &Self::Targets,
        builder: &mut CircuitBuilder<F, D>,
    ) {
        let sum = builder.add(exit_amount, fee_amount);
        builder.connect(sum, funding_tx_amount);
    }

    fn fill_targets(
        &self,
        pw: &mut PartialWitness<F>,
        targets: Self::Targets,
    ) -> anyhow::Result<()> {
        pw.set_target(targets.funding_tx_amount, self.funding_tx_amount)?;
        pw.set_target(targets.exit_amount, self.exit_amount)?;
        pw.set_target(targets.fee_amount, self.fee_amount)
    }
}

#[cfg(test)]
mod tests {
    use crate::circuit::{
        tests::{build_and_prove_test, setup_test_builder_and_witness},
        C,
    };

    use super::*;
    use plonky2::plonk::proof::ProofWithPublicInputs;

    fn run_test(amounts: &Amounts) -> anyhow::Result<ProofWithPublicInputs<F, C, D>> {
        let (mut builder, mut pw) = setup_test_builder_and_witness();
        let targets = AmountsTargets::new(&mut builder);
        Amounts::circuit(&targets, &mut builder);

        amounts.fill_targets(&mut pw, targets).unwrap();
        build_and_prove_test(builder, pw)
    }

    #[test]
    fn test_valid_amounts() {
        let amounts = Amounts::new(100, 60, 40);
        run_test(&amounts).unwrap();
    }

    #[test]
    fn test_invalid_amounts_wrong_sum() {
        let amounts = Amounts::new(100, 50, 30);
        let result = run_test(&amounts);
        assert!(result.is_err());
    }

    #[test]
    fn test_zero_amounts() {
        let amounts = Amounts::new(0, 0, 0);
        run_test(&amounts).unwrap();
    }

    #[test]
    fn test_exit_only_no_fee() {
        let amounts = Amounts::new(100, 100, 0);
        run_test(&amounts).unwrap();
    }

    #[test]
    fn test_fee_only_no_exit() {
        let amounts = Amounts::new(100, 0, 100);
        run_test(&amounts).unwrap();
    }

    #[test]
    fn test_max_amounts() {
        let amounts = Amounts::new(u64::MAX, u64::MAX - 1, 1);
        run_test(&amounts).unwrap();
    }

    #[test]
    #[should_panic(expected = "set twice with different values")]
    fn test_underflow() {
        let amounts = Amounts::new(0, u64::MAX, 1);
        run_test(&amounts).unwrap();
    }

    #[test]
    fn test_invalid_large_fee() {
        let amounts = Amounts::new(100, 10, 100);
        let result = run_test(&amounts);
        assert!(result.is_err());
    }
}
