/// A verifier for the wormhole circuit.
///
///# Example
///
/// Create a verifier and verify a proof:
///
///```
/// use wormhole_circuit::inputs::CircuitInputs;
/// use wormhole_prover::WormholeProver;
/// use wormhole_verifier::WormholeVerifier;
/// #
/// # fn main() -> anyhow::Result<()> {
/// # let inputs = CircuitInputs::default();
/// # let prover = WormholeProver::new();
/// # let proof = prover.commit(&inputs)?.prove()?;
///
/// let verifier = WormholeVerifier::new();
/// verifier.verify(proof)?;
/// # Ok(())
/// # }
/// ```
use plonky2::plonk::{circuit_data::VerifierCircuitData, proof::ProofWithPublicInputs};

use wormhole_circuit::circuit::{WormholeCircuit, C, D, F};

pub struct WormholeVerifier {
    pub circuit_data: VerifierCircuitData<F, C, D>,
}

impl Default for WormholeVerifier {
    fn default() -> Self {
        let wormhole_circuit = WormholeCircuit::new();
        let circuit_data = wormhole_circuit.build_verifier();

        Self { circuit_data }
    }
}

impl WormholeVerifier {
    /// Creates a new [`WormholeVerifier`].
    pub fn new() -> Self {
        Self::default()
    }

    /// Verify a [`ProofWithPublicInputs`] generated from a [`crate::prover::WormholeProver`].
    ///
    /// # Errors
    ///
    /// Returns an error if the proof is not valid.
    pub fn verify(&self, proof: ProofWithPublicInputs<F, C, D>) -> anyhow::Result<()> {
        self.circuit_data.verify(proof)
    }
}

#[cfg(test)]
mod tests {
    use super::WormholeVerifier;
    use plonky2::plonk::proof::ProofWithPublicInputs;
    use wormhole_circuit::codec::FieldElementCodec;
    use wormhole_circuit::exit_account::ExitAccount;
    use wormhole_circuit::inputs::CircuitInputs;
    use wormhole_prover::WormholeProver;

    #[test]
    fn verify_simple_proof() {
        let prover = WormholeProver::new();
        let inputs = CircuitInputs::default();
        let proof = prover.commit(&inputs).unwrap().prove().unwrap();

        let verifier = WormholeVerifier::new();
        verifier.verify(proof).unwrap();
    }

    #[test]
    fn cannot_verify_with_modified_exit_account() {
        let prover = WormholeProver::new();
        let inputs = CircuitInputs::default();
        let mut proof = prover.commit(&inputs).unwrap().prove().unwrap();

        println!("proof before: {:?}", proof.public_inputs);
        let exit_account = &proof.public_inputs[15..19];
        println!("exit_account: {:?}", exit_account);
        let modified_exit_account = ExitAccount::new([8u8; 32]);
        proof.public_inputs[15..19].copy_from_slice(&modified_exit_account.to_field_elements());
        println!("proof after: {:?}", proof.public_inputs);

        let verifier = WormholeVerifier::new();
        let result = verifier.verify(proof);
        assert!(
            result.is_err(),
            "Expected proof to fail with modified exit_account"
        );
    }

    #[test]
    fn cannot_verify_with_any_public_input_modification() {
        let prover = WormholeProver::new();
        let inputs = CircuitInputs::default();
        let proof = prover.commit(&inputs).unwrap().prove().unwrap();
        let verifier = WormholeVerifier::new();

        for ix in 0..proof.public_inputs.len() {
            let mut p = proof.clone();
            for jx in 0..8 {
                p.public_inputs[ix].0 ^= 255 << (8 * jx);
                let result = verifier.verify(p.clone());
                assert!(
                    result.is_err(),
                    "Expected proof to fail with modified inputs"
                );
            }
        }
    }

    #[ignore]
    #[test]
    fn cannot_verify_with_modified_proof() {
        let prover = WormholeProver::new();
        let inputs = CircuitInputs::default();
        let proof = prover.commit(&inputs).unwrap().prove().unwrap();
        let verifier = WormholeVerifier::new();

        let proof_bytes = proof.to_bytes();
        println!("proof length: {:?}", proof_bytes.len());
        for ix in 0..proof_bytes.len() {
            println!("proof_bytes[{}]: {:?}", ix, proof_bytes[ix]);
            let mut b = proof_bytes.clone();
            b[ix] ^= 255;
            let result1 = ProofWithPublicInputs::from_bytes(b, &verifier.circuit_data.common);
            match result1 {
                Ok(p) => {
                    let result2 = verifier.verify(p.clone());
                    assert!(result2.is_err(), "Expected modified proof to fail");
                }
                Err(_) => {
                    continue;
                }
            }
        }
    }
}
