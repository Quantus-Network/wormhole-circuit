use anyhow::bail;
use plonky2::{field::types::PrimeField64, plonk::proof::ProofWithPublicInputs};

use crate::{
    circuit::{C, D, F},
    util::field_elements_to_bytes,
};

const PUBLIC_INPUTS_FELTS_LEN: usize = 19;

/// Inputs required to commit to the wormhole circuit.
#[derive(Debug)]
pub struct CircuitInputs {
    pub public: PublicCircuitInputs,
    pub private: PrivateCircuitInputs,
}

/// All of the public inputs required for the circuit.
#[derive(Debug)]
pub struct PublicCircuitInputs {
    /// The amount sent in the transaction.
    pub funding_tx_amount: u64,
    /// Amount to be withdrawn.
    pub exit_amount: u64,
    /// The fee for the transaction.
    pub fee_amount: u64,
    /// The nullifier.
    pub nullifier: [u8; 32],
    /// The unspendable account hash.
    pub unspendable_account: [u8; 32],
    /// The root hash of the storage trie.
    pub root_hash: [u8; 32],
    /// The address of the account to pay out to.
    pub exit_account: [u8; 32],
}

impl TryFrom<ProofWithPublicInputs<F, C, D>> for PublicCircuitInputs {
    type Error = anyhow::Error;

    fn try_from(proof: ProofWithPublicInputs<F, C, D>) -> Result<Self, Self::Error> {
        let public_inputs = proof.public_inputs;

        if public_inputs.len() != PUBLIC_INPUTS_FELTS_LEN {
            bail!(
                "public inputs should contain: {} field elements, got: {}",
                PUBLIC_INPUTS_FELTS_LEN,
                public_inputs.len()
            )
        }

        let funding_tx_amount = public_inputs[0].to_noncanonical_u64();
        let exit_amount = public_inputs[1].to_noncanonical_u64();
        let fee_amount = public_inputs[2].to_noncanonical_u64();

        let nullifier = field_elements_to_bytes(&public_inputs[3..7])
            .try_into()
            .map_err(|_| anyhow::anyhow!("failed to deserialize bytes into nullifier hash"))?;
        let unspendable_account = field_elements_to_bytes(&public_inputs[7..11])
            .try_into()
            .map_err(|_| {
                anyhow::anyhow!("failed to deserialize bytes into unspendable account hash")
            })?;

        let root_hash: [u8; 32] = field_elements_to_bytes(&public_inputs[11..15])
            .try_into()
            .map_err(|_| anyhow::anyhow!("failed to deserialize root hash from public inputs"))?;

        let exit_account: [u8; 32] = field_elements_to_bytes(&public_inputs[15..19])
            .try_into()
            .map_err(|_| {
                anyhow::anyhow!("failed to deserialize exit account from public inputs")
            })?;

        Ok(PublicCircuitInputs {
            funding_tx_amount,
            exit_amount,
            fee_amount,
            nullifier,
            unspendable_account,
            root_hash,
            exit_account,
        })
    }
}

/// All of the private inputs required for the circuit.
#[derive(Debug)]
pub struct PrivateCircuitInputs {
    /// Raw bytes of the nullifier preimage, used to prevent double spends.
    pub nullifier_preimage: Vec<u8>,
    /// Raw bytes of the unspendable account preimage.
    pub unspendable_account_preimage: Vec<u8>,
    /// A sequence of key-value nodes representing the storage proof.
    ///
    /// Each element is a tuple where the items are the left and right splits of a proof node split
    /// in half at the expected childs hash index.
    pub storage_proof: Vec<(Vec<u8>, Vec<u8>)>,
}

#[cfg(any(test, feature = "testing"))]
pub mod test_helpers {
    use crate::codec::ByteCodec;
    use crate::nullifier::{self, Nullifier};
    use crate::storage_proof::test_helpers::{default_proof, ROOT_HASH};
    use crate::unspendable_account::{self};

    use super::{CircuitInputs, PrivateCircuitInputs, PublicCircuitInputs};

    impl Default for CircuitInputs {
        fn default() -> Self {
            let nullifier_preimage = hex::decode(nullifier::test_helpers::PREIMAGE).unwrap();
            let unspendable_account_preimage =
                hex::decode(unspendable_account::test_helpers::PREIMAGES[0]).unwrap();
            let root_hash: [u8; 32] = hex::decode(ROOT_HASH).unwrap().try_into().unwrap();

            // FIXME: This should be precomputed.
            let nullifier = Nullifier::from_preimage(&nullifier_preimage)
                .hash
                .to_bytes()
                .try_into()
                .unwrap();
            let unspendable_account = hex::decode(unspendable_account::test_helpers::ADRESSES[0])
                .unwrap()
                .try_into()
                .unwrap();

            let exit_account = [0u8; 32];

            Self {
                public: PublicCircuitInputs {
                    funding_tx_amount: 0,
                    exit_amount: 0,
                    fee_amount: 0,
                    nullifier,
                    unspendable_account,
                    root_hash,
                    exit_account,
                },
                private: PrivateCircuitInputs {
                    nullifier_preimage,
                    unspendable_account_preimage,
                    storage_proof: default_proof(),
                },
            }
        }
    }
}
