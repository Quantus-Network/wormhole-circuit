use anyhow::bail;
use plonky2::plonk::proof::ProofWithPublicInputs;

use crate::utils::{felts_to_bytes, felts_to_u128};
use crate::{
    circuit::{C, D, F},
    codec::FieldElementCodec,
    nullifier::Nullifier,
    substrate_account::SubstrateAccount,
    unspendable_account::UnspendableAccount,
};

/// The total size of the public inputs field element vector.
const PUBLIC_INPUTS_FELTS_LEN: usize = 16;

/// Inputs required to commit to the wormhole circuit.
#[derive(Debug)]
pub struct CircuitInputs {
    pub public: PublicCircuitInputs,
    pub private: PrivateCircuitInputs,
}

/// All of the public inputs required for the circuit.
#[derive(Debug)]
pub struct PublicCircuitInputs {
    /// Amount to be withdrawn.
    pub funding_amount: u128,
    /// The nullifier.
    pub nullifier: Nullifier,
    /// The root hash of the storage trie.
    pub root_hash: [u8; 32],
    /// The address of the account to pay out to.
    pub exit_account: SubstrateAccount,
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

        // TODO: Create constants for the indices where each field is expected in the public
        // inputs.
        let funding_amount = felts_to_u128(public_inputs[0..2].try_into()?);
        let nullifier = Nullifier::from_field_elements(&public_inputs[2..6])?;

        let root_hash: [u8; 32] = felts_to_bytes(&public_inputs[6..10])
            .try_into()
            .map_err(|_| anyhow::anyhow!("failed to deserialize root hash from public inputs"))?;

        let exit_account = SubstrateAccount::from_field_elements(&public_inputs[10..14])?;

        Ok(PublicCircuitInputs {
            funding_amount,
            nullifier,
            root_hash,
            exit_account,
        })
    }
}

/// All of the private inputs required for the circuit.
#[derive(Debug)]
pub struct PrivateCircuitInputs {
    /// Raw bytes of the secret of the nullifier and the unspendable account
    pub secret: Vec<u8>,
    /// A sequence of key-value nodes representing the storage proof.
    ///
    /// Each element is a tuple where the items are the left and right splits of a proof node split
    /// in half at the expected childs hash index.
    pub storage_proof: Vec<(Vec<u8>, Vec<u8>)>,
    pub funding_nonce: u32,
    pub funding_account: SubstrateAccount,
    /// The unspendable account hash.
    pub unspendable_account: UnspendableAccount,
}

#[cfg(any(test, feature = "testing"))]
pub mod test_helpers {
    use crate::nullifier::test_helpers::{FUNDING_ACCOUNT, FUNDING_NONCE, SECRET};
    use crate::nullifier::Nullifier;
    use crate::storage_proof::test_helpers::{default_proof, ROOT_HASH};
    use crate::substrate_account::SubstrateAccount;
    use crate::unspendable_account::UnspendableAccount;

    use super::{CircuitInputs, PrivateCircuitInputs, PublicCircuitInputs};

    impl Default for CircuitInputs {
        fn default() -> Self {
            let secret = hex::decode(SECRET).unwrap();
            let root_hash: [u8; 32] = hex::decode(ROOT_HASH).unwrap().try_into().unwrap();

            let funding_account = SubstrateAccount::new(FUNDING_ACCOUNT).unwrap();
            let nullifier = Nullifier::new(&secret, FUNDING_NONCE, FUNDING_ACCOUNT);
            let unspendable_account = UnspendableAccount::new(&secret);
            let exit_account = SubstrateAccount::new(&[254u8; 32]).unwrap();

            Self {
                public: PublicCircuitInputs {
                    funding_amount: 0,
                    nullifier,
                    root_hash,
                    exit_account,
                },
                private: PrivateCircuitInputs {
                    secret,
                    storage_proof: default_proof(),
                    funding_nonce: 0,
                    funding_account,
                    unspendable_account,
                },
            }
        }
    }
}
