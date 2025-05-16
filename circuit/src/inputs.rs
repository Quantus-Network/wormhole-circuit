/// Inputs required to commit to the wormhole circuit.
#[derive(Debug)]
pub struct CircuitInputs {
    /// The amount sent in the funding transaction.
    pub funding_amount: u64,
    /// Amount to be withdrawn.
    pub exit_amount: u64,
    /// The fee for the transaction.
    pub fee_amount: u64,
    /// Raw bytes of the nullifier preimage, used to prevent double spends.
    pub nullifier_preimage: Vec<u8>,
    /// Raw bytes of the unspendable account preimage.
    pub unspendable_account_preimage: Vec<u8>,
    /// A sequence of key-value nodes representing the storage proof.
    ///
    /// Each element is a tuple where the items are the left and right splits of a proof node split
    /// in half at the expected childs hash index.
    pub storage_proof: Vec<(Vec<u8>, Vec<u8>)>,
    /// The root hash of the storage trie.
    pub root_hash: [u8; 32],
    /// The address of the account to pay out to.
    pub exit_account: [u8; 32],
    /// The nonce of the funding transaction
    pub funding_nonce: u32,
    /// The account that funded the unspendable account
    pub funding_account: [u8; 32],
    /// The account that was funded
    pub unspendable_account: [u8; 32],
}

#[cfg(any(test, feature = "testing"))]
pub mod test_helpers {

    use crate::nullifier;
    use crate::storage_proof::test_helpers::{default_proof, ROOT_HASH};
    use crate::unspendable_account;

    use super::CircuitInputs;

    impl Default for CircuitInputs {
        fn default() -> Self {
            let nullifier_preimage = hex::decode(nullifier::test_helpers::PREIMAGE).unwrap();
            let unspendable_account_preimage =
                hex::decode(unspendable_account::test_helpers::PREIMAGES[0]).unwrap();
            let root_hash: [u8; 32] = hex::decode(ROOT_HASH).unwrap().try_into().unwrap();
            Self {
                funding_amount: 0,
                exit_amount: 0,
                fee_amount: 0,
                nullifier_preimage,
                unspendable_account_preimage,
                storage_proof: default_proof(),
                root_hash,
                exit_account: [254u8; 32],
            }
        }
    }
}
