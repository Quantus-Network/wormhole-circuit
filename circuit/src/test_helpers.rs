use storage_proof::{default_storage_proof, DEFAULT_ROOT_HASH};

use crate::inputs::{CircuitInputs, PrivateCircuitInputs, PublicCircuitInputs};
use crate::nullifier::Nullifier;
use crate::substrate_account::SubstrateAccount;
use crate::unspendable_account::UnspendableAccount;

pub const DEFAULT_SECRET: &str = "9aa84f99ef2de22e3070394176868df41d6a148117a36132d010529e19b018b7";
pub const DEFAULT_FUNDING_NONCE: u32 = 0;
pub const DEFAULT_FUNDING_ACCOUNT: &[u8] = &[10u8; 32];

impl CircuitInputs {
    pub fn test_inputs() -> Self {
        let secret = hex::decode(DEFAULT_SECRET).unwrap();
        let root_hash: [u8; 32] = hex::decode(DEFAULT_ROOT_HASH).unwrap().try_into().unwrap();

        let funding_account = SubstrateAccount::new(DEFAULT_FUNDING_ACCOUNT).unwrap();
        let nullifier = Nullifier::new(&secret, DEFAULT_FUNDING_NONCE, DEFAULT_FUNDING_ACCOUNT);
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
                storage_proof: default_storage_proof(),
                funding_nonce: 0,
                funding_account,
                unspendable_account,
            },
        }
    }
}

pub mod storage_proof {
    use plonky2::field::types::Field;

    use crate::{
        circuit::F,
        storage_proof::{LeafInputs, StorageProof},
    };

    pub const DEFAULT_ROOT_HASH: &str =
        "77eb9d80cd12acfd902b459eb3b8876f05f31ef6a17ed5fdb060ee0e86dd8139";
    pub const DEFAULT_STORAGE_PROOF: [(&str, &str); 3] = [
        (
            "802cb08072547dce8ca905abf49c9c644951ff048087cc6f4b497fcc6c24e5592da3bc6a80c9f21db91c755ab0e99f00c73c93eb1742e9d8ba3facffa6e5fda8718006e05e80e4faa006b3beae9cb837950c42a2ab760843d05d224dc437b1add4627ddf6b4580",
            "68ff0ee21014648cb565ea90c578e0d345b51e857ecb71aaa8e307e20655a83680d8496e0fd1b138c06197ed42f322409c66a8abafd87b3256089ea7777495992180966518d63d0d450bdf3a4f16bb755b96e022464082e2cb3cf9072dd9ef7c9b53",
        ),
        (
            "9f02261276cc9d1f8598ea4b6a74b15c2f3000505f0e7b9012096b41c4eb3aaf947f6ea42908010080",
            "91a67194de54f5741ef011a470a09ad4319935c7ddc4ec11f5a9fa75dd173bd8",
        ),
        (
            "80840080",
            "2febfc925f8398a1cf35c5de15443d3940255e574ce541f7e67a3f86dbc2a98580cbfbed5faf5b9f416c54ee9d0217312d230bcc0cb57c5817dbdd7f7df9006a63",
        ),
    ];

    impl StorageProof {
        pub fn test_inputs() -> Self {
            StorageProof::new(
                &default_storage_proof(),
                default_root_hash(),
                LeafInputs::test_inputs(),
            )
        }
    }

    // TODO: Get real inputs from the node.
    impl LeafInputs {
        pub fn test_inputs() -> Self {
            Self::new(
                F::from_canonical_u32(1),
                Default::default(),
                Default::default(),
                [F::from_noncanonical_u64(0), F::from_noncanonical_u64(1)],
            )
        }
    }

    pub fn default_storage_proof() -> Vec<(Vec<u8>, Vec<u8>)> {
        DEFAULT_STORAGE_PROOF
            .map(|(l, r)| {
                let left = hex::decode(l).unwrap();
                let right = hex::decode(r).unwrap();
                (left, right)
            })
            .to_vec()
    }

    pub fn default_root_hash() -> [u8; 32] {
        hex::decode(DEFAULT_ROOT_HASH).unwrap().try_into().unwrap()
    }
}

pub mod nullifier {
    use crate::nullifier::{Nullifier, NullifierInputs};

    use super::{DEFAULT_FUNDING_ACCOUNT, DEFAULT_FUNDING_NONCE, DEFAULT_SECRET};

    impl Nullifier {
        pub fn test_inputs() -> Self {
            let secret = hex::decode(DEFAULT_SECRET).unwrap();
            Self::new(
                secret.as_slice(),
                DEFAULT_FUNDING_NONCE,
                DEFAULT_FUNDING_ACCOUNT,
            )
        }
    }

    impl NullifierInputs {
        pub fn test_inputs() -> Self {
            let secret = hex::decode(DEFAULT_SECRET).unwrap();
            Self::new(&secret, DEFAULT_FUNDING_NONCE, DEFAULT_FUNDING_ACCOUNT)
        }
    }
}
