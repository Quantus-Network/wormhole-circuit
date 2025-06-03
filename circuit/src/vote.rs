use plonky2::{
    field::extension::Extendable,
    hash::hash_types::RichField,
    iop::{
        target::Target,
        witness::{PartialWitness, WitnessWrite},
    },
    plonk::{
        circuit_builder::CircuitBuilder,
        circuit_data::CircuitConfig,
        config::{GenericConfig, PoseidonGoldilocksConfig},
    },
};

/// Public inputs for the vote circuit
#[derive(Debug, Clone)]
pub struct VotePublicInputs {
    /// The proposal ID this vote is for
    pub proposal_id: [u8; 32],
    /// The merkle root of eligible addresses
    pub merkle_root: [u8; 32],
    /// The vote (0 for no, 1 for yes)
    pub vote: bool,
    /// The nullifier to prevent double voting
    pub nullifier: [u8; 32],
}

/// Private inputs for the vote circuit
#[derive(Debug, Clone)]
pub struct VotePrivateInputs {
    /// The private key of the voter
    pub private_key: [u8; 32],
    /// The merkle proof for the voter's address
    pub merkle_proof: Vec<[u8; 32]>, // Sibling hashes in the merkle tree
    /// The position of the voter's address in the merkle tree
    pub position: u64,
}

/// The vote circuit that verifies:
/// 1. The voter's address is in the merkle tree of eligible addresses
/// 2. The nullifier is correctly generated
/// 3. The vote is valid (0 or 1)
pub struct VoteCircuit {
    pub public_inputs: VotePublicInputs,
    pub private_inputs: VotePrivateInputs,
}

impl VoteCircuit {
    pub fn new(public_inputs: VotePublicInputs, private_inputs: VotePrivateInputs) -> Self {
        Self {
            public_inputs,
            private_inputs,
        }
    }

    /// Builds the circuit for vote verification
    pub fn build<F: RichField + Extendable<D>, C: GenericConfig<D, F = F>, const D: usize>(
        &self,
        builder: &mut CircuitBuilder<F, D>,
    ) -> Vec<Target> {
        // TODO: Implement circuit logic:
        // 1. Verify merkle proof
        // 2. Generate and verify nullifier
        // 3. Validate vote

        vec![]
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use plonky2::{
        field::{
            goldilocks_field::GoldilocksField,
            types::{Field, PrimeField64},
        },
        hash::{
            hash_types::{HashOutTarget, RichField},
            poseidon::PoseidonHash,
        },
        iop::witness::PartialWitness,
        plonk::{
            circuit_builder::CircuitBuilder,
            circuit_data::{CircuitConfig, CircuitData},
            config::{Hasher, PoseidonGoldilocksConfig},
        },
    };

    const D: usize = 2;
    type C = PoseidonGoldilocksConfig;
    type F = GoldilocksField;

    // Helper: Simple Poseidon-based Merkle tree for 4 leaves
    fn make_merkle_tree_and_proofs(addresses: &[[u8; 32]]) -> ([u8; 32], Vec<Vec<[u8; 32]>>) {
        assert_eq!(addresses.len(), 4);
        // Hash leaves
        let leaves: Vec<[u8; 32]> = addresses.iter().map(|a| poseidon_hash(a)).collect();
        // Level 1
        let l1_0 = poseidon_hash2(&leaves[0], &leaves[1]);
        let l1_1 = poseidon_hash2(&leaves[2], &leaves[3]);
        // Root
        let root = poseidon_hash2(&l1_0, &l1_1);
        // Proofs: for each leaf, provide sibling and uncle
        let proofs = vec![
            vec![leaves[1], l1_1], // for 0
            vec![leaves[0], l1_1], // for 1
            vec![leaves[3], l1_0], // for 2
            vec![leaves[2], l1_0], // for 3
        ];
        (root, proofs)
    }

    fn poseidon_hash(data: &[u8; 32]) -> [u8; 32] {
        let mut input = [F::ZERO; 4];
        for (i, chunk) in data.chunks(8).enumerate() {
            input[i] = F::from_canonical_u64(u64::from_le_bytes(chunk.try_into().unwrap()));
        }
        let out = PoseidonHash::hash_no_pad(&input).elements;
        let mut res = [0u8; 32];
        for (i, x) in out.iter().enumerate().take(4) {
            res[i * 8..(i + 1) * 8].copy_from_slice(&x.to_canonical_u64().to_le_bytes());
        }
        res
    }
    fn poseidon_hash2(a: &[u8; 32], b: &[u8; 32]) -> [u8; 32] {
        let mut input = [F::ZERO; 8];
        for (i, chunk) in a.chunks(8).enumerate() {
            input[i] = F::from_canonical_u64(u64::from_le_bytes(chunk.try_into().unwrap()));
        }
        for (i, chunk) in b.chunks(8).enumerate() {
            input[4 + i] = F::from_canonical_u64(u64::from_le_bytes(chunk.try_into().unwrap()));
        }
        let out = plonky2::hash::poseidon::PoseidonHash::hash_no_pad(&input).elements;
        let mut res = [0u8; 32];
        for (i, x) in out.iter().enumerate().take(4) {
            res[i * 8..(i + 1) * 8].copy_from_slice(&x.to_canonical_u64().to_le_bytes());
        }
        res
    }

    fn compute_nullifier(private_key: &[u8; 32], proposal_id: &[u8; 32]) -> [u8; 32] {
        // nullifier = Poseidon(Poseidon(private_key), proposal_id)
        let pk_hash = poseidon_hash(private_key);
        poseidon_hash2(&pk_hash, proposal_id)
    }

    #[test]
    fn test_vote_circuit_end_to_end() {
        // 1. Create a test merkle tree of eligible addresses
        let addresses = vec![[1u8; 32], [2u8; 32], [3u8; 32], [4u8; 32]];
        let (root, proofs) = make_merkle_tree_and_proofs(&addresses);

        // 2. Pick an address and its proof
        let leaf_index = 0;
        let address = addresses[leaf_index];
        let merkle_proof = proofs[leaf_index].clone();

        // 3. Prepare vote inputs
        let proposal_id = [42u8; 32];
        let vote = true;
        let private_key = [99u8; 32];
        let nullifier = compute_nullifier(&private_key, &proposal_id);

        let public_inputs = VotePublicInputs {
            proposal_id,
            merkle_root: root,
            vote,
            nullifier,
        };
        let private_inputs = VotePrivateInputs {
            private_key,
            merkle_proof: merkle_proof.clone(),
            position: leaf_index as u64,
        };

        // 4. Build the circuit
        let mut builder = CircuitBuilder::<F, D>::new(CircuitConfig::standard_recursion_config());
        let vote_circuit = VoteCircuit::new(public_inputs, private_inputs);
        let _public_targets = vote_circuit.build::<F, C, D>(&mut builder);

        // 5. Set up the witness (not implemented yet)
        // let mut _pw = PartialWitness::new();
        // TODO: Set witness values for all inputs (public and private)

        // 6. Generate and verify the proof (not implemented yet)
        // let data = builder.build::<C>();
        // let proof = data.prove(pw).unwrap();
        // assert!(data.verify(proof).is_ok());
    }
}
