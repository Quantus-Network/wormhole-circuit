use plonky2::{
    field::types::Field,
    hash::hash_types::{HashOut, HashOutTarget},
    iop::{
        target::{BoolTarget, Target},
        witness::{PartialWitness, WitnessWrite},
    },
    plonk::circuit_builder::CircuitBuilder,
};

use crate::circuit::{CircuitFragment, D, F};
use crate::gadgets::is_const_less_than;

pub const MAX_MERKLE_DEPTH: usize = 32;

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
    /// The sibling hashes in the merkle tree path
    pub merkle_siblings: Vec<[u8; 32]>,
    /// The path indices (0 for left, 1 for right) for each level of the Merkle tree
    pub path_indices: Vec<bool>,
    /// The actual depth of this specific Merkle proof
    pub actual_merkle_depth: usize,
}

/// Holds all the targets created during circuit construction.
#[derive(Clone, Debug)]
pub struct VoteTargets {
    // Public Input Targets
    pub proposal_id_targets: HashOutTarget,
    pub expected_merkle_root_targets: HashOutTarget,
    pub vote_target: BoolTarget,
    pub expected_nullifier_targets: HashOutTarget,

    // Private Input Targets
    pub private_key_targets: HashOutTarget,
    pub merkle_siblings_targets: Vec<HashOutTarget>,
    pub path_indices_targets: Vec<BoolTarget>,
    pub actual_merkle_depth_target: Target,
}

/// Data for the vote circuit, used for witness generation.
#[derive(Debug, Clone)]
pub struct VoteCircuitData {
    pub public_inputs: VotePublicInputs,
    pub private_inputs: VotePrivateInputs,
}

impl VoteCircuitData {
    pub fn new(public_inputs: VotePublicInputs, private_inputs: VotePrivateInputs) -> Self {
        Self {
            public_inputs,
            private_inputs,
        }
    }
}

impl CircuitFragment for VoteCircuitData {
    type Targets = VoteTargets;

    fn circuit(targets: &Self::Targets, builder: &mut CircuitBuilder<F, D>) {
        // --- 1. Merkle Proof Verification ---
        let leaf_hash_targets = builder
            .hash_n_to_hash_no_pad::<plonky2::hash::poseidon::PoseidonHash>(
                targets.private_key_targets.elements.to_vec(),
            );
        let mut current_computed_hash_targets = leaf_hash_targets;

        let n_log = (usize::BITS - (MAX_MERKLE_DEPTH - 1).leading_zeros()) as usize;
        for i in 0..MAX_MERKLE_DEPTH {
            let is_active_level =
                is_const_less_than(builder, i, targets.actual_merkle_depth_target, n_log);

            let sibling_hash_targets = targets.merkle_siblings_targets[i];
            let path_index_bool_target = targets.path_indices_targets[i];

            let mut combined_elements_for_hash = Vec::with_capacity(8);
            let mut potential_left_elements = Vec::with_capacity(4);
            let mut potential_right_elements = Vec::with_capacity(4);

            for k in 0..4 {
                let selected_left_k = builder.select(
                    path_index_bool_target,
                    sibling_hash_targets.elements[k],
                    current_computed_hash_targets.elements[k],
                );
                potential_left_elements.push(selected_left_k);

                let selected_right_k = builder.select(
                    path_index_bool_target,
                    current_computed_hash_targets.elements[k],
                    sibling_hash_targets.elements[k],
                );
                potential_right_elements.push(selected_right_k);
            }
            combined_elements_for_hash.extend(potential_left_elements);
            combined_elements_for_hash.extend(potential_right_elements);

            let parent_hash_candidacy = builder
                .hash_n_to_hash_no_pad::<plonky2::hash::poseidon::PoseidonHash>(
                    combined_elements_for_hash,
                );

            for k in 0..4 {
                current_computed_hash_targets.elements[k] = builder.select(
                    is_active_level,
                    parent_hash_candidacy.elements[k],
                    current_computed_hash_targets.elements[k],
                );
            }
        }

        for k in 0..4 {
            builder.connect(
                current_computed_hash_targets.elements[k],
                targets.expected_merkle_root_targets.elements[k],
            );
        }

        // --- 2. Nullifier Generation & Verification ---
        let mut nullifier_input_elements = Vec::with_capacity(8);
        nullifier_input_elements.extend_from_slice(&leaf_hash_targets.elements);
        nullifier_input_elements.extend_from_slice(&targets.proposal_id_targets.elements);

        let computed_nullifier_targets = builder
            .hash_n_to_hash_no_pad::<plonky2::hash::poseidon::PoseidonHash>(
                nullifier_input_elements,
            );

        for k in 0..4 {
            builder.connect(
                computed_nullifier_targets.elements[k],
                targets.expected_nullifier_targets.elements[k],
            );
        }

        // --- 3. Vote Validation ---
        // targets.vote_target is BoolTarget, which implies it is 0 or 1.
        // No explicit constraint needed here as add_virtual_bool_public_input ensures this.
    }

    fn fill_targets(
        &self,
        pw: &mut PartialWitness<F>,
        targets: Self::Targets,
    ) -> anyhow::Result<()> {
        // Helper to set HashOutTarget from [u8; 32]
        fn set_hash_target_witness(
            pw: &mut PartialWitness<F>,
            target: HashOutTarget,
            val: &[u8; 32],
        ) -> anyhow::Result<()> {
            let felt_vals: [F; 4] = val
                .chunks(8)
                .map(|chunk| F::from_canonical_u64(u64::from_le_bytes(chunk.try_into().unwrap())))
                .collect::<Vec<F>>()
                .try_into()
                .unwrap();
            pw.set_hash_target(
                target,
                HashOut {
                    elements: felt_vals,
                },
            )?;
            Ok(())
        }

        // Set public input witnesses
        set_hash_target_witness(
            pw,
            targets.proposal_id_targets,
            &self.public_inputs.proposal_id,
        )?;
        set_hash_target_witness(
            pw,
            targets.expected_merkle_root_targets,
            &self.public_inputs.merkle_root,
        )?;
        pw.set_bool_target(targets.vote_target, self.public_inputs.vote)?;
        set_hash_target_witness(
            pw,
            targets.expected_nullifier_targets,
            &self.public_inputs.nullifier,
        )?;

        // Set private input witnesses
        set_hash_target_witness(
            pw,
            targets.private_key_targets,
            &self.private_inputs.private_key,
        )?;
        pw.set_target(
            targets.actual_merkle_depth_target,
            F::from_canonical_usize(self.private_inputs.actual_merkle_depth),
        )?;

        for i in 0..MAX_MERKLE_DEPTH {
            if i < self.private_inputs.actual_merkle_depth {
                set_hash_target_witness(
                    pw,
                    targets.merkle_siblings_targets[i],
                    &self.private_inputs.merkle_siblings[i],
                )?;
                pw.set_bool_target(
                    targets.path_indices_targets[i],
                    self.private_inputs.path_indices[i],
                )?;
            } else {
                set_hash_target_witness(pw, targets.merkle_siblings_targets[i], &[0u8; 32])?;
                pw.set_bool_target(targets.path_indices_targets[i], false)?;
            }
        }
        Ok(())
    }
}

impl VoteTargets {
    pub fn new(builder: &mut CircuitBuilder<F, D>) -> Self {
        // Public Input Targets
        let proposal_id_targets = builder.add_virtual_hash_public_input();
        let expected_merkle_root_targets = builder.add_virtual_hash_public_input();
        let vote_target = builder.add_virtual_bool_target_safe(); // Not public by default
        builder.register_public_input(vote_target.target); // Explicitly make it public
        let expected_nullifier_targets = builder.add_virtual_hash_public_input();

        // Private Input Targets
        let private_key_targets = builder.add_virtual_hash();
        let merkle_siblings_targets: Vec<_> = (0..MAX_MERKLE_DEPTH)
            .map(|_| builder.add_virtual_hash())
            .collect();
        let path_indices_targets: Vec<_> = (0..MAX_MERKLE_DEPTH)
            .map(|_| builder.add_virtual_bool_target_safe())
            .collect();
        let actual_merkle_depth_target = builder.add_virtual_target();

        Self {
            proposal_id_targets,
            expected_merkle_root_targets,
            vote_target,
            expected_nullifier_targets,
            private_key_targets,
            merkle_siblings_targets,
            path_indices_targets,
            actual_merkle_depth_target,
        }
    }

    /// Collects all public input targets in the order they were registered.
    pub fn all_public_inputs(&self) -> Vec<Target> {
        let mut pi = Vec::new();
        pi.extend(self.proposal_id_targets.elements);
        pi.extend(self.expected_merkle_root_targets.elements);
        pi.push(self.vote_target.target);
        pi.extend(self.expected_nullifier_targets.elements);
        pi
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
        hash::poseidon::PoseidonHash,
        iop::witness::PartialWitness,
        plonk::{
            circuit_data::CircuitConfig,
            config::{Hasher, PoseidonGoldilocksConfig},
        },
    };

    type C = PoseidonGoldilocksConfig;
    type F = GoldilocksField;

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
        let out = PoseidonHash::hash_no_pad(&input).elements;
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
    fn test_vote_circuit_end_to_end() -> anyhow::Result<()> {
        let private_keys_for_tree = [[1u8; 32], [2u8; 32], [3u8; 32], [4u8; 32]];
        let leaves: Vec<[u8; 32]> = private_keys_for_tree.iter().map(poseidon_hash).collect();

        let l1_0 = poseidon_hash2(&leaves[0], &leaves[1]);
        let l1_1 = poseidon_hash2(&leaves[2], &leaves[3]);
        let root = poseidon_hash2(&l1_0, &l1_1);

        let voter_private_key = private_keys_for_tree[0];
        let merkle_siblings: Vec<[u8; 32]> = vec![leaves[1], l1_1];
        let path_indices: Vec<bool> = vec![false, false];
        let actual_merkle_depth = 2;

        let proposal_id = [42u8; 32];
        let vote = true;
        let nullifier = compute_nullifier(&voter_private_key, &proposal_id);

        let public_inputs_data = VotePublicInputs {
            proposal_id,
            merkle_root: root,
            vote,
            nullifier,
        };
        let private_inputs_data = VotePrivateInputs {
            private_key: voter_private_key,
            merkle_siblings,
            path_indices,
            actual_merkle_depth,
        };

        let vote_circuit_data = VoteCircuitData::new(public_inputs_data, private_inputs_data);

        let config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<F, D>::new(config);

        // Create targets
        let targets = VoteTargets::new(&mut builder);

        // Define constraints
        VoteCircuitData::circuit(&targets, &mut builder);

        // Set up witness
        let mut pw = PartialWitness::new();
        vote_circuit_data.fill_targets(&mut pw, targets.clone())?;

        println!("Building circuit data...");
        let circuit_built_data = builder.build::<C>();

        println!("Proving...");
        let proof = circuit_built_data.prove(pw)?;
        println!("Verifying proof...");
        circuit_built_data.verify(proof.clone())?;

        println!("Vote circuit test passed!");
        Ok(())
    }
}
