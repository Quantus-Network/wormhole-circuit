use plonky2::{
    field::types::Field,
    hash::{
        hash_types::{HashOut, HashOutTarget},
        poseidon::PoseidonHash,
    },
    iop::{target::Target, witness::WitnessWrite},
    plonk::circuit_builder::CircuitBuilder,
};

use crate::gadgets::is_const_less_than;
use crate::inputs::CircuitInputs;
use crate::{
    circuit::{CircuitFragment, D, F},
    util::slice_to_field_elements,
};

pub const MAX_PROOF_LEN: usize = 64;
pub const PROOF_NODE_MAX_SIZE_F: usize = 73;
pub const PROOF_NODE_MAX_SIZE_B: usize = 256;

#[derive(Debug, Clone)]
pub struct StorageProofTargets {
    pub root_hash: HashOutTarget,
    pub proof_len: Target,
    pub proof_data: Vec<Vec<Target>>,
    pub hashes: Vec<HashOutTarget>,
}

impl StorageProofTargets {
    pub fn new(builder: &mut CircuitBuilder<F, D>) -> Self {
        // Setup targets. Each 8-bytes are represented as their equivalent field element. We also
        // need to track total proof length to allow for variable length.
        let proof_data: Vec<_> = (0..MAX_PROOF_LEN)
            .map(|_| builder.add_virtual_targets(PROOF_NODE_MAX_SIZE_F))
            .collect();

        let hashes: Vec<_> = (0..MAX_PROOF_LEN)
            .map(|_| builder.add_virtual_hash())
            .collect();

        Self {
            root_hash: builder.add_virtual_hash_public_input(),
            proof_len: builder.add_virtual_target(),
            proof_data,
            hashes,
        }
    }
}

#[derive(Debug)]
pub struct StorageProof {
    proof: Vec<Vec<F>>,
    hashes: Vec<Vec<F>>,
    root_hash: [u8; 32],
}

impl StorageProof {
    /// The input is a storage proof as a tuple where each part is split at the index where the child node's
    /// hash, if any, appears within this proof node; and a root hash.
    pub fn new(proof: &[(Vec<u8>, Vec<u8>)], root_hash: [u8; 32]) -> Self {
        // First construct the proof and the hash array
        let mut constructed_proof = Vec::with_capacity(proof.len());
        let mut hashes = Vec::with_capacity(proof.len());
        for (left, right) in proof {
            let mut proof_node = Vec::with_capacity(PROOF_NODE_MAX_SIZE_B);
            proof_node.extend_from_slice(left);
            proof_node.extend_from_slice(right);

            // We make sure to convert to field elements after an eventual hash has been appended.
            let proof_node_f = slice_to_field_elements(&proof_node);
            let hash = slice_to_field_elements(right)[..4].to_vec();

            constructed_proof.push(proof_node_f);
            hashes.push(hash);
        }

        StorageProof {
            proof: constructed_proof,
            hashes,
            root_hash,
        }
    }
}

impl From<&CircuitInputs> for StorageProof {
    fn from(inputs: &CircuitInputs) -> Self {
        Self::new(&inputs.private.storage_proof, inputs.public.root_hash)
    }
}

impl CircuitFragment for StorageProof {
    type Targets = StorageProofTargets;

    fn circuit(
        &Self::Targets {
            root_hash,
            proof_len,
            ref proof_data,
            ref hashes,
        }: &Self::Targets,
        builder: &mut CircuitBuilder<F, D>,
    ) {
        // Setup constraints.
        // The first node should be the root node so we initialize `prev_hash` to the provided `root_hash`.
        let mut prev_hash = root_hash;
        let n_log = (usize::BITS - (MAX_PROOF_LEN - 1).leading_zeros()) as usize;
        for i in 0..MAX_PROOF_LEN {
            let node = &proof_data[i];

            let is_proof_node = is_const_less_than(builder, i, proof_len, n_log);
            let computed_hash = builder.hash_n_to_hash_no_pad::<PoseidonHash>(node.clone());

            for y in 0..4 {
                let diff = builder.sub(computed_hash.elements[y], prev_hash.elements[y]);
                let result = builder.mul(diff, is_proof_node.target);
                let zero = builder.zero();
                builder.connect(result, zero);
            }

            // Update `prev_hash` to the hash of the child that's stored within this node.
            prev_hash = hashes[i];
        }
    }

    fn fill_targets(
        &self,
        pw: &mut plonky2::iop::witness::PartialWitness<F>,
        targets: Self::Targets,
    ) -> anyhow::Result<()> {
        const EMPTY_PROOF_NODE: [F; PROOF_NODE_MAX_SIZE_F] = [F::ZERO; PROOF_NODE_MAX_SIZE_F];

        pw.set_hash_target(targets.root_hash, slice_to_hashout(&self.root_hash))?;
        pw.set_target(targets.proof_len, F::from_canonical_usize(self.proof.len()))?;

        for i in 0..MAX_PROOF_LEN {
            match self.proof.get(i) {
                Some(node) => {
                    let mut padded_proof_node = node.clone();
                    padded_proof_node.resize(PROOF_NODE_MAX_SIZE_F, F::ZERO);
                    pw.set_target_arr(&targets.proof_data[i], &padded_proof_node)?;
                }
                None => pw.set_target_arr(&targets.proof_data[i], &EMPTY_PROOF_NODE)?,
            }
        }

        let empty_hash = vec![F::ZERO; 4];
        for i in 0..MAX_PROOF_LEN {
            let hash = self.hashes.get(i).unwrap_or(&empty_hash);
            pw.set_hash_target(targets.hashes[i], HashOut::from_partial(&hash[..4]))?;
        }

        Ok(())
    }
}

fn slice_to_hashout(slice: &[u8]) -> HashOut<F> {
    let elements = slice_to_field_elements(slice);
    HashOut {
        elements: elements.try_into().unwrap(),
    }
}

#[cfg(any(test, feature = "testing"))]
pub mod test_helpers {
    use super::StorageProof;

    pub const ROOT_HASH: &str = "77eb9d80cd12acfd902b459eb3b8876f05f31ef6a17ed5fdb060ee0e86dd8139";
    pub const STORAGE_PROOF: [(&str, &str); 3] = [
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

    impl Default for StorageProof {
        fn default() -> Self {
            StorageProof::new(&default_proof(), default_root_hash())
        }
    }

    pub fn default_proof() -> Vec<(Vec<u8>, Vec<u8>)> {
        STORAGE_PROOF
            .map(|(l, r)| {
                let left = hex::decode(l).unwrap();
                let right = hex::decode(r).unwrap();
                (left, right)
            })
            .to_vec()
    }

    pub fn default_root_hash() -> [u8; 32] {
        hex::decode(ROOT_HASH).unwrap().try_into().unwrap()
    }
}

#[cfg(test)]
pub mod tests {
    use plonky2::plonk::proof::ProofWithPublicInputs;
    use std::panic;

    use super::{
        test_helpers::{default_proof, default_root_hash},
        *,
    };
    use crate::circuit::{
        tests::{build_and_prove_test, setup_test_builder_and_witness},
        C,
    };
    use rand::Rng;

    fn run_test(storage_proof: &StorageProof) -> anyhow::Result<ProofWithPublicInputs<F, C, D>> {
        let (mut builder, mut pw) = setup_test_builder_and_witness();
        let targets = StorageProofTargets::new(&mut builder);
        StorageProof::circuit(&targets, &mut builder);

        storage_proof.fill_targets(&mut pw, targets).unwrap();
        build_and_prove_test(builder, pw)
    }

    #[test]
    fn build_and_verify_proof() {
        let storage_proof = StorageProof::default();
        run_test(&storage_proof).unwrap();
    }

    #[test]
    #[should_panic(expected = "set twice with different values")]
    fn invalid_root_hash_fails() {
        let proof = StorageProof {
            root_hash: [0u8; 32],
            ..Default::default()
        };
        run_test(&proof).unwrap();
    }

    #[test]
    #[should_panic(expected = "set twice with different values")]
    fn tampered_proof_fails() {
        let mut tampered_proof = default_proof();

        // Flip the first byte in the first node hash.
        tampered_proof[0].1[0] ^= 0xFF;
        let proof = StorageProof::new(&tampered_proof, default_root_hash());

        run_test(&proof).unwrap();
    }

    #[ignore = "performance"]
    #[test]
    fn fuzz_tampered_proof() {
        const FUZZ_ITERATIONS: usize = 1000;

        let mut rng = rand::rng();

        // Number of fuzzing iterations
        let mut panic_count = 0;

        for i in 0..FUZZ_ITERATIONS {
            // Clone the original storage proof
            let mut tampered_proof = default_proof();

            // Randomly select a node in the proof to tamper
            let node_index = rng.random_range(0..tampered_proof.len());

            // Randomly select a byte to flip
            let byte_index = rng.random_range(0..tampered_proof[node_index].1.len());

            // Flip random bits in the selected byte (e.g., XOR with a random value)
            tampered_proof[node_index].1[byte_index] ^= rng.random_range(1..=255);

            // Create the proof and inputs
            let proof = StorageProof::new(&tampered_proof, default_root_hash());

            // Catch panic from run_test
            let result = panic::catch_unwind(|| {
                run_test(&proof).unwrap();
            });

            if result.is_err() {
                panic_count += 1;
            } else {
                // Optionally log cases where tampering didn't cause a panic
                println!("Iteration {i}: No panic occurred for tampered proof");
            }
        }

        assert_eq!(
            panic_count, FUZZ_ITERATIONS,
            "Only {panic_count} out of {FUZZ_ITERATIONS} iterations panicked",
        );
    }
}
