use plonky2::{
    hash::{hash_types::HashOutTarget, poseidon::PoseidonHash},
    iop::{
        target::Target,
        witness::{PartialWitness, WitnessWrite},
    },
    plonk::{circuit_builder::CircuitBuilder, config::Hasher},
};

use crate::{
    circuit::{CircuitFragment, D, F},
    codec::ByteCodec,
    inputs::CircuitInputs,
    util::{slice_to_field_elements, FieldHash},
};

// FIXME: Adjust as needed.
pub const PREIMAGE_NUM_TARGETS: usize = 5;

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct Nullifier {
    // FIXME: Should not be public, remove once hash is precomputed in tests.
    pub hash: FieldHash,
    preimage: Vec<F>,
}
impl Nullifier {
    pub fn new(hash: FieldHash, preimage: &[u8]) -> Self {
        let preimage = slice_to_field_elements(preimage);
        Self { hash, preimage }
    }

    /// Cosntructs a new [`Nullifier`] from just the preimage.
    pub fn from_preimage(preimage: &[u8]) -> Self {
        // First, convert the preimage to its representation as field elements.
        let preimage = slice_to_field_elements(preimage);

        // Hash twice to get the nullifier.
        let inner_hash = PoseidonHash::hash_no_pad(&preimage).elements;
        let outer_hash = PoseidonHash::hash_no_pad(&inner_hash).elements;
        let hash = FieldHash(outer_hash);

        Self { hash, preimage }
    }
}

impl From<&CircuitInputs> for Nullifier {
    fn from(inputs: &CircuitInputs) -> Self {
        let hash = FieldHash::from_bytes(inputs.public.nullifier);
        let preimage = &inputs.private.nullifier_preimage;
        Self::new(hash, preimage)
    }
}

#[derive(Debug, Clone)]
pub struct NullifierTargets {
    hash: HashOutTarget,
    preimage: Vec<Target>,
}

impl NullifierTargets {
    pub fn new(builder: &mut CircuitBuilder<F, D>) -> Self {
        Self {
            hash: builder.add_virtual_hash_public_input(),
            preimage: builder.add_virtual_targets(PREIMAGE_NUM_TARGETS),
        }
    }
}

impl CircuitFragment for Nullifier {
    type Targets = NullifierTargets;

    /// Builds a circuit that assert that nullifier was computed with `H(H(nullifier +
    /// extrinsic_index + secret))`
    fn circuit(
        &Self::Targets { hash, ref preimage }: &Self::Targets,
        builder: &mut CircuitBuilder<F, D>,
    ) {
        // Compute the `generated_account` by double-hashing the preimage (salt + secret).
        let inner_hash = builder.hash_n_to_hash_no_pad::<PoseidonHash>(preimage.clone());
        let computed_hash =
            builder.hash_n_to_hash_no_pad::<PoseidonHash>(inner_hash.elements.to_vec());

        // Assert that hashes are equal.
        builder.connect_hashes(computed_hash, hash);
    }

    fn fill_targets(
        &self,
        pw: &mut PartialWitness<F>,
        targets: Self::Targets,
    ) -> anyhow::Result<()> {
        let digest = *self.hash;
        pw.set_hash_target(targets.hash, digest.into())?;
        pw.set_target_arr(&targets.preimage, &self.preimage)?;

        Ok(())
    }
}

#[cfg(any(test, feature = "testing"))]
pub mod test_helpers {
    use super::Nullifier;

    pub const PREIMAGE: &str =
        "776f726d686f6c650908804f8983b91253f3b2e4d49b71afc8e2c707608d9ae456990fb21591037f";

    impl Default for Nullifier {
        fn default() -> Self {
            let preimage = hex::decode(PREIMAGE).unwrap();
            Self::from_preimage(&preimage)
        }
    }
}

#[cfg(test)]
pub mod tests {
    use plonky2::{field::types::Field, plonk::proof::ProofWithPublicInputs};

    use crate::circuit::{
        tests::{build_and_prove_test, setup_test_builder_and_witness},
        C,
    };
    use crate::nullifier::test_helpers::PREIMAGE;

    use super::*;

    fn run_test(nullifier: &Nullifier) -> anyhow::Result<ProofWithPublicInputs<F, C, D>> {
        let (mut builder, mut pw) = setup_test_builder_and_witness();
        let targets = NullifierTargets::new(&mut builder);
        Nullifier::circuit(&targets, &mut builder);

        nullifier.fill_targets(&mut pw, targets).unwrap();
        build_and_prove_test(builder, pw)
    }

    #[test]
    fn build_and_verify_proof() {
        let nullifier = Nullifier::default();
        run_test(&nullifier).unwrap();
    }

    #[test]
    fn invalid_preimage_fails_proof() {
        let mut nullifier = Nullifier::default();

        // Flip the first byte of the preimage.
        let mut invalid_bytes = hex::decode(PREIMAGE).unwrap();
        invalid_bytes[0] ^= 0xFF;
        nullifier.preimage = slice_to_field_elements(&invalid_bytes);

        let res = run_test(&nullifier);
        assert!(res.is_err(),);
    }

    #[test]
    fn all_zero_preimage_is_valid_and_hashes() {
        let preimage_bytes = vec![0u8; 64];
        let nullifier = Nullifier::from_preimage(&preimage_bytes);
        assert!(!nullifier.hash.to_vec().iter().all(Field::is_zero));
    }
}
