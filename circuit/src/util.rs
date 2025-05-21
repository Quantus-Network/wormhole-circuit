//! Utility.
//!
//! This module defines utility functions and constants used across the crate.
use std::ops::Deref;

use plonky2::field::types::{Field, PrimeField64};

use crate::{
    circuit::F,
    codec::{ByteCodec, FieldElementCodec},
};

pub type Digest = [F; 4];

pub const BYTES_PER_FELT: usize = 8;
pub const HASH_NUM_FELTS: usize = 4;

/// A hash that stores the underlying data as field elments.
#[derive(Debug, Default, PartialEq, Eq, Clone, Copy)]
pub struct FieldHash(pub Digest);

impl Deref for FieldHash {
    type Target = Digest;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl From<Digest> for FieldHash {
    fn from(digest: Digest) -> Self {
        Self(digest)
    }
}

impl ByteCodec<{ HASH_NUM_FELTS * BYTES_PER_FELT }> for FieldHash {
    fn to_bytes(&self) -> Vec<u8> {
        field_elements_to_bytes(&self.0)
    }

    fn from_bytes(bytes: [u8; HASH_NUM_FELTS * BYTES_PER_FELT]) -> Self {
        let felts = array_to_field_elements(&bytes);
        Self(felts)
    }
}

impl FieldElementCodec<4> for FieldHash {
    fn to_field_elements(&self) -> Vec<F> {
        self.0.to_vec()
    }

    fn from_field_elements(elements: [F; 4]) -> Self {
        Self(elements)
    }
}

/// Converts a given slice into its field element representation.
pub fn slice_to_field_elements(input: &[u8]) -> Vec<F> {
    let mut field_elements: Vec<F> = Vec::new();
    for chunk in input.chunks(BYTES_PER_FELT) {
        let mut bytes = [0u8; 8];
        bytes[..chunk.len()].copy_from_slice(chunk);
        // Convert the chunk to a field element.
        let value = u64::from_le_bytes(bytes);
        let field_element = F::from_noncanonical_u64(value);
        field_elements.push(field_element);
    }

    field_elements
}

/// Converts a fixed-size byte array into an array of field elements.
pub fn array_to_field_elements<const NUM_FELTS: usize>(input: &[u8]) -> [F; NUM_FELTS] {
    assert_eq!(
        input.len(),
        NUM_FELTS * BYTES_PER_FELT,
        "Invalid input length"
    );

    let mut result = [F::ZERO; NUM_FELTS];
    for (i, out) in result.iter_mut().enumerate().take(NUM_FELTS) {
        let offset = i * BYTES_PER_FELT;
        let mut bytes = [0u8; 8];
        bytes.copy_from_slice(&input[offset..offset + BYTES_PER_FELT]);
        let value = u64::from_le_bytes(bytes);
        *out = F::from_noncanonical_u64(value);
    }

    result
}

/// Converts a given field element slice into its byte representation.
pub fn field_elements_to_bytes(input: &[F]) -> Vec<u8> {
    let mut bytes: Vec<u8> = Vec::new();

    for field_element in input {
        let value = field_element.to_noncanonical_u64();
        let value_bytes = value.to_le_bytes();
        bytes.extend_from_slice(&value_bytes);
    }

    bytes
}
