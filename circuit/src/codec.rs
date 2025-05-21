use crate::circuit::F;

pub trait FieldElementCodec<const SIZE: usize>: Sized {
    fn to_field_elements(&self) -> Vec<F>;
    fn from_field_elements(elements: [F; SIZE]) -> Self;
}

pub trait ByteCodec<const SIZE: usize>: Sized {
    fn to_bytes(&self) -> Vec<u8>;
    fn from_bytes(slice: [u8; SIZE]) -> Self;
}
