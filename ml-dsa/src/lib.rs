use std::cell::RefCell;
use plonky2::plonk::circuit_builder::CircuitBuilder;
use crate::constants::{F, D};

thread_local! {
    pub static CURRENT_BUILDER: RefCell<Option<*mut CircuitBuilder<F, D>>> = RefCell::new(None);
}

pub mod polynomial;
pub mod constants;