use plonky2::plonk::config::{GenericConfig, PoseidonGoldilocksConfig};

pub const D: usize = 2;
pub type F = <C as GenericConfig<D>>::F;
pub type C = PoseidonGoldilocksConfig;