#![cfg_attr(not(feature = "std"), no_std)]

#[cfg(not(feature = "std"))]
extern crate alloc;
#[cfg(feature = "std")]
extern crate std;

pub mod circuit;
pub mod codec;
pub mod gadgets;
pub mod inputs;
pub mod nullifier;
pub mod storage_proof;
pub mod substrate_account;
pub mod unspendable_account;
pub mod utils;
pub mod vote;
