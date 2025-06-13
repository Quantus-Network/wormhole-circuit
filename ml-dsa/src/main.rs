use anyhow::Result;
use plonky2::field::types::Field;
use plonky2::iop::witness::{PartialWitness, WitnessWrite};
use plonky2::plonk::circuit_builder::CircuitBuilder;
use plonky2::plonk::circuit_data::CircuitConfig;
use plonky2::plonk::config::{GenericConfig, PoseidonGoldilocksConfig};

use ml_dsa::constants::{C, D, F};
use ml_dsa::polynomial::Polynomial;

fn main() -> Result<()> {
    // Create two example polynomials
    // p1 = x^2 + 2x + 1
    let p1 = Polynomial::new(vec![
        F::ONE, // constant term
        F::TWO, // coefficient of x (2)
        F::ONE, // coefficient of x^2
    ]);

    // p2 = x^2 + 1
    let p2 = Polynomial::new(vec![
        F::ONE,  // constant term
        F::ZERO, // coefficient of x
        F::ONE,  // coefficient of x^2
    ]);

    // Regular multiplication
    let result = p1.clone() * p2.clone();
    println!("Regular multiplication result:");
    for (i, coeff) in result.coefficients().iter().enumerate() {
        println!("x^{}: {}", i, coeff);
    }

    // Circuit building for multiplication
    println!("\nBuilding circuit for multiplication...");
    let config = CircuitConfig::standard_recursion_config();
    let mut builder = CircuitBuilder::<F, D>::new(config);

    // Set the builder in thread local storage
    Polynomial::set_builder(&mut builder);

    // Create targets for polynomial multiplication in the circuit
    let circuit_result = p1.clone() * p2.clone();

    // Clear the builder from thread local storage
    Polynomial::clear_builder();

    let circuit_data = builder.build::<C>();

    // Generate a proof
    println!("\nGenerating proof...");
    let mut pw = PartialWitness::new();

    // Set witness values for input polynomials
    if let Some(targets) = p1.targets() {
        for (i, &target) in targets.iter().enumerate() {
            pw.set_target(target, p1.coefficients()[i])?;
        }
    }

    if let Some(targets) = p2.targets() {
        for (i, &target) in targets.iter().enumerate() {
            pw.set_target(target, p2.coefficients()[i])?;
        }
    }

    // Set witness values for result polynomial
    if let Some(targets) = circuit_result.targets() {
        for (i, &target) in targets.iter().enumerate() {
            pw.set_target(target, circuit_result.coefficients()[i])?;
        }
    }

    let proof = circuit_data.prove(pw)?;

    // Verify the proof
    println!("Verifying proof...");
    circuit_data.verify(proof)?;
    println!("Proof verified successfully!");

    println!("\nCircuit stats:");
    println!(
        "Number of public inputs: {}",
        circuit_data.common.num_public_inputs
    );
    println!("Gate instances: {:?}", circuit_data.common.gates);
    println!("Circuit degree bits: {}", circuit_data.common.degree_bits());

    Ok(())
}
