use plonky2::field::extension::Extendable;
use plonky2::field::types::Field;
use plonky2::hash::hash_types::RichField;
use plonky2::iop::target::Target;
use plonky2::plonk::circuit_builder::CircuitBuilder;
use std::ops::{Add, Index, Mul, Neg, Sub};

use crate::{
    constants::{D, F},
    CURRENT_BUILDER,
};

#[derive(Clone)]
pub struct Polynomial {
    coeffs: Vec<F>,
    targets: Option<Vec<Target>>,
}

impl Polynomial {
    pub fn new(coeffs: Vec<F>) -> Self {
        let coeffs: Vec<F> = coeffs
            .into_iter()
            .rev()
            .skip_while(|&c| c == F::ZERO)
            .collect::<Vec<_>>()
            .into_iter()
            .rev()
            .collect();

        Self {
            coeffs: if coeffs.is_empty() {
                vec![F::ZERO]
            } else {
                coeffs
            },
            targets: None,
        }
    }

    pub fn zero() -> Self {
        Self {
            coeffs: vec![F::ZERO],
            targets: None,
        }
    }

    pub fn is_zero(&self) -> bool {
        self.coeffs.len() == 1 && self.coeffs[0] == F::ZERO
    }

    pub fn one() -> Self {
        Self {
            coeffs: vec![F::ONE],
            targets: None,
        }
    }

    pub fn is_one(&self) -> bool {
        self.coeffs.len() == 1 && self.coeffs[0] == F::ONE
    }

    pub fn degree(&self) -> usize {
        self.coeffs.len().saturating_sub(1)
    }

    pub fn coefficients(&self) -> &[F] {
        &self.coeffs
    }

    pub fn targets(&self) -> Option<&[Target]> {
        self.targets.as_deref()
    }

    pub fn set_builder(builder: &mut CircuitBuilder<F, D>)
    where
        F: RichField + Extendable<D>,
    {
        CURRENT_BUILDER.with(|b| {
            *b.borrow_mut() = Some(builder as *mut _);
        });
    }

    pub fn clear_builder() {
        CURRENT_BUILDER.with(|b| {
            *b.borrow_mut() = None;
        });
    }

    fn get_builder() -> Option<&'static mut CircuitBuilder<F, D>>
    where
        F: RichField + Extendable<D>,
    {
        CURRENT_BUILDER.with(|b| b.borrow().map(|ptr| unsafe { &mut *ptr }))
    }

    fn get_or_create_targets(&mut self, builder: &mut CircuitBuilder<F, D>) -> Vec<Target>
    where
        F: RichField + Extendable<D>,
    {
        if let Some(targets) = &self.targets {
            targets.clone()
        } else {
            let targets: Vec<_> = self
                .coeffs
                .iter()
                .map(|&coeff| {
                    let target = builder.constant(coeff);
                    builder.register_public_input(target);
                    target
                })
                .collect();
            self.targets = Some(targets.clone());
            targets
        }
    }
}

impl Add for Polynomial {
    type Output = Self;

    fn add(mut self, mut rhs: Self) -> Self::Output {
        let deg1 = self.degree();
        let deg2 = rhs.degree();
        let result_degree = deg1.max(deg2);

        // Extend coefficients with zeros if needed
        let mut result_coeffs = vec![F::ZERO; result_degree + 1];
        for (i, &coeff) in self.coeffs.iter().enumerate() {
            result_coeffs[i] = coeff;
        }
        for (i, &coeff) in rhs.coeffs.iter().enumerate() {
            result_coeffs[i] = result_coeffs[i] + coeff;
        }

        let mut result_targets = None;

        // If we have a builder, create circuit constraints
        if let Some(builder) = Self::get_builder() {
            let poly1_targets = self.get_or_create_targets(builder);
            let poly2_targets = rhs.get_or_create_targets(builder);

            let mut targets = Vec::with_capacity(result_degree + 1);

            // Build addition constraints
            for i in 0..=result_degree {
                let t1 = if i < poly1_targets.len() {
                    poly1_targets[i]
                } else {
                    builder.zero()
                };
                let t2 = if i < poly2_targets.len() {
                    poly2_targets[i]
                } else {
                    builder.zero()
                };
                let sum = builder.add(t1, t2);
                targets.push(sum);
            }

            result_targets = Some(targets);
        }

        Self {
            coeffs: result_coeffs,
            targets: result_targets,
        }
    }
}

impl Neg for Polynomial {
    type Output = Self;

    fn neg(self) -> Self::Output {
        Self::new(self.coeffs.iter().map(|&c| -c).collect())
    }
}

impl Sub for Polynomial {
    type Output = Self;

    fn sub(self, rhs: Self) -> Self::Output {
        self + (-rhs)
    }
}

impl Mul for Polynomial {
    type Output = Self;

    fn mul(mut self, mut rhs: Self) -> Self::Output {
        // Special cases for zero polynomials
        if self.is_zero() || rhs.is_zero() {
            let mut result = Self::zero();

            // If we have a builder, create circuit constraints for zero polynomial
            if let Some(builder) = Self::get_builder() {
                let poly1_targets = self.get_or_create_targets(builder);
                let poly2_targets = rhs.get_or_create_targets(builder);

                // Create zero target and verify it's the product
                let zero_target = builder.zero();
                for i in 0..poly1_targets.len() {
                    for j in 0..poly2_targets.len() {
                        let prod = builder.mul(poly1_targets[i], poly2_targets[j]);
                        builder.connect(prod, zero_target);
                    }
                }
                result.targets = Some(vec![zero_target]);
            }

            return result;
        }

        let deg1 = self.degree();
        let deg2 = rhs.degree();
        let result_degree = deg1 + deg2;

        let mut result_coeffs = vec![F::ZERO; result_degree + 1];

        // Regular coefficient multiplication
        for i in 0..=deg1 {
            for j in 0..=deg2 {
                result_coeffs[i + j] = result_coeffs[i + j] + self.coeffs[i] * rhs.coeffs[j];
            }
        }

        let mut result = Self::new(result_coeffs);

        // If we have a builder, create circuit constraints
        if let Some(builder) = Self::get_builder() {
            let poly1_targets = self.get_or_create_targets(builder);
            let poly2_targets = rhs.get_or_create_targets(builder);

            let mut targets = vec![builder.zero(); result_degree + 1];

            // Build multiplication constraints
            for i in 0..=deg1 {
                for j in 0..=deg2 {
                    let prod = builder.mul(poly1_targets[i], poly2_targets[j]);
                    targets[i + j] = builder.add(targets[i + j], prod);
                }
            }

            result.targets = Some(targets);
        }

        result
    }
}

impl Index<usize> for Polynomial {
    type Output = F;

    fn index(&self, index: usize) -> &Self::Output {
        &self.coeffs[index]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_polynomial_addition() {
        let p1 = Polynomial::new(vec![F::ONE, F::ONE, F::ONE]);
        let p2 = Polynomial::new(vec![F::ONE, F::ONE, F::ONE]);
        let result = p1 + p2;
        assert_eq!(result.coeffs, vec![F::TWO, F::TWO, F::TWO]);
    }

    #[test]
    fn test_polynomial_multiplication() {
        let p1 = Polynomial::new(vec![F::ONE, F::ONE, F::ONE]);
        let p2 = Polynomial::new(vec![F::ONE, F::ONE, F::ONE]);
        let result = p1 * p2;
        assert_eq!(
            result.coeffs,
            vec![F::ONE, F::TWO, F::from_canonical_u16(3), F::TWO, F::ONE]
        );
    }

    #[test]
    fn test_polynomial_zero() {
        let p = Polynomial::zero();
        assert_eq!(p.coeffs, vec![F::ZERO]);

        let p2 = Polynomial::new(vec![F::ZERO]);
        let result = p.clone() + p2;
        assert_eq!(result.coeffs, vec![F::ZERO]);

        let p3 = Polynomial::new(vec![F::ONE, F::ONE, F::ONE]);
        let result = p.clone() * p3;
        assert_eq!(result.coeffs, vec![F::ZERO]);
    }

    #[test]
    fn test_polynomial_one() {
        let p = Polynomial::one();
        assert_eq!(p.coeffs, vec![F::ONE]);

        let p2 = Polynomial::new(vec![F::ONE, F::ONE, F::ONE]);
        let result = p.clone() * p2;
        assert_eq!(result.coeffs, vec![F::ONE, F::ONE, F::ONE]);

        let p3 = Polynomial::new(vec![F::ONE, F::ONE, F::ONE]);
        let result = p.clone() + p3;
        assert_eq!(result.coeffs, vec![F::TWO, F::ONE, F::ONE]);
    }
}
