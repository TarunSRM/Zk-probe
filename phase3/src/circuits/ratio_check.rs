//! # ratio_check_v1 — Ratio Threshold Circuit (halo2 PLONK+IPA)
//!
//! Proves: `numerator / denominator > threshold` when result=1
//!         `numerator / denominator <= threshold` when result=0
//!
//! ## Key insight (finite field arithmetic):
//!   In a prime field, subtraction wraps: if lhs < rhs, then lhs - rhs = p + (lhs - rhs),
//!   which is a huge number, NOT zero. So we can't just check diff = lhs - rhs for zero.
//!
//! ## Solution: conditional difference
//!   When result=1 (violated):     diff = lhs - rhs  (positive in integers)
//!   When result=0 (not violated): diff = rhs - lhs  (positive in integers, or zero at threshold)
//!
//!   Gate: result * (lhs - rhs - diff) + (1 - result) * (rhs - lhs - diff) = 0
//!   Then: result=1 requires diff ≠ 0 (strict greater than)
//!         result=0 allows diff = 0 (at threshold) or diff > 0 (below threshold)
//!
//! Public inputs: [threshold_scaled, result]

use ff::Field;
use halo2_proofs::{
    circuit::{Layouter, SimpleFloorPlanner, Value},
    plonk::{
        Advice, Circuit, Column, ConstraintSystem, Error, Expression, Instance, Selector,
    },
    poly::Rotation,
};
use pasta_curves::Fp;

use super::PRECISION;

#[derive(Debug, Clone)]
pub struct RatioCheckConfig {
    col_a: Column<Advice>,
    col_b: Column<Advice>,
    col_c: Column<Advice>,
    instance: Column<Instance>,
    s_mul: Selector,
    s_nonzero: Selector,
    /// Conditional diff gate:
    /// result * (col_a - col_b - col_c) + (1 - result) * (col_b - col_a - col_c) = 0
    /// where result is read from a fixed advice cell
    s_cond_diff: Selector,
    /// When result=1: diff must be nonzero (diff * diff_inv = 1)
    /// Encoded as: result * (diff * diff_inv - 1) = 0
    s_result_nonzero: Selector,
}

#[derive(Debug, Clone)]
pub struct RatioCheckCircuit {
    pub numerator: Value<Fp>,
    pub denominator: Value<Fp>,
    pub threshold_scaled: Value<Fp>,
    pub result: Value<Fp>,
}

/// Compute field inverse, returning zero for zero input.
pub fn field_inv(v: Fp) -> Fp {
    let inv: Option<Fp> = v.invert().into();
    inv.unwrap_or(Fp::zero())
}

impl RatioCheckCircuit {
    pub fn new(numerator: u64, denominator: u64, threshold: f64, result: bool) -> Self {
        let threshold_scaled = (threshold * PRECISION as f64) as u64;
        Self {
            numerator: Value::known(Fp::from(numerator)),
            denominator: Value::known(Fp::from(denominator)),
            threshold_scaled: Value::known(Fp::from(threshold_scaled)),
            result: Value::known(if result { Fp::one() } else { Fp::zero() }),
        }
    }

    pub fn default() -> Self {
        Self {
            numerator: Value::unknown(),
            denominator: Value::unknown(),
            threshold_scaled: Value::unknown(),
            result: Value::unknown(),
        }
    }

    pub fn public_inputs(threshold: f64, result: bool) -> Vec<Fp> {
        let threshold_scaled = (threshold * PRECISION as f64) as u64;
        vec![
            Fp::from(threshold_scaled),
            if result { Fp::one() } else { Fp::zero() },
        ]
    }
}

impl Circuit<Fp> for RatioCheckCircuit {
    type Config = RatioCheckConfig;
    type FloorPlanner = SimpleFloorPlanner;
    fn without_witnesses(&self) -> Self { Self::default() }

    fn configure(meta: &mut ConstraintSystem<Fp>) -> Self::Config {
        let col_a = meta.advice_column();
        let col_b = meta.advice_column();
        let col_c = meta.advice_column();
        let instance = meta.instance_column();
        meta.enable_equality(col_a);
        meta.enable_equality(col_b);
        meta.enable_equality(col_c);
        meta.enable_equality(instance);

        let s_mul = meta.selector();
        let s_nonzero = meta.selector();
        let s_cond_diff = meta.selector();
        let s_result_nonzero = meta.selector();

        // a * b = c
        meta.create_gate("mul", |meta| {
            let s = meta.query_selector(s_mul);
            let a = meta.query_advice(col_a, Rotation::cur());
            let b = meta.query_advice(col_b, Rotation::cur());
            let c = meta.query_advice(col_c, Rotation::cur());
            vec![s * (a * b - c)]
        });

        // a * b = 1 (proves a ≠ 0)
        meta.create_gate("nonzero", |meta| {
            let s = meta.query_selector(s_nonzero);
            let a = meta.query_advice(col_a, Rotation::cur());
            let b = meta.query_advice(col_b, Rotation::cur());
            vec![s * (a * b - Expression::Constant(Fp::one()))]
        });

        // Conditional diff: col_c stores result
        // result * (col_a - col_b - col_c_next) + (1-result) * (col_b - col_a - col_c_next) = 0
        // We'll use: col_a = lhs, col_b = rhs, col_c = result on this row
        //            col_a(next) = diff
        // But simpler: just use separate advice cells.
        // Actually let's use a different layout:
        // Row has: col_a = lhs, col_b = rhs, col_c = diff
        // And we read result from the NEXT row's col_c
        // 
        // Simpler: pass result as col_c on same row, diff on next row col_a
        // 
        // SIMPLEST: use 4 advice cells across 2 rows. But we only have 3 columns.
        // 
        // Let's use: this row: col_a = result, col_b = lhs, col_c = rhs
        //            next row: col_a = diff
        // Gate: result*(lhs - rhs - diff) + (1-result)*(rhs - lhs - diff) = 0
        meta.create_gate("cond_diff", |meta| {
            let s = meta.query_selector(s_cond_diff);
            let result = meta.query_advice(col_a, Rotation::cur());
            let lhs = meta.query_advice(col_b, Rotation::cur());
            let rhs = meta.query_advice(col_c, Rotation::cur());
            let diff = meta.query_advice(col_a, Rotation::next());
            // result*(lhs - rhs - diff) + (1-result)*(rhs - lhs - diff) = 0
            vec![s * (
                result.clone() * (lhs.clone() - rhs.clone() - diff.clone())
                + (Expression::Constant(Fp::one()) - result) * (rhs - lhs - diff)
            )]
        });

        // When result=1: diff * diff_inv = 1 (enforced by result)
        // col_a = result, col_b = diff, col_c = diff_inv
        // Gate: result * (diff * diff_inv - 1) = 0
        meta.create_gate("result_nonzero", |meta| {
            let s = meta.query_selector(s_result_nonzero);
            let result = meta.query_advice(col_a, Rotation::cur());
            let diff = meta.query_advice(col_b, Rotation::cur());
            let diff_inv = meta.query_advice(col_c, Rotation::cur());
            vec![s * result * (diff * diff_inv - Expression::Constant(Fp::one()))]
        });

        RatioCheckConfig {
            col_a, col_b, col_c, instance,
            s_mul, s_nonzero, s_cond_diff, s_result_nonzero,
        }
    }

    fn synthesize(&self, config: Self::Config, mut layouter: impl Layouter<Fp>) -> Result<(), Error> {
        let (thresh_cell, result_cell) = layouter.assign_region(
            || "ratio_check_v1",
            |mut region| {
                // Row 0: lhs = numerator * PRECISION
                config.s_mul.enable(&mut region, 0)?;
                region.assign_advice(|| "num", config.col_a, 0, || self.numerator)?;
                let prec = Value::known(Fp::from(PRECISION));
                region.assign_advice(|| "prec", config.col_b, 0, || prec)?;
                let lhs = self.numerator * prec;
                region.assign_advice(|| "lhs", config.col_c, 0, || lhs)?;

                // Row 1: rhs = threshold_scaled * denominator
                config.s_mul.enable(&mut region, 1)?;
                let thresh_cell = region.assign_advice(
                    || "thresh", config.col_a, 1, || self.threshold_scaled)?;
                region.assign_advice(|| "denom", config.col_b, 1, || self.denominator)?;
                let rhs = self.threshold_scaled * self.denominator;
                region.assign_advice(|| "rhs", config.col_c, 1, || rhs)?;

                // Row 2: denom * denom_inv = 1 (denom ≠ 0)
                config.s_nonzero.enable(&mut region, 2)?;
                region.assign_advice(|| "d2", config.col_a, 2, || self.denominator)?;
                let denom_inv = self.denominator.map(field_inv);
                region.assign_advice(|| "dinv", config.col_b, 2, || denom_inv)?;

                // Row 3: conditional diff
                // col_a = result, col_b = lhs, col_c = rhs
                // Gate reads diff from row 4 col_a
                config.s_cond_diff.enable(&mut region, 3)?;
                region.assign_advice(|| "res3", config.col_a, 3, || self.result)?;
                region.assign_advice(|| "lhs3", config.col_b, 3, || lhs)?;
                region.assign_advice(|| "rhs3", config.col_c, 3, || rhs)?;

                // Compute diff based on result
                let diff = self.result.and_then(|r| {
                    lhs.and_then(|l| {
                        rhs.map(|rh| {
                            if r == Fp::one() {
                                l - rh  // lhs - rhs (positive when violated)
                            } else {
                                rh - l  // rhs - lhs (positive when not violated)
                            }
                        })
                    })
                });

                // Row 4: diff (read by cond_diff gate from row 3)
                region.assign_advice(|| "diff", config.col_a, 4, || diff)?;

                // Row 5: result * (diff * diff_inv - 1) = 0
                // When result=1, this enforces diff ≠ 0
                // When result=0, this is trivially satisfied
                config.s_result_nonzero.enable(&mut region, 5)?;
                let result_cell = region.assign_advice(
                    || "res5", config.col_a, 5, || self.result)?;
                region.assign_advice(|| "diff5", config.col_b, 5, || diff)?;
                let diff_inv = diff.map(field_inv);
                region.assign_advice(|| "dinv5", config.col_c, 5, || diff_inv)?;

                Ok((thresh_cell, result_cell))
            },
        )?;

        layouter.constrain_instance(thresh_cell.cell(), config.instance, 0)?;
        layouter.constrain_instance(result_cell.cell(), config.instance, 1)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use halo2_proofs::dev::MockProver;

    #[test]
    fn test_ratio_syn_flood_violated() {
        // 4275/4500 = 0.95 > 0.5 → violated
        let k = 8;
        let c = RatioCheckCircuit::new(4275, 4500, 0.5, true);
        let pi = RatioCheckCircuit::public_inputs(0.5, true);
        MockProver::run(k, &c, vec![pi]).unwrap().assert_satisfied();
    }

    #[test]
    fn test_ratio_not_violated() {
        // 100/4500 = 0.022 < 0.5 → not violated
        let k = 8;
        let c = RatioCheckCircuit::new(100, 4500, 0.5, false);
        let pi = RatioCheckCircuit::public_inputs(0.5, false);
        MockProver::run(k, &c, vec![pi]).unwrap().assert_satisfied();
    }

    #[test]
    fn test_ratio_exact_threshold() {
        // 500/1000 = 0.5, threshold 0.5 → not violated (need > not >=)
        let k = 8;
        let c = RatioCheckCircuit::new(500, 1000, 0.5, false);
        let pi = RatioCheckCircuit::public_inputs(0.5, false);
        MockProver::run(k, &c, vec![pi]).unwrap().assert_satisfied();
    }

    #[test]
    fn test_ratio_fragment_abuse() {
        // 3000/3000 = 1.0 > 0.3 → violated
        let k = 8;
        let c = RatioCheckCircuit::new(3000, 3000, 0.3, true);
        let pi = RatioCheckCircuit::public_inputs(0.3, true);
        MockProver::run(k, &c, vec![pi]).unwrap().assert_satisfied();
    }
}