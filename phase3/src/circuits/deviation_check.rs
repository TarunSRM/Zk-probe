//! # deviation_check_v1 — Spike Detection Circuit (halo2 PLONK+IPA)

use ff::Field;
use halo2_proofs::{
    circuit::{Layouter, SimpleFloorPlanner, Value},
    plonk::{
        Advice, Circuit, Column, ConstraintSystem, Error, Expression, Instance, Selector,
    },
    poly::Rotation,
};
use pasta_curves::Fp;

use super::{PRECISION, to_fixed_point};
use super::ratio_check::field_inv;

#[derive(Debug, Clone)]
pub struct DeviationCheckConfig {
    col_a: Column<Advice>,
    col_b: Column<Advice>,
    col_c: Column<Advice>,
    instance: Column<Instance>,
    s_mul: Selector,
    s_nonzero: Selector,
    s_cond_diff: Selector,
    s_result_nonzero: Selector,
}

#[derive(Debug, Clone)]
pub struct DeviationCheckCircuit {
    pub current_rate_scaled: Value<Fp>,
    pub baseline_mean_scaled: Value<Fp>,
    pub multiplier_scaled: Value<Fp>,
    pub result: Value<Fp>,
}

impl DeviationCheckCircuit {
    pub fn new(current_rate: f64, baseline_mean: f64, multiplier: f64, result: bool) -> Self {
        Self {
            current_rate_scaled: Value::known(Fp::from(to_fixed_point(current_rate))),
            baseline_mean_scaled: Value::known(Fp::from(to_fixed_point(baseline_mean))),
            multiplier_scaled: Value::known(Fp::from(to_fixed_point(multiplier))),
            result: Value::known(if result { Fp::one() } else { Fp::zero() }),
        }
    }

    pub fn default() -> Self {
        Self {
            current_rate_scaled: Value::unknown(),
            baseline_mean_scaled: Value::unknown(),
            multiplier_scaled: Value::unknown(),
            result: Value::unknown(),
        }
    }

    pub fn public_inputs(multiplier: f64, result: bool) -> Vec<Fp> {
        vec![
            Fp::from(to_fixed_point(multiplier)),
            if result { Fp::one() } else { Fp::zero() },
        ]
    }
}

impl Circuit<Fp> for DeviationCheckCircuit {
    type Config = DeviationCheckConfig;
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

        meta.create_gate("mul", |meta| {
            let s = meta.query_selector(s_mul);
            let a = meta.query_advice(col_a, Rotation::cur());
            let b = meta.query_advice(col_b, Rotation::cur());
            let c = meta.query_advice(col_c, Rotation::cur());
            vec![s * (a * b - c)]
        });
        meta.create_gate("nonzero", |meta| {
            let s = meta.query_selector(s_nonzero);
            let a = meta.query_advice(col_a, Rotation::cur());
            let b = meta.query_advice(col_b, Rotation::cur());
            vec![s * (a * b - Expression::Constant(Fp::one()))]
        });
        meta.create_gate("cond_diff", |meta| {
            let s = meta.query_selector(s_cond_diff);
            let result = meta.query_advice(col_a, Rotation::cur());
            let lhs = meta.query_advice(col_b, Rotation::cur());
            let rhs = meta.query_advice(col_c, Rotation::cur());
            let diff = meta.query_advice(col_a, Rotation::next());
            vec![s * (
                result.clone() * (lhs.clone() - rhs.clone() - diff.clone())
                + (Expression::Constant(Fp::one()) - result) * (rhs - lhs - diff)
            )]
        });
        meta.create_gate("result_nonzero", |meta| {
            let s = meta.query_selector(s_result_nonzero);
            let result = meta.query_advice(col_a, Rotation::cur());
            let diff = meta.query_advice(col_b, Rotation::cur());
            let diff_inv = meta.query_advice(col_c, Rotation::cur());
            vec![s * result * (diff * diff_inv - Expression::Constant(Fp::one()))]
        });

        DeviationCheckConfig { col_a, col_b, col_c, instance, s_mul, s_nonzero, s_cond_diff, s_result_nonzero }
    }

    fn synthesize(&self, config: Self::Config, mut layouter: impl Layouter<Fp>) -> Result<(), Error> {
        let (mult_cell, result_cell) = layouter.assign_region(
            || "deviation_check_v1",
            |mut region| {
                // Row 0: baseline ≠ 0
                config.s_nonzero.enable(&mut region, 0)?;
                region.assign_advice(|| "base", config.col_a, 0, || self.baseline_mean_scaled)?;
                let base_inv = self.baseline_mean_scaled.map(field_inv);
                region.assign_advice(|| "base_inv", config.col_b, 0, || base_inv)?;

                // Row 1: lhs = current_rate_scaled * PRECISION
                config.s_mul.enable(&mut region, 1)?;
                region.assign_advice(|| "cur", config.col_a, 1, || self.current_rate_scaled)?;
                let prec = Value::known(Fp::from(PRECISION));
                region.assign_advice(|| "prec", config.col_b, 1, || prec)?;
                let lhs = self.current_rate_scaled * prec;
                region.assign_advice(|| "lhs", config.col_c, 1, || lhs)?;

                // Row 2: rhs = baseline_mean_scaled * multiplier_scaled
                config.s_mul.enable(&mut region, 2)?;
                region.assign_advice(|| "base2", config.col_a, 2, || self.baseline_mean_scaled)?;
                let mult_cell = region.assign_advice(
                    || "mult", config.col_b, 2, || self.multiplier_scaled)?;
                let rhs = self.baseline_mean_scaled * self.multiplier_scaled;
                region.assign_advice(|| "rhs", config.col_c, 2, || rhs)?;

                // Row 3: conditional diff
                config.s_cond_diff.enable(&mut region, 3)?;
                region.assign_advice(|| "res3", config.col_a, 3, || self.result)?;
                region.assign_advice(|| "lhs3", config.col_b, 3, || lhs)?;
                region.assign_advice(|| "rhs3", config.col_c, 3, || rhs)?;

                let diff = self.result.and_then(|r| {
                    lhs.and_then(|l| {
                        rhs.map(|rh| {
                            if r == Fp::one() { l - rh } else { rh - l }
                        })
                    })
                });

                // Row 4: diff
                region.assign_advice(|| "diff", config.col_a, 4, || diff)?;

                // Row 5: result * (diff * diff_inv - 1) = 0
                config.s_result_nonzero.enable(&mut region, 5)?;
                let result_cell = region.assign_advice(
                    || "res5", config.col_a, 5, || self.result)?;
                region.assign_advice(|| "diff5", config.col_b, 5, || diff)?;
                let diff_inv = diff.map(field_inv);
                region.assign_advice(|| "dinv5", config.col_c, 5, || diff_inv)?;

                Ok((mult_cell, result_cell))
            },
        )?;

        layouter.constrain_instance(mult_cell.cell(), config.instance, 0)?;
        layouter.constrain_instance(result_cell.cell(), config.instance, 1)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use halo2_proofs::dev::MockProver;

    #[test]
    fn test_deviation_packet_spike() {
        let k = 8;
        let c = DeviationCheckCircuit::new(17770.0, 1.0, 3.0, true);
        let pi = DeviationCheckCircuit::public_inputs(3.0, true);
        MockProver::run(k, &c, vec![pi]).unwrap().assert_satisfied();
    }

    #[test]
    fn test_deviation_not_violated() {
        let k = 8;
        let c = DeviationCheckCircuit::new(2.0, 1.0, 3.0, false);
        let pi = DeviationCheckCircuit::public_inputs(3.0, false);
        MockProver::run(k, &c, vec![pi]).unwrap().assert_satisfied();
    }

    #[test]
    fn test_deviation_flow_churn() {
        let k = 8;
        let c = DeviationCheckCircuit::new(50.0, 5.0, 5.0, true);
        let pi = DeviationCheckCircuit::public_inputs(5.0, true);
        MockProver::run(k, &c, vec![pi]).unwrap().assert_satisfied();
    }
}