//! # rate_check_v1 — Rate Threshold Circuit (halo2 PLONK+IPA)

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

const NANOS_PER_SEC: u64 = 1_000_000_000;

#[derive(Debug, Clone)]
pub struct RateCheckConfig {
    col_a: Column<Advice>,
    col_b: Column<Advice>,
    col_c: Column<Advice>,
    instance: Column<Instance>,
    s_mul: Selector,
    s_sub: Selector,
    s_nonzero: Selector,
    s_cond_diff: Selector,
    s_result_nonzero: Selector,
}

#[derive(Debug, Clone)]
pub struct RateCheckCircuit {
    pub count_before: Value<Fp>,
    pub count_after: Value<Fp>,
    pub time_before_ns: Value<Fp>,
    pub time_after_ns: Value<Fp>,
    pub threshold_scaled: Value<Fp>,
    pub window_duration_ns: Value<Fp>,
    pub result: Value<Fp>,
}

impl RateCheckCircuit {
    pub fn new(
        count_before: u64, count_after: u64,
        time_before_ns: u64, time_after_ns: u64,
        threshold_per_sec: f64, result: bool,
    ) -> Self {
        let window_ns = time_after_ns - time_before_ns;
        Self {
            count_before: Value::known(Fp::from(count_before)),
            count_after: Value::known(Fp::from(count_after)),
            time_before_ns: Value::known(Fp::from(time_before_ns)),
            time_after_ns: Value::known(Fp::from(time_after_ns)),
            threshold_scaled: Value::known(Fp::from(to_fixed_point(threshold_per_sec))),
            window_duration_ns: Value::known(Fp::from(window_ns)),
            result: Value::known(if result { Fp::one() } else { Fp::zero() }),
        }
    }

    pub fn default() -> Self {
        Self {
            count_before: Value::unknown(), count_after: Value::unknown(),
            time_before_ns: Value::unknown(), time_after_ns: Value::unknown(),
            threshold_scaled: Value::unknown(), window_duration_ns: Value::unknown(),
            result: Value::unknown(),
        }
    }

    pub fn public_inputs(threshold_per_sec: f64, window_duration_ns: u64, result: bool) -> Vec<Fp> {
        vec![
            Fp::from(to_fixed_point(threshold_per_sec)),
            Fp::from(window_duration_ns),
            if result { Fp::one() } else { Fp::zero() },
        ]
    }
}

impl Circuit<Fp> for RateCheckCircuit {
    type Config = RateCheckConfig;
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
        let s_sub = meta.selector();
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
        meta.create_gate("sub", |meta| {
            let s = meta.query_selector(s_sub);
            let a = meta.query_advice(col_a, Rotation::cur());
            let b = meta.query_advice(col_b, Rotation::cur());
            let c = meta.query_advice(col_c, Rotation::cur());
            vec![s * (a - b - c)]
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

        RateCheckConfig { col_a, col_b, col_c, instance, s_mul, s_sub, s_nonzero, s_cond_diff, s_result_nonzero }
    }

    fn synthesize(&self, config: Self::Config, mut layouter: impl Layouter<Fp>) -> Result<(), Error> {
        let (thresh_cell, window_cell, result_cell) = layouter.assign_region(
            || "rate_check_v1",
            |mut region| {
                // Row 0: count_delta = count_after - count_before
                config.s_sub.enable(&mut region, 0)?;
                region.assign_advice(|| "ca", config.col_a, 0, || self.count_after)?;
                region.assign_advice(|| "cb", config.col_b, 0, || self.count_before)?;
                let count_delta = self.count_after - self.count_before;
                region.assign_advice(|| "cd", config.col_c, 0, || count_delta)?;

                // Row 1: time_delta = time_after - time_before
                config.s_sub.enable(&mut region, 1)?;
                region.assign_advice(|| "ta", config.col_a, 1, || self.time_after_ns)?;
                region.assign_advice(|| "tb", config.col_b, 1, || self.time_before_ns)?;
                let time_delta = self.time_after_ns - self.time_before_ns;
                region.assign_advice(|| "td", config.col_c, 1, || time_delta)?;

                // Row 2: time_delta ≠ 0
                config.s_nonzero.enable(&mut region, 2)?;
                region.assign_advice(|| "td2", config.col_a, 2, || time_delta)?;
                let td_inv = time_delta.map(field_inv);
                region.assign_advice(|| "td_inv", config.col_b, 2, || td_inv)?;

                // Row 3: lhs = count_delta * (NANOS * PRECISION)
                config.s_mul.enable(&mut region, 3)?;
                region.assign_advice(|| "cd3", config.col_a, 3, || count_delta)?;
                let scale = Value::known(Fp::from(NANOS_PER_SEC * PRECISION));
                region.assign_advice(|| "scale", config.col_b, 3, || scale)?;
                let lhs = count_delta * scale;
                region.assign_advice(|| "lhs", config.col_c, 3, || lhs)?;

                // Row 4: rhs = threshold_scaled * time_delta
                config.s_mul.enable(&mut region, 4)?;
                let thresh_cell = region.assign_advice(
                    || "thresh", config.col_a, 4, || self.threshold_scaled)?;
                region.assign_advice(|| "td4", config.col_b, 4, || time_delta)?;
                let rhs = self.threshold_scaled * time_delta;
                region.assign_advice(|| "rhs", config.col_c, 4, || rhs)?;

                // Row 5: conditional diff
                config.s_cond_diff.enable(&mut region, 5)?;
                region.assign_advice(|| "res5", config.col_a, 5, || self.result)?;
                region.assign_advice(|| "lhs5", config.col_b, 5, || lhs)?;
                region.assign_advice(|| "rhs5", config.col_c, 5, || rhs)?;

                let diff = self.result.and_then(|r| {
                    lhs.and_then(|l| {
                        rhs.map(|rh| {
                            if r == Fp::one() { l - rh } else { rh - l }
                        })
                    })
                });

                // Row 6: diff (read by cond_diff gate)
                region.assign_advice(|| "diff", config.col_a, 6, || diff)?;

                // Row 7: result * (diff * diff_inv - 1) = 0
                config.s_result_nonzero.enable(&mut region, 7)?;
                let result_cell = region.assign_advice(
                    || "res7", config.col_a, 7, || self.result)?;
                region.assign_advice(|| "diff7", config.col_b, 7, || diff)?;
                let diff_inv = diff.map(field_inv);
                region.assign_advice(|| "dinv7", config.col_c, 7, || diff_inv)?;

                // Row 8: window_duration for instance
                let window_cell = region.assign_advice(
                    || "win", config.col_a, 8, || self.window_duration_ns)?;

                Ok((thresh_cell, window_cell, result_cell))
            },
        )?;

        layouter.constrain_instance(thresh_cell.cell(), config.instance, 0)?;
        layouter.constrain_instance(window_cell.cell(), config.instance, 1)?;
        layouter.constrain_instance(result_cell.cell(), config.instance, 2)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use halo2_proofs::dev::MockProver;

    #[test]
    fn test_rate_port_scan_violated() {
        let k = 8;
        let one_sec = 1_000_000_000u64;
        let c = RateCheckCircuit::new(0, 1848, 0, one_sec, 50.0, true);
        let pi = RateCheckCircuit::public_inputs(50.0, one_sec, true);
        MockProver::run(k, &c, vec![pi]).unwrap().assert_satisfied();
    }

    #[test]
    fn test_rate_not_violated() {
        let k = 8;
        let one_sec = 1_000_000_000u64;
        let c = RateCheckCircuit::new(0, 10, 0, one_sec, 50.0, false);
        let pi = RateCheckCircuit::public_inputs(50.0, one_sec, false);
        MockProver::run(k, &c, vec![pi]).unwrap().assert_satisfied();
    }

    #[test]
    fn test_rate_execve_high() {
        let k = 8;
        let one_sec = 1_000_000_000u64;
        let c = RateCheckCircuit::new(0, 150, 0, one_sec, 100.0, true);
        let pi = RateCheckCircuit::public_inputs(100.0, one_sec, true);
        MockProver::run(k, &c, vec![pi]).unwrap().assert_satisfied();
    }
}