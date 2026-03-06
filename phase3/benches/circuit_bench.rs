use criterion::{criterion_group, criterion_main, Criterion};
use halo2_proofs::{
    dev::MockProver,
    plonk::{create_proof, keygen_pk, keygen_vk, verify_proof, SingleVerifier},
    poly::commitment::Params,
    transcript::{Blake2bRead, Blake2bWrite, Challenge255},
};
use pasta_curves::{vesta, Fp};
use rand::rngs::OsRng;

use zknids_phase3::circuits::{
    DeviationCheckCircuit, RateCheckCircuit, RatioCheckCircuit,
};

fn bench_ratio_check(c: &mut Criterion) {
    let k = 8u32;
    let params: Params<vesta::Affine> = Params::new(k);

    let empty = RatioCheckCircuit::default();
    let vk = keygen_vk(&params, &empty).unwrap();
    let pk = keygen_pk(&params, vk.clone(), &empty).unwrap();

    let circuit = RatioCheckCircuit::new(4275, 4500, 0.5, true);
    let instances = RatioCheckCircuit::public_inputs(0.5, true);

    c.bench_function("ratio_check_v1/prove", |b| {
        b.iter(|| {
            let mut transcript = Blake2bWrite::<_, vesta::Affine, Challenge255<_>>::init(vec![]);
            create_proof(&params, &pk, &[circuit.clone()], &[&[&instances]], OsRng, &mut transcript).unwrap();
            transcript.finalize()
        })
    });

    let mut transcript = Blake2bWrite::<_, vesta::Affine, Challenge255<_>>::init(vec![]);
    create_proof(&params, &pk, &[circuit.clone()], &[&[&instances]], OsRng, &mut transcript).unwrap();
    let proof = transcript.finalize();

    c.bench_function("ratio_check_v1/verify", |b| {
        b.iter(|| {
            let strategy = SingleVerifier::new(&params);
            let mut tr = Blake2bRead::<_, vesta::Affine, Challenge255<_>>::init(&proof[..]);
            verify_proof(&params, &vk, strategy, &[&[&instances]], &mut tr).unwrap();
        })
    });
}

fn bench_rate_check(c: &mut Criterion) {
    let k = 8u32;
    let params: Params<vesta::Affine> = Params::new(k);
    let empty = RateCheckCircuit::default();
    let vk = keygen_vk(&params, &empty).unwrap();
    let pk = keygen_pk(&params, vk.clone(), &empty).unwrap();

    let one_sec = 1_000_000_000u64;
    let circuit = RateCheckCircuit::new(0, 1848, 0, one_sec, 50.0, true);
    let instances = RateCheckCircuit::public_inputs(50.0, one_sec, true);

    c.bench_function("rate_check_v1/prove", |b| {
        b.iter(|| {
            let mut transcript = Blake2bWrite::<_, vesta::Affine, Challenge255<_>>::init(vec![]);
            create_proof(&params, &pk, &[circuit.clone()], &[&[&instances]], OsRng, &mut transcript).unwrap();
            transcript.finalize()
        })
    });
}

fn bench_deviation_check(c: &mut Criterion) {
    let k = 8u32;
    let params: Params<vesta::Affine> = Params::new(k);
    let empty = DeviationCheckCircuit::default();
    let vk = keygen_vk(&params, &empty).unwrap();
    let pk = keygen_pk(&params, vk.clone(), &empty).unwrap();

    let circuit = DeviationCheckCircuit::new(17770.0, 1.0, 3.0, true);
    let instances = DeviationCheckCircuit::public_inputs(3.0, true);

    c.bench_function("deviation_check_v1/prove", |b| {
        b.iter(|| {
            let mut transcript = Blake2bWrite::<_, vesta::Affine, Challenge255<_>>::init(vec![]);
            create_proof(&params, &pk, &[circuit.clone()], &[&[&instances]], OsRng, &mut transcript).unwrap();
            transcript.finalize()
        })
    });
}

criterion_group!(benches, bench_ratio_check, bench_rate_check, bench_deviation_check);
criterion_main!(benches);