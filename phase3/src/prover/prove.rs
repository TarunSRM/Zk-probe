//! # Proof Generation (halo2 PLONK+IPA)

use std::path::Path;
use std::time::Instant;

use anyhow::{Context, Result};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use halo2_proofs::{
    plonk::{create_proof, ProvingKey},
    poly::commitment::Params,
    transcript::{Blake2bWrite, Challenge255},
};
use pasta_curves::{vesta, Fp};
use rand::rngs::OsRng;
use tracing::info;
use uuid::Uuid;

use crate::circuits::CircuitTemplate;
use crate::witness::extractor::PreparedCircuit;
use crate::witness::types::ProofInput;
use crate::{CURVE, PROVING_SCHEME, PROVER_VERSION};

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ProofBundle {
    pub proof_metadata: ProofMetadata,
    pub public_inputs: PublicInputs,
    pub cryptographic_proof: CryptographicProof,
    pub verification_instructions: VerificationInstructions,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ProofMetadata {
    pub proof_id: String,
    pub alert_id: String,
    pub generated_at: u64,
    pub generation_time_ms: u64,
    pub prover_version: String,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct PublicInputs {
    pub invariant_id: String,
    pub invariant_type: String,
    pub circuit_template: String,
    pub threshold: f64,
    pub time_window_ns: u64,
    pub detector_version_hash: String,
    pub result: bool,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct CryptographicProof {
    pub scheme: String,
    pub proof_blob: String,
    pub params: String,
    pub curve: String,
    pub k: u32,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct VerificationInstructions {
    pub verifier_command: String,
    pub trustless: bool,
    pub setup_type: String,
}

pub fn generate_proof(
    prepared: PreparedCircuit,
    proof_input: &ProofInput,
    key_dir: &Path,
) -> Result<ProofBundle> {
    let template = prepared.template();
    let k = template.k();
    let name = template.as_str();

    let params_path = crate::prover::setup::params_path(&template, key_dir);

    info!("Generating proof for alert {} [circuit: {}]", proof_input.alert_id, name);
    let start = Instant::now();

    // Load params and regenerate keys (deterministic, fast)
    let params = crate::prover::setup::read_params(&params_path)?;

    let proof_bytes = match prepared {
        PreparedCircuit::Ratio(circuit) => {
            let (_vk, pk) = crate::prover::setup::load_keys_ratio(&params)?;
            let instances = crate::circuits::RatioCheckCircuit::public_inputs(
                proof_input.observation.threshold, proof_input.observation.result);
            create_halo2_proof(&params, &pk, circuit, &[&instances])?
        }
        PreparedCircuit::Rate(circuit) => {
            let (_vk, pk) = crate::prover::setup::load_keys_rate(&params)?;
            let instances = crate::circuits::RateCheckCircuit::public_inputs(
                proof_input.observation.threshold,
                proof_input.observation.window_duration_ns,
                proof_input.observation.result);
            create_halo2_proof(&params, &pk, circuit, &[&instances])?
        }
        PreparedCircuit::Deviation(circuit) => {
            let (_vk, pk) = crate::prover::setup::load_keys_deviation(&params)?;
            let instances = crate::circuits::DeviationCheckCircuit::public_inputs(
                proof_input.observation.threshold, proof_input.observation.result);
            create_halo2_proof(&params, &pk, circuit, &[&instances])?
        }
    };

    let generation_time = start.elapsed();
    let proof_id = Uuid::new_v4().to_string();

    info!("Proof generated: {} bytes in {}ms", proof_bytes.len(), generation_time.as_millis());

    // Embed params in proof bundle so verifier is self-contained
    let params_raw = std::fs::read(&params_path)?;

    Ok(ProofBundle {
        proof_metadata: ProofMetadata {
            proof_id: proof_id.clone(),
            alert_id: proof_input.alert_id.clone(),
            generated_at: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH).unwrap().as_secs(),
            generation_time_ms: generation_time.as_millis() as u64,
            prover_version: PROVER_VERSION.to_string(),
        },
        public_inputs: PublicInputs {
            invariant_id: proof_input.invariant.id.clone(),
            invariant_type: proof_input.invariant.invariant_type.clone(),
            circuit_template: template.as_str().to_string(),
            threshold: proof_input.observation.threshold,
            time_window_ns: proof_input.observation.window_duration_ns,
            detector_version_hash: proof_input.provenance.phase1_detector_hash.clone(),
            result: proof_input.observation.result,
        },
        cryptographic_proof: CryptographicProof {
            scheme: PROVING_SCHEME.to_string(),
            proof_blob: BASE64.encode(&proof_bytes),
            params: BASE64.encode(&params_raw),
            curve: CURVE.to_string(),
            k,
        },
        verification_instructions: VerificationInstructions {
            verifier_command: format!("phase3-verify --proof proof_{}.json", proof_id),
            trustless: true,
            setup_type: "deterministic_ipa".to_string(),
        },
    })
}

/// Create a halo2 proof using IPA commitment.
fn create_halo2_proof<C: halo2_proofs::plonk::Circuit<Fp>>(
    params: &Params<vesta::Affine>,
    pk: &ProvingKey<vesta::Affine>,
    circuit: C,
    instances: &[&[Fp]],
) -> Result<Vec<u8>> {
    let mut transcript = Blake2bWrite::<_, vesta::Affine, Challenge255<_>>::init(vec![]);

    create_proof(
        params,
        pk,
        &[circuit],
        &[instances],
        OsRng,
        &mut transcript,
    )
    .context("halo2 proof generation failed")?;

    Ok(transcript.finalize())
}