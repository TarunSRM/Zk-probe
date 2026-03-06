//! # Proof Verification (halo2 PLONK+IPA)
//!
//! Verifier is self-contained: the ProofBundle includes params (base64).
//! VK is regenerated from params + empty circuit (deterministic).
//! No key files needed. No trust required.

use std::time::Instant;

use anyhow::{Context, Result};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use halo2_proofs::{
    plonk::{verify_proof, SingleVerifier},
    poly::commitment::Params,
    transcript::{Blake2bRead, Challenge255},
};
use pasta_curves::{vesta, Fp};
use tracing::info;

use crate::circuits::{self, CircuitTemplate};
use crate::prover::prove::ProofBundle;

#[derive(Debug, Clone, serde::Serialize)]
pub struct VerificationResult {
    pub valid: bool,
    pub proof_id: String,
    pub alert_id: String,
    pub circuit_template: String,
    pub verification_time_ms: u64,
    pub trustless: bool,
}

/// Verify a proof from its bundle (self-contained, no external files).
pub fn verify_proof_bundle(bundle: &ProofBundle) -> Result<VerificationResult> {
    let start = Instant::now();

    // Decode proof bytes
    let proof_bytes = BASE64.decode(&bundle.cryptographic_proof.proof_blob)
        .context("Failed to decode proof blob")?;

    // Decode params and regenerate VK (deterministic)
    let params_bytes = BASE64.decode(&bundle.cryptographic_proof.params)
        .context("Failed to decode params")?;
    let params: Params<vesta::Affine> = Params::read(&mut &params_bytes[..])
        .context("Failed to deserialize params")?;

    let template = CircuitTemplate::from_str(&bundle.public_inputs.circuit_template)
        .ok_or_else(|| anyhow::anyhow!("Unknown circuit template"))?;

    // Regenerate VK from params (deterministic, no key files)
    // Then verify proof against reconstructed public inputs
    let valid = match template {
        CircuitTemplate::RatioCheckV1 => {
            let (vk, _pk) = crate::prover::setup::load_keys_ratio(&params)?;
            let pi = circuits::RatioCheckCircuit::public_inputs(
                bundle.public_inputs.threshold, bundle.public_inputs.result);
            verify_halo2_proof(&params, &vk, &proof_bytes, &[&pi])?
        }
        CircuitTemplate::RateCheckV1 => {
            let (vk, _pk) = crate::prover::setup::load_keys_rate(&params)?;
            let pi = circuits::RateCheckCircuit::public_inputs(
                bundle.public_inputs.threshold,
                bundle.public_inputs.time_window_ns,
                bundle.public_inputs.result);
            verify_halo2_proof(&params, &vk, &proof_bytes, &[&pi])?
        }
        CircuitTemplate::DeviationCheckV1 => {
            let (vk, _pk) = crate::prover::setup::load_keys_deviation(&params)?;
            let pi = circuits::DeviationCheckCircuit::public_inputs(
                bundle.public_inputs.threshold, bundle.public_inputs.result);
            verify_halo2_proof(&params, &vk, &proof_bytes, &[&pi])?
        }
    };

    let elapsed = start.elapsed();
    info!("Verification: {} ({}ms) [alert: {}]",
        if valid { "✓ VALID" } else { "✗ INVALID" },
        elapsed.as_millis(), bundle.proof_metadata.alert_id);

    Ok(VerificationResult {
        valid,
        proof_id: bundle.proof_metadata.proof_id.clone(),
        alert_id: bundle.proof_metadata.alert_id.clone(),
        circuit_template: template.as_str().to_string(),
        verification_time_ms: elapsed.as_millis() as u64,
        trustless: true,
    })
}

/// Verify a halo2 IPA proof.
fn verify_halo2_proof(
    params: &Params<vesta::Affine>,
    vk: &halo2_proofs::plonk::VerifyingKey<vesta::Affine>,
    proof_bytes: &[u8],
    instances: &[&[Fp]],
) -> Result<bool> {
    let strategy = SingleVerifier::new(params);
    let mut transcript = Blake2bRead::<_, vesta::Affine, Challenge255<_>>::init(&proof_bytes[..]);

    let result = verify_proof(
        params,
        vk,
        strategy,
        &[instances],
        &mut transcript,
    );

    Ok(result.is_ok())
}