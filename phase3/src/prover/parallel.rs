//! # Parallel Proof Worker Pool
//!
//! Proof generation is CPU-bound. This module provides a worker pool
//! that processes multiple alerts concurrently using rayon.
//!
//! Scales automatically with available CPU cores:
//!   1 core  → 1 proof at a time
//!   4 cores → 4 proofs at a time
//!   N cores → N proofs at a time

use std::path::Path;
use std::sync::Arc;

use anyhow::Result;
use rayon::prelude::*;
use tracing::{error, info};

use crate::prover::prove::{generate_proof, ProofBundle};
use crate::verifier::verify::verify_proof_bundle;
use crate::witness::extractor::extract_circuit;
use crate::witness::types::ProofInput;

/// Result of processing a single alert.
pub struct ProofResult {
    pub alert_id: String,
    pub bundle: Option<ProofBundle>,
    pub error: Option<String>,
}

/// Process multiple alerts in parallel.
///
/// Returns results in the same order as inputs.
/// Each alert is: extract → prove → self-verify.
pub fn prove_parallel(
    alerts: &[ProofInput],
    key_dir: &Path,
) -> Vec<ProofResult> {
    let key_dir = Arc::new(key_dir.to_path_buf());

    alerts
        .par_iter()
        .map(|input| {
            let alert_id = input.alert_id.clone();

            match prove_single(input, &key_dir) {
                Ok(bundle) => ProofResult {
                    alert_id,
                    bundle: Some(bundle),
                    error: None,
                },
                Err(e) => {
                    error!("Failed to prove alert {}: {}", alert_id, e);
                    ProofResult {
                        alert_id,
                        bundle: None,
                        error: Some(e.to_string()),
                    }
                }
            }
        })
        .collect()
}

/// Process a single alert: extract → prove → self-verify.
fn prove_single(input: &ProofInput, key_dir: &Path) -> Result<ProofBundle> {
    // 1. Extract witness
    let prepared = extract_circuit(input)?;

    // 2. Generate proof
    let bundle = generate_proof(prepared, input, key_dir)?;

    // 3. Self-verify
    let result = verify_proof_bundle(&bundle)?;
    if !result.valid {
        anyhow::bail!(
            "Self-verification FAILED for alert {}",
            input.alert_id
        );
    }

    info!(
        "✓ Alert {} proven and verified ({}ms prove, {}ms verify)",
        input.alert_id,
        bundle.proof_metadata.generation_time_ms,
        result.verification_time_ms,
    );

    Ok(bundle)
}

/// Configure the thread pool size.
pub fn configure_workers(num_threads: Option<usize>) {
    if let Some(n) = num_threads {
        rayon::ThreadPoolBuilder::new()
            .num_threads(n)
            .build_global()
            .ok();
        info!("Worker pool: {} threads", n);
    } else {
        info!("Worker pool: {} threads (auto)", rayon::current_num_threads());
    }
}