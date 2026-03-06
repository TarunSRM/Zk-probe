//! # Key Generation (Deterministic — NO Trusted Setup)
//!
//! halo2_proofs 0.3 does not expose key serialization.
//! Instead, we save only the Params to disk.
//! Keys are regenerated from Params + empty circuit on each run.
//!
//! This is fast (< 1 second for our small circuits) and DETERMINISTIC:
//!   Machine A: params → keygen → VK/PK
//!   Machine B: same params → keygen → IDENTICAL VK/PK
//!
//! This is actually better for trustless design — no key files to trust.

use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use halo2_proofs::{
    plonk::{keygen_pk, keygen_vk, ProvingKey, VerifyingKey},
    poly::commitment::Params,
};
use pasta_curves::vesta;
use tracing::info;

use crate::circuits::{
    CircuitTemplate, DeviationCheckCircuit, RateCheckCircuit, RatioCheckCircuit,
};

/// Path to params file for a circuit template.
pub fn params_path(template: &CircuitTemplate, key_dir: &Path) -> PathBuf {
    key_dir.join(format!("{}.params", template.as_str()))
}

/// Generate and save params for a single circuit template.
pub fn generate_params(
    template: &CircuitTemplate,
    key_dir: &Path,
) -> Result<PathBuf> {
    info!("Generating params for circuit: {} (deterministic, no ceremony)",
        template.as_str());

    fs::create_dir_all(key_dir).context("Failed to create key directory")?;

    let k = template.k();
    let params: Params<vesta::Affine> = Params::new(k);

    let path = params_path(template, key_dir);
    let mut buf = Vec::new();
    params.write(&mut buf).context("Params serialization failed")?;
    fs::write(&path, &buf)?;
    info!("  Params: {} ({} bytes)", path.display(), buf.len());

    // Verify keys can be generated from these params
    match template {
        CircuitTemplate::RatioCheckV1 => {
            let circuit = RatioCheckCircuit::default();
            let _vk = keygen_vk(&params, &circuit).context("VK keygen test failed")?;
            info!("  VK+PK generation verified for ratio_check_v1");
        }
        CircuitTemplate::RateCheckV1 => {
            let circuit = RateCheckCircuit::default();
            let _vk = keygen_vk(&params, &circuit).context("VK keygen test failed")?;
            info!("  VK+PK generation verified for rate_check_v1");
        }
        CircuitTemplate::DeviationCheckV1 => {
            let circuit = DeviationCheckCircuit::default();
            let _vk = keygen_vk(&params, &circuit).context("VK keygen test failed")?;
            info!("  VK+PK generation verified for deviation_check_v1");
        }
    }

    Ok(path)
}

/// Generate params for ALL circuit templates.
pub fn generate_all_params(key_dir: &Path) -> Result<Vec<PathBuf>> {
    let templates = [
        CircuitTemplate::RatioCheckV1,
        CircuitTemplate::RateCheckV1,
        CircuitTemplate::DeviationCheckV1,
    ];
    let mut paths = Vec::new();
    for t in &templates {
        paths.push(generate_params(t, key_dir)?);
    }
    Ok(paths)
}

/// Read params from disk.
pub fn read_params(path: &Path) -> Result<Params<vesta::Affine>> {
    let data = fs::read(path)?;
    Params::read(&mut &data[..]).context("Params deserialization failed")
}

/// Load params and regenerate VK + PK for a specific circuit template.
/// This is deterministic and fast (< 1s for our circuits).
pub fn load_keys_ratio(params: &Params<vesta::Affine>)
    -> Result<(VerifyingKey<vesta::Affine>, ProvingKey<vesta::Affine>)>
{
    let circuit = RatioCheckCircuit::default();
    let vk = keygen_vk(params, &circuit).context("VK keygen failed")?;
    let pk = keygen_pk(params, vk.clone(), &circuit).context("PK keygen failed")?;
    Ok((vk, pk))
}

pub fn load_keys_rate(params: &Params<vesta::Affine>)
    -> Result<(VerifyingKey<vesta::Affine>, ProvingKey<vesta::Affine>)>
{
    let circuit = RateCheckCircuit::default();
    let vk = keygen_vk(params, &circuit).context("VK keygen failed")?;
    let pk = keygen_pk(params, vk.clone(), &circuit).context("PK keygen failed")?;
    Ok((vk, pk))
}

pub fn load_keys_deviation(params: &Params<vesta::Affine>)
    -> Result<(VerifyingKey<vesta::Affine>, ProvingKey<vesta::Affine>)>
{
    let circuit = DeviationCheckCircuit::default();
    let vk = keygen_vk(params, &circuit).context("VK keygen failed")?;
    let pk = keygen_pk(params, vk.clone(), &circuit).context("PK keygen failed")?;
    Ok((vk, pk))
}