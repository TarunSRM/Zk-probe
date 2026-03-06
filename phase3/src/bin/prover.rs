use std::path::PathBuf;
use clap::Parser;
use tracing::{error, info, warn};
use tracing_subscriber::EnvFilter;

use zknids_phase3::api_client::AggregatorClient;
use zknids_phase3::prover::prove::generate_proof;
use zknids_phase3::prover::parallel::configure_workers;
use zknids_phase3::verifier::verify::verify_proof_bundle;
use zknids_phase3::witness::extractor::extract_circuit;

#[derive(Parser)]
#[command(name = "phase3-prover", about = "zkNIDS — ZK Proof Generation Service (PLONK+IPA)")]
struct Cli {
    #[arg(long, default_value = "keys")]
    key_dir: PathBuf,

    #[arg(long, default_value = "http://10.0.0.50:8080")]
    aggregator: String,

    /// API key for aggregator authentication.
    /// Can also be set via ZKNIDS_API_KEY env var.
    #[arg(long, env = "ZKNIDS_API_KEY", default_value = "")]
    api_key: String,

    #[arg(long)]
    watch: bool,

    #[arg(long, default_value = "5")]
    interval: u64,

    #[arg(long)]
    alert_id: Option<String>,

    #[arg(long)]
    save_dir: Option<PathBuf>,

    /// Number of parallel proof workers (default: auto-detect CPU cores).
    #[arg(long)]
    workers: Option<usize>,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")))
        .init();

    let cli = Cli::parse();

    configure_workers(cli.workers);

    let client = if cli.api_key.is_empty() {
        warn!("No API key provided. Use --api-key or ZKNIDS_API_KEY env var.");
        AggregatorClient::new_no_auth(&cli.aggregator)
    } else {
        AggregatorClient::new(&cli.aggregator, &cli.api_key)
    };

    info!("zkNIDS Phase 3 — Proof Generation Service");
    info!("Scheme: PLONK+IPA (trustless, no ceremony)");
    info!("Aggregator: {}", cli.aggregator);
    info!("Auth: {}", if cli.api_key.is_empty() { "DISABLED" } else { "API key" });
    info!("Keys: {}", cli.key_dir.display());

    if !cli.key_dir.exists() {
        anyhow::bail!("Key directory '{}' not found. Run phase3-setup --all first.", cli.key_dir.display());
    }

    if let Some(ref save_dir) = cli.save_dir {
        std::fs::create_dir_all(save_dir)?;
    }

    if let Some(alert_id) = &cli.alert_id {
        process_alert(&client, alert_id, &cli.key_dir, cli.save_dir.as_deref()).await?;
    } else if cli.watch {
        info!("Watch mode: polling every {}s", cli.interval);
        loop {
            match process_pending(&client, &cli.key_dir, cli.save_dir.as_deref()).await {
                Ok(count) => { if count > 0 { info!("Processed {} alerts", count); } }
                Err(e) => { warn!("Error: {}. Retrying...", e); }
            }
            tokio::time::sleep(tokio::time::Duration::from_secs(cli.interval)).await;
        }
    } else {
        let count = process_pending(&client, &cli.key_dir, cli.save_dir.as_deref()).await?;
        info!("Done. Processed {} alerts.", count);
    }

    Ok(())
}

async fn process_pending(
    client: &AggregatorClient,
    key_dir: &std::path::Path,
    save_dir: Option<&std::path::Path>,
) -> anyhow::Result<usize> {
    let pending = client.get_pending_alerts().await?;
    if pending.is_empty() { return Ok(0); }

    info!("Found {} pending alerts", pending.len());
    let mut processed = 0;

    for alert in &pending {
        match process_alert(client, &alert.alert_id, key_dir, save_dir).await {
            Ok(()) => processed += 1,
            Err(e) => error!("Failed alert {}: {}", alert.alert_id, e),
        }
    }
    Ok(processed)
}

async fn process_alert(
    client: &AggregatorClient,
    alert_id: &str,
    key_dir: &std::path::Path,
    save_dir: Option<&std::path::Path>,
) -> anyhow::Result<()> {
    info!("Processing alert: {}", alert_id);

    client.update_proof_status(alert_id, "generating").await.ok();

    let proof_input = client.get_proof_input(alert_id).await?;
    info!("  Invariant: {} [{}]", proof_input.invariant.id, proof_input.invariant.circuit_template);

    let prepared = extract_circuit(&proof_input)?;
    let bundle = generate_proof(prepared, &proof_input, key_dir)?;
    info!("  Proof: {} ({}ms, {} bytes)",
        bundle.proof_metadata.proof_id,
        bundle.proof_metadata.generation_time_ms,
        bundle.cryptographic_proof.proof_blob.len());

    let verification = verify_proof_bundle(&bundle)?;
    if !verification.valid {
        anyhow::bail!("Self-verification FAILED for {}", alert_id);
    }
    info!("  Verified: ✓ ({}ms)", verification.verification_time_ms);

    if let Some(save_dir) = save_dir {
        let path = save_dir.join(format!("proof_{}.json", bundle.proof_metadata.proof_id));
        std::fs::write(&path, serde_json::to_string_pretty(&bundle)?)?;
        info!("  Saved: {}", path.display());
    }

    client.submit_proof(&bundle).await?;
    info!("  ✓ Submitted to aggregator");

    Ok(())
}