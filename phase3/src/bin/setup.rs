use std::path::PathBuf;
use clap::Parser;
use tracing::info;
use tracing_subscriber::EnvFilter;

use zknids_phase3::circuits::CircuitTemplate;
use zknids_phase3::prover::setup::{generate_all_params, generate_params};

#[derive(Parser)]
#[command(name = "phase3-setup", about = "zkNIDS — Deterministic Params Generation (no trusted setup)")]
struct Cli {
    #[arg(long, value_parser = parse_template)]
    circuit: Option<CircuitTemplate>,

    #[arg(long, conflicts_with = "circuit")]
    all: bool,

    #[arg(long, default_value = "keys")]
    output_dir: PathBuf,
}

fn parse_template(s: &str) -> Result<CircuitTemplate, String> {
    CircuitTemplate::from_str(s).ok_or_else(|| {
        format!("Unknown: '{}'. Use: ratio_check_v1, rate_check_v1, deviation_check_v1", s)
    })
}

fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")))
        .init();

    let cli = Cli::parse();

    info!("zkNIDS Phase 3 — Params Generation");
    info!("Method: Deterministic (PLONK+IPA) — NO trusted setup");
    info!("Output: {}", cli.output_dir.display());
    info!("Params are reproducible: anyone running this command gets identical output.");
    info!("VK + PK are regenerated from params at runtime (deterministic, fast).");

    if cli.all {
        let paths = generate_all_params(&cli.output_dir)?;
        info!("✓ All {} circuit params ready", paths.len());
    } else if let Some(template) = cli.circuit {
        generate_params(&template, &cli.output_dir)?;
        info!("✓ {} params ready", template.as_str());
    } else {
        eprintln!("Specify --circuit <name> or --all");
        std::process::exit(1);
    }

    Ok(())
}