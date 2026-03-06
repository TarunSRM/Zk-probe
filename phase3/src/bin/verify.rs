use std::path::PathBuf;
use clap::Parser;
use tracing::{error, info};
use tracing_subscriber::EnvFilter;

use zknids_phase3::prover::prove::ProofBundle;
use zknids_phase3::verifier::verify::{verify_proof_bundle, VerificationResult};

#[derive(Parser)]
#[command(name = "phase3-verify", about = "zkNIDS — ZK Proof Verifier (trustless, standalone)")]
struct Cli {
    /// Path to a proof JSON file.
    #[arg(long)]
    proof: Option<PathBuf>,

    /// Directory of proof JSON files (batch verify).
    #[arg(long, conflicts_with = "proof")]
    dir: Option<PathBuf>,

    /// Output as JSON.
    #[arg(long)]
    json: bool,
}

fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("warn")))
        .init();

    let cli = Cli::parse();

    if let Some(proof_path) = &cli.proof {
        let result = verify_single(proof_path)?;
        print_result(&result, cli.json);
        if !result.valid { std::process::exit(1); }
    } else if let Some(dir) = &cli.dir {
        let results = verify_batch(dir)?;
        print_batch(&results, cli.json);
        let failed = results.iter().filter(|r| !r.valid).count();
        if failed > 0 { std::process::exit(1); }
    } else {
        eprintln!("Specify --proof <file> or --dir <directory>");
        std::process::exit(1);
    }

    Ok(())
}

fn verify_single(path: &std::path::Path) -> anyhow::Result<VerificationResult> {
    let bundle: ProofBundle = serde_json::from_str(&std::fs::read_to_string(path)?)?;
    verify_proof_bundle(&bundle)
}

fn verify_batch(dir: &std::path::Path) -> anyhow::Result<Vec<VerificationResult>> {
    let mut results = Vec::new();
    for entry in std::fs::read_dir(dir)? {
        let path = entry?.path();
        if path.extension().map_or(false, |e| e == "json") {
            match verify_single(&path) {
                Ok(r) => results.push(r),
                Err(e) => error!("Failed {}: {}", path.display(), e),
            }
        }
    }
    Ok(results)
}

fn print_result(r: &VerificationResult, json: bool) {
    if json {
        println!("{}", serde_json::to_string_pretty(r).unwrap());
    } else {
        let icon = if r.valid { "✓ VALID" } else { "✗ INVALID" };
        println!("{}", icon);
        println!("  Proof ID:    {}", r.proof_id);
        println!("  Alert ID:    {}", r.alert_id);
        println!("  Circuit:     {}", r.circuit_template);
        println!("  Time:        {}ms", r.verification_time_ms);
        println!("  Trustless:   {}", r.trustless);
    }
}

fn print_batch(results: &[VerificationResult], json: bool) {
    if json {
        println!("{}", serde_json::to_string_pretty(results).unwrap());
    } else {
        let valid = results.iter().filter(|r| r.valid).count();
        let total = results.len();
        println!("Batch Verification");
        println!("──────────────────");
        println!("Total:   {}", total);
        println!("Valid:   {} ✓", valid);
        println!("Invalid: {} ✗", total - valid);
        println!();
        for r in results {
            let icon = if r.valid { "✓" } else { "✗" };
            println!("  {} {} [{}] ({}ms)", icon, r.proof_id, r.circuit_template, r.verification_time_ms);
        }
    }
}