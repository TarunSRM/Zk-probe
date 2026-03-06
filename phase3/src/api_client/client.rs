//! HTTP client for the Aggregator REST API.
//!
//! Supports API key authentication via X-API-Key header.
//! Default base URL: `http://10.0.0.50:8080` (configurable).

use anyhow::{Context, Result};
use reqwest::header::{HeaderMap, HeaderValue};
use tracing::info;

use crate::witness::types::{AlertListEntry, ProofInput, ProofSubmission};
use crate::prover::prove::ProofBundle;
use crate::PROVER_VERSION;

/// Client for the Aggregator API with API key authentication.
pub struct AggregatorClient {
    base_url: String,
    client: reqwest::Client,
}

impl AggregatorClient {
    /// Create a new client with API key authentication.
    pub fn new(base_url: &str, api_key: &str) -> Self {
        let mut headers = HeaderMap::new();
        if !api_key.is_empty() {
            headers.insert("x-api-key",
                HeaderValue::from_str(api_key).expect("Invalid API key"));
        }
        headers.insert("content-type",
            HeaderValue::from_static("application/json"));

        let client = reqwest::Client::builder()
            .default_headers(headers)
            .timeout(std::time::Duration::from_secs(30))
            .build()
            .expect("Failed to build HTTP client");

        Self {
            base_url: base_url.trim_end_matches('/').to_string(),
            client,
        }
    }

    /// Create client without auth (for dev/testing with --no-auth server).
    pub fn new_no_auth(base_url: &str) -> Self {
        Self::new(base_url, "")
    }

    /// Default client for the GNS3 deployment.
    /// Reads API key from ZKNIDS_API_KEY env var.
    pub fn default_gns3() -> Self {
        let api_key = std::env::var("ZKNIDS_API_KEY").unwrap_or_default();
        Self::new("http://10.0.0.50:8080", &api_key)
    }

    /// Fetch all alerts with proof_status=pending.
    pub async fn get_pending_alerts(&self) -> Result<Vec<AlertListEntry>> {
        let url = format!("{}/api/alerts?proof_status=pending", self.base_url);
        info!("Fetching pending alerts from {}", url);
        let resp = self.client.get(&url).send().await
            .context("Failed to reach aggregator")?;

        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            anyhow::bail!("GET alerts failed: HTTP {} — {}", status, body);
        }

        let alerts: Vec<AlertListEntry> = resp.json().await
            .context("Failed to parse alert list")?;
        info!("Found {} pending alerts", alerts.len());
        Ok(alerts)
    }

    /// Fetch proof input for a specific alert.
    pub async fn get_proof_input(&self, alert_id: &str) -> Result<ProofInput> {
        let url = format!("{}/api/alerts/{}/proof_input", self.base_url, alert_id);
        let resp = self.client.get(&url).send().await
            .context("Failed to reach aggregator")?;

        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            anyhow::bail!("GET proof_input failed: HTTP {} — {}", status, body);
        }

        let input: ProofInput = resp.json().await
            .context("Failed to parse proof input")?;
        Ok(input)
    }

    pub async fn submit_proof(&self, bundle: &ProofBundle) -> Result<()> {
        let url = format!("{}/api/alerts/{}/proof",
            self.base_url, bundle.proof_metadata.alert_id);

        // Send the full ProofBundle as-is — server stores it directly,
        // verifier reads it directly. No flattening.
        let resp = self.client.post(&url).json(bundle).send().await
            .context("Failed to submit proof")?;

        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            anyhow::bail!("Proof submission failed: HTTP {} — {}", status, body);
        }

        info!("Proof submitted for alert {}", bundle.proof_metadata.alert_id);
        Ok(())
    }

    /// Update proof status for an alert.
    pub async fn update_proof_status(&self, alert_id: &str, status: &str) -> Result<()> {
        let url = format!("{}/api/alerts/{}/proof_status", self.base_url, alert_id);
        let body = serde_json::json!({ "proof_status": status });

        let resp = self.client.patch(&url).json(&body).send().await
            .context("Failed to update proof status")?;

        if !resp.status().is_success() {
            let s = resp.status();
            let b = resp.text().await.unwrap_or_default();
            anyhow::bail!("Status update failed: HTTP {} — {}", s, b);
        }

        Ok(())
    }
}