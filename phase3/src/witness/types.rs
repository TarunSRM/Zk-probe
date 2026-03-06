use serde::{Deserialize, Serialize};

/// Response from `GET /api/alerts/{id}/proof_input`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProofInput {
    pub alert_id: String,
    pub invariant: InvariantInfo,
    pub observation: ObservationData,
    pub provenance: ProvenanceData,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InvariantInfo {
    pub id: String,
    #[serde(rename = "type")]
    pub invariant_type: String,
    pub circuit_template: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ObservationData {
    pub observed_value: f64,
    pub threshold: f64,
    #[serde(default = "default_operator")]
    pub threshold_operator: String,
    pub result: bool,
    #[serde(default = "default_window_ns")]
    pub window_duration_ns: u64,
}

fn default_operator() -> String { "greater_than".to_string() }
fn default_window_ns() -> u64 { 1_000_000_000 }

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProvenanceData {
    #[serde(default)]
    pub snapshot_hash: String,
    #[serde(default)]
    pub flow_hash: String,
    #[serde(default)]
    pub phase1_detector_hash: String,
    #[serde(default)]
    pub phase2_detector_hash: String,
}

/// Minimal fields we need from GET /api/alerts response.
/// The aggregator returns all DB columns; we ignore extras.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AlertListEntry {
    pub alert_id: String,
    #[serde(default)]
    pub invariant_id: String,
    #[serde(default)]
    pub severity: String,
    #[serde(default)]
    pub proof_status: String,
    #[serde(default)]
    pub received_at: Option<f64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProofSubmission {
    pub proof_id: String,
    pub alert_id: String,
    pub proof_status: String,
    pub proof_blob: String,
    pub verification_key: String,
    pub circuit_template: String,
    pub public_inputs: serde_json::Value,
    pub generation_time_ms: u64,
    pub prover_version: String,
}