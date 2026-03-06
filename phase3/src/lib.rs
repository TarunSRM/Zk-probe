//! # zkNIDS Phase 3 — Zero-Knowledge Verification Layer
//!
//! Generates PLONK+IPA ZK-SNARK proofs (fully trustless, no ceremony)
//! attesting that Phase 2 invariant evaluations were computed correctly,
//! WITHOUT revealing the underlying network traffic data.
//!
//! ## Proving System
//!
//! - **Scheme:** PLONK with IPA (Inner Product Argument) commitments
//! - **Curve:** Pasta curves (Pallas/Vesta)
//! - **Library:** halo2 (by Zcash / Electric Coin Company)
//! - **Trusted Setup:** NONE — fully deterministic, reproducible by anyone
//!
//! ## Architecture
//!
//! ```text
//! Aggregator DB (alerts with proof_status=pending)
//!       │
//!       ▼  GET /api/alerts/{id}/proof_input
//! Witness Generator (extracts private/public inputs)
//!       │
//!       ▼  Selects circuit by circuit_template field
//! Circuit (PLONK arithmetization)
//!       │
//!       ▼  create_proof()
//! Proof (~600 bytes)
//!       │
//!       ├──▶ Self-verification (verify_proof)
//!       │
//!       ▼  POST /api/alerts/{id}/proof
//! Aggregator DB (proof_status = verified)
//!       │
//!       ▼  WebSocket broadcast
//! Dashboard (shows ✓ Verified)
//! ```

pub mod circuits;
pub mod prover;
pub mod verifier;
pub mod witness;
pub mod api_client;

/// Phase 3 version string (used in proof metadata).
pub const PROVER_VERSION: &str = "phase3-v0.1.0";

/// Proving system identifier.
pub const PROVING_SCHEME: &str = "plonk_ipa";

/// Curve identifier.
pub const CURVE: &str = "Pasta (Pallas/Vesta)";