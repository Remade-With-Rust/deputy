//! # deputy-deploy
//!
//! The final pipeline stages (`docs/PIPELINE.md` §5–§6):
//!
//! - [`promote`] — `Scanned → Promoted | Quarantined`: copy clean, verified bytes from the
//!   dirty store into the append-only prod store with a hash-chained receipt (M5).
//! - [`gate`] — the **fail-closed deploy gate**: allow a deployment only if every dependency is
//!   promoted, clean, and receipted; block otherwise (M6).
//! - [`materialize`] — vendor the prod copies back into a source tree (Cargo source
//!   replacement), so builds consume Deputy's owned, verified artifacts (M6).
#![forbid(unsafe_code)]

mod gate;
mod materialize;
mod promote;

#[cfg(test)]
mod tests;

pub use gate::{gate, GateDecision, GateViolation};
pub use materialize::{materialize, MaterializePlan, MaterializedCrate};
pub use promote::{promote, Promotion, Receipt};
