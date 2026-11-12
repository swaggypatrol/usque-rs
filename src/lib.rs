#![warn(
    clippy::all,
    clippy::pedantic,
    clippy::nursery,
    clippy::cargo,
    rust_2018_idioms
)]
#![allow(
    clippy::module_name_repetitions,
    clippy::must_use_candidate,
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    clippy::cast_precision_loss,
    // Transitive dependency duplicates we cannot control:
    clippy::multiple_crate_versions,
    clippy::redundant_pub_crate,
    clippy::similar_names,
    clippy::fn_params_excessive_bools,
    clippy::large_futures,
    clippy::items_after_statements,
    clippy::too_many_lines,
    clippy::cargo_common_metadata
)]
//! Packet processing shared by the client and its integration tests.

pub mod datagram;
pub mod gro;
pub mod icmp;
pub mod packet;
