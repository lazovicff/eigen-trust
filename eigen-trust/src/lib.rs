//! # Eigen Trust
//!
//! A library for managing trust in a distributed network with zero-knowledge
//! features.
//!
//! ## Main characteristics:
//! **Self-policing** - the shared ethics of the user population is defined and
//! enforced by the peers themselves and not by some central authority.
//!
//! **Minimal** - computation, infrastructure, storage, and message complexity
//! are reduced to a minimum.
//!
//! **Incorruptible** - Reputation should be obtained by consistent good
//! behavior through several transactions. This is enforced for all users, so no
//! one can cheat the system and obtain a higher reputation. It is also
//! resistant to malicious collectives.
//!
//! ## Usage:
//! ```rust
//! use eigen_trust::{
//! 	eigen_trust_circuit::utils::read_params, EigenError, Keypair, LevelFilter, Multiaddr, Node,
//! 	PeerId,
//! };
//! use std::str::FromStr;
//!
//! const BOOTSTRAP_PEERS: [(&str, &str); 2] = [
//! 	(
//! 		"/ip4/127.0.0.1/tcp/58584",
//! 		"12D3KooWLyTCx9j2FMcsHe81RMoDfhXbdyyFgNGQMdcrnhShTvQh",
//! 	),
//! 	(
//! 		"/ip4/127.0.0.1/tcp/58601",
//! 		"12D3KooWKBKXsLwbmVBySEmbKayJzfWp3tPCKrnDCsmNy9prwjvy",
//! 	),
//! ];
//!
//! const DEFAULT_ADDRESS: &str = "/ip4/0.0.0.0/tcp/0";
//! const INTERVAL: u64 = 10;
//!
//! #[tokio::main]
//! async fn main() -> Result<(), EigenError> {
//! 	let local_key = Keypair::generate_ed25519();
//! 	let local_address =
//! 		Multiaddr::from_str(DEFAULT_ADDRESS).map_err(|_| EigenError::InvalidAddress)?;
//!
//! 	let mut bootstrap_nodes = Vec::new();
//! 	for info in BOOTSTRAP_PEERS.iter() {
//! 		let peer_addr = Multiaddr::from_str(info.0).map_err(|_| EigenError::InvalidAddress)?;
//! 		let peer_id = PeerId::from_str(info.1).map_err(|_| EigenError::InvalidPeerId)?;
//!
//! 		bootstrap_nodes.push((peer_id, peer_addr));
//! 	}
//!
//! 	let params = read_params("../data/params-18.bin");
//! 	let node = Node::new(local_key, local_address, bootstrap_nodes, INTERVAL, params)?;
//! 	node.main_loop(Some(1)).await?;
//!
//! 	Ok(())
//! }
//! ```
//!
//! ## Implementation
//! The library is implemented according to the original [Eigen Trust paper](http://ilpubs.stanford.edu:8090/562/1/2002-56.pdf).
//! It is developed under the Ethereum Foundation grant.

#![feature(array_zip, array_try_map)]
#![allow(clippy::tabs_in_doc_comments)]
#![deny(
	future_incompatible,
	nonstandard_style,
	missing_docs,
	deprecated,
	unreachable_code,
	unreachable_patterns,
	absolute_paths_not_starting_with_crate,
	unsafe_code,
	clippy::unwrap_used,
	clippy::panic,
	clippy::unnecessary_cast,
	clippy::cast_lossless,
	clippy::cast_possible_wrap,
	clippy::cast_precision_loss
)]
#![warn(trivial_casts)]
#![forbid(unsafe_code)]

/// The module for global constants.
pub mod constants;
/// The module for epoch-related calculations, like seconds until the next
/// epoch, current epoch, etc.
mod epoch;
/// The module for the node setup, running the main loop, and handling network
/// events.
mod node;
/// The module for the peer related functionalities, like:
/// - Adding/removing neighbors
/// - Calculating the global trust score
/// - Calculating local scores toward neighbors for a given epoch
/// - Keeping track of neighbors scores towards us
mod peer;
/// The module for defining the request-response protocol.
mod protocol;

pub use eigen_trust_circuit;
pub use epoch::Epoch;
pub use libp2p::{identity::Keypair, Multiaddr, PeerId};
pub use log::LevelFilter;
pub use node::Node;
pub use peer::{
	utils::{extract_pub_key, extract_sk_bytes, extract_sk_limbs, keypair_from_sk_bytes},
	Peer,
};

/// The crate-wide error variants.
#[derive(Debug, Clone, PartialEq)]
pub enum EigenError {
	/// Invalid keypair passed into node config.
	InvalidKeypair,
	/// Invalid multiaddress passed into node config.
	InvalidAddress,
	/// Invalid Pubkey
	InvalidPubkey,
	/// Invalid peer id passed.
	InvalidPeerId,
	/// Invalid trust score passed into node config.
	InvalidNumNeighbours,
	/// Peer not Identified
	PeerNotIdentified,
	/// Node failed to start listening on specified address. Usually because the
	/// address is already in use.
	ListenFailed,
	/// Node failed to connect to a neighbor.
	DialError,
	/// Max number of neighbors reached for a peer.
	MaxNeighboursReached,
	/// Failed to calculate current epoch.
	EpochError,
	/// Signature generation failed.
	SignatureError,
	/// Hash error
	HashError,
	/// Proving error
	ProvingError,
	/// Verification error
	VerificationError,
	/// Failed to generate proving key.
	KeygenFailed,
	/// Invalid bootstrap public key.
	InvalidBootstrapPubkey,
	/// Unknown error.
	Unknown,
}

impl From<EigenError> for u8 {
	fn from(e: EigenError) -> u8 {
		match e {
			EigenError::InvalidKeypair => 0,
			EigenError::InvalidAddress => 1,
			EigenError::InvalidPubkey => 2,
			EigenError::InvalidPeerId => 3,
			EigenError::InvalidNumNeighbours => 4,
			EigenError::PeerNotIdentified => 5,
			EigenError::ListenFailed => 6,
			EigenError::DialError => 7,
			EigenError::MaxNeighboursReached => 8,
			EigenError::EpochError => 9,
			EigenError::SignatureError => 10,
			EigenError::HashError => 11,
			EigenError::ProvingError => 12,
			EigenError::VerificationError => 13,
			EigenError::KeygenFailed => 14,
			EigenError::InvalidBootstrapPubkey => 15,
			EigenError::Unknown => 16,
		}
	}
}

impl From<u8> for EigenError {
	fn from(err: u8) -> Self {
		match err {
			0 => EigenError::InvalidKeypair,
			1 => EigenError::InvalidAddress,
			2 => EigenError::InvalidPubkey,
			3 => EigenError::InvalidPeerId,
			4 => EigenError::InvalidNumNeighbours,
			5 => EigenError::PeerNotIdentified,
			6 => EigenError::ListenFailed,
			7 => EigenError::DialError,
			8 => EigenError::MaxNeighboursReached,
			9 => EigenError::EpochError,
			10 => EigenError::SignatureError,
			11 => EigenError::HashError,
			12 => EigenError::ProvingError,
			13 => EigenError::VerificationError,
			14 => EigenError::KeygenFailed,
			15 => EigenError::InvalidBootstrapPubkey,
			_ => EigenError::Unknown,
		}
	}
}
