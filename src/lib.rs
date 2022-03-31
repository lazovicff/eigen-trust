//! # Eigen Trust
//!
//! A library for managing trust in a distributed network with zero-knowledge features.
//!
//! ## Main characteristics:
//! **Self-policing** - the shared ethics of the user population is defined and
//! enforced by the peers themselves and not by some central authority.
//!
//! **Minimal** - computation, infrastructure, storage, and message complexity are reduced to a minimum.
//!
//! **Incorruptible** - Reputation should be obtained by consistent good behavior through several transactions.
//! This is enforced for all users, so no one can cheat the system and obtain a higher reputation.
//! It is also resistant to malicious collectives.
//!
//! ## Usage (Milestone 1 Version)
//! ```rust
//! use eigen_trust::{
//!     utils::generate_trust_matrix,
//!     network::{Network, NetworkConfig},
//!     peer::PeerConfig,
//! };
//! use rand::thread_rng;
//! 
//! 
//! // Configure the peer.
//! #[derive(Clone, Copy, Debug)]
//! struct Peer;
//! impl PeerConfig for Peer {
//!     type Index = usize;
//!     type Score = f64;
//! }
//!
//! // Configure the network.
//! struct Network4Config;
//! impl NetworkConfig for Network4Config {
//!     type Peer = Peer;
//!     const DELTA: f64 = 0.001;
//!     const SIZE: usize = 4;
//!     const MAX_ITERATIONS: usize = 1000;
//!     const PRETRUST_WEIGHT: f64 = 0.5;
//! }
//! 
//! let rng = &mut thread_rng();
//! let num_peers: usize = Network4Config::SIZE;
//!
//! let mut pre_trust_scores = vec![0.0; num_peers];
//! pre_trust_scores[0] = 0.5;
//! pre_trust_scores[1] = 0.5;
//!
//! let default_score = 1. / <<Network4Config as NetworkConfig>::Peer as PeerConfig>::Score::from(num_peers as f64);
//! let initial_trust_scores = vec![default_score; num_peers];
//! let mc: Vec<Vec<f64>> = generate_trust_matrix(num_peers, rng);
//!
//! let mut network = Network::<Network4Config>::bootstrap(pre_trust_scores, initial_trust_scores, mc);
//!
//! network.converge(rng);
//!
//! let global_trust_scores = network.get_global_trust_scores();
//!
//! println!("is_converged: {}", network.is_converged());
//! println!("{:?}", global_trust_scores);
//! ```
//! ## Implementation
//! The library is implemented accourding to the original [Eigen Trust paper](http://ilpubs.stanford.edu:8090/562/1/2002-56.pdf).
//! It is developed under the Ethereum Foundation grant.
//!
//! NOTE: This library is still in development. Use at your own risk.

/// The module for the higher level network functions. It contains the functionality for creating peers,
/// bootstrapping the networks, and interactions between peers.
pub mod network;

/// The module for peer management. It contains the functionality for creating a peer,
/// adding local trust scores and calculating the global global trust score.
pub mod peer;

/// The module for utility functions.
pub mod utils;
