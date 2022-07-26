//! The module for the node setup, running the main loop, and handling network
//! events.

use crate::{
	epoch::Epoch,
	peer::{pubkey::Pubkey, Peer},
	protocol::{
		req_res::{Request, Response},
		EigenEvent, EigenTrustBehaviour,
	},
	EigenError,
};
use eigen_trust_circuit::halo2wrong::{
	curves::bn256::Bn256, halo2::poly::kzg::commitment::ParamsKZG,
};
use futures::StreamExt;
use libp2p::{
	core::{either::EitherError, upgrade::Version},
	identify::IdentifyEvent,
	identity::Keypair,
	noise::{Keypair as NoiseKeypair, NoiseConfig, X25519Spec},
	request_response::{RequestResponseEvent, RequestResponseMessage},
	swarm::{ConnectionHandlerUpgrErr, Swarm, SwarmBuilder, SwarmEvent},
	tcp::TcpConfig,
	yamux::YamuxConfig,
	Multiaddr, PeerId, Transport,
};
use std::io::Error as IoError;
use tokio::{
	select,
	time::{self, Duration, Instant},
};

/// The Node struct.
pub struct Node {
	/// Swarm object.
	swarm: Swarm<EigenTrustBehaviour>,
	interval: Duration,
	peer: Peer,
}

impl Node {
	/// Create a new node, given the local keypair, local address, and bootstrap
	/// nodes.
	pub fn new(
		local_key: Keypair,
		local_address: Multiaddr,
		interval_secs: u64,
		params: ParamsKZG<Bn256>,
	) -> Result<Self, EigenError> {
		let noise_keys = NoiseKeypair::<X25519Spec>::new()
			.into_authentic(&local_key)
			.map_err(|e| {
				log::error!("NoiseKeypair.into_authentic {}", e);
				EigenError::InvalidKeypair
			})?;

		// 30 years in seconds
		// Basically, we want connections to be open for a long time.
		let connection_duration = Duration::from_secs(86400 * 365 * 30);
		let interval_duration = Duration::from_secs(interval_secs);
		let transport = TcpConfig::new()
			.nodelay(true)
			.upgrade(Version::V1)
			.authenticate(NoiseConfig::xx(noise_keys).into_authenticated())
			.multiplex(YamuxConfig::default())
			.timeout(connection_duration)
			.boxed();

		let peer = Peer::new(local_key.clone(), params)?;
		let beh =
			EigenTrustBehaviour::new(connection_duration, interval_duration, local_key.public());

		// Setting up the transport and swarm.
		let local_peer_id = PeerId::from(local_key.public());
		let mut swarm = SwarmBuilder::new(transport, beh, local_peer_id).build();

		swarm.listen_on(local_address).map_err(|e| {
			log::debug!("swarm.listen_on {:?}", e);
			EigenError::ListenFailed
		})?;

		Ok(Self {
			swarm,
			interval: interval_duration,
			peer,
		})
	}

	/// Get the mutable swarm.
	pub fn get_swarm_mut(&mut self) -> &mut Swarm<EigenTrustBehaviour> {
		&mut self.swarm
	}

	/// Get the swarm.
	pub fn get_swarm(&self) -> &Swarm<EigenTrustBehaviour> {
		&self.swarm
	}

	/// Get the peer struct.
	pub fn get_peer(&self) -> &Peer {
		&self.peer
	}

	/// Get the mutable peer struct.
	pub fn get_peer_mut(&mut self) -> &mut Peer {
		&mut self.peer
	}

	/// Send the request for an opinion to all neighbors, in the passed epoch.
	pub fn send_epoch_requests(&mut self, epoch: Epoch) {
		for peer_id in self.peer.neighbors() {
			let request = Request::Opinion(epoch);
			self.get_swarm_mut()
				.behaviour_mut()
				.send_request(&peer_id, request);
		}
	}

	/// Handle the request response event.
	fn handle_req_res_events(&mut self, event: RequestResponseEvent<Request, Response>) {
		use RequestResponseEvent::*;
		use RequestResponseMessage::{Request as Req, Response as Res};
		match event {
			Message {
				peer,
				message: Req {
					request: Request::Opinion(epoch),
					channel,
					..
				},
			} => {
				// First we calculate the local opinions for the requested epoch.
				self.peer.calculate_local_opinion(peer, epoch);
				// Then we send the local opinion to the peer.
				let opinion = self.peer.get_local_opinion(&(peer, epoch));
				let response = Response::Opinion(opinion);
				let res = self
					.get_swarm_mut()
					.behaviour_mut()
					.send_response(channel, response);
				if let Err(e) = res {
					log::error!("Failed to send the response {:?}", e);
				}
			},
			Message {
				peer,
				message: Req {
					request: Request::Identify(pub_key),
					channel,
					..
				},
			} => {
				self.peer.identify_neighbor(peer, pub_key);
				let res = Pubkey::from_keypair(self.peer.get_keypair());
				match res {
					Ok(local_pubkey) => {
						let response = Response::Identify(local_pubkey);
						let res = self
							.get_swarm_mut()
							.behaviour_mut()
							.send_response(channel, response);
						if let Err(e) = res {
							log::error!("Failed to send the response {:?}", e);
						}
					},
					Err(e) => {
						log::error!("Failed to generate local pubkey {:?}", e);
						let response = Response::InternalError(e);
						let res = self
							.get_swarm_mut()
							.behaviour_mut()
							.send_response(channel, response);
						if let Err(e) = res {
							log::error!("Failed to send the response {:?}", e);
						}
					},
				}
			},
			Message {
				peer,
				message: Res { response, .. },
			} => {
				// If we receive a response, we update the neighbors's opinion about us.
				match response {
					Response::Opinion(opinion) => {
						self.peer
							.cache_neighbor_opinion((peer, opinion.epoch), opinion);
					},
					Response::Identify(pub_key) => {
						self.peer.identify_neighbor(peer, pub_key);
					},
					other => log::error!("Received error response {:?}", other),
				};
			},
			OutboundFailure {
				peer,
				request_id,
				error,
			} => {
				log::error!(
					"Outbound failure {:?} from {:?}: {:?}",
					request_id,
					peer,
					error
				);
			},
			InboundFailure {
				peer,
				request_id,
				error,
			} => {
				log::error!(
					"Inbound failure {:?} from {:?}: {:?}",
					request_id,
					peer,
					error
				);
			},
			ResponseSent { peer, request_id } => {
				log::debug!("Response sent {:?} to {:?}", request_id, peer);
			},
		};
	}

	/// Handle the identify protocol events.
	fn handle_identify_events(&mut self, event: IdentifyEvent) {
		match event {
			IdentifyEvent::Received { peer_id, info } => {
				self.peer.identify_neighbor_native(peer_id, info.public_key);
				log::info!("Neighbor identified {:?}", peer_id);
			},
			IdentifyEvent::Sent { peer_id } => {
				log::debug!("Identify request sent to {:?}", peer_id);
			},
			IdentifyEvent::Pushed { peer_id } => {
				log::debug!("Identify request pushed to {:?}", peer_id);
			},
			IdentifyEvent::Error { peer_id, error } => {
				log::error!("Identify error {:?} from {:?}", error, peer_id);
			},
		}
	}

	/// A method for handling the swarm events.
	pub fn handle_swarm_events(
		&mut self,
		event: SwarmEvent<
			EigenEvent,
			EitherError<ConnectionHandlerUpgrErr<IoError>, std::io::Error>,
		>,
	) {
		match event {
			SwarmEvent::Behaviour(EigenEvent::RequestResponse(event)) => {
				self.handle_req_res_events(event);
			},
			SwarmEvent::Behaviour(EigenEvent::Identify(event)) => {
				self.handle_identify_events(event);
			},
			SwarmEvent::NewListenAddr { address, .. } => log::info!("Listening on {:?}", address),
			// When we connect to a peer, we automatically add him as a neighbor.
			SwarmEvent::ConnectionEstablished { peer_id, .. } => {
				let res = self.get_peer_mut().add_neighbor(peer_id);
				if let Err(e) = res {
					log::error!("Failed to add neighbor {:?}", e);
				}
				log::info!("Connection established with {:?}", peer_id);
			},
			// When we disconnect from a peer, we automatically remove him from the neighbors list.
			SwarmEvent::ConnectionClosed { peer_id, cause, .. } => {
				self.get_peer_mut().remove_neighbor(peer_id);
				log::info!("Connection closed with {:?} ({:?})", peer_id, cause);
			},
			SwarmEvent::Dialing(peer_id) => log::info!("Dialing {:?}", peer_id),
			e => log::debug!("{:?}", e),
		}
	}

	/// Dial the neighbor directly.
	pub fn dial_neighbor(&mut self, addr: Multiaddr) {
		let res = self.swarm.dial(addr).map_err(|_| EigenError::DialError);
		log::debug!("swarm.dial {:?}", res);
	}

	/// Start the main loop of the program. This function has two main tasks:
	/// - To start an interval timer for sending the request for opinions.
	/// - To handle the swarm + request/response events.
	/// The amount of intervals/epochs is determined by the `interval_limit`
	/// parameter.
	pub async fn main_loop(mut self, interval_limit: Option<u32>) -> Result<(), EigenError> {
		let now = Instant::now();
		let secs_until_next_epoch = Epoch::secs_until_next_epoch(self.interval.as_secs())?;
		log::info!("Epoch starts in: {} seconds", secs_until_next_epoch);
		// Figure out when the next epoch will start.
		let start = now + Duration::from_secs(secs_until_next_epoch);

		// Setup the interval timer.
		let mut interval = time::interval_at(start, self.interval);

		// Count the number of epochs passed
		let mut count = 0;

		loop {
			select! {
				biased;
				// The interval timer tick. This is where we request opinions from the neighbors.
				_ = interval.tick() => {
					let current_epoch = Epoch::current_epoch(self.interval.as_secs())?;

					// Log out the global trust score for the previous epoch.
					let ops = self.peer.get_neighbor_opinions_at(current_epoch.previous());
					let ops_non_zero: Vec<&f64> = ops.iter().filter(|&&item| item > 0.0).collect();
					let score = self.peer.global_trust_score_at(current_epoch);
					log::info!("{:?} started, score: {}, ops: {:?}", current_epoch, score, ops_non_zero);

					// Send the request for opinions to all neighbors.
					self.send_epoch_requests(current_epoch);

					// Increment the epoch counter, break out of the loop if we reached the limit
					if let Some(num) = interval_limit {
						count += 1;
						if count >= num {
							break;
						}
					}
				},
				// The swarm event.
				event = self.swarm.select_next_some() => self.handle_swarm_events(event),
			}
		}

		Ok(())
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::{constants::GENESIS_EPOCH, peer::utils::keypair_from_sk_bytes};
	use eigen_trust_circuit::halo2wrong::halo2::poly::commitment::ParamsProver;
	use std::str::FromStr;

	const INTERVAL: u64 = 120;
	const ADDR_1: &str = "/ip4/127.0.0.1/tcp/56706";
	const ADDR_2: &str = "/ip4/127.0.0.1/tcp/58601";
	const SK_1: &str = "AF4yAqwCPzpBcit4FtTrHso4BBR9onk7qS9Q1SWSLSaV";
	const SK_2: &str = "7VoQFngkSo36s5yzZtnjtZ5SLe1VGukCZdb5Uc9tSDNC";

	#[tokio::test]
	async fn should_emit_connection_event_on_bootstrap() {
		let sk_bytes1 = bs58::decode(SK_1).into_vec().unwrap();
		let sk_bytes2 = bs58::decode(SK_2).into_vec().unwrap();

		let local_key1 = keypair_from_sk_bytes(sk_bytes1).unwrap();
		let peer_id1 = local_key1.public().to_peer_id();

		let local_key2 = keypair_from_sk_bytes(sk_bytes2).unwrap();
		let peer_id2 = local_key2.public().to_peer_id();

		let local_address1 = Multiaddr::from_str(ADDR_1).unwrap();
		let local_address2 = Multiaddr::from_str(ADDR_2).unwrap();

		let params = ParamsKZG::new(13);

		let mut node1 =
			Node::new(local_key1, local_address1.clone(), INTERVAL, params.clone()).unwrap();

		let mut node2 = Node::new(local_key2, local_address2.clone(), INTERVAL, params).unwrap();

		node1.dial_neighbor(local_address2);

		// For node 2
		// 1. New listen addr
		// 2. Incoming connection
		// 3. Connection established
		// For node 1
		// 1. New listen addr
		// 2. Connection established
		for _ in 0..5 {
			select! {
				event2 = node2.get_swarm_mut().select_next_some() => {
					if let SwarmEvent::ConnectionEstablished { peer_id, .. } = event2 {
						assert_eq!(peer_id, peer_id1);
					}
				},
				event1 = node1.get_swarm_mut().select_next_some() => {
					if let SwarmEvent::ConnectionEstablished { peer_id, .. } = event1 {
						assert_eq!(peer_id, peer_id2);
					}
				},

			}
		}
	}

	#[tokio::test]
	async fn should_identify_neighbors() {
		let sk_bytes1 = bs58::decode(SK_1).into_vec().unwrap();
		let sk_bytes2 = bs58::decode(SK_2).into_vec().unwrap();

		let local_key1 = keypair_from_sk_bytes(sk_bytes1).unwrap();
		let peer_id1 = local_key1.public().to_peer_id();

		let local_key2 = keypair_from_sk_bytes(sk_bytes2).unwrap();
		let peer_id2 = local_key2.public().to_peer_id();

		let local_address1 = Multiaddr::from_str(ADDR_1).unwrap();
		let local_address2 = Multiaddr::from_str(ADDR_2).unwrap();

		let params = ParamsKZG::new(13);

		let mut node1 =
			Node::new(local_key1.clone(), local_address1, INTERVAL, params.clone()).unwrap();

		let mut node2 =
			Node::new(local_key2.clone(), local_address2.clone(), INTERVAL, params).unwrap();

		node1.dial_neighbor(local_address2);

		// For node 2
		// 1. New listen addr
		// 2. Incoming connection
		// 3. Connection established
		// For node 1
		// 1. New listen addr
		// 2. Connection established
		for _ in 0..9 {
			select! {
				event2 = node2.get_swarm_mut().select_next_some() => node2.handle_swarm_events(event2),
				event1 = node1.get_swarm_mut().select_next_some() => node1.handle_swarm_events(event1),

			}
		}

		let neighbors1: Vec<PeerId> = node1.get_peer().neighbors();
		let neighbors2: Vec<PeerId> = node2.get_peer().neighbors();
		let expected_neighbor1 = vec![peer_id2];
		let expected_neighbor2 = vec![peer_id1];
		assert_eq!(neighbors1, expected_neighbor1);
		assert_eq!(neighbors2, expected_neighbor2);

		let pubkey1 = node2.get_peer().get_pub_key_native(peer_id1).unwrap();
		let pubkey2 = node1.get_peer().get_pub_key_native(peer_id2).unwrap();
		assert_eq!(pubkey1, local_key1.public());
		assert_eq!(pubkey2, local_key2.public());
	}

	#[tokio::test]
	async fn should_handle_request_for_opinion() {
		let sk_bytes1 = bs58::decode(SK_1).into_vec().unwrap();
		let sk_bytes2 = bs58::decode(SK_2).into_vec().unwrap();

		let local_key1 = keypair_from_sk_bytes(sk_bytes1).unwrap();
		let peer_id1 = local_key1.public().to_peer_id();

		let local_key2 = keypair_from_sk_bytes(sk_bytes2).unwrap();
		let peer_id2 = local_key2.public().to_peer_id();

		let local_address1 = Multiaddr::from_str(ADDR_1).unwrap();
		let local_address2 = Multiaddr::from_str(ADDR_2).unwrap();

		let params = ParamsKZG::new(13);

		let mut node1 = Node::new(local_key1, local_address1, INTERVAL, params.clone()).unwrap();

		let mut node2 =
			Node::new(local_key2, local_address2.clone(), INTERVAL, params.clone()).unwrap();

		node1.dial_neighbor(local_address2);

		// For node 2
		// 1. New listen addr
		// 2. Incoming connection
		// 3. Connection established
		// For node 1
		// 1. New listen addr
		// 2. Connection established
		for _ in 0..9 {
			select! {
				event2 = node2.get_swarm_mut().select_next_some() => node2.handle_swarm_events(event2),
				event1 = node1.get_swarm_mut().select_next_some() => node1.handle_swarm_events(event1),
			}
		}

		let peer1 = node1.get_peer_mut();
		let peer2 = node2.get_peer_mut();

		let next_epoch = Epoch(GENESIS_EPOCH);

		peer1.set_score(peer_id2, 5);
		peer2.set_score(peer_id1, 5);

		peer1.calculate_local_opinion(peer_id2, next_epoch);
		peer2.calculate_local_opinion(peer_id1, next_epoch);

		node1.send_epoch_requests(next_epoch);
		node2.send_epoch_requests(next_epoch);

		// Expecting 2 request messages
		// Expecting 2 response sent messages
		// Expecting 2 response received messages
		// Total of 6 messages
		for _ in 0..6 {
			select! {
				event1 = node1.get_swarm_mut().select_next_some() => {
					node1.handle_swarm_events(event1);
				},
				event2 = node2.get_swarm_mut().select_next_some() => {
					node2.handle_swarm_events(event2);
				},
			}
		}

		let peer1 = node1.get_peer();
		let peer2 = node2.get_peer();
		let peer1_neighbor_opinion = peer1.get_neighbor_opinion(&(peer_id2, next_epoch));
		let peer2_neighbor_opinion = peer2.get_neighbor_opinion(&(peer_id1, next_epoch));

		assert_eq!(peer1_neighbor_opinion.epoch, next_epoch);
		assert_eq!(peer1_neighbor_opinion.op, 0.1);

		assert_eq!(peer2_neighbor_opinion.epoch, next_epoch);
		assert_eq!(peer2_neighbor_opinion.op, 0.1);
	}

	#[tokio::test]
	async fn should_run_main_loop() {
		let sk_bytes1 = bs58::decode(SK_1).into_vec().unwrap();
		let sk_bytes2 = bs58::decode(SK_2).into_vec().unwrap();

		let local_key1 = keypair_from_sk_bytes(sk_bytes1).unwrap();
		let local_key2 = keypair_from_sk_bytes(sk_bytes2).unwrap();

		let local_address1 = Multiaddr::from_str(ADDR_1).unwrap();
		let local_address2 = Multiaddr::from_str(ADDR_2).unwrap();

		let params = ParamsKZG::new(13);

		let mut node1 = Node::new(local_key1, local_address1, INTERVAL, params.clone()).unwrap();
		let node2 = Node::new(local_key2, local_address2.clone(), INTERVAL, params).unwrap();

		node1.dial_neighbor(local_address2);

		let join1 = tokio::spawn(async move { node1.main_loop(Some(1)).await });
		let join2 = tokio::spawn(async move { node2.main_loop(Some(1)).await });

		let (res1, res2) = tokio::join!(join1, join2);
		res1.unwrap().unwrap();
		res2.unwrap().unwrap();
	}
}
