//! The module for peer management. It contains the functionality for creating a
//! manager, and calculating the global trust scores for assigned children.

use crate::{
	kd_tree::{KdTree, Key},
	peer::Peer,
	EigenError,
};
use ark_std::{collections::BTreeMap, fmt::Debug, vec::Vec, One, Zero};

/// Manager structure.
#[derive(Clone, Debug)]
pub struct Manager {
	/// The unique identifier of the manager.
	index: Key,
	/// Global trust scores of the children.
	global_trust_scores: BTreeMap<Key, f64>,
	/// Pre-trust scores of the whole network.
	pre_trust_scores: BTreeMap<Key, f64>,
	/// State of all children.
	children_states: BTreeMap<Key, bool>,
	/// Children of this manager.
	children: Vec<Key>,
}

impl Manager {
	/// Create a new manager.
	pub fn new(index: Key, pre_trust_scores: BTreeMap<Key, f64>) -> Self {
		Self {
			index,
			// Initially, global trust score is equal to pre trusted score.
			global_trust_scores: pre_trust_scores.clone(),
			pre_trust_scores,
			children_states: BTreeMap::new(),
			children: Vec::new(),
		}
	}

	/// Assign a child to this manager.
	pub fn add_child(&mut self, child: Key) {
		self.children.push(child);
	}

	/// Loop trought all the children and calculate their global trust scores.
	pub fn heartbeat(
		&mut self,
		peers: &BTreeMap<Key, Peer>,
		managers: &BTreeMap<Key, Manager>,
		manager_tree: &KdTree,
		delta: f64,
		pre_trust_weight: f64,
		num_managers: u64,
	) -> Result<(), EigenError> {
		let children = self.children.clone();
		for peer in children {
			self.heartbeat_child(
				&peer,
				peers,
				managers,
				manager_tree,
				delta,
				pre_trust_weight,
				num_managers,
			)?;
		}

		Ok(())
	}

	/// Calculate the global trust score for chlild with id `index`.
	pub fn heartbeat_child(
		&mut self,
		index: &Key,
		peers: &BTreeMap<Key, Peer>,
		managers: &BTreeMap<Key, Manager>,
		manager_tree: &KdTree,
		delta: f64,
		pre_trust_weight: f64,
		num_managers: u64,
	) -> Result<(), EigenError> {
		let child_converged = self.children_states.get(index).unwrap_or(&false);
		if *child_converged {
			return Ok(());
		}

		let mut cached_global_scores: BTreeMap<Key, f64> = BTreeMap::new();

		// Calculate the global scores from previous iteration and cache them.
		for (peer_index, _) in peers.iter() {
			let global_score = self.calculate_global_trust_score_for(
				peer_index,
				managers,
				manager_tree,
				num_managers,
			)?;
			cached_global_scores.insert(*peer_index, global_score);
		}

		let mut new_global_trust_score = f64::zero();
		for (key_j, neighbor_j) in peers.iter() {
			// Skip if the neighbor is the same as child.
			if index == key_j {
				continue;
			}

			// Compute ti = `c_1i*t_1(k) + c_ji*t_z(k) + ... + c_ni*t_n(k)`
			// We are going through each neighbor and taking their local trust
			// towards peer `i`, and multiplying it by that neighbor's global trust score.
			// This means that neighbors' opinion about peer i is weighted by their global
			// trust score. If a neighbor has a low trust score (is not trusted by the
			// network), their opinion is not taken seriously, compared to neighbors with a
			// high trust score.
			let trust_score = neighbor_j.get_local_trust_score(index);
			let global_score = cached_global_scores
				.get(key_j)
				.ok_or(EigenError::PeerNotFound)?;
			let neighbor_opinion = trust_score * global_score;
			new_global_trust_score += neighbor_opinion;
		}

		// (1 - a)*ti + a*p_i
		// The new global trust score (ti) is taken into account.
		// It is weighted by the `pre_trust_weight`, which dictates how seriously the
		// pre-trust score is taken.
		let peer_d = peers.get(index).ok_or(EigenError::PeerNotFound)?;
		new_global_trust_score = (f64::one() - pre_trust_weight) * new_global_trust_score
			+ pre_trust_weight * peer_d.get_pre_trust_score();

		// Converge if the difference between the new and old global trust score is less
		// than delta.
		let diff = (new_global_trust_score - self.get_global_trust_score_for(index)).abs();
		if diff <= delta {
			self.children_states.insert(*index, true);
		}

		self.global_trust_scores
			.insert(*index, new_global_trust_score);

		Ok(())
	}

	/// Calculate the global trust score for the peer with id `index`. This is where we go to
	/// all the managers of that peer and collect their cached global trust scores
	/// for this peer. We then do the majority vote, to settle on a particular
	/// score.
	pub fn calculate_global_trust_score_for(
		&self,
		index: &Key,
		managers: &BTreeMap<Key, Manager>,
		manager_tree: &KdTree,
		num_managers: u64,
	) -> Result<f64, EigenError> {
		let mut scores: BTreeMap<[u8; 8], u64> = BTreeMap::new();
		// TODO: Should it be 2/3 majority or 1/2 majority?
		let majority = (num_managers / 3) * 2;

		let mut hash = *index;
		for _ in 0..num_managers {
			hash = hash.hash();
			let manager_key = manager_tree
				.search(hash)
				.map_err(|_| EigenError::PeerNotFound)?;
			let manager = managers.get(&manager_key).ok_or(EigenError::PeerNotFound)?;
			let score = manager.get_global_trust_score_for(index);

			let score_bytes = score.to_be_bytes();

			let count = scores.entry(score_bytes).or_insert(0);
			*count += 1;

			if *count > majority {
				return Ok(score);
			}
		}

		// We reached the end of the vote without finding a majority.
		Err(EigenError::GlobalTrustCalculationFailed)
	}

	/// Get the children for this manager.
	pub fn get_children(&self) -> Vec<Key> {
		self.children.clone()
	}

	/// Check if the global scores for children are converged.
	pub fn is_converged(&self) -> bool {
		for child in self.children.iter() {
			if !self.children_states.get(child).unwrap_or(&false) {
				return false;
			}
		}
		true
	}

	/// Reset all the children's states to false.
	pub fn reset(&mut self) {
		self.children_states.clear();
	}

	/// Get cached global trust score of the child peer.
	pub fn get_global_trust_score_for(&self, index: &Key) -> f64 {
		*self.global_trust_scores.get(index).unwrap_or(&0.)
	}

	/// Get pre trust score.
	pub fn get_pre_trust_score(&self) -> f64 {
		*self.pre_trust_scores.get(&self.index).unwrap_or(&0.)
	}

	/// Get the index of the peer.
	pub fn get_index(&self) -> Key {
		self.index.clone()
	}
}

#[cfg(test)]
mod test {
	use super::*;

	#[test]
	fn should_create_manager_and_add_children() {
		let key0 = Key::from(0);
		let key1 = Key::from(1);
		let key2 = Key::from(2);
		let mut pre_trusted_scores = BTreeMap::new();
		pre_trusted_scores.insert(key0, 0.3);
		pre_trusted_scores.insert(key1, 0.3);
		let mut manager = Manager::new(key0, pre_trusted_scores);

		assert_eq!(manager.get_index(), key0);
		assert_eq!(manager.get_pre_trust_score(), 0.3);
		assert_eq!(manager.get_global_trust_score_for(&key1), 0.3);

		manager.add_child(key1);
		manager.add_child(key2);

		assert_eq!(manager.get_children(), vec![key1, key2]);
		assert_eq!(manager.is_converged(), false);
	}

	#[test]
	fn should_vote_correctly_on_global_trust_score() {
		let key0 = Key::from(0);
		let key1 = Key::from(1);
		let key2 = Key::from(2);
		let key3 = Key::from(3);

		let num_managers = 4;

		let keys = vec![key0, key1, key2, key3];
		let manager_tree = KdTree::new(keys).unwrap();

		let key_of_interest = key2;
		
		// Every manager will have the same pre-trust scores.
		let mut pre_trusted_scores = BTreeMap::new();
		pre_trusted_scores.insert(key_of_interest, 0.3);
		let manager0 = Manager::new(key0, pre_trusted_scores.clone());
		let manager1 = Manager::new(key1, pre_trusted_scores.clone());
		let manager2 = Manager::new(key2, pre_trusted_scores.clone());
		let manager3 = Manager::new(key3, pre_trusted_scores.clone());

		let mut managers = BTreeMap::new();
		managers.insert(key0, manager0.clone());
		managers.insert(key1, manager1.clone());
		managers.insert(key2, manager2.clone());
		managers.insert(key3, manager3.clone());

		let res = manager0.calculate_global_trust_score_for(&key_of_interest, &managers, &manager_tree, num_managers)
			.unwrap();
		assert_eq!(res, 0.3);

		// 2 of the managers will have different pre-trust scores.
		let mut wrong_pre_trusted_scores = BTreeMap::new();
		wrong_pre_trusted_scores.insert(key_of_interest, 0.2);
		let manager2 = Manager::new(key2, wrong_pre_trusted_scores.clone());
		let manager3 = Manager::new(key3, wrong_pre_trusted_scores.clone());

		managers.insert(key2, manager2.clone());
		managers.insert(key3, manager3.clone());

		let res = manager0.calculate_global_trust_score_for(&key_of_interest, &managers, &manager_tree, num_managers);
		assert_eq!(res.err().unwrap(), EigenError::GlobalTrustCalculationFailed);
	}

	#[test]
	fn manager_should_converge() {
		let key0 = Key::from(0);
		let key1 = Key::from(1);
		let key2 = Key::from(2);
		let key3 = Key::from(3);

		let mut pre_trust_scores = BTreeMap::new();
		pre_trust_scores.insert(key0, 0.4);
		pre_trust_scores.insert(key1, 0.4);
		pre_trust_scores.insert(key2, 0.4);
		pre_trust_scores.insert(key3, 0.4);

		let mut manager0 = Manager::new(key0, pre_trust_scores.clone());
		let mut manager1 = Manager::new(key1, pre_trust_scores.clone());
		let mut manager2 = Manager::new(key2, pre_trust_scores.clone());
		let mut manager3 = Manager::new(key3, pre_trust_scores.clone());

		let peer0 = Peer::new(key0, pre_trust_scores.clone());
		let peer1 = Peer::new(key1, pre_trust_scores.clone());
		let peer2 = Peer::new(key2, pre_trust_scores.clone());
		let peer3 = Peer::new(key3, pre_trust_scores.clone());

		manager0.add_child(key1);
		manager1.add_child(key2);
		manager2.add_child(key3);
		manager3.add_child(key0);

		let peer_keys = vec![key0, key1, key2, key3];
		let manager_tree = KdTree::new(peer_keys).unwrap();

		let mut managers = BTreeMap::new();
		managers.insert(key0, manager0.clone());
		managers.insert(key1, manager1.clone());
		managers.insert(key2, manager2.clone());
		managers.insert(key3, manager3.clone());

		let mut peers = BTreeMap::new();
		peers.insert(key0, peer0);
		peers.insert(key1, peer1);
		peers.insert(key2, peer2);
		peers.insert(key3, peer3);

		let delta = 0.00001;
		let pre_trust_weight = 0.4;
		let num_managers = 1;

		while !manager0.is_converged() {
			manager0
				.heartbeat(
					&peers,
					&managers,
					&manager_tree,
					delta,
					pre_trust_weight,
					num_managers,
				)
				.unwrap();
		}

		assert_eq!(manager0.is_converged(), true);
		let global_trust_score_before = manager0.get_global_trust_score_for(&key1);
		manager0
			.heartbeat(
				&peers,
				&managers,
				&manager_tree,
				delta,
				pre_trust_weight,
				num_managers,
			)
			.unwrap();
		let global_trust_score_after = manager0.get_global_trust_score_for(&key1);

		// The global trust score should not change after converging.
		assert_eq!(global_trust_score_before, global_trust_score_after);

		// Should be able to restart the manager.
		manager0.reset();
		assert_eq!(manager0.is_converged(), false);
	}

	#[test]
	fn global_trust_score_deterministic_calculation() {
		let key0 = Key::from(0);
		let key1 = Key::from(1);
		let key2 = Key::from(2);
		let key3 = Key::from(3);

		// Adding pre-trust scores.
		let mut pre_trust_scores = BTreeMap::new();
		pre_trust_scores.insert(key0, 0.25);
		pre_trust_scores.insert(key1, 0.25);
		pre_trust_scores.insert(key2, 0.25);
		pre_trust_scores.insert(key3, 0.25);

		// Creating managers.
		let manager0 = Manager::new(key0, pre_trust_scores.clone());
		let manager1 = Manager::new(key1, pre_trust_scores.clone());
		let manager2 = Manager::new(key2, pre_trust_scores.clone());
		let manager3 = Manager::new(key3, pre_trust_scores.clone());

		// Creating peers.
		let peer0 = Peer::new(key0, pre_trust_scores.clone());
		let peer1 = Peer::new(key1, pre_trust_scores.clone());
		let peer2 = Peer::new(key2, pre_trust_scores.clone());
		let peer3 = Peer::new(key3, pre_trust_scores.clone());

		// Creating manager tree.
		let peer_keys = vec![key0, key1, key2, key3];
		let manager_tree = KdTree::new(peer_keys.clone()).unwrap();

		// Creating managers map.
		let mut managers = BTreeMap::new();
		managers.insert(key0, manager0);
		managers.insert(key1, manager1);
		managers.insert(key2, manager2);
		managers.insert(key3, manager3);

		// Assigning children to managers.
		for key in &peer_keys {
			let hash = key.hash();
			let manager = manager_tree.search(hash).unwrap();
			managers.get_mut(&manager).unwrap().add_child(*key);
		}

		// Creating peers map.
		let mut peers = BTreeMap::new();
		peers.insert(key0, peer0);
		peers.insert(key1, peer1);
		peers.insert(key2, peer2);
		peers.insert(key3, peer3);

		// Defining parameters.
		let delta = 0.00001;
		let pre_trust_weight = 0.4;
		let num_managers = 1;

		// Clone it before running the loop, so that we get deterministic results,
		// instead of operating on mutable objects.
		let managers_clone = managers.clone();

		// Running heartbeat.
		for key in peer_keys {
			managers
				.get_mut(&key)
				.unwrap()
				.heartbeat(
					&peers,
					&managers_clone,
					&manager_tree,
					delta,
					pre_trust_weight,
					num_managers,
				)
				.unwrap();
		}

		let sum_of_local_scores =
			// local score of peer1 towards peer0, times their global score
			//             0.25                       *                       0.25
			peers[&key1].get_local_trust_score(&key0) * managers[&key0].get_global_trust_score_for(&key1) +
			// local score of peer2 towards peer0, times their global score
			//             0.25                       *                       0.25
			peers[&key2].get_local_trust_score(&key0) * managers[&key0].get_global_trust_score_for(&key2) +
			// local score of peer3 towards peer0, times their global score
			//             0.25                       *                       0.25
			peers[&key3].get_local_trust_score(&key0) * managers[&key0].get_global_trust_score_for(&key3);
		assert_eq!(peers[&key1].get_local_trust_score(&key0), 0.25);
		// Weird rounding error.
		assert_eq!(sum_of_local_scores, 0.1875);

		// (1.0 - 0.4) * 0.1875 + 0.4 * 0.25 = 0.2125
		let new_global_trust_score = (f64::one() - pre_trust_weight) * sum_of_local_scores
			+ pre_trust_weight * peers[&key0].get_pre_trust_score();
		assert_eq!(
			managers[&key1].get_global_trust_score_for(&key0),
			new_global_trust_score
		);
		// Weird rounding error unfourtunately.
		assert_eq!(managers[&key1].get_global_trust_score_for(&key0), 0.2125);
	}
}