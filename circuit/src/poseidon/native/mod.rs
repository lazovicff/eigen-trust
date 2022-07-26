pub mod sponge;

use super::params::RoundParams;
use halo2wrong::halo2::arithmetic::FieldExt;
use std::marker::PhantomData;

pub struct Poseidon<F: FieldExt, const WIDTH: usize, P>
where
	P: RoundParams<F, WIDTH>,
{
	inputs: [F; WIDTH],
	_params: PhantomData<P>,
}

impl<F: FieldExt, const WIDTH: usize, P> Poseidon<F, WIDTH, P>
where
	P: RoundParams<F, WIDTH>,
{
	pub fn new(inputs: [F; WIDTH]) -> Self {
		Poseidon {
			inputs,
			_params: PhantomData,
		}
	}

	fn apply_round_constants(state: &[F; WIDTH], round_consts: &[F; WIDTH]) -> [F; WIDTH] {
		let mut next_state = [F::zero(); WIDTH];
		for i in 0..WIDTH {
			let state = state[i];
			let round_const = round_consts[i];
			let sum = state + round_const;
			next_state[i] = sum;
		}
		next_state
	}

	fn apply_mds(state: &[F; WIDTH], mds: &[[F; WIDTH]; WIDTH]) -> [F; WIDTH] {
		let mut new_state = [F::zero(); WIDTH];
		// Compute mds matrix
		for i in 0..WIDTH {
			for j in 0..WIDTH {
				let mds_ij = &mds[i][j];
				let m_product = state[j] * mds_ij;
				new_state[i] += m_product;
			}
		}
		new_state
	}

	pub fn permute(&self) -> [F; WIDTH] {
		let full_rounds = P::full_rounds();
		let half_full_rounds = full_rounds / 2;
		let partial_rounds = P::partial_rounds();
		let mds = P::mds();
		let round_constants = P::round_constants();
		let total_count = P::round_constants_count();

		let first_round_end = half_full_rounds * WIDTH;
		let first_round_constants = &round_constants[0..first_round_end];

		let second_round_end = first_round_end + partial_rounds * WIDTH;
		let second_round_constants = &round_constants[first_round_end..second_round_end];

		let third_round_constants = &round_constants[second_round_end..total_count];

		let mut state = self.inputs;
		for round in 0..half_full_rounds {
			let round_consts = P::load_round_constants(round, first_round_constants);
			state = Self::apply_round_constants(&state, &round_consts);
			for i in 0..WIDTH {
				state[i] = P::sbox_f(state[i]);
			}
			state = Self::apply_mds(&state, &mds);
		}

		for round in 0..partial_rounds {
			let round_consts = P::load_round_constants(round, second_round_constants);
			state = Self::apply_round_constants(&state, &round_consts);
			state[0] = P::sbox_f(state[0]);
			state = Self::apply_mds(&state, &mds);
		}

		for round in 0..half_full_rounds {
			let round_consts = P::load_round_constants(round, third_round_constants);
			state = Self::apply_round_constants(&state, &round_consts);
			for i in 0..WIDTH {
				state[i] = P::sbox_f(state[i]);
			}
			state = Self::apply_mds(&state, &mds);
		}

		state
	}
}

#[cfg(test)]
mod test {
	use super::*;
	use crate::poseidon::params::{bn254_5x5::Params5x5Bn254, hex_to_field};
	use halo2wrong::curves::bn256::Fr;

	type TestPoseidon = Poseidon<Fr, 5, Params5x5Bn254>;

	#[test]
	fn test_native_poseidon_5x5() {
		let inputs: [Fr; 5] = [
			"0x0000000000000000000000000000000000000000000000000000000000000000",
			"0x0000000000000000000000000000000000000000000000000000000000000001",
			"0x0000000000000000000000000000000000000000000000000000000000000002",
			"0x0000000000000000000000000000000000000000000000000000000000000003",
			"0x0000000000000000000000000000000000000000000000000000000000000004",
		]
		.map(|n| hex_to_field(n));

		let outputs: [Fr; 5] = [
			"0x299c867db6c1fdd79dcefa40e4510b9837e60ebb1ce0663dbaa525df65250465",
			"0x1148aaef609aa338b27dafd89bb98862d8bb2b429aceac47d86206154ffe053d",
			"0x24febb87fed7462e23f6665ff9a0111f4044c38ee1672c1ac6b0637d34f24907",
			"0x0eb08f6d809668a981c186beaf6110060707059576406b248e5d9cf6e78b3d3e",
			"0x07748bc6877c9b82c8b98666ee9d0626ec7f5be4205f79ee8528ef1c4a376fc7",
		]
		.map(|n| hex_to_field(n));

		let poseidon = TestPoseidon::new(inputs);

		let out = poseidon.permute();

		assert_eq!(out, outputs);
	}
}
