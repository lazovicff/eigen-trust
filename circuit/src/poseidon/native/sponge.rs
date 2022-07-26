use crate::poseidon::{native::Poseidon, RoundParams};
use halo2wrong::halo2::arithmetic::FieldExt;
use std::marker::PhantomData;

pub struct PoseidonSponge<F: FieldExt, const WIDTH: usize, P>
where
	P: RoundParams<F, WIDTH>,
{
	inputs: Vec<F>,
	_params: PhantomData<P>,
}

impl<F: FieldExt, const WIDTH: usize, P> PoseidonSponge<F, WIDTH, P>
where
	P: RoundParams<F, WIDTH>,
{
	pub fn new() -> Self {
		Self {
			inputs: Vec::new(),
			_params: PhantomData,
		}
	}

	pub fn update(&mut self, inputs: &[F]) {
		self.inputs.extend_from_slice(inputs);
	}

	pub fn load_state(chunk: &[F]) -> [F; WIDTH] {
		assert!(chunk.len() <= WIDTH);
		let mut fixed_chunk = [F::zero(); WIDTH];
		fixed_chunk[..chunk.len()].copy_from_slice(chunk);
		fixed_chunk
	}

	pub fn squeeze(&mut self) -> F {
		assert!(!self.inputs.is_empty());

		let mut state = [F::zero(); WIDTH];

		for chunk in self.inputs.chunks(WIDTH) {
			let loaded_state = Self::load_state(chunk);
			let input = loaded_state.zip(state).map(|(lhs, rhs)| lhs + rhs);

			let pos = Poseidon::<_, WIDTH, P>::new(input);
			state = pos.permute();
		}

		state[0]
	}
}
