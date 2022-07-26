pub mod bn254_10x5;
pub mod bn254_5x5;

use halo2wrong::halo2::{arithmetic::FieldExt, plonk::Expression};

pub trait RoundParams<F: FieldExt, const WIDTH: usize>: Sbox {
	fn full_rounds() -> usize;
	fn partial_rounds() -> usize;

	fn round_constants_count() -> usize {
		let partial_rounds = Self::partial_rounds();
		let full_rounds = Self::full_rounds();
		(partial_rounds + full_rounds) * WIDTH
	}

	fn round_constants() -> Vec<F> {
		let round_constants_raw = Self::round_constants_raw();
		let round_constants: Vec<F> = round_constants_raw
			.iter()
			.map(|x| hex_to_field(x))
			.collect();
		assert_eq!(round_constants.len(), Self::round_constants_count());
		round_constants
	}

	fn load_round_constants(round: usize, round_consts: &[F]) -> [F; WIDTH] {
		let mut result = [F::zero(); WIDTH];
		for i in 0..WIDTH {
			result[i] = round_consts[round * WIDTH + i];
		}
		result
	}

	fn mds() -> [[F; WIDTH]; WIDTH] {
		let mds_raw = Self::mds_raw();
		mds_raw.map(|row| row.map(|item| hex_to_field(item)))
	}

	fn round_constants_raw() -> Vec<&'static str>;
	fn mds_raw() -> [[&'static str; WIDTH]; WIDTH];
}

pub trait Sbox {
	fn sbox_expr<F: FieldExt>(exp: Expression<F>) -> Expression<F>;
	fn sbox_f<F: FieldExt>(f: F) -> F;
}

pub fn hex_to_field<F: FieldExt>(s: &str) -> F {
	let s = &s[2..];
	let mut bytes = hex::decode(s).expect("Invalid params");
	bytes.reverse();
	let mut bytes_wide: [u8; 64] = [0; 64];
	bytes_wide[..bytes.len()].copy_from_slice(&bytes[..]);
	F::from_bytes_wide(&bytes_wide)
}
