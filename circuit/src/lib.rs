//! The module for the main EigenTrust circuit.

#![feature(array_try_map)]
#![feature(array_zip)]
#![allow(clippy::needless_range_loop)]

pub mod gadgets;
pub mod poseidon;
pub mod utils;

use gadgets::{
	accumulate::{AccumulatorChip, AccumulatorConfig},
	and::{AndChip, AndConfig},
	is_equal::{IsEqualChip, IsEqualConfig},
	mul::{MulChip, MulConfig},
	select::{SelectChip, SelectConfig},
	set::{FixedSetChip, FixedSetConfig},
};
pub use halo2wrong;
use halo2wrong::halo2::{
	arithmetic::FieldExt,
	circuit::{AssignedCell, Layouter, Region, SimpleFloorPlanner, Value},
	plonk::{Advice, Circuit, Column, ConstraintSystem, Error, Instance},
};
use poseidon::{params::RoundParams, PoseidonChip, PoseidonConfig};
use std::marker::PhantomData;

/// The halo2 columns config for the main circuit.
#[derive(Clone, Debug)]
pub struct EigenTrustConfig {
	// Gadgets
	set: FixedSetConfig,
	is_equal: IsEqualConfig,
	and: AndConfig,
	select: SelectConfig,
	poseidon: PoseidonConfig<5>,
	accumulator: AccumulatorConfig,
	mul: MulConfig,
	// EigenTrust columns
	temp: Column<Advice>,
	pub_ins: Column<Instance>,
}

/// The EigenTrust main circuit.
#[derive(Clone)]
pub struct EigenTrustCircuit<
	F: FieldExt,
	const SIZE: usize,
	const NUM_BOOTSTRAP: usize,
	P: RoundParams<F, 5>,
> {
	pubkey_v: Value<F>,
	epoch: Value<F>,
	secret_i: [Value<F>; 4],
	/// Opinions of peers j to the peer i (the prover).
	op_ji: [Value<F>; SIZE],
	/// Opinon from peer i (the prover) to the peer v (the verifyer).
	c_v: Value<F>,
	// Bootstrap data
	bootstrap_pubkeys: [F; NUM_BOOTSTRAP],
	boostrap_score: Value<F>,
	genesis_epoch: Value<F>,
	_params: PhantomData<P>,
}

impl<F: FieldExt, const S: usize, const B: usize, P: RoundParams<F, 5>>
	EigenTrustCircuit<F, S, B, P>
{
	/// Create a new EigenTrustCircuit.
	pub fn new(
		pubkey_v: F,
		epoch: F,
		secret_i: [F; 4],
		op_ji: [F; S],
		c_v: F,
		bootstrap_pubkeys: [F; B],
		boostrap_score: F,
		genesis_epoch: F,
	) -> Self {
		Self {
			pubkey_v: Value::known(pubkey_v),
			epoch: Value::known(epoch),
			secret_i: secret_i.map(|val| Value::known(val)),
			op_ji: op_ji.map(|c| Value::known(c)),
			c_v: Value::known(c_v),
			bootstrap_pubkeys,
			boostrap_score: Value::known(boostrap_score),
			genesis_epoch: Value::known(genesis_epoch),
			_params: PhantomData,
		}
	}

	pub fn assign_temp(
		column: Column<Advice>,
		name: &str,
		region: &mut Region<'_, F>,
		offset: &mut usize,
		value: Value<F>,
	) -> Result<AssignedCell<F, F>, Error> {
		let res = region.assign_advice(|| name, column, *offset, || value)?;
		*offset += 1;

		Ok(res)
	}

	pub fn assign_fixed(
		column: Column<Advice>,
		name: &str,
		region: &mut Region<'_, F>,
		offset: &mut usize,
		value: F,
	) -> Result<AssignedCell<F, F>, Error> {
		let res = region.assign_advice_from_constant(|| name, column, *offset, value)?;
		*offset += 1;

		Ok(res)
	}
}

impl<F: FieldExt, const S: usize, const B: usize, P: RoundParams<F, 5>> Circuit<F>
	for EigenTrustCircuit<F, S, B, P>
{
	type Config = EigenTrustConfig;
	type FloorPlanner = SimpleFloorPlanner;

	fn without_witnesses(&self) -> Self {
		Self {
			pubkey_v: Value::unknown(),
			epoch: Value::unknown(),
			secret_i: [Value::unknown(); 4],
			op_ji: [Value::unknown(); S],
			c_v: Value::unknown(),
			bootstrap_pubkeys: self.bootstrap_pubkeys,
			boostrap_score: Value::unknown(),
			genesis_epoch: Value::unknown(),
			_params: PhantomData,
		}
	}

	/// Make the circuit config.
	fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
		let set = FixedSetChip::<_, B>::configure(meta);
		let is_equal = IsEqualChip::configure(meta);
		let and = AndChip::configure(meta);
		let select = SelectChip::configure(meta);
		let poseidon = PoseidonChip::<_, 5, P>::configure(meta);
		let accumulator = AccumulatorChip::<_, S>::configure(meta);
		let mul = MulChip::configure(meta);

		let temp = meta.advice_column();
		let fixed = meta.fixed_column();
		let pub_ins = meta.instance_column();

		meta.enable_equality(temp);
		meta.enable_constant(fixed);
		meta.enable_equality(pub_ins);

		EigenTrustConfig {
			set,
			is_equal,
			and,
			select,
			poseidon,
			accumulator,
			mul,
			temp,
			pub_ins,
		}
	}

	/// Synthesize the circuit.
	fn synthesize(
		&self,
		config: Self::Config,
		mut layouter: impl Layouter<F>,
	) -> Result<(), Error> {
		let (zero, ops, c_v, sk, epoch, genesis_epoch, bootstrap_score, pubkey_v) = layouter
			.assign_region(
				|| "temp",
				|mut region: Region<'_, F>| {
					let mut offset = 0;
					let zero = Self::assign_fixed(
						config.temp,
						"zero",
						&mut region,
						&mut offset,
						F::zero(),
					)?;

					let sk = self
						.secret_i
						.try_map::<_, Result<AssignedCell<F, F>, Error>>(|v| {
							Self::assign_temp(config.temp, "op", &mut region, &mut offset, v)
						})?;

					let epoch = Self::assign_temp(
						config.temp,
						"epoch",
						&mut region,
						&mut offset,
						self.epoch,
					)?;
					let genesis_epoch = Self::assign_temp(
						config.temp,
						"genesis_epoch",
						&mut region,
						&mut offset,
						self.genesis_epoch,
					)?;
					let bootstrap_score = Self::assign_temp(
						config.temp,
						"bootstrap_score",
						&mut region,
						&mut offset,
						self.boostrap_score,
					)?;
					let pubkey_v = Self::assign_temp(
						config.temp,
						"pubkey_v",
						&mut region,
						&mut offset,
						self.pubkey_v,
					)?;
					let c_v =
						Self::assign_temp(config.temp, "c_v", &mut region, &mut offset, self.c_v)?;

					let ops = self
						.op_ji
						.try_map::<_, Result<AssignedCell<F, F>, Error>>(|op| {
							Self::assign_temp(config.temp, "ops", &mut region, &mut offset, op)
						})?;

					Ok((
						zero,
						ops,
						c_v,
						sk,
						epoch,
						genesis_epoch,
						bootstrap_score,
						pubkey_v,
					))
				},
			)?;

		let acc_chip = AccumulatorChip::new(ops);
		let t_i = acc_chip.synthesize(config.accumulator, layouter.namespace(|| "accumulator"))?;

		// Recreate the pubkey_i
		let inputs = [
			zero.clone(),
			sk[0].clone(),
			sk[1].clone(),
			sk[2].clone(),
			sk[3].clone(),
		];
		let poseidon_pk = PoseidonChip::<_, 5, P>::new(inputs);
		let res = poseidon_pk.synthesize(&config.poseidon, layouter.namespace(|| "poseidon_pk"))?;
		let pubkey_i = res[0].clone();

		// Check the bootstrap set membership
		let set_membership = FixedSetChip::new(self.bootstrap_pubkeys, pubkey_i.clone());
		let is_bootstrap =
			set_membership.synthesize(config.set, layouter.namespace(|| "set_membership"))?;

		// Is the epoch equal to the genesis epoch?
		let is_eq_chip = IsEqualChip::new(epoch.clone(), genesis_epoch);
		let is_genesis = is_eq_chip.synthesize(config.is_equal, layouter.namespace(|| "is_eq"))?;

		// Is this the bootstrap peer at genesis epoch?
		let and_chip = AndChip::new(is_bootstrap, is_genesis);
		let is_bootstrap_and_genesis =
			and_chip.synthesize(config.and, layouter.namespace(|| "and"))?;

		// Select the appropriate score, depending on the conditions
		let select_chip = SelectChip::new(is_bootstrap_and_genesis, bootstrap_score, t_i);
		let t_i_select = select_chip.synthesize(config.select, layouter.namespace(|| "select"))?;

		let mul_chip = MulChip::new(t_i_select, c_v);
		let op_v = mul_chip.synthesize(config.mul, layouter.namespace(|| "mul"))?;

		let m_hash_input = [zero, epoch, op_v, pubkey_v, pubkey_i];
		let poseidon_m_hash = PoseidonChip::<_, 5, P>::new(m_hash_input);
		let res = poseidon_m_hash
			.synthesize(&config.poseidon, layouter.namespace(|| "poseidon_m_hash"))?;
		let m_hash = res[0].clone();

		layouter.constrain_instance(m_hash.cell(), config.pub_ins, 0)?;

		Ok(())
	}
}

#[cfg(test)]
mod test {
	use super::*;
	use halo2wrong::{
		curves::bn256::{Bn256, Fr},
		halo2::{arithmetic::Field, dev::MockProver},
	};
	use poseidon::{native::Poseidon, params::bn254_5x5::Params5x5Bn254};
	use rand::thread_rng;
	use utils::{generate_params, prove_and_verify};

	const SIZE: usize = 256;
	const NUM_BOOTSTRAP: usize = 12;
	const MAX_SCORE: u64 = 100000000;

	#[test]
	fn test_eigen_trust_verify() {
		let k = 13;

		let mut rng = thread_rng();
		let pubkey_v = Fr::random(&mut rng);

		let epoch = Fr::one();
		let sk = [(); 4].map(|_| Fr::random(&mut rng));

		// Data from neighbors of i
		let op_ji = [(); SIZE].map(|_| Fr::from_u128(1));
		let c_v = Fr::from_u128(1);

		let bootstrap_pubkeys = [(); NUM_BOOTSTRAP].map(|_| Fr::random(&mut rng));
		let bootstrap_score = Fr::from(MAX_SCORE);
		let genesis_epoch = Fr::one();

		let eigen_trust = EigenTrustCircuit::<Fr, SIZE, NUM_BOOTSTRAP, Params5x5Bn254>::new(
			pubkey_v,
			epoch,
			sk,
			op_ji,
			c_v,
			bootstrap_pubkeys,
			bootstrap_score,
			genesis_epoch,
		);

		let inputs_sk = [Fr::zero(), sk[0], sk[1], sk[2], sk[3]];
		let pubkey_i = Poseidon::<_, 5, Params5x5Bn254>::new(inputs_sk).permute()[0];
		let opv = Fr::from(256);
		let inputs = [Fr::zero(), epoch, opv, pubkey_v, pubkey_i];
		let m_hash_poseidon = Poseidon::<_, 5, Params5x5Bn254>::new(inputs).permute()[0];

		let prover = match MockProver::<Fr>::run(k, &eigen_trust, vec![vec![m_hash_poseidon]]) {
			Ok(prover) => prover,
			Err(e) => panic!("{}", e),
		};

		assert_eq!(prover.verify(), Ok(()));
	}

	#[test]
	fn test_eigen_trust_production_prove_verify() {
		let k = 13;

		let mut rng = thread_rng();
		let pubkey_v = Fr::random(&mut rng);

		let epoch = Fr::one();
		let sk = [(); 4].map(|_| Fr::random(&mut rng));

		// Data from neighbors of i
		let op_ji = [(); SIZE].map(|_| Fr::from_u128(1));
		let c_v = Fr::from_u128(1);

		let bootstrap_pubkeys = [(); NUM_BOOTSTRAP].map(|_| Fr::random(&mut rng));
		let bootstrap_score = Fr::from(MAX_SCORE);
		let genesis_epoch = Fr::one();

		let eigen_trust = EigenTrustCircuit::<Fr, SIZE, NUM_BOOTSTRAP, Params5x5Bn254>::new(
			pubkey_v,
			epoch,
			sk,
			op_ji,
			c_v,
			bootstrap_pubkeys,
			bootstrap_score,
			genesis_epoch,
		);

		let inputs_sk = [Fr::zero(), sk[0], sk[1], sk[2], sk[3]];
		let pubkey_i = Poseidon::<_, 5, Params5x5Bn254>::new(inputs_sk).permute()[0];
		let opv = Fr::from(256);
		let inputs = [Fr::zero(), epoch, opv, pubkey_v, pubkey_i];
		let m_hash_poseidon = Poseidon::<_, 5, Params5x5Bn254>::new(inputs).permute()[0];

		let params = generate_params(k);
		let res =
			prove_and_verify::<Bn256, _, _>(params, eigen_trust, &[&[m_hash_poseidon]], &mut rng)
				.unwrap();
		assert!(res);
	}
}
