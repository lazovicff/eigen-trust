use halo2wrong::halo2::{
	arithmetic::FieldExt,
	circuit::{AssignedCell, Layouter, Region},
	plonk::{Advice, Column, ConstraintSystem, Error, Selector},
	poly::Rotation,
};

use super::is_boolean::{IsBooleanChip, IsBooleanConfig};

#[derive(Clone, Debug)]
pub struct AndConfig {
	is_bool: IsBooleanConfig,
	x: Column<Advice>,
	y: Column<Advice>,
	selector: Selector,
}

pub struct AndChip<F: FieldExt> {
	x: AssignedCell<F, F>,
	y: AssignedCell<F, F>,
}

impl<F: FieldExt> AndChip<F> {
	pub fn new(x: AssignedCell<F, F>, y: AssignedCell<F, F>) -> Self {
		AndChip { x, y }
	}

	/// Make the circuit config.
	pub fn configure(meta: &mut ConstraintSystem<F>) -> AndConfig {
		let is_bool = IsBooleanChip::configure(meta);
		let x = meta.advice_column();
		let y = meta.advice_column();
		let s = meta.selector();

		meta.enable_equality(x);
		meta.enable_equality(y);

		meta.create_gate("and", |v_cells| {
			let x_exp = v_cells.query_advice(x, Rotation::cur());
			let y_exp = v_cells.query_advice(y, Rotation::cur());
			let res_exp = v_cells.query_advice(x, Rotation::next());
			let s_exp = v_cells.query_selector(s);

			vec![
				// (x * y) - z == 0
				s_exp * ((x_exp * y_exp) - res_exp),
			]
		});

		AndConfig {
			is_bool,
			x,
			y,
			selector: s,
		}
	}

	/// Synthesize the circuit.
	pub fn synthesize(
		&self,
		config: AndConfig,
		mut layouter: impl Layouter<F>,
	) -> Result<AssignedCell<F, F>, Error> {
		let is_bool_x = IsBooleanChip::new(self.x.clone());
		let is_bool_y = IsBooleanChip::new(self.y.clone());
		let x_checked =
			is_bool_x.synthesize(config.is_bool.clone(), layouter.namespace(|| "is_bool_x"))?;
		let y_checked = is_bool_y.synthesize(config.is_bool, layouter.namespace(|| "is_bool_y"))?;

		layouter.assign_region(
			|| "and",
			|mut region: Region<'_, F>| {
				config.selector.enable(&mut region, 0)?;

				let assigned_x = x_checked.copy_advice(|| "x", &mut region, config.x, 0)?;
				let assigned_y = y_checked.copy_advice(|| "y", &mut region, config.y, 0)?;

				let res = assigned_x.value().cloned() * assigned_y.value();

				let res_assigned = region.assign_advice(|| "res", config.x, 1, || res)?;

				Ok(res_assigned)
			},
		)
	}
}

#[cfg(test)]
mod test {
	use super::*;
	use crate::utils::{generate_params, prove_and_verify};
	use halo2wrong::{
		curves::bn256::{Bn256, Fr},
		halo2::{
			circuit::{SimpleFloorPlanner, Value},
			dev::MockProver,
			plonk::{Circuit, Instance},
		},
	};

	#[derive(Clone)]
	struct TestConfig {
		and: AndConfig,
		temp: Column<Advice>,
		pub_ins: Column<Instance>,
	}

	#[derive(Clone)]
	struct TestCircuit<F: FieldExt> {
		x: F,
		y: F,
	}

	impl<F: FieldExt> TestCircuit<F> {
		fn new(x: F, y: F) -> Self {
			Self { x, y }
		}
	}

	impl<F: FieldExt> Circuit<F> for TestCircuit<F> {
		type Config = TestConfig;
		type FloorPlanner = SimpleFloorPlanner;

		fn without_witnesses(&self) -> Self {
			self.clone()
		}

		fn configure(meta: &mut ConstraintSystem<F>) -> TestConfig {
			let and = AndChip::configure(meta);
			let temp = meta.advice_column();
			let pub_ins = meta.instance_column();

			meta.enable_equality(temp);
			meta.enable_equality(pub_ins);

			TestConfig { and, pub_ins, temp }
		}

		fn synthesize(
			&self,
			config: TestConfig,
			mut layouter: impl Layouter<F>,
		) -> Result<(), Error> {
			let (x, y) = layouter.assign_region(
				|| "temp",
				|mut region: Region<'_, F>| {
					let x = region.assign_advice(
						|| "temp_x",
						config.temp,
						0,
						|| Value::known(self.x),
					)?;
					let y = region.assign_advice(
						|| "temp_y",
						config.temp,
						1,
						|| Value::known(self.y),
					)?;

					Ok((x, y))
				},
			)?;
			let and_chip = AndChip::new(x, y);
			let res = and_chip.synthesize(config.and, layouter.namespace(|| "and"))?;

			layouter.constrain_instance(res.cell(), config.pub_ins, 0)?;
			Ok(())
		}
	}

	#[test]
	fn test_and() {
		let test_chip = TestCircuit::new(Fr::from(1), Fr::from(1));

		let pub_ins = vec![Fr::from(1)];
		let k = 4;
		let prover = MockProver::run(k, &test_chip, vec![pub_ins]).unwrap();
		assert_eq!(prover.verify(), Ok(()));
	}

	#[test]
	fn test_and_production() {
		let test_chip = TestCircuit::new(Fr::from(1), Fr::from(1));

		let k = 4;
		let rng = &mut rand::thread_rng();
		let params = generate_params(k);
		let res =
			prove_and_verify::<Bn256, _, _>(params, test_chip, &[&[Fr::from(1)]], rng).unwrap();

		assert!(res);
	}
}
