use halo2wrong::halo2::{
	arithmetic::FieldExt,
	circuit::{AssignedCell, Layouter, Region},
	plonk::{Advice, Column, ConstraintSystem, Error, Selector},
	poly::Rotation,
};

#[derive(Clone, Debug)]
pub struct MulConfig {
	x: Column<Advice>,
	y: Column<Advice>,
	selector: Selector,
}

pub struct MulChip<F: FieldExt> {
	x: AssignedCell<F, F>,
	y: AssignedCell<F, F>,
}

impl<F: FieldExt> MulChip<F> {
	pub fn new(x: AssignedCell<F, F>, y: AssignedCell<F, F>) -> Self {
		MulChip { x, y }
	}

	/// Make the circuit config.
	pub fn configure(meta: &mut ConstraintSystem<F>) -> MulConfig {
		let x = meta.advice_column();
		let y = meta.advice_column();
		let s = meta.selector();

		meta.enable_equality(x);
		meta.enable_equality(y);

		meta.create_gate("mul", |v_cells| {
			let x_exp = v_cells.query_advice(x, Rotation::cur());
			let y_exp = v_cells.query_advice(y, Rotation::cur());
			let x_next_exp = v_cells.query_advice(x, Rotation::next());
			let s_exp = v_cells.query_selector(s);

			vec![
				// (x * y) - res == 0
				s_exp * ((x_exp * y_exp) - x_next_exp),
			]
		});

		MulConfig { x, y, selector: s }
	}

	/// Synthesize the circuit.
	pub fn synthesize(
		&self,
		config: MulConfig,
		mut layouter: impl Layouter<F>,
	) -> Result<AssignedCell<F, F>, Error> {
		layouter.assign_region(
			|| "mul",
			|mut region: Region<'_, F>| {
				config.selector.enable(&mut region, 0)?;
				let assigned_x = self.x.copy_advice(|| "x", &mut region, config.x, 0)?;
				let assigned_y = self.y.copy_advice(|| "y", &mut region, config.y, 0)?;

				let out = assigned_x.value().cloned() * assigned_y.value();

				let out_assigned = region.assign_advice(|| "out", config.x, 1, || out)?;

				Ok(out_assigned)
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
		mul: MulConfig,
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
			let mul = MulChip::configure(meta);
			let temp = meta.advice_column();
			let pub_ins = meta.instance_column();

			meta.enable_equality(temp);
			meta.enable_equality(pub_ins);

			TestConfig { mul, temp, pub_ins }
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
			let mul_chip = MulChip::new(x, y);
			let res = mul_chip.synthesize(config.mul, layouter.namespace(|| "mul"))?;

			layouter.constrain_instance(res.cell(), config.pub_ins, 0)?;
			Ok(())
		}
	}

	#[test]
	fn test_mul() {
		let test_chip = TestCircuit::new(Fr::from(5), Fr::from(2));

		let k = 4;
		let pub_ins = vec![Fr::from(10)];
		let prover = MockProver::run(k, &test_chip, vec![pub_ins]).unwrap();
		assert_eq!(prover.verify(), Ok(()));
	}

	#[test]
	fn test_mul_production() {
		let test_chip = TestCircuit::new(Fr::from(5), Fr::from(2));

		let k = 4;
		let rng = &mut rand::thread_rng();
		let params = generate_params(k);
		let res =
			prove_and_verify::<Bn256, _, _>(params, test_chip, &[&[Fr::from(10)]], rng).unwrap();

		assert!(res);
	}
}
