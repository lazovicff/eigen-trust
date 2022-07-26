use halo2wrong::halo2::{
	arithmetic::FieldExt,
	circuit::{AssignedCell, Layouter, Region, Value},
	plonk::{Advice, Column, ConstraintSystem, Error, Expression, Selector},
	poly::Rotation,
};

#[derive(Clone, Debug)]
pub struct IsZeroConfig {
	x: Column<Advice>,
	x_inv: Column<Advice>,
	b: Column<Advice>,
	selector: Selector,
}

pub struct IsZeroChip<F: FieldExt> {
	x: AssignedCell<F, F>,
}

impl<F: FieldExt> IsZeroChip<F> {
	pub fn new(x: AssignedCell<F, F>) -> Self {
		IsZeroChip { x }
	}

	/// Make the circuit config.
	pub fn configure(meta: &mut ConstraintSystem<F>) -> IsZeroConfig {
		let x = meta.advice_column();
		let x_inv = meta.advice_column();
		let b = meta.advice_column();
		let s = meta.selector();

		meta.enable_equality(x);
		meta.enable_equality(b);

		meta.create_gate("is_equal", |v_cells| {
			let one = Expression::Constant(F::one());
			let x_exp = v_cells.query_advice(x, Rotation::cur());
			let x_inv_exp = v_cells.query_advice(x_inv, Rotation::cur());
			let b_exp = v_cells.query_advice(b, Rotation::cur());
			let sel_exp = v_cells.query_selector(s);

			vec![
				// x * b == 0
				sel_exp.clone() * (x_exp.clone() * b_exp.clone()),
				// x * x_inv + b - 1 == 0
				sel_exp * (x_exp * x_inv_exp + b_exp - one),
			]
		});

		IsZeroConfig {
			x,
			x_inv,
			b,
			selector: s,
		}
	}

	/// Synthesize the circuit.
	pub fn synthesize(
		&self,
		config: IsZeroConfig,
		mut layouter: impl Layouter<F>,
	) -> Result<AssignedCell<F, F>, Error> {
		let is_zero = layouter.assign_region(
			|| "is_eq",
			|mut region: Region<'_, F>| {
				config.selector.enable(&mut region, 0)?;

				let one = Value::known(F::one());
				let x_inv = self.x.value().and_then(|val| {
					let val_opt: Option<F> = val.invert().into();
					Value::known(val_opt.unwrap_or(F::one()))
				});
				let b = one - self.x.value().cloned() * x_inv;

				self.x.copy_advice(|| "x", &mut region, config.x, 0)?;
				region.assign_advice(|| "x_inv", config.x_inv, 0, || x_inv)?;
				let assigned_b = region.assign_advice(|| "b", config.b, 0, || b)?;

				Ok(assigned_b)
			},
		)?;

		Ok(is_zero)
	}
}

#[cfg(test)]
mod test {
	use super::*;
	use crate::utils::{generate_params, prove_and_verify};
	use halo2wrong::{
		curves::bn256::{Bn256, Fr},
		halo2::{
			circuit::SimpleFloorPlanner,
			dev::MockProver,
			plonk::{Circuit, Instance},
		},
	};

	#[derive(Clone)]
	struct TestConfig {
		is_zero: IsZeroConfig,
		pub_ins: Column<Instance>,
		temp: Column<Advice>,
	}

	#[derive(Clone)]
	struct TestCircuit<F: FieldExt> {
		numba: F,
	}

	impl<F: FieldExt> TestCircuit<F> {
		fn new(x: F) -> Self {
			Self { numba: x }
		}
	}

	impl<F: FieldExt> Circuit<F> for TestCircuit<F> {
		type Config = TestConfig;
		type FloorPlanner = SimpleFloorPlanner;

		fn without_witnesses(&self) -> Self {
			self.clone()
		}

		fn configure(meta: &mut ConstraintSystem<F>) -> TestConfig {
			let is_zero = IsZeroChip::configure(meta);
			let temp = meta.advice_column();
			let instance = meta.instance_column();

			meta.enable_equality(instance);
			meta.enable_equality(temp);

			TestConfig {
				is_zero,
				pub_ins: instance,
				temp,
			}
		}

		fn synthesize(
			&self,
			config: TestConfig,
			mut layouter: impl Layouter<F>,
		) -> Result<(), Error> {
			let numba = layouter.assign_region(
				|| "temp",
				|mut region: Region<'_, F>| {
					region.assign_advice(|| "temp_x", config.temp, 0, || Value::known(self.numba))
				},
			)?;
			let is_zero_chip = IsZeroChip::new(numba);
			let is_zero =
				is_zero_chip.synthesize(config.is_zero, layouter.namespace(|| "is_zero"))?;
			layouter.constrain_instance(is_zero.cell(), config.pub_ins, 0)?;
			Ok(())
		}
	}

	#[test]
	fn test_is_zero() {
		let test_chip = TestCircuit::new(Fr::from(0));

		let pub_ins = vec![Fr::one()];
		let k = 4;
		let prover = MockProver::run(k, &test_chip, vec![pub_ins]).unwrap();
		assert_eq!(prover.verify(), Ok(()));
	}

	#[test]
	fn test_is_zero_production() {
		let test_chip = TestCircuit::new(Fr::from(0));

		let k = 4;
		let rng = &mut rand::thread_rng();
		let params = generate_params(k);
		let res = prove_and_verify::<Bn256, _, _>(params, test_chip, &[&[Fr::one()]], rng).unwrap();

		assert!(res);
	}
}
