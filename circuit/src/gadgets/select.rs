use halo2wrong::halo2::{
	arithmetic::FieldExt,
	circuit::{AssignedCell, Layouter, Region},
	plonk::{Advice, Column, ConstraintSystem, Error, Selector},
	poly::Rotation,
};

use super::is_boolean::IsBooleanChip;
use crate::gadgets::is_boolean::IsBooleanConfig;

#[derive(Clone, Debug)]
pub struct SelectConfig {
	is_bool: IsBooleanConfig,
	bit: Column<Advice>,
	x: Column<Advice>,
	y: Column<Advice>,
	selector: Selector,
}

pub struct SelectChip<F: FieldExt> {
	bit: AssignedCell<F, F>,
	x: AssignedCell<F, F>,
	y: AssignedCell<F, F>,
}

impl<F: FieldExt> SelectChip<F> {
	pub fn new(bit: AssignedCell<F, F>, x: AssignedCell<F, F>, y: AssignedCell<F, F>) -> Self {
		SelectChip { bit, x, y }
	}

	/// Make the circuit config.
	pub fn configure(meta: &mut ConstraintSystem<F>) -> SelectConfig {
		let boolean_config = IsBooleanChip::configure(meta);
		// Q: Should we make a new column for the bit?
		// Or use the one from the IsBoolean chip
		// This way seems more correct?
		let bit = meta.advice_column();
		let x = meta.advice_column();
		let y = meta.advice_column();
		let s = meta.selector();

		meta.enable_equality(bit);
		meta.enable_equality(x);
		meta.enable_equality(y);

		meta.create_gate("select", |v_cells| {
			let bit_exp = v_cells.query_advice(bit, Rotation::cur());
			let x_exp = v_cells.query_advice(x, Rotation::cur());
			let y_exp = v_cells.query_advice(y, Rotation::cur());

			let res_exp = v_cells.query_advice(x, Rotation::next());

			let s_exp = v_cells.query_selector(s);

			vec![
				// bit * (a - b) - (r - b)
				s_exp * (bit_exp.clone() * (x_exp - y_exp.clone()) - (res_exp - y_exp)),
			]
		});

		SelectConfig {
			is_bool: boolean_config,
			bit,
			x,
			y,
			selector: s,
		}
	}

	/// Synthesize the circuit.
	pub fn synthesize(
		&self,
		config: SelectConfig,
		mut layouter: impl Layouter<F>,
	) -> Result<AssignedCell<F, F>, Error> {
		let is_boolean_chip = IsBooleanChip::new(self.bit.clone());
		let assigned_bool = is_boolean_chip
			.synthesize(config.is_bool.clone(), layouter.namespace(|| "is_boolean"))?;

		layouter.assign_region(
			|| "select",
			|mut region: Region<'_, F>| {
				config.selector.enable(&mut region, 0)?;

				let assigned_bit =
					assigned_bool.copy_advice(|| "bit", &mut region, config.bit, 0)?;
				let assigned_x = self.x.copy_advice(|| "x", &mut region, config.x, 0)?;
				let assigned_y = self.y.copy_advice(|| "y", &mut region, config.y, 0)?;

				let res = assigned_bit.value().and_then(|bit_f| {
					if bool::from(bit_f.is_zero()) {
						assigned_y.value().cloned()
					} else {
						assigned_x.value().cloned()
					}
				});

				let assigned_res = region.assign_advice(|| "res", config.x, 1, || res)?;

				Ok(assigned_res)
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
		select: SelectConfig,
		temp: Column<Advice>,
		pub_ins: Column<Instance>,
	}

	#[derive(Clone)]
	struct TestCircuit<F: FieldExt> {
		x: F,
		y: F,
		bit: F,
	}

	impl<F: FieldExt> TestCircuit<F> {
		fn new(bit: F, x: F, y: F) -> Self {
			Self { bit, x, y }
		}
	}

	impl<F: FieldExt> Circuit<F> for TestCircuit<F> {
		type Config = TestConfig;
		type FloorPlanner = SimpleFloorPlanner;

		fn without_witnesses(&self) -> Self {
			self.clone()
		}

		fn configure(meta: &mut ConstraintSystem<F>) -> TestConfig {
			let select = SelectChip::configure(meta);
			let temp = meta.advice_column();
			let pub_ins = meta.instance_column();

			meta.enable_equality(temp);
			meta.enable_equality(pub_ins);

			TestConfig {
				select,
				temp,
				pub_ins,
			}
		}

		fn synthesize(
			&self,
			config: TestConfig,
			mut layouter: impl Layouter<F>,
		) -> Result<(), Error> {
			let (assigned_bit, assigned_x, assigned_y) = layouter.assign_region(
				|| "temp",
				|mut region: Region<'_, F>| {
					let bit = region.assign_advice(
						|| "temp_bit",
						config.temp,
						0,
						|| Value::known(self.bit),
					)?;
					let x = region.assign_advice(
						|| "temp_x",
						config.temp,
						1,
						|| Value::known(self.x),
					)?;
					let y = region.assign_advice(
						|| "temp_y",
						config.temp,
						2,
						|| Value::known(self.y),
					)?;

					Ok((bit, x, y))
				},
			)?;
			let select_chip = SelectChip::new(assigned_bit, assigned_x, assigned_y);
			let res = select_chip.synthesize(config.select, layouter.namespace(|| "select"))?;

			layouter.constrain_instance(res.cell(), config.pub_ins, 0)?;
			Ok(())
		}
	}

	#[test]
	fn test_select() {
		let test_chip = TestCircuit::new(Fr::from(0), Fr::from(2), Fr::from(3));

		let pub_ins = vec![Fr::from(3)];
		let k = 4;
		let prover = MockProver::run(k, &test_chip, vec![pub_ins]).unwrap();
		assert_eq!(prover.verify(), Ok(()));
	}

	#[test]
	fn test_select_production() {
		let test_chip = TestCircuit::new(Fr::from(0), Fr::from(2), Fr::from(3));

		let k = 4;
		let rng = &mut rand::thread_rng();
		let params = generate_params(k);
		let res =
			prove_and_verify::<Bn256, _, _>(params, test_chip, &[&[Fr::from(3)]], rng).unwrap();

		assert!(res);
	}
}
