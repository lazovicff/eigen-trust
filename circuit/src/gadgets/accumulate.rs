use halo2wrong::halo2::{
	arithmetic::FieldExt,
	circuit::{AssignedCell, Layouter, Region},
	plonk::{Advice, Column, ConstraintSystem, Error, Selector},
	poly::Rotation,
};

#[derive(Clone, Debug)]
pub struct AccumulatorConfig {
	acc: Column<Advice>,
	items: Column<Advice>,
	selector: Selector,
}

pub struct AccumulatorChip<F: FieldExt, const S: usize> {
	items: [AssignedCell<F, F>; S],
	start: AssignedCell<F, F>,
}

impl<F: FieldExt, const S: usize> AccumulatorChip<F, S> {
	pub fn new(items: [AssignedCell<F, F>; S], start: AssignedCell<F, F>) -> Self {
		AccumulatorChip { items, start }
	}

	/// Make the circuit config.
	pub fn configure(meta: &mut ConstraintSystem<F>) -> AccumulatorConfig {
		let acc = meta.advice_column();
		let items = meta.advice_column();
		let fixed = meta.fixed_column();
		let s = meta.selector();

		meta.enable_equality(acc);
		meta.enable_equality(items);
		meta.enable_equality(fixed);

		meta.create_gate("acc", |v_cells| {
			let acc_exp = v_cells.query_advice(acc, Rotation::cur());
			let item_exp = v_cells.query_advice(items, Rotation::cur());
			let acc_next = v_cells.query_advice(acc, Rotation::next());

			let s = v_cells.query_selector(s);

			vec![s * (acc_exp + item_exp - acc_next)]
		});

		AccumulatorConfig {
			acc,
			items,
			selector: s,
		}
	}

	/// Synthesize the circuit.
	pub fn synthesize(
		&self,
		config: AccumulatorConfig,
		mut layouter: impl Layouter<F>,
	) -> Result<AssignedCell<F, F>, Error> {
		layouter.assign_region(
			|| "acc",
			|mut region: Region<'_, F>| {
				config.selector.enable(&mut region, 0)?;
				let zero = self
					.start
					.copy_advice(|| "start", &mut region, config.acc, 0)?;
				let item = self.items[0].copy_advice(|| "item", &mut region, config.items, 0)?;

				let val = zero.value().cloned() + item.value();
				let mut acc = region.assign_advice(|| "acc", config.acc, 1, || val)?;

				for i in 1..S {
					config.selector.enable(&mut region, i)?;
					let item =
						self.items[i].copy_advice(|| "item", &mut region, config.items, i)?;
					let val = acc.value().cloned() + item.value();
					acc = region.assign_advice(|| "acc", config.acc, i + 1, || val)?;
				}

				Ok(acc)
			},
		)
	}
}

#[cfg(test)]
mod test {
	use super::*;
	use halo2wrong::{
		curves::bn256::Fr,
		halo2::{
			circuit::{SimpleFloorPlanner, Value},
			dev::MockProver,
			plonk::{Circuit, Instance},
		},
	};

	#[derive(Clone)]
	struct TestConfig {
		acc: AccumulatorConfig,
		temp: Column<Advice>,
		pub_ins: Column<Instance>,
	}

	#[derive(Clone)]
	struct TestCircuit<F: FieldExt> {
		items: [F; 3],
	}

	impl<F: FieldExt> TestCircuit<F> {
		fn new(items: [F; 3]) -> Self {
			Self { items }
		}
	}

	impl<F: FieldExt> Circuit<F> for TestCircuit<F> {
		type Config = TestConfig;
		type FloorPlanner = SimpleFloorPlanner;

		fn without_witnesses(&self) -> Self {
			self.clone()
		}

		fn configure(meta: &mut ConstraintSystem<F>) -> TestConfig {
			let acc = AccumulatorChip::<_, 3>::configure(meta);
			let temp = meta.advice_column();
			let pub_ins = meta.instance_column();

			meta.enable_equality(temp);
			meta.enable_equality(pub_ins);

			TestConfig { acc, temp, pub_ins }
		}

		fn synthesize(
			&self,
			config: TestConfig,
			mut layouter: impl Layouter<F>,
		) -> Result<(), Error> {
			let (arr, start) = layouter.assign_region(
				|| "temp",
				|mut region: Region<'_, F>| {
					let mut arr: [Option<AssignedCell<F, F>>; 3] = [(); 3].map(|_| None);
					for i in 0..3 {
						arr[i] = Some(region.assign_advice(
							|| "temp",
							config.temp,
							i,
							|| Value::known(self.items[i]),
						)?);
					}

					let start = region.assign_advice(
						|| "temp",
						config.temp,
						3,
						|| Value::known(F::zero()),
					)?;
					Ok((arr.map(|a| a.unwrap()), start))
				},
			)?;
			let acc_chip = AccumulatorChip::new(arr, start);
			let sum = acc_chip.synthesize(config.acc, layouter.namespace(|| "acc"))?;

			layouter.constrain_instance(sum.cell(), config.pub_ins, 0)?;
			Ok(())
		}
	}

	#[test]
	fn test_acc() {
		let test_chip = TestCircuit::new([Fr::from(1); 3]);

		let k = 4;
		let pub_ins = vec![Fr::from(3)];
		let prover = MockProver::run(k, &test_chip, vec![pub_ins]).unwrap();
		assert_eq!(prover.verify(), Ok(()));
	}
}