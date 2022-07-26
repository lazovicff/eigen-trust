#[cfg(test)]
mod test {
	use halo2wrong::halo2::{
		arithmetic::FieldExt,
		circuit::{AssignedCell, Layouter, Region},
		plonk::{Advice, Column, ConstraintSystem, Error, Fixed, Selector},
		poly::Rotation,
	};

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
		a: Column<Advice>,
		fixed: Column<Fixed>,
		pub_ins: Column<Instance>,
	}

	#[derive(Clone)]
	struct TestCircuit<F: FieldExt> {
		a: Value<F>,
	}

	impl<F: FieldExt> TestCircuit<F> {
		fn new(a: F) -> Self {
			Self { a: Value::known(a) }
		}
	}

	impl<F: FieldExt> Circuit<F> for TestCircuit<F> {
		type Config = TestConfig;
		type FloorPlanner = SimpleFloorPlanner;

		fn without_witnesses(&self) -> Self {
			self.clone()
		}

		fn configure(meta: &mut ConstraintSystem<F>) -> TestConfig {
			let a = meta.advice_column();
			let fixed = meta.fixed_column();
			let pub_ins = meta.instance_column();

			meta.enable_equality(a);
			// meta.enable_constant(fixed);
			meta.enable_equality(pub_ins);

			TestConfig { a, fixed, pub_ins }
		}

		fn synthesize(
			&self,
			config: TestConfig,
			mut layouter: impl Layouter<F>,
		) -> Result<(), Error> {
			let res = layouter.assign_region(
				|| "temp",
				|mut region: Region<'_, F>| {
					let a = region.assign_advice(|| "temp", config.a, 0, || self.a)?;

					let fix = region.assign_fixed(
						|| "temp",
						config.fixed,
						0,
						|| Value::known(F::from(1)),
					)?;

					let next = a.value().cloned() * fix.value().cloned();

					let res = region.assign_advice(|| "temp", config.a, 1, || next)?;

					Ok(res)
				},
			)?;

			layouter.constrain_instance(res.cell(), config.pub_ins, 0)?;
			Ok(())
		}
	}

	#[test]
	fn test_fixed() {
		let test_chip = TestCircuit::new(Fr::from(1));

		let k = 4;
		let pub_ins = vec![Fr::from(1)];
		let prover = MockProver::run(k, &test_chip, vec![pub_ins]).unwrap();
		assert_eq!(prover.verify(), Ok(()));
	}

	#[test]
	#[ignore = "Failing to assign to fixed column"]
	fn test_fixed_production() {
		let test_chip = TestCircuit::new(Fr::from(1));

		let k = 4;
		let rng = &mut rand::thread_rng();
		let params = generate_params(k);
		let res =
			prove_and_verify::<Bn256, _, _>(params, test_chip, &[&[Fr::from(1)]], rng).unwrap();
		assert!(res);
	}
}
