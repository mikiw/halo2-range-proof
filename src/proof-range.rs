use std::marker::PhantomData;

use group::ff::Field;
use group::ff::PrimeField;

use halo2_proofs::{
    circuit::{AssignedCell, Chip, Layouter, SimpleFloorPlanner, Value},
    dev::MockProver,
    pasta::Fp,
    plonk::{Advice, Circuit, Column, ConstraintSystem, Error, Instance, Selector},
    // poly::Rotation,
};
use halo2_gadgets::poseidon::{
    primitives::{P128Pow5T3 as PoseidonSpec, ConstantLength},
    Hash as PoseidonHash, Pow5Chip,
};

// WIDTH = 3, RATE = 2; the permutation constants are implied by Pow5Chip
// (P128Pow5T3) so we no longer pass PoseidonSpec here.
type PoseidonChip<F> = Pow5Chip<F, 3, 2>;

#[derive(Clone, Debug)]
struct InRangeConfig<F: PrimeField> {
    advice: [Column<Advice>; 3],
    instance: Column<Instance>,
    s_gate: Selector,
    poseidon_config: <PoseidonChip<F> as Chip<F>>::Config,
}

struct InRangeChip<F: PrimeField> {
    config: InRangeConfig<F>,
    _marker: PhantomData<F>,
}

impl<F: PrimeField> Chip<F> for InRangeChip<F> {
    type Config = InRangeConfig<F>;
    type Loaded = ();

    fn config(&self) -> &Self::Config {
        &self.config
    }

    fn loaded(&self) -> &Self::Loaded {
        &()
    }
}

#[derive(Clone)]
struct Number<F: PrimeField>(AssignedCell<F, F>);

impl<F: PrimeField> InRangeChip<F> {
    fn construct(config: InRangeConfig<F>) -> Self {
        Self {
            config,
            _marker: PhantomData,
        }
    }

    fn configure(meta: &mut ConstraintSystem<F>) -> InRangeConfig<F> {
        let advice = [meta.advice_column(), meta.advice_column(), meta.advice_column()];
        let instance = meta.instance_column();
        for col in &advice {
            meta.enable_equality(*col);
        }
        meta.enable_equality(instance);

        let poseidon_config = PoseidonHash::<F, PoseidonChip<F>, PoseidonSpec, ConstantLength<1>, 3, 2>::configure(
            meta,
            advice[0..3].try_into().unwrap(),
            advice[2],
        );

        InRangeConfig {
            advice,
            instance,
            s_gate: meta.selector(),
            poseidon_config,
        }
    }

    fn assign(
        &self,
        mut layouter: impl Layouter<F>,
        number_val: Value<F>,
        lower_val: Value<F>,
        upper_val: Value<F>,
    ) -> Result<AssignedCell<F, F>, Error> {
        let number = layouter.assign_region(
            || "load number",
            |mut region| region.assign_advice(|| "number", self.config.advice[0], 0, || number_val),
        )?;

        let lower = layouter.assign_region(
            || "load lower bound",
            |mut region| region.assign_advice(|| "lower", self.config.advice[1], 0, || lower_val),
        )?;

        let upper = layouter.assign_region(
            || "load upper bound",
            |mut region| region.assign_advice(|| "upper", self.config.advice[1], 1, || upper_val),
        )?;

        // Simple flag that is always 1 (for demo purposes)
        let flag = layouter.assign_region(
            || "dummy in‑range flag",
            |mut region| {
                region.assign_advice(|| "flag", self.config.advice[2], 0, || Value::known(F::ONE))
            },
        )?;

        // Poseidon hash commitment of the input number
        let poseidon = PoseidonHash::<F, PoseidonChip<F>, PoseidonSpec, ConstantLength<1>, 3, 2>::construct(self.config.poseidon_config.clone());

        let commitment = poseidon.hash(layouter.namespace(|| "hash number"), [number.clone()])?;

        // Expose hash result as public input
        layouter.constrain_instance(commitment.cell(), self.config.instance, 0)?;

        // Expose the flag as the output
        layouter.assign_region(
            || "expose flag",
            |mut region| {
                flag.copy_advice(|| "flag_copy", &mut region, self.config.advice[2], 1)?;
                Ok(flag)
            },
        )
    }
}

#[derive(Default)]
struct InRangeCircuit<F: PrimeField> {
    number: Value<F>,
    lower: Value<F>,
    upper: Value<F>,
}

impl<F: PrimeField> Circuit<F> for InRangeCircuit<F> {
    type Config = InRangeConfig<F>;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self::default()
    }

    fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
        InRangeChip::configure(meta)
    }

    fn synthesize(
        &self,
        config: Self::Config,
        layouter: impl Layouter<F>,
    ) -> Result<(), Error> {
        let chip = InRangeChip::construct(config);
        chip.assign(layouter, self.number, self.lower, self.upper)?;
        Ok(())
    }
}

fn main() {
    let k = 6;
    let number = Fp::from(27);
    let lower = Fp::from(18);
    let upper = Fp::from(65);

    let circuit = InRangeCircuit::<Fp> {
        number: Value::known(number),
        lower: Value::known(lower),
        upper: Value::known(upper),
    };

    let mut poseidon = PoseidonHash::<Fp, PoseidonChip<Fp>, PoseidonSpec, ConstantLength<1>, 3, 2>::init();
    poseidon.update([number]);
    let commitment = poseidon.squeeze();

    let public_inputs = vec![vec![commitment]];

    let prover = MockProver::run(k, &circuit, public_inputs).unwrap();
    assert_eq!(prover.verify(), Ok(()));
}
