use halo2_proofs::{
    arithmetic::FieldExt,
    circuit::{Layouter, SimpleFloorPlanner, Value},
    plonk::{Circuit, Column, ConstraintSystem, Error, Instance},
};
use halo2_gadgets::{
    poseidon::{primitives::P128Pow5T3, PoseidonChip, PoseidonConfig},
    less_than::{LtChip, LtConfig},
};
use pasta_curves::pallas::Base as Fp;

/// How many bits do we allow for the secret? (<= 252 in circom example)
const N_BITS: usize = 64;     // fits money amounts, age, etc.

#[derive(Clone)]
struct RangeCommitConfig {
    // one instance column holds [commitment, lower, upper]
    instance: Column<Instance>,
    // Poseidon and < gadgets live in their own configs
    poseidon: PoseidonConfig<3, 2>,
    lt: LtConfig<N_BITS>,
}

#[derive(Default)]
pub struct RangeCommitCircuit {
    pub secret:  Option<Fp>,   // private witness
    pub lower:   Fp,           // public
    pub upper:   Fp,           // public
}

impl Circuit<Fp> for RangeCommitCircuit {
    type Config = RangeCommitConfig;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self { Self::default() }

    fn configure(meta: &mut ConstraintSystem<Fp>) -> Self::Config {
        // public column
        let instance = meta.instance_column();
        meta.enable_equality(instance);

        // Poseidon chip needs 2 advice cols, 1 fixed, 1 selector
        let poseidon = PoseidonChip::<Fp, P128Pow5T3, 3, 2>::configure(meta);

        // Less-than chip uses one advice col
        let lt = LtChip::<Fp, N_BITS>::configure(meta);

        RangeCommitConfig { instance, poseidon, lt }
    }

    fn synthesize(
        &self,
        cfg:   Self::Config,
        mut layouter: impl Layouter<Fp>
    ) -> Result<(), Error> {

        //--------------------------------------------------------------------
        // 1. allocate the secret number
        //--------------------------------------------------------------------
        let secret_cell = layouter.assign_region(
            || "load secret",
            |mut region| {
                region.assign_advice(
                    || "secret",
                    cfg.poseidon.message[0],   // first advice col from Poseidon config
                    0,
                    || Value::known(self.secret.expect("secret witness missing")),
                )
            }
        )?;

        //--------------------------------------------------------------------
        // 2. Poseidon commitment = H(secret)
        //--------------------------------------------------------------------
        let mut sponge = PoseidonChip::construct(cfg.poseidon.clone());
        let commitment = sponge.hash(
            layouter.namespace(|| "Poseidon hash"),
            &[secret_cell.clone()]
        )?;
        // constrain to public instance[0]
        layouter.constrain_instance(commitment.cell(), cfg.instance, 0)?;

        //--------------------------------------------------------------------
        // 3.  lower < secret    and    secret < upper
        //--------------------------------------------------------------------
        let lt_chip = LtChip::<Fp, N_BITS>::construct(cfg.lt.clone());

        // lower bound : public instance row 1
        let lower_cell = layouter.assign_region(
            || "load lower",
            |mut region| {
                region.assign_advice_from_instance(
                    || "lower",
                    cfg.instance, 1,
                    cfg.lt.advice, 0
                )
            }
        )?;
        // upper bound : public instance row 2
        let upper_cell = layouter.assign_region(
            || "load upper",
            |mut region| {
                region.assign_advice_from_instance(
                    || "upper",
                    cfg.instance, 2,
                    cfg.lt.advice, 1
                )
            }
        )?;

        // lower < secret
        let _ = lt_chip.assign(
            layouter.namespace(|| "lower < secret"),
            lower_cell.clone(),
            secret_cell.clone(),
        )?;

        // secret < upper
        let _ = lt_chip.assign(
            layouter.namespace(|| "secret < upper"),
            secret_cell,
            upper_cell,
        )?;

        Ok(())
    }
}