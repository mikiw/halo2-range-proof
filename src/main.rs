mod range;

use halo2_proofs::{
    plonk::{create_proof, keygen_pk, keygen_vk, verify_proof},
    poly::kzg::{commitment::ParamsKZG, strategy::SingleVerifier},
    transcript::{Blake2bRead, Blake2bWrite, Challenge255},
};
use rand_core::OsRng;
use pasta_curves::pallas;
use range::RangeCommitCircuit;

fn main() {
    // ---------------- public parameters -----------------
    let k = 8;                                        // 2^8 rows
    let params: ParamsKZG<pallas::Base> = ParamsKZG::new(k);

    // ---------------- public inputs ---------------------
    let lower  = 18u64;
    let upper  = 65u64;
    let secret = 27u64;

    let commitment = pallas::Base::from(secret);

    // ------------------- keys ---------------------------
    let empty  = RangeCommitCircuit::default();
    let vk     = keygen_vk(&params, &empty).unwrap();
    let pk     = keygen_pk(&params, vk, &empty).unwrap();

    // ------------------- witness ------------------------
    let circuit = RangeCommitCircuit {
        secret: Some(pallas::Base::from(secret)),
        lower:  pallas::Base::from(lower),
        upper:  pallas::Base::from(upper),
    };

    // instance column layout: [commit, lower, upper]
    let instance = vec![vec![
        commitment,
        pallas::Base::from(lower),
        pallas::Base::from(upper),
    ]];

    // ----------------- create proof ---------------------
    let mut transcript = Blake2bWrite::<_, _, Challenge255<_>>::init(vec![]);
    create_proof(
        &params,
        &pk,
        &[circuit],
        &[&instance],
        OsRng,
        &mut transcript,
    )
    .unwrap();
    let proof = transcript.finalize();

    // ---------------- verify ----------------------------
    let mut verifier = Blake2bRead::<_, _, Challenge255<_>>::init(&proof[..]);
    let strategy = SingleVerifier::new(&params);
    verify_proof(
        &params,
        pk.get_vk(),
        strategy,
        &[&instance],
        &mut verifier,
    )
    .unwrap();

    println!("🎉  range proof verified!");
}