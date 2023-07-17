extern crate alloc;

use std::time::Instant;

use super::CairoClaim;
use super::merkle::MerkleTreeVariant;
// use super::merkle::MerkleTreeImpl;
use ark_poly::EvaluationDomain;
use ministark::merkle::MatrixMerkleTree;
use binary::AirPublicInput;
use ministark::merkle::MerkleTree;
use layouts::CairoTrace;
use layouts::CairoWitness;
use layouts::SharpAirConfig;
use ministark::stark::Stark;
use ministark::Air;
use ministark::Matrix;
use ministark::Proof;
use ministark::ProofOptions;
use ministark::challenges::Challenges;
use ministark::channel::ProverChannel;
use ministark::composer::DeepPolyComposer;
use ministark::fri::FriProver;
use ministark::prover::ProvingError;
use ministark::random::draw_multiple;
use ministark::trace::Queries;
use ministark::utils::GpuAllocator;
use ministark::utils::GpuVec;
use ministark_gpu::fields::p3618502788666131213697322783095070105623107215331596699973092056135872020481::ark::Fp;
use sha2::Digest;

impl<
        A: SharpAirConfig<Fp = Fp, Fq = Fp, PublicInputs = AirPublicInput<Fp>>,
        T: CairoTrace<Fp = Fp, Fq = Fp>,
        D: Digest + Send + Sync + 'static,
    > CairoClaim<A, T, D>
{
    #[allow(clippy::too_many_lines, dead_code)]
    pub async fn prove_sharp(
        &self,
        options: ProofOptions,
        witness: CairoWitness<Fp>,
    ) -> Result<Proof<Fp, Fp, D, MerkleTreeVariant<D, Fp>>, ProvingError> {
        let now = Instant::now();
        let trace = self.generate_trace(witness);
        println!(
            "Generated execution trace (cols={}, rows={}) in {:.0?}",
            trace.base_columns().num_cols(),
            trace.base_columns().num_rows(),
            now.elapsed(),
        );

        let now = Instant::now();
        let air = Air::new(trace.len(), self.get_public_inputs(), options);
        let public_coin = self.gen_public_coin(&air);
        let mut channel = ProverChannel::<Self>::new(&air, public_coin);
        println!("Init air: {:?}", now.elapsed());

        // reverse engineering TODOs:
        // 1. don't create leaf hash if row is single item
        // 2. commit to out of order rows
        let now = Instant::now();
        let trace_xs = air.trace_domain();
        let lde_xs = air.lde_domain();
        let base_trace = trace.base_columns();
        assert_eq!(A::NUM_BASE_COLUMNS, base_trace.num_cols());
        let base_trace_polys = base_trace.interpolate(trace_xs);
        let mut base_trace_lde = base_trace_polys.evaluate(lde_xs);
        // NOTE: SHARP commits to bit reversed trace rows
        // TODO: naturally cooley-tuckey fft results in bit reversed evaluations
        // bit reverse should be more optimally integrated into this code
        // base_trace_lde.bit_reverse_rows();
        let base_trace_tree = MerkleTreeVariant::<D, Fp>::from_matrix(&base_trace_lde);
        // base_trace_lde.bit_reverse_rows();
        channel.commit_base_trace(base_trace_tree.root());
        let num_challenges = air.num_challenges();
        let challenges = Challenges::new(draw_multiple(&mut channel.public_coin, num_challenges));
        let hints = air.gen_hints(&challenges);
        println!("Base trace: {:?}", now.elapsed());

        let now = Instant::now();
        let extension_trace = trace.build_extension_columns(&challenges);
        let num_extension_cols = extension_trace.as_ref().map_or(0, Matrix::num_cols);
        assert_eq!(A::NUM_EXTENSION_COLUMNS, num_extension_cols);
        let extension_trace_polys = extension_trace.as_ref().map(|t| t.interpolate(trace_xs));
        let mut extension_trace_lde = extension_trace_polys.as_ref().map(|p| p.evaluate(lde_xs));
        let extension_trace_tree = if let Some(extension_trace_lde) = extension_trace_lde.as_mut() {
            // extension_trace_lde.bit_reverse_rows();
            let extension_trace_tree = MerkleTreeVariant::<D, Fp>::from_matrix(extension_trace_lde);
            // extension_trace_lde.bit_reverse_rows();
            channel.commit_extension_trace(extension_trace_tree.root());
            Some(extension_trace_tree)
        } else {
            None
        };
        println!("Extension trace: {:?}", now.elapsed());

        #[cfg(debug_assertions)]
        self.validate_constraints(&challenges, &hints, base_trace, extension_trace.as_ref());
        drop((trace, extension_trace));

        let now = Instant::now();
        let num_composition_coeffs = air.num_composition_constraint_coeffs();
        let composition_coeffs = draw_multiple(&mut channel.public_coin, num_composition_coeffs);
        let x_lde = lde_xs.elements().collect::<Vec<_>>();
        println!("X lde: {:?}", now.elapsed());
        let now = Instant::now();
        let composition_evals = A::eval_constraint(
            air.composition_constraint(),
            &challenges,
            &hints,
            &composition_coeffs,
            air.lde_blowup_factor(),
            x_lde.to_vec_in(GpuAllocator),
            &base_trace_lde,
            extension_trace_lde.as_ref(),
        );
        println!("Constraint eval: {:?}", now.elapsed());
        let now = Instant::now();
        let composition_poly = composition_evals.into_polynomials(air.lde_domain());
        let composition_trace_cols = air.ce_blowup_factor();
        let composition_trace_polys = Matrix::from_rows(
            GpuVec::try_from(composition_poly)
                .unwrap()
                .chunks(composition_trace_cols)
                .map(<[Fp]>::to_vec)
                .collect(),
        );
        let mut composition_trace_lde = composition_trace_polys.evaluate(air.lde_domain());
        // composition_trace_lde.bit_reverse_rows();
        let composition_trace_tree =
            MerkleTreeVariant::<D, Fp>::from_matrix(&composition_trace_lde);
        // composition_trace_lde.bit_reverse_rows();

        channel.commit_composition_trace(composition_trace_tree.root());
        println!("Constraint composition polys: {:?}", now.elapsed());

        let now = Instant::now();
        let z = channel.get_ood_point();
        let mut deep_poly_composer = DeepPolyComposer::new(
            &air,
            z,
            &base_trace_polys,
            extension_trace_polys.as_ref(),
            composition_trace_polys,
        );
        let (execution_trace_oods, composition_trace_oods) = deep_poly_composer.get_ood_evals();
        channel.send_execution_trace_ood_evals(execution_trace_oods);
        channel.send_composition_trace_ood_evals(composition_trace_oods);

        let deep_coeffs = self.gen_deep_coeffs(&mut channel.public_coin, &air);
        let deep_composition_poly = deep_poly_composer.into_deep_poly(deep_coeffs);
        let deep_composition_lde = deep_composition_poly.into_evaluations(lde_xs);
        println!("Deep composition: {:?}", now.elapsed());

        let now = Instant::now();
        let fri_options = options.into_fri_options();
        let mut fri_prover = FriProver::<Fp, D, MerkleTreeVariant<D, Fp>>::new(fri_options);
        fri_prover.build_layers(&mut channel, deep_composition_lde.try_into().unwrap());

        channel.grind_fri_commitments();

        let query_positions = Vec::from_iter(channel.get_fri_query_positions());
        let fri_proof = fri_prover.into_proof(&query_positions);
        println!("FRI: {:?}", now.elapsed());

        let queries = Queries::new(
            &base_trace_lde,
            extension_trace_lde.as_ref(),
            &composition_trace_lde,
            &base_trace_tree,
            extension_trace_tree.as_ref(),
            &composition_trace_tree,
            &query_positions,
        );
        Ok(channel.build_proof(queries, fri_proof))
    }
}
