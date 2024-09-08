#![feature(slice_as_chunks)]

mod merkle_data;
mod fri_data;

use ark_std::string::String;
use ark_ff::{BigInteger, Field};
use ark_ff::PrimeField;
use ark_serialize::CanonicalDeserialize;
use ark_serialize::CanonicalSerialize;
use binary::AirPrivateInput;
use binary::AirPublicInput;
use binary::CompiledProgram;
use binary::Layout;
use binary::Memory;
use binary::RegisterStates;
use layouts::CairoWitness;
use ministark::stark::Stark;
use ministark::{Air, Proof};
use ministark::ProofOptions;
use ministark_gpu::fields::p3618502788666131213697322783095070105623107215331596699973092056135872020481;
use sandstorm::claims;
use std::fs;
use std::fs::File;
use std::io::Write;
use std::path::PathBuf;
use std::time::Instant;
use ethnum::{u256, AsU256};
use ministark::fri::FriVerifier;
use structopt::StructOpt;
use ministark::hash::{Digest};
use ministark::merkle::{ MerkleTree, MerkleTreeConfig, };
use ministark::random::{PublicCoin};
use ministark_gpu::utils::bit_reverse_index;
use sandstorm::claims::recursive::CairoVerifierClaim;
use serde::Serialize;
use sandstorm::claims::starknet::EthVerifierClaim;
use crate::fri_data::FriData;
use crate::merkle_data::MerkleData;

/// Modulus of Starkware's 252-bit prime field used for Cairo
const STARKWARE_PRIME_HEX_STR: &str =
    "0x800000000000011000000000000000000000000000000000000000000000001";

/// Modulus of 64-bit goldilocks field
#[cfg(feature = "experimental_claims")]
const GOLDILOCKS_PRIME_HEX_STR: &str = "0xffffffff00000001";

#[derive(StructOpt, Debug)]
#[structopt(name = "sandstorm", about = "cairo prover")]
struct SandstormOptions {
    #[structopt(long, parse(from_os_str))]
    program: PathBuf,
    #[structopt(long, parse(from_os_str))]
    air_public_input: PathBuf,
    #[structopt(subcommand)]
    command: Command,
}

#[derive(StructOpt, Debug)]
enum Command {
    Prove {
        #[structopt(long, parse(from_os_str))]
        output: PathBuf,
        #[structopt(long, parse(from_os_str))]
        air_private_input: PathBuf,
        // TODO: add validation to the proof options
        #[structopt(long, default_value = "65")]
        num_queries: u8,
        #[structopt(long, default_value = "2")]
        lde_blowup_factor: u8,
        #[structopt(long, default_value = "16")]
        proof_of_work_bits: u8,
        #[structopt(long, default_value = "8")]
        fri_folding_factor: u8,
        #[structopt(long, default_value = "16")]
        fri_max_remainder_coeffs: u8,
    },
    Verify {
        #[structopt(long, parse(from_os_str))]
        proof: PathBuf,
        #[structopt(long, default_value = "80")]
        required_security_bits: u8,
    },
}

fn debug() {
    let program = "../example/array-sum.json";
    let air_public_input = "../example/air-public-input.json";

    let program_file = File::open(program).expect("could not open program file");
    let air_public_input_file = File::open(air_public_input).expect("could not open public input");
    let program_json: serde_json::Value = serde_json::from_reader(program_file).unwrap();
    let prime: String = serde_json::from_value(program_json["prime"].clone()).unwrap();
    let prover_command = Command::Prove {
        output: "../example/array-sum.proof".into(),
        air_private_input: "../example/air-private-input.json".into(),
        num_queries: 1,
        lde_blowup_factor: 2,
        proof_of_work_bits: 16,
        fri_folding_factor: 8,
        fri_max_remainder_coeffs: 16
    };

    let verifier_command = Command::Verify {
        proof: "../example/array-sum.proof".into(),
        required_security_bits: 80
    };
    match prime.to_lowercase().as_str() {
        STARKWARE_PRIME_HEX_STR => {
            use p3618502788666131213697322783095070105623107215331596699973092056135872020481::ark::Fp;
            let program: CompiledProgram<Fp> = serde_json::from_value(program_json).unwrap();
            let air_public_input: AirPublicInput<Fp> =
                serde_json::from_reader(air_public_input_file).unwrap();
            match air_public_input.layout {
                Layout::Starknet => {
                    use claims::starknet::EthVerifierClaim;
                    println!("Starknet");
                    let claim1 = EthVerifierClaim::new(program.clone(), air_public_input.clone());
                    let claim2 = EthVerifierClaim::new(program, air_public_input);
                    println!("Generate proof:");
                    execute_command(prover_command, claim1);
                    println!("Verify:");
                    execute_command(verifier_command, claim2);
                }
                Layout::Recursive => {
                    use claims::recursive::CairoVerifierClaim;
                    println!("Recursive");
                    let claim1 = CairoVerifierClaim::new(program.clone(), air_public_input.clone());
                    let claim2 = CairoVerifierClaim::new(program, air_public_input);

                    // println!("Generate proof:");
                    execute_command(prover_command, claim1);
                    println!("Verify:");
                    execute_command(verifier_command, claim2);
                }
                _ => unimplemented!(),
            }
        }
        prime => unimplemented!("prime field p={prime} is not supported yet. Consider enabling the \"experimental_claims\" feature."),
    }

}

fn main() {
    // debug();
    let program = "example/array-sum.json";
    let air_public_input = "example/air-public-input.json";

    let program_file = File::open(program).expect("could not open program file");
    let air_public_input_file = File::open(air_public_input).expect("could not open public input");
    let program_json: serde_json::Value = serde_json::from_reader(program_file).unwrap();

    use p3618502788666131213697322783095070105623107215331596699973092056135872020481::ark::Fp;
    let program: CompiledProgram<Fp> = serde_json::from_value(program_json).unwrap();
    let air_public_input: AirPublicInput<Fp> =
        serde_json::from_reader(air_public_input_file).unwrap();
    let claim1 = EthVerifierClaim::new(program, air_public_input);
    separate_starknet_proof(claim1);
}


fn separate_starknet_proof<>(
    claim: EthVerifierClaim,
) {
    let proof_path = "example/array-sum.proof";
    let proof_bytes = fs::read(proof_path).unwrap();
    let proof = Proof::<EthVerifierClaim>::deserialize_compressed(&*proof_bytes).unwrap();

    // FRI query positions
    let (indices, fri_verifier) = generate_verifier(&claim, proof.clone());
    let query_positions: Vec<_> = indices.iter().map(
        |x| x.as_u256()
    ).collect();

    let alphas: Vec<_> = fri_verifier.layer_alphas.iter().map(
        |alpha| {
            let alpha_byte = alpha.0.to_bytes_be();
            u256::from_be_bytes(alpha_byte.try_into().unwrap())
        }
    ).collect();

    let Proof {
        options,
        base_trace_commitment,
        extension_trace_commitment,
        composition_trace_commitment,
        execution_trace_ood_evals,
        composition_trace_ood_evals,
        trace_queries,
        trace_len,
        fri_proof,
        pow_nonce,
        ..
    } = proof;

    // // Merkle proof for Base trace
    // let base_trace_proof = trace_queries.base_trace_proof;
    // // generate base trace input for VerifyMerkle contract.
    // let base_merkle_data = MerkleData::new(&base_trace_proof, &base_trace_commitment, &query_positions);
    // base_merkle_data.write_to_json("base_trace_proof");
    //
    // let extension_trace_proof = trace_queries.extension_trace_proof;
    //
    // if !extension_trace_proof.is_none() {
    //     let extension_merkle_data = MerkleData::new(&extension_trace_proof.unwrap(), &extension_trace_commitment.unwrap(), &query_positions);
    //     extension_merkle_data.write_to_json("extension_trace_proof");
    // }
    // //
    // let composition_trace_proof = trace_queries.composition_trace_proof;
    // let composition_merkle_data = MerkleData::new(&composition_trace_proof, &composition_trace_commitment, &query_positions);
    // composition_merkle_data.write_to_json("composition_trace_proof");

    let layers_flattenend_rows = fri_proof.layers.iter().map(|layer| {
        layer.flattenend_rows.clone()
    }).collect::<Vec<_>>();
    let layers_merkle_proof = fri_proof.layers.iter().map(|layer| {
        layer.merkle_proof.clone()
    }).collect::<Vec<_>>();
    let layers_commitments = fri_proof.layers.iter().map(|layer| {
        layer.commitment.clone()
    }).collect::<Vec<_>>();
    let fri_data = FriData::new(
        layers_flattenend_rows,
        layers_merkle_proof,
        layers_commitments,
        &indices,
        &alphas,
        &options,
        trace_len - 1);
    fri_data.write_to_json("fri_layer");

    // let xs = query_positions
    //     .iter()
    //     .map(|pos| lde_domain.element(bit_reverse_index(lde_domain_size, *pos)))
    //     .collect::<Vec<A::Fp>>();
}

fn generate_verifier<Claim: Stark<Fp = impl Field + ark_ff::FftField>>(
    claim: &Claim,
    proof: Proof<Claim>
) -> (Vec<usize>, FriVerifier<<Claim as Stark>::Fq, <Claim as Stark>::Digest, <Claim as Stark>::MerkleTree>) {
    let Proof {
        options,
        base_trace_commitment,
        extension_trace_commitment,
        composition_trace_commitment,
        execution_trace_ood_evals,
        composition_trace_ood_evals,
        trace_len,
        fri_proof,
        pow_nonce,
        ..
    } = proof;


    // generate queries from public coin
    let air = Air::new(trace_len, claim.get_public_inputs(), options);
    let mut public_coin = claim.gen_public_coin(&air);
    public_coin.reseed_with_digest(&base_trace_commitment);
    let _ = extension_trace_commitment.map(|commitment| {
        public_coin.reseed_with_digest(&commitment);
        commitment
    });
    public_coin.reseed_with_digest(&composition_trace_commitment);
    let ood_evals = [
        execution_trace_ood_evals.clone(),
        composition_trace_ood_evals.clone(),
    ]
        .concat();
    public_coin.reseed_with_field_elements(&ood_evals);
    let fri_verifier = FriVerifier::<<Claim as Stark>::Fq, <Claim as Stark>::Digest, <Claim as Stark>::MerkleTree>::new(
        &mut public_coin,
        options.into_fri_options(),
        fri_proof,
        trace_len - 1,
    ).unwrap();
    if options.grinding_factor != 0 {
        public_coin.reseed_with_int(pow_nonce);
    }
    let lde_domain_size = air.trace_len() * air.lde_blowup_factor();
    let query_positions =
        Vec::from_iter(public_coin.draw_queries(options.num_queries.into(), lde_domain_size));

    (query_positions, fri_verifier)
}

fn execute_command<Fp: PrimeField, Claim: Stark<Fp = Fp, Witness = CairoWitness<Fp>>>(
    command: Command,
    claim: Claim,
) {
    match command {
        Command::Prove {
            output,
            air_private_input,
            num_queries,
            lde_blowup_factor,
            proof_of_work_bits,
            fri_folding_factor,
            fri_max_remainder_coeffs,
        } => {
            let options = ProofOptions::new(
                num_queries,
                lde_blowup_factor,
                proof_of_work_bits,
                fri_folding_factor,
                fri_max_remainder_coeffs,
            );
            prove(options, &air_private_input, &output, claim)
        }
        Command::Verify {
            proof,
            required_security_bits,
        } => verify(required_security_bits, &proof, claim),
    }
}

fn verify<Claim: Stark<Fp = impl Field>>(
    required_security_bits: u8,
    proof_path: &PathBuf,
    claim: Claim,
) {
    let proof_bytes = fs::read(proof_path).unwrap();
    let proof = Proof::<Claim>::deserialize_compressed(&*proof_bytes).unwrap();
    let now = Instant::now();
    claim.verify(proof, required_security_bits.into()).unwrap();
    println!("Proof verified in: {:?}", now.elapsed());
}

fn prove<Fp: PrimeField, Claim: Stark<Fp = Fp, Witness = CairoWitness<Fp>>>(
    options: ProofOptions,
    private_input_path: &PathBuf,
    output_path: &PathBuf,
    claim: Claim,
) {
    let private_input_file =
        File::open(private_input_path).expect("could not open private input file");

    let private_input: AirPrivateInput = serde_json::from_reader(private_input_file).unwrap();

    let trace_path = &private_input.trace_path;
    // println!("{:?}", trace_path);
    let trace_file = File::open(trace_path).expect("could not open trace file");
    let register_states = RegisterStates::from_reader(trace_file);

    let memory_path = &private_input.memory_path;
    let memory_file = File::open(memory_path).expect("could not open memory file");
    let memory = Memory::from_reader(memory_file);

    let witness = CairoWitness::new(private_input, register_states, memory);

    let now = Instant::now();
    let proof = pollster::block_on(claim.prove(options, witness)).unwrap();
    println!("Proof generated in: {:?}", now.elapsed());
    let security_level_bits = proof.security_level_bits();
    println!("Proof security (conjectured): {security_level_bits}bit");
    println!("Base trace commitment: {:?}", proof.base_trace_commitment);

    let mut proof_bytes = Vec::new();
    proof.serialize_compressed(&mut proof_bytes).unwrap();
    println!("Proof size: {:?}KB", proof_bytes.len() / 1024);
    let mut f = File::create(output_path).unwrap();
    f.write_all(proof_bytes.as_slice()).unwrap();
    f.flush().unwrap();
    println!("Proof written to {}", output_path.as_path().display());
}
