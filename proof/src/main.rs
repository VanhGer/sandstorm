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
use ethnum::{u256, AsU256, U256};
use ministark::fri::FriVerifier;
use structopt::StructOpt;
use ministark::hash::{Digest};
use ministark::merkle::{ MerkleTree, MerkleTreeConfig, };
use ministark::random::{PublicCoin};
use ministark::utils::SerdeOutput;
use crypto::merkle::{ LeafVariantMerkleTreeProof};
use sandstorm::claims::recursive::CairoVerifierClaim;
use serde::Serialize;
use sha3::Keccak256;
use crypto::hash::keccak::{MaskedKeccak256HashFn};
use sandstorm::claims::starknet::EthVerifierClaim;

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

fn generate_proof() {
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

                    println!("Generate proof:");
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
    let indices: Vec<_> = generate_positions(&claim, proof.clone());
    let query_positions: Vec<_> = indices.iter().map(
        |x| x.as_u256()
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


    // Merkle proof for Base trace
    let base_trace_proof = trace_queries.base_trace_proof;
    // generate base trace input for VerifyMerkle contract.
    generate_merkle_input(&base_trace_proof, &base_trace_commitment, &query_positions, "base_trace_proof");

    let extension_trace_proof = trace_queries.extension_trace_proof;

    if !extension_trace_proof.is_none() {
        generate_merkle_input(&extension_trace_proof.unwrap(), &extension_trace_commitment.unwrap(), &query_positions, "extension_trace_proof");
    }
    //
    let composition_trace_proof = trace_queries.composition_trace_proof;
    generate_merkle_input(&composition_trace_proof, &composition_trace_commitment, &query_positions, "composition_trace_proof");

}

fn generate_merkle_input(
    trace_proof: &LeafVariantMerkleTreeProof<MaskedKeccak256HashFn<20>>,
    trace_root: &SerdeOutput<Keccak256>,
    query_positions: &[u256],
    file_name: &str
) {
    let expected_root = u256::from_be_bytes(trace_root.clone().as_bytes());
    let merkle_view = match trace_proof {
        LeafVariantMerkleTreeProof::Hashed(x) => Some(x),
        _ => None,
    };
    if merkle_view.is_none() {
        let merkle_view = match trace_proof {
            LeafVariantMerkleTreeProof::Unhashed(x) => Some(x),
            _ => None,
        }.unwrap();

        let initial_values: Vec<_> = merkle_view.initial_leaves.iter().map(
            |leaf| {
                let leaf_byte = leaf.0.to_bytes_be();
                // let leaf_byte = leaf..to_bytes_be();
                u256::from_be_bytes(leaf_byte.try_into().unwrap())
            }).collect();
        let height = merkle_view.height.as_u256();
        let sibling_values: Vec<_> = merkle_view.sibling_leaves.iter().map(
            |val| {
                let val_byte = val.0.to_bytes_be();
                u256::from_be_bytes(val_byte.try_into().unwrap())
            }).collect();
        let nodes: Vec<_> = merkle_view.nodes.iter().map(
            |node| u256::from_be_bytes(node.as_bytes())).collect();

        let num_leaves = 1 << merkle_view.height;
        let mut initial_merkle_queue: Vec<U256> = Vec::new();
        for i in 0..query_positions.len() {
            initial_merkle_queue.push(query_positions[i].clone() + num_leaves);
            initial_merkle_queue.push(initial_values[i]);
        }

        let mut merkle_view = Vec::new();
        merkle_view.extend(sibling_values.iter().cloned());
        merkle_view.extend(nodes.iter().cloned());
        write_to_json(&initial_merkle_queue, &merkle_view, height, expected_root, file_name);

    } else {
        let merkle_view = merkle_view.unwrap();
        let initial_values: Vec<_> = merkle_view.initial_leaves.iter().map(
            |leaf| u256::from_be_bytes(leaf.as_bytes())).collect();
        let height = merkle_view.height.as_u256();
        let sibling_values: Vec<_> = merkle_view.sibling_leaves.iter().map(
            |val| u256::from_be_bytes(val.as_bytes())).collect();
        let nodes: Vec<_> = merkle_view.nodes.iter().map(
            |node| u256::from_be_bytes(node.as_bytes())).collect();

        let num_leaves = 1 << merkle_view.height;
        let mut initial_merkle_queue: Vec<U256> = Vec::new();
        for i in 0..query_positions.len() {
            initial_merkle_queue.push(query_positions[i].clone() + num_leaves);
            initial_merkle_queue.push(initial_values[i]);
        }

        let mut merkle_view = Vec::new();
        merkle_view.extend(sibling_values.iter().cloned());
        merkle_view.extend(nodes.iter().cloned());
        write_to_json(&initial_merkle_queue, &merkle_view, height, expected_root, file_name);
    }
}

#[derive(Serialize)]
struct MerkleData {
    initial_merkle_queue: Vec<String>,
    merkle_view: Vec<String>,
    height: String,
    expected_root: String,
}
fn write_to_json(initial_merkle_queue: &[u256], merkle_view: &[u256], height: u256, root: u256, file_name: &str) {

    let initial_merkle_queue: Vec<String> = initial_merkle_queue.iter().map(|x| x.to_string()).collect();
    let merkle_view: Vec<String> = merkle_view.iter().map(|x| x.to_string()).collect();
    let height = height.to_string();
    let root = root.to_string();
    let data = MerkleData {
        initial_merkle_queue,
        merkle_view,
        height,
        expected_root: root,
    };

    let file_path = format!("proof/{}.json", file_name);
    let mut file = File::create(file_path).expect("Unable to create file");
    let json_data = serde_json::to_string(&data).expect("Unable to serialize data");
    file.write_all(json_data.as_bytes()).expect("Unable to write data");
}

fn generate_positions<Claim: Stark<Fp = impl Field + ark_ff::FftField>>(claim: &Claim, proof: Proof<Claim>) -> Vec<usize> {
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


    // generate queries from public coin
    let air = Air::new(trace_len, claim.get_public_inputs(), options);
    let mut public_coin = claim.gen_public_coin(&air);
    public_coin.reseed_with_digest(&base_trace_commitment);
    let extension_trace_commitment = extension_trace_commitment.map(|commitment| {
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
    let _ = FriVerifier::<<Claim as Stark>::Fq, <Claim as Stark>::Digest, <Claim as Stark>::MerkleTree>::new(
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

    query_positions

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
