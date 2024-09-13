use std::fs::File;
use std::io::Write;
use std::marker::PhantomData;
use ark_ff::{inv, BigInt, BigInteger, BigInteger256, FftField, Field, Fp, MontBackend, PrimeField};
use ark_poly::{EvaluationDomain, Radix2EvaluationDomain};
use ark_std::iterable::Iterable;
use ark_std::log2;
use ethnum::{u256, AsU256, U256};
use ministark::fri::{fold_positions, FriOptions, LayerProof};
use serde::{Serialize, Serializer};
use serde::ser::SerializeStruct;
use ministark::hash::{Digest, ElementHashFn};
use ministark::{Proof, ProofOptions};
use ministark_gpu::fields::p3618502788666131213697322783095070105623107215331596699973092056135872020481::ark::FpMontConfig;
use ministark_gpu::fields::p3618502788666131213697322783095070105623107215331596699973092056135872020481::MODULUS;
use ministark_gpu::GpuField;
use ministark_gpu::utils::bit_reverse_index;
use num_bigint::{BigUint};
use crypto::merkle::LeafVariantMerkleTreeProof;

pub struct FriLayerData <D: Digest, H: ElementHashFn<ark_ff::Fp<MontBackend<FpMontConfig, 4>, 4>>>{
    pub proof: Vec<U256>,
    pub fri_queue: Vec<U256>,
    pub evaluation_point: U256,
    pub fri_step_size: U256,
    pub expected_root: U256,
    phantom_data_d: PhantomData<D>,
    phantom_data_h: PhantomData<H>
}

pub struct FriData <D: Digest, H: ElementHashFn<ark_ff::Fp<MontBackend<FpMontConfig, 4>, 4>>>{
    pub layers: Vec<FriLayerData<D, H>>,
}

impl <D: Digest, H: ElementHashFn<Fp<MontBackend<FpMontConfig, 4>, 4>>> FriData<D, H> {
    pub fn new<const N: usize>(
        layers_flattended_rows: Vec<Vec<Fp<MontBackend<FpMontConfig, 4>, 4>>>,
        layers_merkle_proof: Vec<LeafVariantMerkleTreeProof<H>>,
        layers_commitments: Vec<D>,
        query_positions: &[usize],
        alphas: &[u256],
        options: &ProofOptions,
        trace_len: usize,
    ) -> Self {

        let mut fri_data: Vec<FriLayerData<D, H>> = Vec::new();
        assert_eq!(alphas.len(), layers_commitments.len());

        let mut positions = query_positions.clone().to_vec();

        let fri_options = options.into_fri_options();
        let domain_offset = fri_options.domain_offset::<Fp<MontBackend<FpMontConfig, 4>, 4>>();
        let mut domain_size = (trace_len - 1).next_power_of_two() * options.lde_blowup_factor as usize;
        let mut log_layer_size = log2(domain_size) as usize;
        let log_sub = log2(options.fri_folding_factor as usize) as usize;
        let folding_domain: Radix2EvaluationDomain<Fp<MontBackend<FpMontConfig, 4>, 4>> = Radix2EvaluationDomain::new(16).unwrap();
        let mut domain = Radix2EvaluationDomain::new_coset(domain_size, domain_offset).unwrap();
        let mut domain_generator = domain.group_gen();
        // let mut abc = Fp::ONE;
        // domain = folding_domain.get_coset(domain_generator).unwrap();
        // let mut fri_generator_u = u256::from_str_hex("0x5ec467b88826aba4537602d514425f3b0bdf467bbf302458337c45f6021e539").unwrap().to_be_bytes().to_vec();
        // let big_num = BigUint::from_bytes_be(&fri_generator_u);
        // let folding_generator = BigInt::from(big_num);
        let fri_generator = folding_domain.group_gen;
        // println!("fri generator: {:?}", u256::from_be_bytes(fri_generator.0.to_bytes_be().try_into().unwrap()));
        //
        // let abc = fri_generator.into_bigint();
        // println!("abc: {:?}", abc.to_string());
        // let g_b: BigInt<4> = BigInt!("2679026602897868112349604024891625875968950767352485125058791696935099163961");
        // let g: Fp<MontBackend<FpMontConfig, 4>, 4> = Fp::new(g_b);
        // let mut res = [0; 32];
        // res.copy_from_slice(.0);
        // res
        // println!("g: {:?}", u256::from_be_bytes(g.0.to_bytes_be().try_into().unwrap()));
        //
        let g_p_k: BigInt<4> = BigInt!("1135556255784795209597073582213630114779425416329054743238782484815939647907");
        let g_pk: Fp<MontBackend<FpMontConfig, 4>, 4> = Fp::new(g_p_k);
        // println!("p_g^k: {:?}", u256::from_be_bytes(g_pk.0.to_bytes_be().try_into().unwrap()));
        //
        // let test: BigInt<4> = BigInt!("1977105619003255188446323775752871214816867924898495858931742486978925822257");
        // let abc: Fp<MontBackend<FpMontConfig, 4>, 4> = Fp::new(test);
        // println!("q1: {:?}", u256::from_be_bytes(abc.0.to_bytes_be().try_into().unwrap()));
        //
        // println!("offset {:?}", u256::from_be_bytes(domain_offset.0.to_bytes_be().try_into().unwrap()));
        //
        let mut fri_group: [Fp<MontBackend<FpMontConfig, 4>, 4>; 16] = [fri_generator; 16];
        fri_group[0] = fri_generator.pow([0]);
        fri_group[1] = fri_generator.pow([8]);
        for i in 1..8 {
            let index = bit_reverse_index(8, i);
            let d = fri_generator.pow([i as u64]);
            fri_group[2* index] = d;
            let n_idx = 8 + i;
            let d = fri_generator.pow([n_idx as u64]);
            fri_group[2 * index + 1] =  d;
        }
        // for x in &fri_group {
        //     println!("pow {:?}", u256::from_be_bytes(x.clone().0.to_bytes_be().try_into().unwrap()));
        //
        // }
        // let test_domain = Radix2EvaluationDomain::new(16).unwrap();

        let cal_folding_generator = domain_generator.pow([(domain_size / 16) as u64]);
        println!("generator: {:?}", domain_generator.into_bigint().to_string());

        for i in 0..layers_commitments.len() {
                let inverse_points: Vec<_> = positions.iter().map(|position| {
                    let bit_rev_pos = bit_reverse_index(domain_size / N, *position / N) as u64;
                    let cur_bit_rev_pos = bit_reverse_index(domain_size, *position);
                    println!("{:?},  {:?}", position, bit_rev_pos);
                    let offset = domain_generator.pow([bit_rev_pos]);
                    let offset2 = domain_generator.pow([cur_bit_rev_pos as u64]);
                    // offset.inverse().unwrap()
                    // let fri_offset = fri_generator.pow([*position % N]);
                    let folding_domain = folding_domain.get_coset(offset).unwrap();
                    let cosetIdx = position & (!(N - 1));
                    println!("cosetIdx: {:?}", cosetIdx);
                    let offset_within_coset = position - cosetIdx;
                    // let g = folding_domain.group_gen();

                    // let k = bit_reverse_index(N, offset_within_coset);
                    let k = offset_within_coset;
                    let c = folding_domain.size_inv;

                    let g_pow_neg_k = fri_group[k].clone().inverse().unwrap();
                    // let g_pow_k = .pow([k as u64]);
                    // println!("g: {:?}, k = {:?}", u256::from_be_bytes(g.0.to_bytes_be().try_into().unwrap()), k);
                    // println!("g^k: {:?}", u256::from_be_bytes(g_pow_k.0.to_bytes_be().try_into().unwrap()));
                    let offset_inv = folding_domain.offset_inv;
                    // let offset = folding_domain.offset.clone();
                    let tmp  =  domain_generator.pow([bit_reverse_index(domain_size, *position) as u64]).inverse().unwrap();
                    let rrr = g_pow_neg_k * offset_inv;
                    let t = 1;
                    rrr

                }).collect();
                let inverse_points: Vec<_> = positions.iter().map(|position| {
                    domain_generator.pow([bit_reverse_index(domain_size, *position) as u64]).inverse().unwrap()
                }).collect();
                // println!("inverse points: ");x`
                // let abc = fri_generator.into_bigint();
                // println!("abc: {:?}", abc.to_string());
                // for i in 0..inverse_points.len() {
                //     println!("position: {:?}", positions[i] + (1<< log_layer_size));
                //     println!("inverse_points: {:?}", inverse_points[i].clone().into_bigint().to_string());
                // }


                let fri_layer_data = FriLayerData::new::<N>(
                        &inverse_points,
                        &layers_merkle_proof[i],
                        &layers_commitments[i],
                        &layers_flattended_rows[i],
                        alphas[i], &positions, options, log_layer_size);

                fri_data.push(fri_layer_data);

            positions = fold_positions(&positions, options.fri_folding_factor as usize);
            log_layer_size -= log_sub;
            domain_size = domain_size / options.fri_folding_factor as usize;
            domain_generator = domain_generator.pow([options.fri_folding_factor as u64]);
        }

        Self {
            layers: fri_data
        }
    }

    pub fn write_to_json(&self,  file_name: &str) {
        for i in 0..self.layers.len() {
            let name = format!("{}_{}", file_name, i.to_string());
            self.layers[i].write_to_json(&name);

        }
    }
}

impl <D, H> FriLayerData<D, H>
where
    D: Digest,
    H: ElementHashFn<Fp<MontBackend<FpMontConfig, 4>, 4>>
{

    pub fn new<const N: usize>(
        inverse_points: &[Fp<MontBackend<FpMontConfig, 4>, 4>],
        merkle_proof: &LeafVariantMerkleTreeProof<H>,
        expected_root: &D,
        flattenend_rows: &[Fp<MontBackend<FpMontConfig, 4>, 4>],
        alpha: u256,
        positions: &[usize],
        options: &ProofOptions,
        log_layer_size: usize,
    ) -> Self {

        let expected_root = u256::from_be_bytes(expected_root.as_bytes());
        let flattenend_rows = flattenend_rows.to_vec();
        let mut proof: Vec<u256> = Vec::new();
        let mut fri_queue: Vec<u256> = Vec::new();
        let mut fri_value: Vec<u256> = Vec::new();
        let mut fri_pos: Vec<usize> = positions.to_vec().iter().map(|pos| *pos + (1 << log_layer_size)).collect();

        let inverse_points = inverse_points.to_vec();

        let rows = flattenend_rows.as_chunks::<N>().0.to_vec();
        assert_eq!(positions.len(), inverse_points.len());

        let mut row_i = 0;
        let mut pos_i = 0;
        let mut pos = positions[pos_i];
        while row_i < rows.len() {
            let cosetIdx = pos & (!(N - 1));

            for j in cosetIdx..(cosetIdx+N) {
                if pos != j {
                    // let val_bytes = rows[row_i][j - cosetIdx].clone().into_bigint().to_bytes_be();
                    let val_bytes = rows[row_i][j - cosetIdx].0.to_bytes_be();
                    proof.push(u256::from_be_bytes(val_bytes.try_into().unwrap()));
                } else {
                    // let val_bytes = rows[row_i][j - cosetIdx].clone().into_bigint().to_bytes_be();
                    let val_bytes = rows[row_i][j - cosetIdx].0.to_bytes_be();

                    fri_value.push(u256::from_be_bytes(val_bytes.try_into().unwrap()));
                    pos_i += 1;
                    if pos_i < positions.len() {
                        pos = positions[pos_i];
                    }
                }
            }
            row_i += 1;
        }



        let merkle_view = match merkle_proof {
            LeafVariantMerkleTreeProof::Hashed(x) => Some(x),
            _ => None,
        };
        if merkle_view.is_none() {
            let merkle_view = match merkle_proof {
                LeafVariantMerkleTreeProof::Unhashed(x) => Some(x),
                _ => None,
            }.unwrap();
            let sibling_values: Vec<_> = merkle_view.sibling_leaves.iter().map(
                |val| {
                    let val_byte = val.0.to_bytes_be();
                    u256::from_be_bytes(val_byte.try_into().unwrap())
                }).collect();
            let nodes: Vec<_> = merkle_view.nodes.iter().map(
                |node| u256::from_be_bytes(node.as_bytes())).collect();
            proof.extend(sibling_values.iter().cloned());
            proof.extend(nodes.iter().cloned());


        } else {
            let merkle_view = merkle_view.unwrap();
            let sibling_values: Vec<_> = merkle_view.sibling_leaves.iter().map(
                |val| u256::from_be_bytes(val.as_bytes())).collect();
            let nodes: Vec<_> = merkle_view.nodes.iter().map(
                |node| u256::from_be_bytes(node.as_bytes())).collect();

            proof.extend(sibling_values.iter().cloned());
            proof.extend(nodes.iter().cloned());
        }

        for i in 0..positions.len() {
            fri_queue.push(fri_pos[i].as_u256());
            fri_queue.push(fri_value[i]);
            fri_queue.push(u256::from_be_bytes(inverse_points[i].clone().into_bigint().to_bytes_be().try_into().unwrap()));
        }

        let fri_step_size = log2(options.fri_folding_factor as usize);

        FriLayerData {
            proof,
            fri_queue,
            evaluation_point: alpha,
            fri_step_size: fri_step_size.as_u256(),
            expected_root,
            phantom_data_d: PhantomData,
            phantom_data_h: PhantomData,
        }
    }

    pub fn write_to_json(&self,  file_name: &str) {
        let file_path = format!("proof/{}.json", file_name);
        let mut file = File::create(file_path).expect("Unable to create file");
        let json_data = serde_json::to_string(&self).expect("Unable to serialize data");
        file.write_all(json_data.as_bytes()).expect("Unable to write data");
    }
}


impl <
    D: Digest,
    H: ElementHashFn<ark_ff::Fp<MontBackend<FpMontConfig, 4>, 4>>
    > Serialize for FriLayerData<D, H>
{
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut state = serializer.serialize_struct("FriLayerData", 5)?;
        let proof: Vec<String> = self.proof.iter().map(|x| x.to_string()).collect();
        let fri_queue: Vec<String> = self.fri_queue.iter().map(|x| x.to_string()).collect();
        let evaluation_point = self.evaluation_point.to_string();
        let fri_step_size = self.fri_step_size.to_string();
        let expected_root = self.expected_root.to_string();

        state.serialize_field("proof", &proof)?;
        state.serialize_field("friQueue", &fri_queue)?;
        state.serialize_field("evaluationPoint", &evaluation_point)?;
        state.serialize_field("friStepSize", &fri_step_size)?;
        state.serialize_field("expected_root", &expected_root)?;
        state.end()
    }
}