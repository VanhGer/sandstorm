use std::fs::File;
use std::io::Write;
use std::marker::PhantomData;
use ark_ff::{inv, BigInteger, FftField, Field, MontBackend};
use ark_poly::domain::DomainCoeff;
use ark_poly::{EvaluationDomain, Radix2EvaluationDomain};
use ark_std::iterable::Iterable;
use ark_std::log2;
use ethnum::{u256, AsU256, U256};
use ministark::fri::{fold_positions, FriOptions, LayerProof};
use ministark::merkle::MatrixMerkleTree;
use serde::{Serialize, Serializer};
use serde::ser::SerializeStruct;
use ministark::hash::{Digest, ElementHashFn};
use ministark::{Proof, ProofOptions};
use ministark_gpu::fields::p3618502788666131213697322783095070105623107215331596699973092056135872020481::ark::FpMontConfig;
use ministark_gpu::GpuField;
use ministark_gpu::utils::bit_reverse_index;
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

impl <D: Digest, H: ElementHashFn<ark_ff::Fp<MontBackend<FpMontConfig, 4>, 4>>> FriData<D, H> {
    pub fn new(
        layers_flattended_rows: Vec<Vec<ark_ff::Fp<MontBackend<FpMontConfig, 4>, 4>>>,
        layers_merkle_proof: Vec<LeafVariantMerkleTreeProof<H>>,
        layers_commitments: Vec<D>,
        query_positions: &[usize],
        alphas: &[u256],
        options: &ProofOptions,
        max_poly_degree: usize,
    ) -> Self {

        let mut fri_data: Vec<FriLayerData<D, H>> = Vec::new();
        assert_eq!(alphas.len(), layers_commitments.len());

        let mut positions = query_positions.clone().to_vec();

        let fri_options = options.into_fri_options();
        let domain_offset = fri_options.domain_offset::<ark_ff::Fp<MontBackend<FpMontConfig, 4>, 4>>();
        let mut domain_size = max_poly_degree.next_power_of_two() * options.lde_blowup_factor as usize;
        let mut log_layer_size = log2(domain_size) as usize;
        let log_sub = log2(options.fri_folding_factor as usize) as usize;

        let domain = Radix2EvaluationDomain::new_coset(domain_size, domain_offset).unwrap();
        let mut domain_generator = domain.group_gen();

        for i in 0..layers_commitments.len() {

            let inverse_points: Vec<_> = positions.iter().map(|position| {
                domain_generator.pow([bit_reverse_index(domain_size, *position) as u64]).inverse().unwrap()
            }).collect();
            let fri_layer_data = match options.fri_folding_factor {
                2 => FriLayerData::new::<2>(
                    &inverse_points,
                    &layers_merkle_proof[i],
                    &layers_commitments[i],
                    &layers_flattended_rows[i],
                    alphas[i], &positions, options, log_layer_size),
                4 => FriLayerData::new::<4>(
                    &inverse_points,
                    &layers_merkle_proof[i],
                    &layers_commitments[i],
                    &layers_flattended_rows[i],
                    alphas[i], &positions, options, log_layer_size),
                8 => FriLayerData::new::<8>(
                    &inverse_points,
                    &layers_merkle_proof[i],
                    &layers_commitments[i],
                    &layers_flattended_rows[i],
                    alphas[i], &positions, options, log_layer_size),
                16 => FriLayerData::new::<16>(
                    &inverse_points,
                    &layers_merkle_proof[i],
                    &layers_commitments[i],
                    &layers_flattended_rows[i],
                    alphas[i], &positions, options, log_layer_size),
                _ => unreachable!("Not supported"),
            };
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
    H: ElementHashFn<ark_ff::Fp<MontBackend<FpMontConfig, 4>, 4>>
{

    pub fn new<const N: usize>(
        inverse_points: &[ark_ff::Fp<MontBackend<FpMontConfig, 4>, 4>],
        merkle_proof: &LeafVariantMerkleTreeProof<H>,
        expected_root: &D,
        flattenend_rows: &[ark_ff::Fp<MontBackend<FpMontConfig, 4>, 4>],
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
        assert_eq!(positions.len(), rows.len());
        assert_eq!(positions.len(), inverse_points.len());

        let mut i = 0;
        let mut next_i = 0;
        let mut pos = positions[i];
        while i < positions.len() {
            let cosetIdx = pos & (!(N - 1));

            for j in cosetIdx..(cosetIdx+N) {
                if pos != j {
                    let val_bytes = rows[i][j - cosetIdx].0.to_bytes_be();
                    proof.push(u256::from_be_bytes(val_bytes.try_into().unwrap()));
                } else {
                    let val_bytes = rows[i][j - cosetIdx].0.to_bytes_be();
                    fri_value.push(u256::from_be_bytes(val_bytes.try_into().unwrap()));
                    next_i = next_i + 1;
                    if next_i < positions.len() {
                        pos = positions[next_i];
                    }
                }
            }
            i = next_i;
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
            fri_queue.push(u256::from_be_bytes(inverse_points[i].0.to_bytes_be().try_into().unwrap()));
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