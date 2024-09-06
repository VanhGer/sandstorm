use std::fs::File;
use std::io::Write;
use ark_ff::BigInteger;
use ethnum::{u256, AsU256, U256};
use ministark::hash::Digest;
use ministark::utils::SerdeOutput;
use serde::{Serialize, Serializer};
use serde::ser::SerializeStruct;
use sha3::Keccak256;
use crypto::hash::keccak::MaskedKeccak256HashFn;
use crypto::merkle::LeafVariantMerkleTreeProof;


pub struct MerkleData {
    pub initial_merkle_queue: Vec<U256>,
    pub merkle_view: Vec<U256>,
    pub height: U256,
    pub expected_root: U256,
}

impl MerkleData {

    pub fn new(
        trace_proof: &LeafVariantMerkleTreeProof<MaskedKeccak256HashFn<20>>,
        trace_root: &SerdeOutput<Keccak256>,
        query_positions: &[u256],
        // file_name: &str
    ) -> Self {
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

            // let initial_merkle_queue: Vec<String> = initial_merkle_queue.iter().map(|x| x.to_string()).collect();
            // let merkle_view: Vec<String> = merkle_view.iter().map(|x| x.to_string()).collect();
            // let height = height.to_string();
            // let root = expected_root.to_string();

            Self {
                initial_merkle_queue,
                merkle_view,
                height,
                expected_root,
            }

            // self.write_to_json(data);

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

            Self {
                initial_merkle_queue,
                merkle_view,
                height,
                expected_root,
            }
        }
    }

    pub fn write_to_json(&self,  file_name: &str) {
        let file_path = format!("proof/{}.json", file_name);
        let mut file = File::create(file_path).expect("Unable to create file");
        let json_data = serde_json::to_string(&self).expect("Unable to serialize data");
        file.write_all(json_data.as_bytes()).expect("Unable to write data");
    }
}


impl Serialize for MerkleData {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut state = serializer.serialize_struct("MerkleData", 4)?;
        let initial_merkle_queue: Vec<String> = self.initial_merkle_queue.iter().map(|x| x.to_string()).collect();
        let merkle_view: Vec<String> = self.merkle_view.iter().map(|x| x.to_string()).collect();
        let height = self.height.to_string();
        let expected_root = self.expected_root.to_string();

        state.serialize_field("initial_merkle_queue", &initial_merkle_queue)?;
        state.serialize_field("merkle_view", &merkle_view)?;
        state.serialize_field("height", &height)?;
        state.serialize_field("expected_root", &expected_root)?;
        state.end()
    }
}