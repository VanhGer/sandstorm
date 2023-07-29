use ministark::hash::ElementHashFn;
use ministark::hash::HashFn;
use ministark::utils::SerdeOutput;
use ministark_gpu::fields::p3618502788666131213697322783095070105623107215331596699973092056135872020481::ark::Fp;
use ruint::aliases::U256;
use digest::Digest as _;
use super::utils::mask_bytes;
use super::utils::to_montgomery;
use sha3::Keccak256;

/// Hash function used by StarkWare's Solidity verifier
pub struct Keccak256HashFn;

impl HashFn for Keccak256HashFn {
    type Digest = SerdeOutput<Keccak256>;
    const COLLISION_RESISTANCE: u32 = 128;

    fn hash(bytes: impl IntoIterator<Item = u8>) -> SerdeOutput<Keccak256> {
        let mut hasher = Keccak256::new();
        for byte in bytes {
            hasher.update([byte]);
        }
        SerdeOutput::new(hasher.finalize())
    }

    fn merge(v0: &SerdeOutput<Keccak256>, v1: &SerdeOutput<Keccak256>) -> SerdeOutput<Keccak256> {
        let mut hasher = Keccak256::new();
        hasher.update(**v0);
        hasher.update(**v1);
        SerdeOutput::new(hasher.finalize())
    }

    fn merge_with_int(seed: &SerdeOutput<Keccak256>, value: u64) -> SerdeOutput<Keccak256> {
        let mut hasher = Keccak256::new();
        hasher.update(**seed);
        hasher.update(value.to_be_bytes());
        SerdeOutput::new(hasher.finalize())
    }

    fn hash_chunks<'a>(chunks: impl IntoIterator<Item = &'a [u8]>) -> Self::Digest {
        let mut hasher = Keccak256::new();
        for chunk in chunks {
            hasher.update(chunk);
        }
        SerdeOutput::new(hasher.finalize())
    }
}

impl ElementHashFn<Fp> for Keccak256HashFn {
    fn hash_elements(elements: impl IntoIterator<Item = Fp>) -> SerdeOutput<Keccak256> {
        let mut hasher = Keccak256::new();
        for element in elements {
            hasher.update(U256::from(to_montgomery(element)).to_be_bytes::<32>());
        }
        SerdeOutput::new(hasher.finalize())
    }
}

pub struct MaskedKeccak256HashFn<const N_UNMASKED_BYTES: u32>;

impl<const N_UNMASKED_BYTES: u32> HashFn for MaskedKeccak256HashFn<N_UNMASKED_BYTES> {
    type Digest = SerdeOutput<Keccak256>;
    const COLLISION_RESISTANCE: u32 = N_UNMASKED_BYTES * 8 / 2;

    fn hash(bytes: impl IntoIterator<Item = u8>) -> Self::Digest {
        let mut hash = Keccak256HashFn::hash(bytes);
        mask_bytes::<N_UNMASKED_BYTES>(&mut hash);
        hash
    }

    fn merge(v0: &Self::Digest, v1: &Self::Digest) -> Self::Digest {
        let mut hash = Keccak256HashFn::merge(v0, v1);
        mask_bytes::<N_UNMASKED_BYTES>(&mut hash);
        hash
    }

    fn merge_with_int(seed: &Self::Digest, value: u64) -> Self::Digest {
        let mut hash = Keccak256HashFn::merge_with_int(seed, value);
        mask_bytes::<N_UNMASKED_BYTES>(&mut hash);
        hash
    }

    fn hash_chunks<'a>(chunks: impl IntoIterator<Item = &'a [u8]>) -> Self::Digest {
        let mut hash = Keccak256HashFn::hash_chunks(chunks);
        mask_bytes::<N_UNMASKED_BYTES>(&mut hash);
        hash
    }
}

impl<const N_UNMASKED_BYTES: u32> ElementHashFn<Fp> for MaskedKeccak256HashFn<N_UNMASKED_BYTES> {
    fn hash_elements(elements: impl IntoIterator<Item = Fp>) -> Self::Digest {
        let mut hash = Keccak256HashFn::hash_elements(elements);
        mask_bytes::<N_UNMASKED_BYTES>(&mut hash);
        hash
    }
}
