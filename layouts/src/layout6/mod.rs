//! Matches Layout 6 from StarkWare's open source verifier
//! <https://github.com/starkware-libs/starkex-contracts/blob/master/evm-verifier/solidity/contracts/cpu/layout6/CpuConstraintPoly.sol#L794>

mod air;
pub mod pedersen;
mod trace;

pub use air::AirConfig;
pub use trace::ExecutionTrace;

// must be a power-of-two
pub const CYCLE_HEIGHT: usize = 16;
pub const PUBLIC_MEMORY_STEP: usize = 8;
pub const MEMORY_STEP: usize = 2;
pub const RANGE_CHECK_STEP: usize = 4;

/// How many cycles per pedersen hash
pub const PEDERSEN_BUILTIN_RATIO: usize = 32;

/// How many cycles per 128 bit range check
pub const RANGE_CHECK_BUILTIN_RATIO: usize = 16;
pub const RANGE_CHECK_BUILTIN_PARTS: usize = 8;

pub const NUM_BASE_COLUMNS: usize = 9;
pub const NUM_EXTENSION_COLUMNS: usize = 1;
