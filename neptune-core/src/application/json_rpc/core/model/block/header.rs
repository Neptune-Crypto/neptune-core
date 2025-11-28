use num_bigint::BigUint;
use serde::Deserialize;
use serde::Deserializer;
use serde::Serialize;
use serde::Serializer;
use tasm_lib::prelude::Digest;
use tasm_lib::triton_vm::prelude::BFieldElement;

use crate::api::export::BlockHeight;
use crate::api::export::Timestamp;
use crate::protocol::consensus::block::block_header::BlockHeader;
use crate::protocol::consensus::block::block_header::BlockPow;
use crate::protocol::consensus::block::difficulty_control::Difficulty;
use crate::protocol::consensus::block::difficulty_control::ProofOfWork;
use crate::protocol::consensus::block::guesser_receiver_data::GuesserReceiverData;
use crate::protocol::consensus::block::pow::POW_MEMORY_TREE_HEIGHT;

// TODO: Mirror consensus impl (RpcBlockPow = RpcPow<POW_MEMORY_TREE_HEIGHT>)
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct RpcBlockPow {
    pub root: Digest,
    #[serde(with = "serde_arrays")]
    pub path_a: [Digest; POW_MEMORY_TREE_HEIGHT],
    #[serde(with = "serde_arrays")]
    pub path_b: [Digest; POW_MEMORY_TREE_HEIGHT],
    pub nonce: Digest,
}

impl From<BlockPow> for RpcBlockPow {
    fn from(pow: BlockPow) -> Self {
        Self {
            root: pow.root,
            path_a: pow.path_a,
            path_b: pow.path_b,
            nonce: pow.nonce,
        }
    }
}

impl From<RpcBlockPow> for BlockPow {
    fn from(rpc: RpcBlockPow) -> Self {
        Self {
            root: rpc.root,
            path_a: rpc.path_a,
            path_b: rpc.path_b,
            nonce: rpc.nonce,
        }
    }
}

#[derive(Copy, Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct RpcGuesserReceiverData {
    pub receiver_digest: Digest,
    pub lock_script_hash: Digest,
}

impl From<GuesserReceiverData> for RpcGuesserReceiverData {
    fn from(data: GuesserReceiverData) -> Self {
        RpcGuesserReceiverData {
            receiver_digest: data.receiver_digest,
            lock_script_hash: data.lock_script_hash,
        }
    }
}

impl From<RpcGuesserReceiverData> for GuesserReceiverData {
    fn from(rpc: RpcGuesserReceiverData) -> Self {
        Self {
            receiver_digest: rpc.receiver_digest,
            lock_script_hash: rpc.lock_script_hash,
        }
    }
}

pub type RpcBlockHeight = BlockHeight;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RpcDifficulty(pub Difficulty);

impl From<Difficulty> for RpcDifficulty {
    fn from(d: Difficulty) -> Self {
        Self(d)
    }
}

impl From<RpcDifficulty> for Difficulty {
    fn from(r: RpcDifficulty) -> Self {
        r.0
    }
}

impl Serialize for RpcDifficulty {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let big: BigUint = self.0.into();
        serializer.serialize_str(&big.to_string())
    }
}

impl<'de> Deserialize<'de> for RpcDifficulty {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        let big = BigUint::parse_bytes(s.as_bytes(), 10)
            .ok_or_else(|| serde::de::Error::custom("invalid number"))?;
        let difficulty = Difficulty::from_biguint(big)
            .ok_or_else(|| serde::de::Error::custom("cannot convert to Difficulty"))?;
        Ok(Self(difficulty))
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RpcProofOfWork(pub ProofOfWork);

impl Serialize for RpcProofOfWork {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let big: BigUint = self.0.into();
        serializer.serialize_str(&big.to_string())
    }
}

impl From<ProofOfWork> for RpcProofOfWork {
    fn from(d: ProofOfWork) -> Self {
        Self(d)
    }
}

impl From<RpcProofOfWork> for ProofOfWork {
    fn from(r: RpcProofOfWork) -> Self {
        r.0
    }
}

impl<'de> Deserialize<'de> for RpcProofOfWork {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        let big = BigUint::parse_bytes(s.as_bytes(), 10)
            .ok_or_else(|| serde::de::Error::custom("invalid number"))?;
        let proof_of_work = big
            .try_into()
            .map_err(|_| serde::de::Error::custom("cannot convert to ProofOfWork"))?;
        Ok(Self(proof_of_work))
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct RpcBlockHeader {
    pub version: BFieldElement,
    pub height: RpcBlockHeight,
    pub prev_block_digest: Digest,
    pub timestamp: Timestamp,
    pub pow: RpcBlockPow,
    pub cumulative_proof_of_work: RpcProofOfWork,
    pub difficulty: RpcDifficulty,
    pub guesser_receiver_data: RpcGuesserReceiverData,
}

impl From<&BlockHeader> for RpcBlockHeader {
    fn from(header: &BlockHeader) -> Self {
        RpcBlockHeader {
            version: header.version,
            height: header.height,
            prev_block_digest: header.prev_block_digest,
            timestamp: header.timestamp,
            pow: header.pow.into(),
            cumulative_proof_of_work: header.cumulative_proof_of_work.into(),
            difficulty: header.difficulty.into(),
            guesser_receiver_data: header.guesser_receiver_data.into(),
        }
    }
}

impl From<RpcBlockHeader> for BlockHeader {
    fn from(header: RpcBlockHeader) -> Self {
        BlockHeader {
            version: header.version,
            height: header.height,
            prev_block_digest: header.prev_block_digest,
            timestamp: header.timestamp,
            pow: header.pow.into(),
            cumulative_proof_of_work: header.cumulative_proof_of_work.into(),
            difficulty: header.difficulty.into(),
            guesser_receiver_data: header.guesser_receiver_data.into(),
        }
    }
}
