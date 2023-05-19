use crate::models::blockchain::shared::Hash;
use anyhow::bail;
use get_size::GetSize;
use itertools::Itertools;
use serde::{Deserialize, Serialize};
use std::hash::{Hash as StdHash, Hasher as StdHasher};
use triton_opcodes::instruction::LabelledInstruction;
use triton_opcodes::program::Program;
use triton_opcodes::shortcuts::{halt, read_io};
use triton_vm::bfield_codec::BFieldCodec;
use twenty_first::shared_math::tip5::{Digest, DIGEST_LENGTH};

use super::amount::AmountLike;
use super::native_coin::{native_coin_program, NATIVE_COIN_TYPESCRIPT_DIGEST};
use super::{native_coin, Amount};
use twenty_first::shared_math::b_field_element::BFieldElement;
use twenty_first::util_types::algebraic_hasher::{AlgebraicHasher, Hashable};

pub const PUBLIC_KEY_LENGTH_IN_BYTES: usize = 33;
pub const PUBLIC_KEY_LENGTH_IN_BFES: usize = 5;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Coin {
    pub type_script_hash: Digest,
    pub state: Vec<BFieldElement>,
}

impl BFieldCodec for Coin {
    fn decode(sequence: &[BFieldElement]) -> anyhow::Result<Box<Self>> {
        if sequence.len() < DIGEST_LENGTH {
            bail!("Cannot decode coin: could not parse type script hash.");
        }

        let digest = Digest::decode(&sequence[0..DIGEST_LENGTH])?;
        let seq = Vec::<BFieldElement>::decode(&sequence[DIGEST_LENGTH..])?;

        if seq[0].value() as usize != seq.len() - 1 {
            bail!("Cannot decode coin: state is not validly length-prepended.");
        }

        Ok(Box::new(Self {
            type_script_hash: *digest,
            state: seq[1..].to_vec(),
        }))
    }

    fn encode(&self) -> Vec<BFieldElement> {
        vec![self.type_script_hash.encode(), self.state.encode()].concat()
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Utxo {
    pub lock_script_hash: Digest,
    pub coins: Vec<Coin>,
}

impl GetSize for Utxo {
    fn get_stack_size() -> usize {
        std::mem::size_of::<Self>()
    }

    fn get_heap_size(&self) -> usize {
        // self.lock_script.get_heap_size() + self.coins.len() * (std::mem::size_of::<Digest>())
        let mut total = self.lock_script_hash.get_heap_size();
        for v in self.coins.iter() {
            total += std::mem::size_of::<Digest>();
            total += v.state.len() * std::mem::size_of::<BFieldElement>();
        }

        total
    }

    fn get_size(&self) -> usize {
        Self::get_stack_size() + GetSize::get_heap_size(self)
    }
}

impl Utxo {
    pub fn new(lock_script: LockScript, coins: Vec<Coin>) -> Self {
        Self {
            lock_script_hash: lock_script.hash(),
            coins,
        }
    }

    pub fn new_native_coin(lock_script: LockScript, amount: Amount) -> Self {
        Self::new(
            lock_script,
            vec![Coin {
                type_script_hash: native_coin::NATIVE_COIN_TYPESCRIPT_DIGEST,
                state: amount.to_sequence(),
            }],
        )
    }

    pub fn get_native_coin_amount(&self) -> Amount {
        self.coins
            .iter()
            .filter(|coin| coin.type_script_hash == NATIVE_COIN_TYPESCRIPT_DIGEST)
            .map(|coin| Amount::from_bfes(&coin.state))
            .sum()
    }
}

impl Hashable for Utxo {
    fn to_sequence(&self) -> Vec<BFieldElement> {
        let lock_script_bfes: Vec<BFieldElement> = self.lock_script_hash.values().to_vec();

        let coins_bfes = self
            .coins
            .iter()
            .flat_map(|coin| {
                [
                    vec![BFieldElement::new(
                        coin.type_script_hash.to_sequence().len() as u64,
                    )],
                    coin.type_script_hash.to_sequence(),
                    vec![BFieldElement::new(coin.state.len() as u64)],
                    coin.state.clone(),
                ]
                .concat()
            })
            .collect_vec();

        [
            vec![BFieldElement::new(lock_script_bfes.len() as u64)],
            lock_script_bfes,
            vec![BFieldElement::new(coins_bfes.len() as u64)],
            coins_bfes,
        ]
        .concat()
    }
}

/// Make `Utxo` hashable with `StdHash` for using it in `HashMap`.
///
/// The Clippy warning is safe to suppress, because we do not violate the invariant: k1 == k2 => hash(k1) == hash(k2).
#[allow(clippy::derived_hash_with_manual_eq)]
impl StdHash for Utxo {
    fn hash<H: StdHasher>(&self, state: &mut H) {
        let neptune_hash = Hash::hash(self);
        StdHash::hash(&neptune_hash, state);
    }
}

impl BFieldCodec for Utxo {
    fn decode(sequence: &[BFieldElement]) -> anyhow::Result<Box<Self>> {
        if sequence.len() < DIGEST_LENGTH + 1 {
            bail!("Cannot decode UTXO from Vec of BFieldElements because length too small.");
        }

        let lock_script_hash = *Digest::decode(&sequence[0..DIGEST_LENGTH])?;

        let num_coins = match sequence.get(DIGEST_LENGTH) {
            Some(result) => result.value(),
            None => bail!("Could not get number of coins in UTXO."),
        };

        let mut coins = vec![];
        let mut read_index = DIGEST_LENGTH + 1;
        for _ in 0..num_coins {
            let coin_sequence_length = match sequence.get(read_index) {
                Some(result) => result.value() as usize,
                None => bail!("Could not get coin sequence length in UTXO."),
            };
            read_index += 1;
            if sequence.len() < read_index + coin_sequence_length {
                bail!("Format error when decoding coins.");
            }
            let coin_sequence = &sequence[read_index..read_index + coin_sequence_length];
            coins.push(*Coin::decode(coin_sequence)?);
        }
        Ok(Box::new(Self {
            lock_script_hash,
            coins,
        }))
    }

    fn encode(&self) -> Vec<BFieldElement> {
        let mut sequence = self.lock_script_hash.values().to_vec();
        sequence.push(BFieldElement::new(self.coins.len() as u64));
        for coin in self.coins.iter() {
            sequence.append(&mut coin.encode());
        }
        sequence
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, GetSize)]
pub struct LockScript {
    pub program: Program,
}

impl From<Vec<LabelledInstruction>> for LockScript {
    fn from(instrs: Vec<LabelledInstruction>) -> Self {
        Self {
            program: Program::new(&instrs),
        }
    }
}

impl From<&[LabelledInstruction]> for LockScript {
    fn from(instrs: &[LabelledInstruction]) -> Self {
        Self {
            program: Program::new(instrs),
        }
    }
}

impl BFieldCodec for LockScript {
    fn decode(_sequence: &[BFieldElement]) -> anyhow::Result<Box<Self>> {
        panic!() // should not get here
    }

    fn encode(&self) -> Vec<BFieldElement> {
        self.program.to_bwords()
    }
}

impl LockScript {
    pub fn new(program: Program) -> Self {
        Self { program }
    }

    pub fn anyone_can_spend() -> Self {
        Self {
            program: Program::new(&vec![vec![read_io(); DIGEST_LENGTH], vec![halt()]].concat()),
        }
    }

    pub fn hash(&self) -> Digest {
        Hash::hash_varlen(&self.program.to_bwords())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, GetSize)]
pub struct TypeScript {
    pub program: Program,
}

impl Hashable for TypeScript {
    fn to_sequence(&self) -> Vec<BFieldElement> {
        self.program.to_sequence()
    }
}

impl From<Vec<LabelledInstruction>> for TypeScript {
    fn from(instrs: Vec<LabelledInstruction>) -> Self {
        Self {
            program: Program::new(&instrs),
        }
    }
}

impl From<&[LabelledInstruction]> for TypeScript {
    fn from(instrs: &[LabelledInstruction]) -> Self {
        Self {
            program: Program::new(instrs),
        }
    }
}

impl TypeScript {
    pub fn new(program: Program) -> Self {
        Self { program }
    }

    pub fn hash(&self) -> Digest {
        Hash::hash_varlen(&self.program.to_bwords())
    }

    pub fn native_coin() -> Self {
        Self {
            program: native_coin_program(),
        }
    }
}

#[cfg(test)]
mod utxo_tests {

    use rand::{thread_rng, Rng};
    use tracing_test::traced_test;
    use twenty_first::shared_math::other::random_elements;

    use super::*;

    fn make_random_utxo() -> Utxo {
        let mut rng = thread_rng();
        let lock_script = LockScript::anyone_can_spend();
        let lock_script_hash = lock_script.hash();
        let num_coins = rng.gen_range(0..10);
        let mut coins = vec![];
        for _i in 0..num_coins {
            let type_script = TypeScript::native_coin();
            let state: Vec<BFieldElement> = random_elements(rng.gen_range(0..10));
            coins.push(Coin {
                type_script_hash: Hash::hash(&type_script),
                state,
            });
        }

        Utxo {
            lock_script_hash,
            coins,
        }
    }

    #[test]
    fn hash_utxo_test() {
        let output = make_random_utxo();
        let _digest = Hash::hash(&output);
    }

    #[traced_test]
    #[test]
    fn serialization_test() {
        let utxo = make_random_utxo();
        let serialized: String = serde_json::to_string(&utxo).unwrap();
        let utxo_again: Utxo = serde_json::from_str(&serialized).unwrap();
        assert_eq!(utxo, utxo_again);
    }
}
