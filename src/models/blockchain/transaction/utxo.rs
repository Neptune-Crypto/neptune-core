use crate::models::blockchain::shared::Hash;
use get_size::GetSize;
use num_traits::Zero;
use serde::{Deserialize, Serialize};
use std::hash::{Hash as StdHash, Hasher as StdHasher};
use triton_opcodes::instruction::LabelledInstruction;
use triton_opcodes::program::Program;
use triton_opcodes::shortcuts::{halt, read_io};
use twenty_first::shared_math::bfield_codec::BFieldCodec;
use twenty_first::shared_math::tip5::{Digest, DIGEST_LENGTH};

use super::native_coin::{native_coin_program, NATIVE_COIN_TYPESCRIPT_DIGEST};
use super::{native_coin, Amount};
use twenty_first::shared_math::b_field_element::BFieldElement;
use twenty_first::util_types::algebraic_hasher::AlgebraicHasher;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, BFieldCodec)]

pub struct Coin {
    pub type_script_hash: Digest,
    pub state: Vec<BFieldElement>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, BFieldCodec)]
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
                state: amount.encode(),
            }],
        )
    }

    pub fn get_native_coin_amount(&self) -> Amount {
        self.coins
            .iter()
            .filter(|coin| coin.type_script_hash == NATIVE_COIN_TYPESCRIPT_DIGEST)
            .map(|coin| match Amount::decode(&coin.state) {
                Ok(boxed_amount) => *boxed_amount,
                Err(_) => Amount::zero(),
            })
            .sum()
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

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, GetSize)]
pub struct LockScript {
    pub program: Program,
}

impl BFieldCodec for LockScript {
    fn encode(&self) -> Vec<BFieldElement> {
        self.program.encode()
    }

    fn decode(bytes: &[BFieldElement]) -> anyhow::Result<Box<Self>> {
        Ok(Box::new(Self {
            program: *Program::decode(bytes)?,
        }))
    }

    fn static_length() -> Option<usize> {
        None
    }
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
        Hash::hash_varlen(&self.program.encode())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, GetSize)]
pub struct TypeScript {
    pub program: Program,
}

impl BFieldCodec for TypeScript {
    fn encode(&self) -> Vec<BFieldElement> {
        self.program.encode()
    }

    fn decode(bytes: &[BFieldElement]) -> anyhow::Result<Box<Self>> {
        Ok(Box::new(Self {
            program: *Program::decode(bytes)?,
        }))
    }

    fn static_length() -> Option<usize> {
        None
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
        Hash::hash_varlen(&self.program.encode())
    }

    pub fn native_coin() -> Self {
        Self {
            program: native_coin_program(),
        }
    }
}

#[cfg(test)]
mod utxo_tests {

    use itertools::Itertools;
    use rand::{
        distributions::WeightedIndex, prelude::Distribution, random, seq::SliceRandom, thread_rng,
        Rng, RngCore,
    };
    use tracing_test::traced_test;
    use triton_opcodes::instruction::ALL_INSTRUCTION_NAMES;
    use twenty_first::shared_math::other::random_elements;

    use super::*;

    fn is_instruction_name(s: &str) -> bool {
        ALL_INSTRUCTION_NAMES.contains(&s)
    }

    fn label_gen(size: usize) -> String {
        let mut rng = rand::thread_rng();
        let mut new_label = || -> String { (0..size).map(|_| rng.gen_range('a'..='z')).collect() };
        let mut label = new_label();
        while is_instruction_name(&label) {
            label = new_label();
        }
        label
    }

    fn new_label_gen(labels: &mut Vec<String>) -> String {
        let mut rng = rand::thread_rng();
        let count = labels.len() * 3 / 2;
        let index = rng.gen_range(0..=count);

        labels.get(index).cloned().unwrap_or_else(|| {
            let label_size = 4;
            let new_label = label_gen(label_size);
            labels.push(new_label.clone());
            new_label
        })
    }

    fn instruction_gen(labels: &mut Vec<String>) -> Vec<String> {
        let mut rng = thread_rng();

        let difficult_instructions = vec!["push", "dup", "swap", "skiz", "call"];
        let simple_instructions = ALL_INSTRUCTION_NAMES
            .into_iter()
            .filter(|name| !difficult_instructions.contains(name))
            .collect_vec();

        let generators = vec![vec!["simple"], difficult_instructions].concat();
        // Test difficult instructions more frequently.
        let weights = vec![simple_instructions.len(), 2, 6, 6, 2, 10];

        assert_eq!(
            generators.len(),
            weights.len(),
            "all generators must have weights"
        );
        let dist = WeightedIndex::new(&weights).expect("a weighted distribution of generators");

        match generators[dist.sample(&mut rng)] {
            "simple" => {
                let index: usize = rng.gen_range(0..simple_instructions.len());
                let instruction = simple_instructions[index];
                vec![instruction.to_string()]
            }

            "push" => {
                let max: i128 = BFieldElement::MAX as i128;
                let arg: i128 = rng.gen_range(-max..max);
                vec!["push".to_string(), format!("{arg}")]
            }

            "dup" => {
                let arg: usize = rng.gen_range(0..15);
                vec!["dup".to_string(), format!("{arg}")]
            }

            "swap" => {
                let arg: usize = rng.gen_range(1..15);
                vec!["swap".to_string(), format!("{arg}")]
            }

            "skiz" => {
                let mut target: Vec<String> = instruction_gen(labels);
                target.insert(0, "skiz".to_string());
                target
            }

            "call" => {
                let some_label: String = new_label_gen(labels);
                vec!["call".to_string(), some_label]
            }

            unknown => panic!("Unknown generator, {unknown}"),
        }
    }

    fn whitespace_gen(max_size: usize) -> String {
        let mut rng = rand::thread_rng();
        let spaces = [" ", "\t", "\r", "\r\n", "\n", " // comment\n"];
        let weights = [5, 1, 1, 1, 2, 1];
        assert_eq!(spaces.len(), weights.len(), "all generators have weights");
        let dist = WeightedIndex::new(weights).expect("a weighted distribution of generators");
        let size = rng.gen_range(1..=std::cmp::max(1, max_size));
        (0..size).map(|_| spaces[dist.sample(&mut rng)]).collect()
    }

    // FIXME: Apply shrinking.
    #[allow(unstable_name_collisions)]
    // reason = "Switch to standard library intersperse_with() when it's ported"
    pub fn program_gen(size: usize) -> String {
        // Generate random program
        let mut labels = vec![];
        let mut program: Vec<Vec<String>> =
            (0..size).map(|_| instruction_gen(&mut labels)).collect();

        // Embed all used labels randomly
        for label in labels.into_iter().sorted().dedup() {
            program.push(vec![format!("{label}:")]);
        }
        program.shuffle(&mut rand::thread_rng());

        program
            .into_iter()
            .flatten()
            .intersperse_with(|| whitespace_gen(5))
            .collect()
    }

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

    #[traced_test]
    #[test]
    fn codec_test() {
        for _ in 0..10 {
            let utxo = make_random_utxo();
            let encoded = utxo.encode();
            let decoded = *Utxo::decode(&encoded).unwrap();
            assert_eq!(utxo, decoded);
        }
    }

    #[test]
    fn test_type_script_encode() {
        let program = program_gen(63);
        let program = Program::from_code(&program).unwrap();
        let type_script = TypeScript { program };

        let encodede = type_script.encode();
        let decoded = *TypeScript::decode(&encodede).unwrap();
        assert_eq!(type_script, decoded);
    }

    #[test]
    fn test_coin_decode() {
        let type_script_hash: Digest = random();
        let state_length = thread_rng().next_u32() as usize % 100;
        let state: Vec<BFieldElement> = random_elements(state_length);
        let coin = Coin {
            type_script_hash,
            state,
        };

        let encoded = coin.encode();
        let decoded = *Coin::decode(&encoded).unwrap();
        assert_eq!(coin, decoded);
    }
}
