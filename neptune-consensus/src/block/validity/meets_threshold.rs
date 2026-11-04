use num_bigint::BigUint;
use tasm_lib::arithmetic::digest::to_u320::DigestToU320;
use tasm_lib::arithmetic::u320::mul_u160::U320MulU160;
use tasm_lib::arithmetic::u480::lt::Lt as U480Lt;
use tasm_lib::data_type::DataType;
use tasm_lib::prelude::BasicSnippet;
use tasm_lib::prelude::Library;
use tasm_lib::triton_vm::prelude::*;

/// Whether a block hash meets the threshold that a difficulty sets, *i.e.*
/// `hash <= floor((p^5 - 1) / difficulty)`, evaluated as
/// `hash * difficulty <= p^5 - 1` to avoid dividing.
///
/// ```text
/// BEFORE: _ [difficulty: u160] [hash: Digest]
/// AFTER:  _ meets_threshold
/// ```
#[derive(Debug, Copy, Clone)]
pub(super) struct MeetsThreshold;

impl MeetsThreshold {
    /// `p^5 - 1` as a u480, least significant limb first.
    fn max_threshold_limbs() -> [u32; U480Lt::NUM_LIMBS] {
        let p_to_the_fifth = BigUint::from(BFieldElement::P).pow(5);
        let mut limbs = (p_to_the_fifth - 1u32).to_u32_digits();
        limbs.resize(U480Lt::NUM_LIMBS, 0);
        limbs.try_into().unwrap()
    }
}

impl BasicSnippet for MeetsThreshold {
    fn parameters(&self) -> Vec<(DataType, String)> {
        vec![
            (DataType::U160, "difficulty".to_string()),
            (DataType::Digest, "hash".to_string()),
        ]
    }

    fn return_values(&self) -> Vec<(DataType, String)> {
        vec![(DataType::Bool, "meets_threshold".to_string())]
    }

    fn entrypoint(&self) -> String {
        "neptune_consensus_block_meets_threshold".to_string()
    }

    fn code(&self, library: &mut Library) -> Vec<LabelledInstruction> {
        let digest_to_u320 = library.import(Box::new(DigestToU320));
        let u320_mul_u160 = library.import(Box::new(U320MulU160));
        let u480_lt = library.import(Box::new(U480Lt));

        let push_max_threshold = Self::max_threshold_limbs()
            .iter()
            .rev()
            .flat_map(|&limb| triton_asm!(push { limb }))
            .collect::<Vec<_>>();

        triton_asm!(
            // BEFORE: _ [difficulty] [hash]
            // AFTER:  _ meets_threshold
            {self.entrypoint()}:
                call {digest_to_u320}
                // _ [difficulty: u160] [hash_as_u320]

                call {u320_mul_u160}
                // _ [product: u480]

                {&push_max_threshold}
                // _ [product: u480] [max_threshold: u480]

                call {u480_lt}
                // _ (max_threshold < product)

                push 0 eq
                // _ (product <= max_threshold)

                return
        )
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use neptune_primitives::difficulty_control::Difficulty;
    use rand::rngs::StdRng;
    use rand::RngExt;
    use rand::SeedableRng;
    use tasm_lib::triton_vm::vm::VM;

    use super::*;

    fn meets_threshold_in_vm(difficulty: Difficulty, hash: Digest) -> bool {
        let mut library = Library::new();
        let meets_threshold = library.import(Box::new(MeetsThreshold));
        let program = Program::new(&triton_asm!(
            read_io {Digest::LEN} read_io {Digest::LEN}
            call {meets_threshold}
            write_io 1
            halt
            {&library.all_imports()}
        ));

        let mut difficulty_limbs = BigUint::from(difficulty).to_u32_digits();
        difficulty_limbs.resize(U320MulU160::NUM_RHS_LIMBS, 0);
        let input = difficulty_limbs
            .iter()
            .rev()
            .map(|&limb| bfe!(limb))
            .chain(hash.reversed().values())
            .collect::<Vec<_>>();
        let output = VM::run(program, PublicInput::new(input), NonDeterminism::default()).unwrap();

        output == [bfe!(1)]
    }

    fn hash_at_offset_from_target(difficulty: Difficulty, offset: i8) -> Digest {
        let target = BigUint::from(difficulty.target());
        let hash = match offset {
            0 => target,
            1 => target + 1u32,
            -1 => target - 1u32,
            _ => unreachable!(),
        };
        hash.try_into().unwrap()
    }

    #[test]
    fn hash_just_above_the_target_does_not_meet_it() {
        for difficulty in [
            Difficulty::MINIMUM,
            Difficulty::new([0, 1, 0, 0, 0]),
            Difficulty::new([u32::MAX, u32::MAX, 0, 0, 0]),
            Difficulty::MAXIMUM,
        ] {
            let hash = hash_at_offset_from_target(difficulty, 1);
            assert!(!meets_threshold_in_vm(difficulty, hash));
        }
    }

    #[test]
    fn largest_hash_meets_no_threshold() {
        let hash = Digest::new([BFieldElement::new(BFieldElement::MAX); Digest::LEN]);
        assert!(!meets_threshold_in_vm(Difficulty::MINIMUM, hash));
        assert!(!meets_threshold_in_vm(Difficulty::MAXIMUM, hash));
    }

    #[test]
    fn random_hash_does_not_meet_a_high_threshold() {
        let mut rng = StdRng::seed_from_u64(1);
        let difficulty = Difficulty::new([0, 0, 0, 0, 1]);
        for _ in 0..10 {
            assert!(!meets_threshold_in_vm(difficulty, rng.random()));
        }
    }

    #[test]
    fn zero_hash_meets_every_threshold() {
        assert!(meets_threshold_in_vm(
            Difficulty::MINIMUM,
            Digest::default()
        ));
        assert!(meets_threshold_in_vm(
            Difficulty::MAXIMUM,
            Digest::default()
        ));
    }

    #[test]
    fn agrees_with_host_around_the_target_and_on_random_hashes() {
        let mut rng = StdRng::seed_from_u64(0);
        let mut difficulties = vec![Difficulty::MINIMUM, Difficulty::MAXIMUM];
        for _ in 0..20 {
            let num_limbs = rng.random_range(1..=5);
            let mut limbs = [0u32; 5];
            limbs[..num_limbs].fill_with(|| rng.random());
            difficulties.push(Difficulty::new(limbs));
        }

        for difficulty in difficulties {
            for offset in [-1, 0, 1] {
                let hash = hash_at_offset_from_target(difficulty, offset);
                assert_eq!(
                    hash <= difficulty.target(),
                    meets_threshold_in_vm(difficulty, hash),
                    "difficulty {difficulty}, offset {offset}"
                );
            }
            for _ in 0..3 {
                let hash: Digest = rng.random();
                assert_eq!(
                    hash <= difficulty.target(),
                    meets_threshold_in_vm(difficulty, hash),
                    "difficulty {difficulty}, hash {hash}"
                );
            }
        }
    }
}
