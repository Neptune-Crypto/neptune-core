use triton_opcodes::{program::Program, shortcuts::halt};
use twenty_first::shared_math::{b_field_element::BFieldElement, tip5::Digest};

pub const NATIVE_COIN_TYPESCRIPT_DIGEST: Digest = Digest::new([
    BFieldElement::new(0xf00ba12u64),
    BFieldElement::new(0xdeadbeefu64),
    BFieldElement::new(0xb0000b5u64),
    BFieldElement::new(0xdeadbeefu64),
    BFieldElement::new(0xdeadbeefu64),
]);

pub fn native_coin_program() -> Program {
    // todo: insert inflation check logic here
    Program::new(&[halt()])
}
