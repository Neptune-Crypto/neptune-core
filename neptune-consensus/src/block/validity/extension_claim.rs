//! A program a soft fork could add as a required claim, with the recursion
//! it needs built in: it finds its own claim in the parent's appendix, which
//! rule 1.d of `PredecessorIsValid` proves whole. The rule itself is left
//! out; only the recursion is here, as a test that the design admits it.

use std::sync::OnceLock;

use get_size2::GetSize;
use neptune_primitives::mast_hash::MastHash;
use serde::Deserialize;
use serde::Serialize;
use tasm_lib::data_type::Literal;
use tasm_lib::field;
use tasm_lib::field_with_size;
use tasm_lib::hashing::algebraic_hasher::hash_varlen::HashVarlen;
use tasm_lib::hashing::hash_from_stack::HashFromStack;
use tasm_lib::memory::encode_to_memory;
use tasm_lib::memory::FIRST_NON_DETERMINISTICALLY_INITIALIZED_MEMORY_ADDRESS;
use tasm_lib::prelude::*;
use tasm_lib::structure::verify_nd_si_integrity::VerifyNdSiIntegrity;
use tasm_lib::triton_vm::prelude::*;
use tasm_lib::verifier::own_program_digest::OwnProgramDigest;

use super::predecessor_is_valid::PredecessorIsValid;
use crate::block::block_appendix::BlockAppendix;
use crate::block::Block;
use crate::proof_abstractions::tasm::builtins as tasm;
use crate::proof_abstractions::tasm::program::spec::TritonProgramSpecification;
use crate::proof_abstractions::tasm::program::TritonProgram;
use crate::proof_abstractions::SecretWitness;

/// What the program divines about the parent: enough to recompute the
/// parent's hash around the appendix.
#[derive(Debug, Clone, BFieldCodec, GetSize, PartialEq, Eq, Serialize, Deserialize, TasmObject)]
pub(super) struct ParentForExtension {
    header_mast_hash: Digest,
    body_mast_hash: Digest,
    /// The hash of the parent's proof's encoding.
    proof_leaf: Digest,
    appendix: BlockAppendix,
}

impl ParentForExtension {
    pub(super) fn new(parent: &Block) -> Self {
        Self {
            header_mast_hash: parent.header().mast_hash(),
            body_mast_hash: parent.body().mast_hash(),
            proof_leaf: Tip5::hash_varlen(&parent.proof.encode()),
            appendix: parent.appendix().clone(),
        }
    }

    fn hash(&self) -> Digest {
        let leaf = |digest: Digest| Tip5::hash_varlen(&digest.encode());
        let left = Tip5::hash_pair(leaf(self.header_mast_hash), leaf(self.body_mast_hash));
        let appendix_leaf = Tip5::hash_varlen(&self.appendix.encode());
        let right = Tip5::hash_pair(appendix_leaf, Digest::default());
        let kernel = Tip5::hash_pair(left, right);
        Tip5::hash_pair(leaf(kernel), self.proof_leaf)
    }
}

#[derive(Debug, Clone)]
pub(super) struct ExtensionClaimWitness {
    program: ExtensionClaim,
    parent_hash: Digest,
    tip_body_mast_hash: Digest,
    parent: ParentForExtension,
}

impl ExtensionClaimWitness {
    pub(super) fn new(
        program: ExtensionClaim,
        parent_hash: Digest,
        tip_body_mast_hash: Digest,
        parent: ParentForExtension,
    ) -> Self {
        Self {
            program,
            parent_hash,
            tip_body_mast_hash,
            parent,
        }
    }
}

impl SecretWitness for ExtensionClaimWitness {
    fn standard_input(&self) -> PublicInput {
        PublicInput::new(ExtensionClaim::claim_input(
            self.parent_hash,
            self.tip_body_mast_hash,
        ))
    }

    fn output(&self) -> Vec<BFieldElement> {
        vec![]
    }

    fn program(&self) -> Program {
        self.program.program()
    }

    fn nondeterminism(&self) -> NonDeterminism {
        let mut nondeterminism = NonDeterminism::default();
        encode_to_memory(
            &mut nondeterminism.ram,
            FIRST_NON_DETERMINISTICALLY_INITIALIZED_MEMORY_ADDRESS,
            &self.parent,
        );
        nondeterminism
    }
}

/// Input: the parent's hash and the tip's body MAST hash (5 words each).
/// Output: none.
///
/// Divines the parent's header hash, body hash, proof leaf and appendix,
/// which must hash to the parent's hash; reads the parent's height and the
/// parent's parent hash from the predecessor claim in that appendix; and,
/// for a parent at or past the activation height, finds its own claim there
/// about the parent's parent and body.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(super) struct ExtensionClaim {
    predecessor_program_digest: Digest,
    activation_height: u64,
}

impl ExtensionClaim {
    const PARENT_HASH_MISMATCH_ERROR_ID: i128 = 1_000_620;
    const MISSING_PREDECESSOR_CLAIM_ERROR_ID: i128 = 1_000_621;
    const MISSING_OWN_CLAIM_ERROR_ID: i128 = 1_000_622;

    /// Requiring its own claim from parents at this height on, which carry
    /// the claim of this predecessor program.
    pub(super) fn new(predecessor_program: &PredecessorIsValid, activation_height: u64) -> Self {
        Self {
            predecessor_program_digest: predecessor_program.hash(),
            activation_height,
        }
    }

    pub(super) fn claim_input(
        parent_hash: Digest,
        tip_body_mast_hash: Digest,
    ) -> Vec<BFieldElement> {
        [parent_hash, tip_body_mast_hash]
            .iter()
            .flat_map(|digest| digest.reversed().values())
            .collect()
    }

    pub(super) fn claim(&self, parent_hash: Digest, tip_body_mast_hash: Digest) -> Claim {
        Claim::new(self.hash()).with_input(Self::claim_input(parent_hash, tip_body_mast_hash))
    }
}

impl TritonProgram for ExtensionClaim {
    fn library_and_code(&self) -> (Library, Vec<LabelledInstruction>) {
        let mut library = Library::new();
        let audit = library.import(Box::new(
            VerifyNdSiIntegrity::<ParentForExtension>::default(),
        ));
        let own_program_digest = library.import(Box::new(OwnProgramDigest));
        let hash_varlen = library.import(Box::new(HashVarlen));
        let hash_digest = library.import(Box::new(HashFromStack::new(DataType::Digest)));
        let own_digest_alloc = library.kmalloc(Digest::LEN as u32);
        // The parent's parent hash, then the parent's body hash.
        let expected_input_alloc = library.kmalloc(2 * Digest::LEN as u32);

        let read_digest = triton_asm!(addi {Digest::LEN - 1} read_mem {Digest::LEN} pop 1);
        let digests_are_equal = DataType::Digest.compare();
        let push_predecessor_program_digest =
            Literal::Digest(self.predecessor_program_digest).push_to_stack_code();
        // The input list's words, in the digest's orientation.
        let read_input_digest = |offset: usize| triton_asm!(addi {offset + Digest::LEN} read_mem {Digest::LEN} pop 1 swap 4 swap 1 swap 3 swap 1);
        // BEFORE: _ *claim[i]_si num_claims i
        // AFTER:  _ *claim[i + 1]_si num_claims (i + 1)
        let next_claim = triton_asm!(
            pick 2 read_mem 1
            // Crashes unless the size is a u32.
            dup 1 pop_count pop 1
            addi 2 add
            place 2 addi 1
        );

        let find_predecessor_claim = "extension_claim_find_predecessor_claim".to_string();
        let require_own_claim = "extension_claim_require_own_claim".to_string();
        let find_own_claim = "extension_claim_find_own_claim".to_string();
        let code = triton_asm!(
            call {own_program_digest}
            push {own_digest_alloc.write_address()} write_mem {Digest::LEN} pop 1
            read_io {Digest::LEN}
            // _ [parent_hash]
            // The tip's body: this program has no rule about it.
            read_io {Digest::LEN} pop {Digest::LEN}
            push {FIRST_NON_DETERMINISTICALLY_INITIALIZED_MEMORY_ADDRESS}
            hint parent = stack[0]
            dup 0 call {audit} pop 1
            // _ [parent_hash] *parent

            dup 0 {&field!(ParentForExtension::proof_leaf)} {&read_digest}
            push 0 push 0 push 0 push 0 push 0
            dup 10 {&field_with_size!(ParentForExtension::appendix)} call {hash_varlen}
            hash
            // _ [parent_hash] *parent [proof_leaf] [right_node]
            dup 10 {&field!(ParentForExtension::body_mast_hash)} {&read_digest} call {hash_digest}
            dup 15 {&field!(ParentForExtension::header_mast_hash)} {&read_digest} call {hash_digest}
            hash hash call {hash_digest} hash
            // _ [parent_hash] *parent [recomputed_parent_hash]
            dup 10 dup 10 dup 10 dup 10 dup 10
            assert_vector error_id {Self::PARENT_HASH_MISMATCH_ERROR_ID}
            pop 5
            // _ [parent_hash] *parent

            dup 0 {&field!(ParentForExtension::appendix)} {&field!(BlockAppendix::claims)}
            read_mem 1 addi 2 place 1 push 0
            call {find_predecessor_claim}
            // _ [parent_hash] *parent *claim[i]_si num_claims i
            pop 2 addi 1
            dup 0 {&field!(Claim::input)} addi {Digest::LEN + 1} read_mem 1 pop 1
            // _ [parent_hash] *parent *predecessor_claim parent_height
            push {self.activation_height} swap 1 lt
            // _ [parent_hash] *parent *predecessor_claim (parent_height < activation_height)
            push 0 eq skiz call {require_own_claim}
            pop 2 pop {Digest::LEN}
            halt

            // The parent's predecessor claim: the one about the parent's
            // body.
            // INVARIANT: _ [parent_hash] *parent *claim[i]_si num_claims i
            {find_predecessor_claim}:
                dup 1 dup 1 eq
                push 0 eq assert error_id {Self::MISSING_PREDECESSOR_CLAIM_ERROR_ID}
                dup 2 addi 1 {&field!(Claim::program_digest)} {&read_digest}
                {&push_predecessor_program_digest}
                {&digests_are_equal}
                dup 3 addi 1 {&field_with_size!(Claim::input)} pick 1 pop 1
                push {Digest::LEN + 1} swap 1 lt push 0 eq mul
                // _ [parent_hash] *parent *claim[i]_si num_claims i shape_matches
                dup 3 addi 1 {&field!(Claim::input)} {&read_input_digest(0)}
                dup 9 {&field!(ParentForExtension::body_mast_hash)} {&read_digest}
                {&digests_are_equal} mul
                skiz return
                {&next_claim}
                recurse

            // BEFORE: _ [parent_hash] *parent *predecessor_claim
            // AFTER:  _ [parent_hash] *parent *predecessor_claim
            {require_own_claim}:
                dup 0 {&field!(Claim::output)} addi 1 {&read_digest}
                // _ [parent_hash] *parent *predecessor_claim [parent_prev_block_hash]
                push {expected_input_alloc.write_address()} write_mem {Digest::LEN}
                dup 2 {&field!(ParentForExtension::body_mast_hash)} {&read_digest}
                pick 5 write_mem {Digest::LEN} pop 1
                // _ [parent_hash] *parent *predecessor_claim
                dup 1 {&field!(ParentForExtension::appendix)} {&field!(BlockAppendix::claims)}
                read_mem 1 addi 2 place 1 push 0
                call {find_own_claim}
                pop 3
                return

            // INVARIANT: _ [parent_hash] *parent *predecessor_claim *claim[i]_si num_claims i
            {find_own_claim}:
                dup 1 dup 1 eq
                push 0 eq assert error_id {Self::MISSING_OWN_CLAIM_ERROR_ID}
                dup 2 addi 1 {&field!(Claim::program_digest)} {&read_digest}
                push {own_digest_alloc.read_address()} read_mem {Digest::LEN} pop 1
                {&digests_are_equal}
                dup 3 addi 1 {&field_with_size!(Claim::input)} pick 1 pop 1
                push {2 * Digest::LEN + 1} eq mul
                // _ … i shape_matches
                dup 3 addi 1 {&field!(Claim::input)} {&read_input_digest(0)}
                push {expected_input_alloc.write_address()} {&read_digest}
                {&digests_are_equal} mul
                dup 3 addi 1 {&field!(Claim::input)} {&read_input_digest(Digest::LEN)}
                push {expected_input_alloc.write_address()} addi {Digest::LEN} {&read_digest}
                {&digests_are_equal} mul
                skiz return
                {&next_claim}
                recurse

            {&library.all_imports()}
        );

        (library, code)
    }

    fn hash(&self) -> Digest {
        static HASHES: OnceLock<
            std::sync::Mutex<std::collections::HashMap<ExtensionClaim, Digest>>,
        > = OnceLock::new();
        let hashes = HASHES.get_or_init(Default::default);
        if let Some(hash) = hashes.lock().unwrap().get(self) {
            return *hash;
        }
        let hash = self.program().hash();
        hashes.lock().unwrap().insert(*self, hash);
        hash
    }
}

impl TritonProgramSpecification for ExtensionClaim {
    fn source(&self) {
        let own_program_digest = tasm::own_program_digest();
        let parent_hash = tasm::tasmlib_io_read_stdin___digest();
        let _tip_body_mast_hash = tasm::tasmlib_io_read_stdin___digest();
        let parent: ParentForExtension =
            tasm::decode_from_memory(FIRST_NON_DETERMINISTICALLY_INITIALIZED_MEMORY_ADDRESS);
        assert_eq!(parent_hash, parent.hash());
        let body_mast_hash_input = parent.body_mast_hash.reversed().values();
        let predecessor_claim = parent
            .appendix
            .iter()
            .find(|claim| {
                claim.program_digest == self.predecessor_program_digest
                    && claim.input.len() > Digest::LEN
                    && claim.input[..Digest::LEN] == body_mast_hash_input
            })
            .expect("parent must carry the predecessor claim");
        let parent_height = predecessor_claim.input[Digest::LEN].value();
        if parent_height < self.activation_height {
            return;
        }
        let parent_prev_block_hash =
            Digest::new(predecessor_claim.output[..Digest::LEN].try_into().unwrap());
        let expected_input = Self::claim_input(parent_prev_block_hash, parent.body_mast_hash);
        assert!(parent.appendix.iter().any(|claim| {
            claim.program_digest == own_program_digest && claim.input == expected_input
        }));
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use rand::rngs::StdRng;
    use rand::RngExt;
    use rand::SeedableRng;

    use super::*;
    use crate::block::block_body::BlockBody;
    use crate::block::block_header::BlockHeader;
    use crate::block::validity::epoch_table::Epoch;
    use crate::block::validity::epoch_table::EpochTable;
    use crate::block::BlockProof;

    const ACTIVATION_HEIGHT: u64 = 100;

    fn extension() -> ExtensionClaim {
        ExtensionClaim::new(&PredecessorIsValid::new(), ACTIVATION_HEIGHT)
    }

    /// A random block at this height on this parent, with these claims.
    fn block(rng: &mut StdRng, parent: Option<&Block>, height: u64, claims: Vec<Claim>) -> Block {
        let mut header: BlockHeader = rng.random();
        header.height = height.into();
        if let Some(parent) = parent {
            header.prev_block_digest = parent.hash();
        }
        let body: BlockBody = rng.random();
        Block::new(
            header,
            body,
            BlockAppendix::new(claims),
            BlockProof::Invalid,
        )
    }

    /// The shape of the predecessor claim a block carries about its parent:
    /// the block's body hash and height first in the input, the parent's
    /// hash first in the output.
    fn predecessor_claim(parent: &Block, body: &BlockBody, height: u64) -> Claim {
        let epochs = EpochTable::new(&[Epoch {
            height: bfe!(ACTIVATION_HEIGHT),
            ..Default::default()
        }]);
        let input = [
            body.mast_hash().reversed().values().to_vec(),
            vec![bfe!(height)],
            epochs.encode(),
        ]
        .concat();
        let output = [parent.hash().values().to_vec(), vec![bfe!(0); 20]].concat();
        Claim::new(PredecessorIsValid::new().hash())
            .with_input(input)
            .with_output(output)
    }

    /// A parent at this height carrying the predecessor claim and these
    /// claims, and the witness for a tip on it.
    fn parent_and_witness(
        rng: &mut StdRng,
        height: u64,
        extra_claims: impl FnOnce(&Block, &BlockBody) -> Vec<Claim>,
    ) -> (Block, ExtensionClaimWitness) {
        let grandparent = block(rng, None, height - 1, vec![]);
        let body: BlockBody = rng.random();
        let claims = [
            vec![predecessor_claim(&grandparent, &body, height)],
            extra_claims(&grandparent, &body),
        ]
        .concat();
        let mut header: BlockHeader = rng.random();
        header.height = height.into();
        header.prev_block_digest = grandparent.hash();
        let parent = Block::new(
            header,
            body,
            BlockAppendix::new(claims),
            BlockProof::Invalid,
        );
        let tip_body: BlockBody = rng.random();
        let witness = ExtensionClaimWitness::new(
            extension(),
            parent.hash(),
            tip_body.mast_hash(),
            ParentForExtension::new(&parent),
        );
        (parent, witness)
    }

    fn own_claim(grandparent: &Block, body: &BlockBody) -> Vec<Claim> {
        vec![extension().claim(grandparent.hash(), body.mast_hash())]
    }

    fn assert_accepts(witness: &ExtensionClaimWitness) {
        let input = witness.standard_input();
        let rust = witness.program.run_rust(&input, witness.nondeterminism());
        let tasm = witness.program.run_tasm(&input, witness.nondeterminism());
        assert_eq!(Vec::<BFieldElement>::new(), rust.unwrap());
        assert_eq!(Vec::<BFieldElement>::new(), tasm.unwrap());
    }

    fn assert_rejects(witness: &ExtensionClaimWitness, error_id: i128) {
        witness
            .program
            .test_assertion_failure(
                witness.standard_input(),
                witness.nondeterminism(),
                &[error_id],
            )
            .unwrap();
    }

    #[test]
    fn divined_parent_hashes_like_the_block() {
        let mut rng = StdRng::seed_from_u64(0);
        let parent = block(&mut rng, None, 7, vec![]);
        assert_eq!(parent.hash(), ParentForExtension::new(&parent).hash());
    }

    #[test]
    fn parent_carrying_the_claim_is_accepted() {
        let mut rng = StdRng::seed_from_u64(1);
        for height in [ACTIVATION_HEIGHT, ACTIVATION_HEIGHT + 5] {
            let (_, witness) = parent_and_witness(&mut rng, height, own_claim);
            assert_accepts(&witness);
        }
    }

    #[test]
    fn parent_below_activation_needs_no_claim() {
        let mut rng = StdRng::seed_from_u64(2);
        let (_, witness) = parent_and_witness(&mut rng, ACTIVATION_HEIGHT - 1, |_, _| vec![]);
        assert_accepts(&witness);
    }

    #[test]
    fn parent_without_the_claim_is_rejected() {
        let mut rng = StdRng::seed_from_u64(3);
        let (_, witness) = parent_and_witness(&mut rng, ACTIVATION_HEIGHT, |_, _| vec![]);
        assert_rejects(&witness, ExtensionClaim::MISSING_OWN_CLAIM_ERROR_ID);
    }

    #[test]
    fn claim_about_another_grandparent_or_body_is_rejected() {
        let mut rng = StdRng::seed_from_u64(4);
        let other_grandparent = |grandparent: &Block, body: &BlockBody| {
            let mut hash = grandparent.hash();
            hash.0[0] += bfe!(1);
            vec![extension().claim(hash, body.mast_hash())]
        };
        let other_body = |grandparent: &Block, body: &BlockBody| {
            let mut hash = body.mast_hash();
            hash.0[0] += bfe!(1);
            vec![extension().claim(grandparent.hash(), hash)]
        };
        let (_, witness) = parent_and_witness(&mut rng, ACTIVATION_HEIGHT, other_grandparent);
        assert_rejects(&witness, ExtensionClaim::MISSING_OWN_CLAIM_ERROR_ID);
        let (_, witness) = parent_and_witness(&mut rng, ACTIVATION_HEIGHT, other_body);
        assert_rejects(&witness, ExtensionClaim::MISSING_OWN_CLAIM_ERROR_ID);
    }

    #[test]
    fn appendix_not_the_parents_is_rejected() {
        let mut rng = StdRng::seed_from_u64(5);
        let (parent, mut witness) = parent_and_witness(&mut rng, ACTIVATION_HEIGHT, |_, _| vec![]);
        let claims = [
            parent.appendix().claims().to_vec(),
            own_claim(&block(&mut rng, None, 1, vec![]), parent.body()),
        ]
        .concat();
        witness.parent.appendix = BlockAppendix::new(claims);
        assert_rejects(&witness, ExtensionClaim::PARENT_HASH_MISMATCH_ERROR_ID);
    }

    #[test]
    fn parent_without_predecessor_claim_is_rejected() {
        let mut rng = StdRng::seed_from_u64(6);
        let (_, mut witness) = parent_and_witness(&mut rng, ACTIVATION_HEIGHT, own_claim);
        let parent = block(
            &mut rng,
            None,
            ACTIVATION_HEIGHT,
            witness.parent.appendix.claims()[1..].to_vec(),
        );
        witness.parent_hash = parent.hash();
        witness.parent = ParentForExtension::new(&parent);
        assert_rejects(&witness, ExtensionClaim::MISSING_PREDECESSOR_CLAIM_ERROR_ID);
    }
}
