pub mod block_appendix;
pub mod block_body;
pub mod block_header;
pub mod block_height;
pub mod block_info;
pub mod block_kernel;
pub mod block_selector;
pub mod difficulty_control;
pub mod mutator_set_update;
pub mod validity;

use std::sync::OnceLock;

use block_appendix::BlockAppendix;
use block_body::BlockBody;
use block_header::BlockHeader;
use block_header::ADVANCE_DIFFICULTY_CORRECTION_FACTOR;
use block_header::ADVANCE_DIFFICULTY_CORRECTION_WAIT;
use block_header::MINIMUM_BLOCK_TIME;
use block_header::TARGET_BLOCK_INTERVAL;
use block_height::BlockHeight;
use block_kernel::BlockKernel;
use difficulty_control::Difficulty;
use get_size2::GetSize;
use itertools::Itertools;
use mutator_set_update::MutatorSetUpdate;
use num_traits::CheckedSub;
use num_traits::Zero;
use serde::Deserialize;
use serde::Serialize;
use tasm_lib::triton_vm::prelude::*;
use tasm_lib::twenty_first::util_types::mmr::mmr_accumulator::MmrAccumulator;
use tasm_lib::twenty_first::util_types::mmr::mmr_trait::Mmr;
use tracing::debug;
use tracing::warn;
use twenty_first::math::b_field_element::BFieldElement;
use twenty_first::math::bfield_codec::BFieldCodec;
use twenty_first::math::digest::Digest;
use validity::block_primitive_witness::BlockPrimitiveWitness;
use validity::block_program::BlockProgram;
use validity::block_proof_witness::BlockProofWitness;

use super::transaction::transaction_kernel::TransactionKernelProxy;
use super::transaction::utxo::Utxo;
use super::transaction::Transaction;
use super::type_scripts::native_currency_amount::NativeCurrencyAmount;
use super::type_scripts::time_lock::TimeLock;
use crate::config_models::network::Network;
use crate::job_queue::triton_vm::TritonVmJobQueue;
use crate::models::blockchain::block::difficulty_control::difficulty_control;
use crate::models::blockchain::shared::Hash;
use crate::models::blockchain::transaction::utxo::Coin;
use crate::models::blockchain::transaction::validity::single_proof::SingleProof;
use crate::models::proof_abstractions::mast_hash::MastHash;
use crate::models::proof_abstractions::tasm::program::ConsensusProgram;
use crate::models::proof_abstractions::tasm::program::TritonVmProofJobOptions;
use crate::models::proof_abstractions::timestamp::Timestamp;
use crate::models::proof_abstractions::verifier::verify;
use crate::models::proof_abstractions::SecretWitness;
use crate::models::state::wallet::address::hash_lock_key::HashLockKey;
use crate::models::state::wallet::address::ReceivingAddress;
use crate::models::state::wallet::expected_utxo::ExpectedUtxo;
use crate::models::state::wallet::expected_utxo::UtxoNotifier;
use crate::models::state::wallet::WalletSecret;
use crate::prelude::twenty_first;
use crate::util_types::mutator_set::addition_record::AdditionRecord;
use crate::util_types::mutator_set::commit;
use crate::util_types::mutator_set::mutator_set_accumulator::MutatorSetAccumulator;

/// Maximum block size in number of `BFieldElement`.
///
/// This number limits the number of outputs in a block's transaction to around
/// 25000. This limit ensures that it remains feasible to run an archival node
/// even in the event of denial-of-service attack, where the attacker creates
/// blocks with many outputs.
pub(crate) const MAX_BLOCK_SIZE: usize = 250_000;

/// Duration of timelock for half of all mining rewards.
///
/// Half the block subsidy is liquid immediately. Half of it is locked for this
/// time period. Likewise, half the guesser fee is liquid immediately; and half
/// is time locked for this period.
pub(crate) const MINING_REWARD_TIME_LOCK_PERIOD: Timestamp = Timestamp::years(3);

pub(crate) const INITIAL_BLOCK_SUBSIDY: NativeCurrencyAmount = NativeCurrencyAmount::coins(64);

/// All blocks have proofs except the genesis block
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, BFieldCodec, GetSize, Default)]
pub enum BlockProof {
    Genesis,
    #[default]
    Invalid,
    SingleProof(Proof),
}

/// Public fields of `Block` are read-only, enforced by #[readonly::make].
/// Modifications are possible only through `Block` methods.
///
/// Example:
///
/// test: verify that compile fails on an attempt to mutate block
/// internals directly (bypassing encapsulation)
///
/// ```compile_fail,E0594
/// use neptune_cash::models::blockchain::block::Block;
/// use neptune_cash::config_models::network::Network;
/// use neptune_cash::prelude::twenty_first::math::b_field_element::BFieldElement;
/// use tasm_lib::prelude::Digest;
///
/// let mut block = Block::genesis(Network::RegTest);
///
/// let height = block.kernel.header.height;
///
/// let nonce = Digest::default();
///
/// // this line fails to compile because we try to
/// // mutate an internal field.
/// block.kernel.header.nonce = nonce;
/// ```
// ## About the private `digest` field:
//
// The `digest` field represents the `Block` hash.  It is an optimization so
// that the hash can be lazily computed at most once (per modification).
//
// It is wrapped in `OnceLock<_>` for interior mutability because (a) the hash()
// method is used in many methods that are `&self` and (b) because `Block` is
// passed between tasks/threads, and thus `Rc<RefCell<_>>` is not an option.
//
// The field must be reset whenever the Block is modified.  As such, we should
// not permit direct modification of internal fields, particularly `kernel`
//
// Therefore `[readonly::make]` is used to make public `Block` fields read-only
// (not mutable) outside of this module.  All methods that modify Block also
// reset the `digest` field.
//
// We manually implement `PartialEq` and `Eq` so that digest field will not be
// compared.  Otherwise, we could have identical blocks except one has
// initialized digest field and the other has not.
//
// The field should not be serialized, so it has the `#[serde(skip)]` attribute.
// Upon deserialization, the field will have Digest::default() which is desired
// so that the digest will be recomputed if/when hash() is called.
//
// We likewise skip the field for `BFieldCodec`, and `GetSize` because there
// exist no impls for `OnceLock<_>` so derive fails.
//
// A unit test-suite exists in module tests::digest_encapsulation.
#[allow(non_local_definitions)] // needed for [Deserialize] macro from serde
#[derive(Clone, Debug, Serialize, Deserialize, BFieldCodec, GetSize)]
#[readonly::make]
pub struct Block {
    /// Everything but the proof
    pub kernel: BlockKernel,

    pub proof: BlockProof,

    // this is only here as an optimization for Block::hash()
    // so that we lazily compute the hash at most once.
    #[serde(skip)]
    #[bfield_codec(ignore)]
    #[get_size(ignore)]
    digest: OnceLock<Digest>,
}

impl PartialEq for Block {
    fn eq(&self, other: &Self) -> bool {
        // TBD: is it faster overall to compare hashes or equality
        // of kernel and blocktype fields?
        // In the (common?) case where hash has already been
        // computed for both `Block` comparing hash equality
        // should be faster.
        self.hash() == other.hash()
    }
}
impl Eq for Block {}

impl Block {
    /// Create a block template with an invalid block proof, from a block
    /// primitive witness.
    #[cfg(test)]
    pub(crate) fn block_template_invalid_proof_from_witness(
        primitive_witness: BlockPrimitiveWitness,
        block_timestamp: Timestamp,
        target_block_interval: Option<Timestamp>,
    ) -> Block {
        let body = primitive_witness.body().to_owned();
        let header = primitive_witness.header(block_timestamp, target_block_interval);
        let proof = BlockProof::Invalid;
        let appendix = BlockAppendix::default();
        Block::new(header, body, appendix, proof)
    }

    /// Create a block template with an invalid block proof.
    ///
    /// To be used in tests where you don't care about block validity.
    #[cfg(test)]
    pub(crate) fn block_template_invalid_proof(
        predecessor: &Block,
        transaction: Transaction,
        block_timestamp: Timestamp,
        target_block_interval: Option<Timestamp>,
    ) -> Block {
        let primitive_witness = BlockPrimitiveWitness::new(predecessor.to_owned(), transaction);
        Self::block_template_invalid_proof_from_witness(
            primitive_witness,
            block_timestamp,
            target_block_interval,
        )
    }

    pub(crate) async fn block_template_from_block_primitive_witness(
        primitive_witness: BlockPrimitiveWitness,
        timestamp: Timestamp,
        target_block_interval: Option<Timestamp>,
        triton_vm_job_queue: &TritonVmJobQueue,
        proof_job_options: TritonVmProofJobOptions,
    ) -> anyhow::Result<Block> {
        let body = primitive_witness.body().to_owned();
        let header = primitive_witness.header(timestamp, target_block_interval);
        let (appendix, proof) = {
            let block_proof_witness = BlockProofWitness::produce(primitive_witness).await?;
            let appendix = block_proof_witness.appendix();
            let claim = BlockProgram::claim(&body, &appendix);
            let proof = BlockProgram
                .prove(
                    claim,
                    block_proof_witness.nondeterminism(),
                    triton_vm_job_queue,
                    proof_job_options,
                )
                .await?;
            (appendix, BlockProof::SingleProof(proof))
        };

        Ok(Block::new(header, body, appendix, proof))
    }

    async fn make_block_template_with_valid_proof(
        predecessor: &Block,
        transaction: Transaction,
        block_timestamp: Timestamp,
        target_block_interval: Option<Timestamp>,
        triton_vm_job_queue: &TritonVmJobQueue,
        proof_job_options: TritonVmProofJobOptions,
    ) -> anyhow::Result<Block> {
        let tx_claim = SingleProof::claim(transaction.kernel.mast_hash());
        assert!(
            verify(
                tx_claim.clone(),
                transaction.proof.clone().into_single_proof().clone()
            )
            .await,
            "Transaction proof must be valid to generate a block"
        );
        assert!(
            transaction.kernel.merge_bit,
            "Merge-bit must be set in transactions before they can be included in blocks."
        );
        let primitive_witness = BlockPrimitiveWitness::new(predecessor.to_owned(), transaction);
        Self::block_template_from_block_primitive_witness(
            primitive_witness,
            block_timestamp,
            target_block_interval,
            triton_vm_job_queue,
            proof_job_options,
        )
        .await
    }

    /// Compose a block.
    ///
    /// Create a block with valid block proof, but without proof-of-work.
    pub(crate) async fn compose(
        predecessor: &Block,
        transaction: Transaction,
        block_timestamp: Timestamp,
        target_block_interval: Option<Timestamp>,
        triton_vm_job_queue: &TritonVmJobQueue,
        proof_job_options: TritonVmProofJobOptions,
    ) -> anyhow::Result<Block> {
        Self::make_block_template_with_valid_proof(
            predecessor,
            transaction,
            block_timestamp,
            target_block_interval,
            triton_vm_job_queue,
            proof_job_options,
        )
        .await
    }

    /// Returns the block Digest
    ///
    /// performance note:
    ///
    /// The digest is never computed until hash() is called.  Subsequent calls
    /// will not recompute it unless the Block was modified since the last call.
    #[inline]
    pub fn hash(&self) -> Digest {
        *self.digest.get_or_init(|| self.kernel.mast_hash())
    }

    #[inline]
    fn unset_digest(&mut self) {
        // note: this replaces the OnceLock so the digest will be calc'd in hash()
        self.digest = Default::default();
    }

    /// sets header header nonce.
    ///
    /// note: this causes block digest to change.
    #[inline]
    pub fn set_header_nonce(&mut self, nonce: Digest) {
        self.kernel.header.nonce = nonce;
        self.unset_digest();
    }

    /// Set the guesser digest in the block's header.
    ///
    /// Note: this causes the block digest to change.
    #[inline]
    pub(crate) fn set_header_guesser_digest(&mut self, guesser_after_image: Digest) {
        self.kernel.header.guesser_digest = guesser_after_image;
        self.unset_digest();
    }

    /// sets header timestamp and difficulty.
    ///
    /// These must be set as a pair because the difficulty depends
    /// on the timestamp, and may change with it.
    ///
    /// note: this causes block digest to change.
    #[inline]
    pub(crate) fn set_header_timestamp_and_difficulty(
        &mut self,
        timestamp: Timestamp,
        difficulty: Difficulty,
    ) {
        self.kernel.header.timestamp = timestamp;
        self.kernel.header.difficulty = difficulty;

        self.unset_digest();
    }

    #[inline]
    pub fn header(&self) -> &BlockHeader {
        &self.kernel.header
    }

    #[inline]
    pub fn body(&self) -> &BlockBody {
        &self.kernel.body
    }

    /// Return the mutator set as it looks after the application of this block.
    ///
    /// Includes the guesser-fee UTXOs which are not included by the
    /// `mutator_set_accumulator` field on the block body.
    pub(crate) fn mutator_set_accumulator_after(&self) -> MutatorSetAccumulator {
        let mut msa = self.kernel.body.mutator_set_accumulator.clone();
        let mutator_set_update = MutatorSetUpdate::new(vec![], self.guesser_fee_addition_records());
        mutator_set_update.apply_to_accumulator(&mut msa)
            .expect("mutator set update derived from guesser fees should be applicable to mutator set accumulator contained in body");
        msa
    }

    #[inline]
    pub(crate) fn appendix(&self) -> &BlockAppendix {
        &self.kernel.appendix
    }

    /// note: this causes block digest to change to that of the new block.
    #[inline]
    pub fn set_block(&mut self, block: Block) {
        *self = block;
    }

    /// The number of coins that can be printed into existence with the mining
    /// a block with this height.
    pub fn block_subsidy(block_height: BlockHeight) -> NativeCurrencyAmount {
        let mut reward: NativeCurrencyAmount = INITIAL_BLOCK_SUBSIDY;
        let generation = block_height.get_generation();

        for _ in 0..generation {
            reward.div_two();

            // Early return here is important bc of test-case generators with
            // arbitrary block heights.
            if reward.is_zero() {
                return NativeCurrencyAmount::zero();
            }
        }

        reward
    }

    /// returns coinbase reward amount for this block.
    ///
    /// note that this amount may differ from self::block_subsidy(self.height)
    /// because a miner can choose to accept less than the calculated reward amount.
    pub fn coinbase_amount(&self) -> NativeCurrencyAmount {
        // A block must always have a Coinbase.
        // we impl this method in part to cement that guarantee.
        self.body()
            .transaction_kernel
            .coinbase
            .unwrap_or_else(NativeCurrencyAmount::zero)
    }

    pub fn genesis(network: Network) -> Self {
        let premine_distribution = Self::premine_distribution();
        let total_premine_amount = premine_distribution
            .iter()
            .map(|(_receiving_address, amount)| *amount)
            .sum();

        let mut ms_update = MutatorSetUpdate::default();
        let mut genesis_mutator_set = MutatorSetAccumulator::default();
        let mut genesis_tx_outputs = vec![];
        for ((receiving_address, _amount), utxo) in premine_distribution
            .iter()
            .zip(Self::premine_utxos(network))
        {
            let utxo_digest = Hash::hash(&utxo);
            // generate randomness for mutator set commitment
            // Sender randomness cannot be random because there is no sender.
            let bad_randomness = Self::premine_sender_randomness(network);

            let receiver_digest = receiving_address.privacy_digest();

            // Add pre-mine UTXO to MutatorSet
            let addition_record = commit(utxo_digest, bad_randomness, receiver_digest);
            ms_update.additions.push(addition_record);
            genesis_mutator_set.add(&addition_record);

            // Add pre-mine UTXO + commitment to coinbase transaction
            genesis_tx_outputs.push(addition_record)
        }

        let genesis_txk = TransactionKernelProxy {
            inputs: vec![],
            outputs: genesis_tx_outputs,
            fee: NativeCurrencyAmount::coins(0),
            timestamp: network.launch_date(),
            public_announcements: vec![],
            coinbase: Some(total_premine_amount),
            mutator_set_hash: MutatorSetAccumulator::default().hash(),
            merge_bit: false,
        }
        .into_kernel();

        let body: BlockBody = BlockBody::new(
            genesis_txk,
            genesis_mutator_set.clone(),
            MmrAccumulator::new_from_leafs(vec![]),
            MmrAccumulator::new_from_leafs(vec![]),
        );

        let header = BlockHeader::genesis(network);

        let appendix = BlockAppendix::default();

        Self::new(header, body, appendix, BlockProof::Genesis)
    }

    /// sender randomness is tailored to the network. This change
    /// percolates into the mutator set hash and eventually into all transaction
    /// kernels. The net result is that broadcasting transaction on other
    /// networks invalidates the lock script proofs.
    pub(crate) fn premine_sender_randomness(network: Network) -> Digest {
        Digest::new(bfe_array![network as u64, 0, 0, 0, 0])
    }

    fn premine_distribution() -> Vec<(ReceivingAddress, NativeCurrencyAmount)> {
        // The premine UTXOs can be hardcoded here.
        let authority_wallet = WalletSecret::devnet_wallet();
        let authority_receiving_address = authority_wallet
            .nth_generation_spending_key(0)
            .to_address()
            .into();
        vec![
            // chiefly for testing; anyone can access these coins by generating
            // the devnet wallet as above
            (authority_receiving_address, NativeCurrencyAmount::coins(20)),

            // Legacy address (for testing), generated on alphanet v0.5.0
            (ReceivingAddress::from_bech32m("nolgam1lf8vc5xpa4jf9vjakts632fct5q80d4m6tax39nrl8c55dta2h7n7lnkh9pmwckl0ndwc7897xwfgx5vv02xdt3099z62222wazz7tjl6umzewla9xzxyqefh2w47v4eh0xzvfsxjk6kq5u84rwwlflq7cs726ljttl6ls860te04cwpy5kk8n40qqjnps0gdp46namhsa3cqt0uc0s5e34h6s5rw2kl77uvvs4rlnn5t8wtuefsduuccwsxmk27r8d48g49swgafhj6wmvu5cx3lweqhnxgdgm7mmdq7ck6wkurw2jzl64k9u34kzgu9stgd47ljzte0hz0n2lcng83vtpf0u9f4hggw4llqsz2fqpe4096d9v5fzg7xvxg6zvr7gksq4yqgn8shepg5xsczmzz256m9c6r8zqdkzy4tk9he59ndtdkrrr8u5v6ztnvkvmy4sed7p7plm2y09sgksw6zcjayls4wl9fnqu97kyx9cdknksar7h8jetygur979rt5arcwmvp2dy3ynt6arna2yjpevt9209v9g2p5cvp6gjp9850w3w6afeg8yuhp6u447hrudcssyjauqa2p7jk4tz37wg70yrdhsgn35sc0hdkclvpapu75dgtmswk0vtgadx44mqdps6ry6005xqups9dpc93u66qj9j7lfaqgdqrrfg9pkxhjl99ge387rh257x2phfvjvc8y66p22wax8myyhm7mgmlxu9gug0km3lmn4lzcyj32mduy6msy4kfn5z2tr67zfxadnj6wc0av27mk0j90pf67uzp9ps8aekr24kpv5n3qeczfznen9vj67ft95s93t26l8uh87qr6kp8lsyuzm4h36de830h6rr3lhg5ac995nrsu6h0p56t5tnglvx0s02mr0ts95fgcevveky5kkw6zgj6jd5m3n5ljhw862km8sedr30xvg8t9vh409ufuxdnfuypvqdq49z6mp46p936pjzwwqjda6yy5wuxx9lffrxwcmfqzch6nz2l4mwd2vlsdr58vhygppy6nm6tduyemw4clwj9uac4v990xt6jt7e2al7m6sjlq4qgxfjf4ytx8f5j460vvr7yac9hsvlsat2vh5gl55mt4wr7v5p3m6k5ya5442xdarastxlmpf2vqz5lusp8tlglxkj0jksgwqgtj6j0kxwmw40egpzs5rr996xpv8wwqyja4tmw599n9fh77f5ruxk69vtpwl9z5ezmdn92cpyyhwff59ypp0z5rv98vdvm67umqzt0ljjan30u3a8nga35fdy450ht9gef24mveucxqwv5aflge5r3amxsvd7l30j9kcqm7alq0ks2wqpde7pdct2gmvafxvjg3ad0a3h58assjaszvmykl3k5tn238gstm2shlvad4a53mm5ztvp5q2zt4pdzj0ssevlkumwhc0g5cxnxc9u7rh9gffkq7h9ufcxkgtghe32sv3vwzkessr52mcmajt83lvz45wqru9hht8cytfedtjlv7z7en6pp0guja85ft3rv6hzf2e02e7wfu38s0nyfzkc2qy2k298qtmxgrpduntejtvenr80csnckajnhu44399tkm0a7wdldalf678n9prd54twwlw24xhppxqlquatfztllkeejlkfxuayddwagh6uzx040tqlcs7hcflnu0ywynmz0chz48qcx7dsc4gpseu0dqvmmezpuv0tawm78nleju2vp4lkehua56hrnuj2wuc5lqvxlnskvp53vu7e2399pgp7xcwe3ww23qcd9pywladq34nk6cwcvtj3vdfgwf6r7s6vq46y2x05e043nj6tu8am2und8z3ftf3he5ccjxamtnmxfd79m04ph36kzx6e789dhqrwmwcfrn9ulsedeplk3dvrmad6f20y9qfl6n6kzaxkmmmaq4d6s5rl4kmhc7fcdkrkandw2jxdjckuscu56syly8rtjatj4j2ug23cwvep3dgcdvmtr32296nf9vdl3rcu0r7hge23ydt83k5nhtnexuqrnamveacz6c43eay9nz4pjjwjatkgp80lg9tnf5kdr2eel8s2fk6v338x4hu00htemm5pq6qlucqqq5tchhtekjzdu50erqd2fkdu9th3wl0mqxz5u7wnpgwgpammv2yqpa5znljegyhke0dz9vg27uh5t5x6qdgf7vu54lqssejekwzfxchjyq2s8frm9fmt688w76aug56v6n3w5xdre78xplfsdw3e4j6dc5w7tf83r25re0duq6h8z54wnkqr9yh2k0skjqea4elgcr4aw7hks9m8w3tx8w9xlxpqqll2zeql55ew7e90dyuynkqxfuqzv45t22ljamdll3udvqrllprdltthzm866jdaxkkrnryj4cmc2m7sk99clgql3ynrhe9kynqn4mh3tepk8dtq7cndtc2hma29s4cuylsvg04s70uyr53w5656su5rjem5egss08zrfaef0mww6t8pr26uph2n8a2cs55ydx4xhasjqk7xs0akh6f26j2ec4d8pd0kdf4jya6p9jl48wmy5autdpw2q8mehrq6kypt573genj66l5zkq6xvrdqugmfczxa2gj9ylx3pgpjqnhuem9udfkj9qr2y8lh728sr7uaedu5wwmfa72ykh395jqh7f7f9p2gskn6u7k844kpnwe3eqv84pl53r6x9af88a8ey7298njdg03h8mxqz2x6z8ys3qpuxq768tjq0zhrnjgns8d78euzwsvx6vn4f9tftrp68zcch3h75mc9drpt7tpvnyyqfjuqclxhdwhdwtsakecv04p9r3jx90htql9a3ht5mxrj4ercv4cd52wk4qhu7dn4tqe7yclqx2l36gcsrzmdlv440qls7qjpq6k95mst485vpennnur8h62a7d7syvyer89qtyfzlfhz8a5a0x5tuwhc9mah0e944xzhsc6uvpv8vat44w7r3xyw8q85y77jux8zhndrhdn36swryffqmpkxgcw4g29q40sul4fl5vrfru08a5j3rd3jl8799srpf2xqpxq38wwvhr4mxqf5wwdqfqq7harshggvufzlgn0l9fq0j76dyuge75jmzy8celvw6wesfs82n4jw2k8jnus2zds5a67my339uuzka4w72tau6j7wyu0lla0mcjpaflphsuy7f2phev6tr8vc9nj2mczkeg4vy3n5jkgecwgrvwu3vw9x5knpkxzv8kw3dpzzxy3rvrs56vxw8ugmyz2vdj6dakjyq3feym4290l7hgdt0ac5u49sekezzf0ghwmlek4h75fkzpvuly9zupw32dd3l9my282nekgk78fe6ayjyhczetxf8r82yd2askl52kmupr9xaxw0jd08dsd3523ea6ge48384rlmt4mu4w4x0q9s", Network::Main).unwrap(), NativeCurrencyAmount::coins(1)),

            // Legacy address (for testing), generated on betanet v0.10.0
            (ReceivingAddress::from_bech32m("nolgam19ch0269tvlvvamk7em5mhtpja3pe8tm58dmzegy8psnkq8ezqtltw7ykxlcjh5fgjgrgcwcnshpy6ulcyjdg24ncfu7q956cc0knrhgju3spvemslp5d7tncd9n5mxfq2yrhzjlpnrrr65qd4a3kyj9f52gs6m4f7am0at96rx5uez9unm4d2a4chvtpp0wa5ewjxrs2stwv79vfqaes6qep2vcvg4hfcv937hj0cs7eng9f396z57mtxfscmkjvh675zy0pdx577taj7en80x47heufykth59waue2rshqu3r7hfna67uk224exep60smfr8xch0f20ay7gw7r0nyx79ndzge8r893xsk3ksqravln2j74jrxadkl0tkljc3z0ynwzae7f8drmfmp2gtja94hx764hsf9tfsakj4av67hw6ey7u48wsqkmnvflznuvkn8f3xxl9w3dk4fvv2wqx5h7ystz5p9j0l8q0r3tzp42ehvfwaxl5vlwwvv5l9yzwjj2wlmttteghqn5563j4u2dqmr5p0tskg083ecv4p9w7l2vgl63m95q29uhjlmu2ktq7fdj9pmw2svtwwhekhz9ljxsk0mdajyhy0a4znz9sswe86ncx82g5pa69vy0p5elqu8rljeh0y7hm73et6pzrfwkuywet5pmf03qsyma3s3kw07zhmxrajxl92chfyxm6jttqpcm7zh3djmdxkpj9y3eecha3jvu58h88qnym6475v3q466yhtsnxglznupu9jmp0cd3zs0nt4s77jsdq4s5gmepx6yt76n5kt2j666tql4u9cz8s5ua6qu4e2qcdk4jxep94u680434yvr4jklqnxveu9ywq7a8lhk4rk6hdhhmr3me8ajcqtweumdjtst7a6l7sprvly6m7rm9u4n69un8slyjk2ljphu4t2ay34zg0n5e6p0hnwqdcxm8yxcruc5cfcl7cf04smzq6tu26ael5mwz0857v7scy2vf6v4aj6akdx2q0d87uf7q9yrylqkmay4cw6upnncyy3rhxve4qzt86gc5qx6jhw79lstv0wthh6q3pfs5hqvafq6pgfewp90wmq4npvml2vgeukklymlth4zc3et4cktnzdetyzatwa5r3p9rj2edtstd7c648pja9z5dgp3g7ehfwxeal87kfr8ndyqmr0ta2rmsmzfp7n8r0llsd5jgnk7ngvh5vr5kq26nw2dp8r37l7nuc98v2llgz8eshzalndkjuzxuh32tx4w2pn2vg5xydurh8d87ud9zryfd50jqywvff7pmt7p63d3qtyx9j9zz573sttkyh6p5v7lypf4lvxmpuf55syhn6l669qdwszkll9h3hj58dka4v378hahqxrg7gdpzrnm8gy4wav5gmvx83k8wvnvkhr7h70y79j0h46xxunxfqumkfeylhretm4t5pzxnp205mr2r3ltvplqvnpgmljfnnetfkwphj4g2t4hk6z9lcclf48cy7xa58hk24z2t3f7l5ll4m6yhrnsklqm4h0l4vu5qe0hzpte3nvv2rm9g8t34y7k9qdmgjsczu745ez6e2e8zwzjdvdtr652a6cq3q2qy267vf6hedsmuntf036qg0mcmnus4zgwv0r6gy4n7f7f9dnmjmcwe6s8yha2y4cnfp4t7g3dp3fta5x0ynluu26p7kcf985udmunpwysnp40slnp955z2anqlejmt0l5y4a4u5ueyduz47ar9dvta8nvw8g8tn0ngeurcu522deawk97c4w84h0hm6yr2gc69cp0pcsur9xhekcphw35xe2e9knqgz2m0dvvq3q5pztc7dufkxn2ej56awzz408m6frhfpx8vwwz9xy57lltsnz0tyc0dtney8y7td0hyjpjnvd4j6thcnalmk3ml0pdh2fjqrlmjyt0tx6udqpjxug92jee7wc8nw55m8wjcjgu5dsejhh9rz6utxremem97xklqnsg5rz7phyfzxeguax04e0mc7kf0eys326upy3mx694nqzt9hdmftrht3meh2td9qjrp85ersm3e34ccgugtflep0jpl4ctxv5q27ev778uydxuvjd7cxl9yxvu84gsrz8xz9qatj4steqzse2np7s6qprr379vvgxrppy9lhz9pfnkvur5y6lx4d2p0e02zu2uak0eklcsv69jcmp2tfkqwdp9wwl9zsduhsanwa20g092g9cay4jrz0ul40lcygtlquw7lmhqc3qawdyyrgs9zzc8wl59tx549wnlusfc46avmsw743s4vqckr8jx7h3algpjl69lkmv5udmpqnaxjxhf8sltxjfzt8w2763dratpz7w0vgcye0mtyv052s5k8829q3nzsxd9hly7xtr5evrgp9njgatjkkn96ehsq798u9fdg59vfzxt4yjyyveetq26zac52dt4962yqraqd8njgecyq2as7p3j567dmxf7dxh6lywyzjszawwxdjuhlqj59667tptwhnumy2nsn0vchsf9th8vap4nl6gy60lu2qmrtwgur307rce8wsqm442ahg95sh3n92jj7tcjhqyjn0j327rvjad0wsxlujvga9p8xaupdu3ml9k6gmj063cxx9vk55w68a0ucjxmre0qc8hlnun7gvmssrx6j4sz2uvuqs993ay6vqqzdcqyvzfmye4af7nrw975vez4pjphm948deqkde7dzfuhvqjexy8n9d5xy58ppks5eu5e6xgnt0gwmeq7fvm8vpk3cl8jawvmguxkkry5wt6ed6wgs2rg4wwcjeadh3wawxy7vmsh6cytv683hckpux903frf37gfumevt797eum6kdk8gznxeajgrj0ge6kqntglhtftems3utfy0csqzvmat37zkp0j7qexn5md724c35axq4j4kaulyuamzzr4rdmsedha49z6w82h9fnn7mx9ascjn4lc32pcsgxwajh5lyllfkj4j5ee3n6vlvdufrtzmgjp4xh7cngr9wtesucv9ze5375gqc6v0yx3k9fsls9h33qlflf8tjsspppcglt7m546vd933zrql0mg358nv0q43r8w02de9xd3jkejm0tgeyghcgcumsfhjew7nhwsy5yk38wxfdernaep2drz0c8xj4d4xxgryxgp5pvdpg8wk3ncj5yczlz5tqf3sg2xe8v9njzdheamzmxsl3mq90g4uv93mrw047lycepc0smxxjx7gkqy39vpmy4lkqh534hnwh7jmp0ar9h0w5z3vs6jteztweftr473h5prurtfh64lr0q3xycjzy9kg8wmhq956xurdkswr9n05ne8z800jkmwfvkxd9tk2kp7vljqfxfws7dj3kl7wpgqfptg4zha4fhn4ll5vklug7cs5gcmgtu4vvd3dhd8vpst8xjnf8nuu", Network::Main).unwrap(), NativeCurrencyAmount::coins(1)),

            // Generation address (for testing), generated on 9c1c4438 using `neptune-cli next-receiving-address` (third invocation)
            (ReceivingAddress::from_bech32m("nolgam1dx64scz84qrkqtwclxrvmucuv72d2zzn6hq7hgcpxjll0dcdznepky7w7vureuakdpm0gmpukl4zu902cyj640r7pcg9346269f4953l8g83vdxl964ca9vl4kjnrhzx63v9m6hgkj4nd9rgdkldlfma9pljndd38sdfeehd39fr49w8pa87y0jsp7udwlden9rsl08hw2p0qztcr54tu0m3cu7la48jeskt5fnjelphr5pz65c5rpum707jxqcglpzsj4lqwlwntqc587mkfc82f56vmh3p68yje7uwclkmmyr5cx4tg0dl9fp7naamkruxn0vfyh200gxpfgsszxsn27l7dt5ddnmh0pgz8rw7fl6zv72y48vtpyx0fezpms5w782gnl8te0nexvvdc08ttch2nf9swj2ln884ugncaj8x02plfvzwt5czntgcxu045xzzrph3tzt6aypz83e0mfdqknf2p44m8nvk3dkv0nm7upvk5m95jxj7nlr046ttvpp489wnqz0sspu863x2juu3dnt24jg86h2y6z63p5qme8fk235trhyvu2sg7rjx0x8732mp29ky3tm54l5ug3lnawrs3pj4hf0p82hk7yljq46mz4v9z67nzzymz4qxn67tpclg60y8a7ln38jlayckk924mpfemrqfderyn8pgduc8a0sy4z3c6yumry0x62jz3t6zh8euvwwpu92jg0w6jful7ydruz0hg5l46mz56524zh4q3xge74scpmd5ga08upyntv0ekftg2s3pgp35c4dke5rcyk259m82j6n9z3l35etwly2xlxjfkzglcy93xsdw5hqn4ajynpvuafute0s8es836ja6ldnwsc2a7u333nd2907wulg35j0d02u5a0cv2cffdsyjxvykps3lep3xsn7r8h9hcm0g9t4tqd9vavktw3ksq55eq9fu2alfdlh3udsqtdt0ex2kvqq0t2zwqwhmmxp78s7utl683vkffxalyngd7va85hsquqrdemwz29y3z2yua54p0djqqu8kwx3j5et4dpx7xq5qt4chrjqaknlfy4fccjc8c37eljchz5qng8lfz3gl8em44p2mzyvwh46ymmmy4753sqqnfht3l05kqh0vctp0lc2x4zus75rpy6t6c7gxddtzjx0xc6xhe0qvess3cjhmaaprkmk9nctk4za02mfg35ez7qu4ldl36xl77fwhdyyfe2snzgw049zc6j7m4xpldmn8ytkx80y6w0chg3p2477eyuatv0r6d5euf86hqmrx7acszl4s3xl696s707upm88s2nnp4tehxuenukt4lrktgyu5fhtzts7ygauwzwz0fz8tnah7vfymgzxf5lp9zynm04g53kmwjpvhu0nv79l30x6yn7xx98r6vgzchgff2gcw9gpgkfxgjz98xjy7samt43l05kn3hwzredm26wmgcp4ct3s363e3cvhma9zhjfwr4mr5sdvws0243teu70fuhpqp4w9snkvz2qenfswx2e2yammmdpw9jgdjkvs6lpxh6uhymjajsvhh7g2c7zk5rhxsccv9guppqd03tu0xa2u60s4zknumg44cxspqvm34gzzltm4ljcymyj98ewlf6a7g5s7hj8l46x640ng9q0cs4rv3vu5l7k5xcz5zyp679eqfsphzg86zpn55jzq2xw367yyuu4vecczhpd8qvmkgc2ygceydlrhq9rreup443qc4r0m5ejmu70jm78t5j4ncgw7sj8nz9pxyv27rjpdtpmqf8q72s6fmn4k9a38scgmz6ugskpeac7fnxxkcq0v5yqjsc9npe3c3n2nrxzvvlu6l9y4m65jueunuh5xvunp5vhc0lmzml5z3nr3ff57nyt6cn5ltzga66q4yt8nzvy9fu54rqajq82wcpulnmq666d7qaf8ceql65umz60838ezvczwcsw2qjtct3qtvkpvzukeflrtj820w48jvzvd9qu30tp3auwv3dt0xuw3we0vy39jc2aqanu5f6v3p4fz2c8clldgz6mrxktwrlu70gwk2h4pmevurr7gnj3a9avn9zf0mqgf3xjjk7vmmrkn9yck8wem88fffcjgqwh3pprwqg5q9j79ryj3dl6d56dundgu3vv7qqnysxdxlwu2fxnhz78w0g4knmxcpe4p97dxf4ye3kly6rw5lr49qgwkxy2qlyvrlzy080ekuqj3cmtmde4ft68k6j285wwmcrvt3xhlqkg2fndcqj7mr2ezae9vs8wp9attqmv2vq9xeyk6q2pfkq7s0hcat32tlru3g5jja5ntkwsspcejvzv6dpuup9atezshyxk7gsmex3rm4l3ycx02ytd3nmhrutpphgpjqvtnurgswxaqynrsgv6g9r0dslls7k9shlh0tfv5rzpy7j6mc3cxfl9w7sxlcegf7atcl4gezvqm9ddxxlzufe3rjxhme24vl4n2c9mr9t6s67m5vpvuhvtxfeq98wa58qku4vs7zfh8n09t2a5dygyrr0qfcyhejqnajt7d75dlnr25tav6hslx6wh8ylzyng7y50hyut4gf382jgk3xyly9w7rzs44q903dr7ux0cmqcy7hqm06cj07zuq20vnjrvkxcj40xzlr4y3vzp5kmvqhm0s5zsz9skpyyj0lkf06zfxr50z9me30j4w70vhurtjkgqcdkh6f0wlmsp238988mkkknuhg3xk5fs6pmxcdyh6lkjp62dtqcmxe2g3tcceqxaaprd2tfdycqnknavrlsxsmplp7g0nwkpp9j3vztzd0yx6jlegwuswrrdjz86879ykz8k2g3yl6790h0ccfpecef229yx8srn0aq65lqn5vyl35g73t5vq6242gscasrv2avz8kj9sklgd26s7emtacnlwkedy33n666dzyfh9xu6qjm3w93clmam4f9avqmtq9f3qzptq4gr5wcdec6222hvzxr4wp0ta9kucxnxwefet6rskzep2sfrwwg3zgwz9cx3d3rxpa3hs7pwfvjj2w5kj4tfhpunfpc4cvyzr964p8klwtkxc32mamrwa78u844js89v6666udf87vz2ql5300q4avkpqmx5v3rxd8fuk752gvs5gmh4s0p5mjpzu6wdjx299sydxwcdx4amzfnkjfaz22x8k25qu894r3zl2gk5d4futyv0zakd73vhedl4t3d92k24nuh3gu8jcvykux0nsuupd89pdd07sjk7xjyy825jh00xvntct9mxj3q7rhfagewl36havdk03lkzjq8v976as2tmh54va38g8e9mxvesdwduwya4nqa6ghx42x6nmq72mnnqjrs40yasydt8l682e4j4hyuwcfgyaxt7qvfsk7pp25rm8ydzyd60a2q9mw0hr02hq0g5tr08mkcfksk5k", Network::Main).unwrap(), NativeCurrencyAmount::coins(1)),

            // Actual premine recipients, added 2024-11-18, in 1981345bd86fcb8d14966ff4c546b117cf314a07
            (ReceivingAddress::from_bech32m("nolgam1v0j838fvl7ud8q964x7urcyetufmy9nfllmy0xej9837lanjl2vfmsar7w2ncraxhgpxg4d4pntd6kmjxhgvhjcdelr75zj4fqvws88dfunsn6fj0fnkxlch3rqcdstmpv28v732tvcvvctcjxw3drn5gpygmflhasj5zu043vzr6hmjpt4tedn94p4mzerp69xp9d8cx9u697f8ds4vrw7rmpk74lk06pt4q0lx4d5e7el5r0fywqxk3s8dvgxtehlvpde9kkt7y654ddpusmn0yhr4whgvh4nvffp2eahnvmslhruwymzpqdf5c99l9redvtuk9kg32zfenwjqkere2xltvfhqfpm54cxltcj8lfr5ttcakytztwcr457jyx6yuam6dma7khjkspx0nu0m5kut2neja956hkj3p3ej8hutavv2zkmygff4gca55hd6apyhhslsyfs24s60ldzktd7hj7gkdtgfm2l8vdd8pkuh02q0k3ce6utpltzpw6anx8zk8jn3f8kuansk3fs98zlxxpvqrl9w2ayq9axuc64lfvp9teluwhvwc7w2veujpqk3jxdag4d9uav7tt9lc02pnejw8v2fvl03a50jra8mf82j879z3wklw8n357fmtaaf48e8xaak7jfz6a6lmele0h8yhv6f9kf79ashn3sggh35kfqpx8wevnku7kz2kdrj4x5m3y4wze47g3rp3xvjpmlqx6yl7plxg8a33ljm0c09p2v5t36j2ym7t5u2fpcjvvy92vj3dnew8729u9lslrzuxa5yrmf3qntdegeq3hygru2uee5xya3mam2aejf285eh843vxkdvg8xeqg9lfyjkdgamchweg40srfju6aef0v3ads4wswyw6fyrnz8ltdhnd7cn0t7ucpwtdhfy8jcw94fygks8pxcuuerk0smkwrr6wvqegtdprtfzpya8c8gx9n8weaxjtfag7h7vqw957ncwkmfj27j7jvjewcapfef43ujgu4clyj8jhzkuyrlvgxz3vf2wdx4atl7l89q9qhwvtltqne4a0t64zwpx87aqkcvjysnuf6ct9h5uxyp3768fglzc6arvs00f3lznppgnuakzy0k7aw5620eddfu7eq0gusc7c348ng3yl85hm42y54leyshyfh4lhadzj927wl3sw4l5k00l4cwamfjxmaklp4e7qny3jvjvzkzs33c346prn4reljyn2rjpurms9ha2jcj55dfpwa33cj73nananj5mvy6s2w8ec0sftwzu2w0w3smjv3mvvf3glclwswvzrghy6jd7a2vtdr4dtrrw2tdfssvpa6qc2955f27rgrqt2yg2h3xs5qy94xtsz6ufjqtafl7cffhja6e0wznf8qnt9wd6ng062x9pgztrh5pvhqjcud9nqdsmydumz9h6lzneawln3ds4y8zfvjcnq4h654ypnts7wfwty9tr65nnmjvprqqrss9js325p94kh5yctshlkhuqt4705r5etgzavazw0w6l9yra56z9kxzwjxfcar407tfaw4l0elk3ddr54c4e8uqnnlg8gwuzsd84dmefvk958hmzdxvg2x5r995ez6y4wkqn08gyrwejf9z3unjtx097zehntjlklsfmfk2gw4v0eh9jd6jr0ztz8m22t7ajse3w8yyl6ht34hp8pdzr0qa0vvqyx4ulft6enutr3axjh9kdrcjzh28ky00vxkln7nmqp8xe9hvyqt2s2qgp8g5lu6tkmzav9vy7nq0ww5vp2x56gf6y9he6nm7f4xzqarwy52nan8m479h6drvmdnaxw5scddgwv669gpjwg7zd352tagdgwxz5gl9pvdcztzjur64jkg0hed60vws3al2dt3az4gfn00txe4c4s8djvzmml06degdccsuxnmxh3vrphjqeekqrgszu8w9jwksfrayeyhhlzxtzejgxy4c2apv4rknp0dq7rf6us2ns6zlkwpmul70fj3xv30uv9edcn87ggy55trph5plhzvf0vp0pz5yvq8p9hgrq3pl75wnvv074v9uldnn5tej0aewedvulv499mamxu88g3z4spactyzhl8jtgrypquasfvv2ucucg90lslzvsnxg5q2wgwc9c30ru6jf5ktmjfa3jm4whead4ln0l49y6z9l3p0eu4ax4qpns3kfuc5a6er5lltf65pxe46yaxcwf893wdqtaj8uz67t50nkwztwmp427auy65ck7506qf9ullc23vqy74sj2lnpgq84vtfyz74ywxza5kxzs4a3xtkvgg7a07u08dnlwqkkhkx6jj2srvsxk49nkutd3cd526n62fe6a9acmpah4l3uapzaja2y9cx3ncdmkpry7e869svyz7m0scm6vsyj9amxpctswkdft0tqp68fgyheluuy95x07m64pe45avnjcchtgulef7yrjqzmauhpx2j8xe9d529kx5j8wnpsnwyycduz59588hn75zzg09skrpjhe8mxj3ljds6k3p563n2n2v7w3d86amphe2fvu0ay25qcfqq39znjk34l85pxnv3q7ftl4x2cmkkr7gr3tz3jn72jkcj4xa92lzu0pp58mrp06gr8dual30y0r9pn5aeasggymtmswgpeyxqur8yqck75pfykz8lzzavwgv0fg43uly70tt4hs5e64hvn0t88w3j0wq3p34scwc5kdl79yj0xyz8zlelhr0yzn4fnwgs6c0te55v22eef7kzc32m8edu8rs5wymk6r9whnwkhy9lh0r5z8xssw7tel9nvsf7fjs8f9pjuxwe8s5nw7xhgh5s4rpfy3jg0kg6asjxrjcjts30436eud4ctrenesptz2x7ngv52h74dy7gaymvujxnxz7xmsl69v24lwj5580ndtrl5uqavt4v6nr85gh7ectvq0mpsyrcy3qaq6pwgkjy62uypwshegzrllcsre9wkau4v4ttv385qzgxt773pqxefs2nyd0wnpd5fk35uewa7gzghn5vwey07rlea2v5amd90njt95zm7umrdsp7l5q92gywjfuzyhmzup75pjxm067eym43vkxp03dcsv0tjsr253yz9kfpe3uw9j9v8tnlhhnrjgywzd88sqagsrdasm6prxzwf4qt4vp7r5f2vzswzdk94gk0mu5gzhnr4se47wykyyvs6ugvc8gg6n3sv5f4vvht0m2r9av296cmf2jdfs52jw8r05k3wqmvy7xn8frz0x2vc6wa66cmll68k9kxh9hj8dv59x96d020fgt004wwxpgquwl8mgsxm9tpcdqr55mce3ep3ckhmvjqzyzplm69xza2nrfjjcc82gp6y72s6e0cmwvw2x4qhjfp32l8jnr7njckl2yacscqffkmmtud7e2ttqrppte6v79rm0chzqpyv", Network::Main).unwrap(), NativeCurrencyAmount::coins(2000)),
            (ReceivingAddress::from_bech32m("nolgam1u9r0el5lvaz4883zzf588t0rgcm87anaxvgqq5e3ptzzzxh6da546lf2vhtwkfm29thvz6m94u6twxvzvve9m2ucda53fd8z80xt29wplnuq40u5r4pzw9k7eyexps2q3hsdqu5hhzpnpq2wmpq4lcfj4deqh09tdgmkuvw5y7ay2xqaaj0xc0aclnwd7qs7asclsvgr9r225alnfyf9x09xutyp629s2mfts2un2cmq9s07xwllw8cvsufulxmacruzfyxx9w0jkksys39w47vvgehlv6ncuzhl7tzrvj79xla9rfy20f2da5nptw9h5h6ua8dsn8q0qz0d7y5ndlcqz3whr7h40mjxgg3ueycs7zz9r0rc3znu8vph74nw22y38h89zy20lv82mekq3xu9cumytxqlsnugjs5tp78mgm3prpcmtzezgwzl8vntm00n3x99hhdvsp8lkjuvnjndxyczmgl554xl96x55djrjnv4mxvqlswzvxnw8lkw87f959v2pktmeg3yx86ku23fsfp0x8jh2te94vuk9ahwp7zkaw4njjsjp6a79qvxfcujwr89xhwgzzfjffnj5vusye7907s6vzgfms6xfzu07ugwr3dskakjazre2mn4xvxpzznjaatnztfla69c43x7un4er2c8x06ucwe72gzt9xvh487q6l8dq2ejwamfpllw5mrarrrvf9wu36r8pvwa45ck8005060lk67y74f09dz2h780ddruq79a5racn05gepc2qr0s85n8550ulvcmqzv8nmwxetaj7hl78mg8nx9ftju3ak2uf5ur45s26yle02s5netsdaukx7thfkalnr83f8kp7grajgx4glcknxzkc7326rttl34up9h7c7f7k76n43zgwjg8mwx22cyf0mc0g67kcf3637urst5fl2ez9ja2at7nhr00hug999e7g7e02nu7jxesq07zqdmpwta64zzxfvpwqy4lfd35qmyvm4ftjfdnw8mvglfmsflan5vz466svsq298pm748kc22cvyn35xfy6rzzq73dl8cytj7kchcx6mjj58ll2xdhk2kf0a25ea5quktkep8t9awrww6x6ynnepc8chgnvvtg90ueu7tgr0t25pnurcn6csukvpyvn988ynpmry2lrd8e6q6ur4k9nd3rd4xsrge6nlu5hcjrv2xhv5vmcavts8rapxrr4773u0dthe08pd3yu2vnetkk28k08ae6t3dchr2hlfq6tlmnq20taj6xz7uq7wccx30ntrf9h7r2r5tgmpd6c7m3vgq69qtft3xlw8qs8tc00j4vslhudmv2cgd0mgncgvzrmvetrnt0zmwft9c6xkeyt609cmxc405jzwt3ysj249vmhh7heq2j7524qthgsu3d0ns9rc9amslk2anscy67rrn456pe5kjcrr9ft9javak5gl49qtyegnyuh6r7jgsfv3w6v8zl6zy2qww7v7e3yyvdmwvfhfusuj9kvacrtwpa55fm283ez4jyz5t59esyj4df0qnly0vn7j4h03zyhquw6psxcu8zwz3edylauq922j6ggrztsyemaj6wm6887saw329kg6gpa78zp89z5vwthawkagh9tf5usjsdqqdlj3v0047ecwshruz2u9mr2fnnc8m0as0qj7unpvyhlyem3ud4refpwx233hg2gtnj28duea985zmr4hmq6dzq03sp7jglgvx427s75u8czzxmsj9uyasq4qke6nanxmr67xekf60p3wgakd339ry2z5nkrey5qwtewknrvzaelnzl0nfwzlvkaws3mgng8dzy6nx5y097algffhh7ln7qt9uetuz6jehtctc9q6jevdvee2g73lsqxmel8decsqephv3cdtrly0q63ztrjx7hr0tudfuhy402zjd9yg8227x2ve2eda8qw9hcw5lv7ec77t77fqdjpu3stn6rzlvavupd6vxdf4nkm743xtdu2c5kuqhl8z449njj3vqu8q3x3t60lc2cppedllv2wy6xdfjlnk7mjuupesl5z67f7qcjr349wj4e9zg5fxy7qax2j4sgef86khhvnhjec9u0v79n29ah79eynj5utvksvuwp4zreceq6fke7x0pcte8s2506u3kzd46ps06znwydz9z727vsdvalnxlj4v7rdeqnrvw8ckl9pjt8fpv0773lydy3n6te63s37729j897d2emfyk0f45xmjgzdrsmtvpf6ejc0mljque390su0lf8yvd3lsducr6cvnagkkketfxxha45rvh9dw84wpl3x8skzjh54ht2u7ljv8mxww67lrfgq6lmx7vx0qdfwufz33mpuychkpz2hr00ptsshuukp4yrn95v2qg0ldumvx07lz8864kq4rwmhedcd8g6f7sqyewqqxz38drudukyytany97t3m7sp2zucntlqpk860kggcf0nydppvw46gyrg2f8rwq4f03y5w560mqgf4eaumkq74qzzh332p724pap7lhqv2tru2562aadlvyfaqj433zmqt2qjerz6c6p8aqq55wm98xsjp8d6vzsvuj07k5tlqqjdjanwecq9z3k86dcjc38hdgkurjnhmtux5nr3u84cjkzp5qxv6k86z4jvl73zxcc66uk2278jw5tvkr36j7pqnkdy9xkhdnycu8vlp4sne084e9r37n34xt238a95ntws0knuxlx5xkw3g3p7x8qvn2a9xey5yxk9zrupr4tf42lc7qx0thwh4mga63ucgkwffkc06kw58rh5zx2vf4yhdpx72lq9nwyvg0vkuhpjyswfuulesdldsrym0jm66zh4qyw96zc26xnk9ltd3zlpyj8ql9r3wq8sn8ww9w7andwx0kgqa3d69mnkz5mvydqls4zsm8npk8s75fgf4h3n666sghn72ryfn9xpdvyqk847g7w68mxu6rq7kvfrwsq4y7a3gt84rfk2cfkdvrraxecuzp3lmr6kde8gz92f2khrhynwe4dkjwrs9lhs9xkpew0jl6drfh945h9ejev8l8s4scrnc5qu4g94hvpswk7a69x6wmz3hv3h6s6udz2akjdpq2gmm0zq9r7llprzan7ls3l3wpcmjh9dlzg0e9tjvqngvzptksl9vzjrnfhperw5xkvaaaum50062a5wpz7uhrjxesrxa97r4vpv5hmuywrtwwlpzavgfacql6s6d5upvy8506ma8kddtmak0hwm55cxj0xw7ntukq20x076krwkcsp94hrq9k5uxp9ppdeyzdju7r9alushp0q0pw47lj99ah74g9y7d67ndw266xwlkar5zukztf6ffzcaza2p23nlqpgcsv7fpgvu86029wlfv6ke9hvcwqkw3ddn0rul6h9trcs04nnvnzukzfpf4nkz87dqw2", Network::Main).unwrap(), NativeCurrencyAmount::coins(250)),
            (ReceivingAddress::from_bech32m("nolgam1jv5eueyvcq0eyej64h20j2k56r33rev830gmdxe038kwqjrcr3n889wu7at7njguhfkzahe6fc7jzpjrv5v6q4mak0hmtwsuj2g272e9yjshvwqlhuj4tsfhy9kkepa3068lxye9ta5l48zck5wkx5zj2ww3zfr3gk7pfrx2mv8zc2gdx2qwh43wjv2ztpcs5w0kfkalt950eupzx3jd0xu56aaumeg5try2vfdy49l96pzsetre9zt97skm6dqrckm8543suas4udnlh0l8a98rdxyljuhyk4zg29pculzdjr484xfeg9dfcf4l2ans3rkglug2hd3khczkwlgejv4wu8rxxuxcmg38f2qyn7rnjm278npfeh0fzn2q8me9tmxx4vg9tn9j36zv522fdg4uqvncn635v9k6hegwf48xffh5r3tdz0cm4hz2tatamfw4qtsc8mhnnsvwq4zv795kvv3xvms92w22trar6c2xsxsk9cvlpnq0aje7gq90h979v5vlt6u240yhck5mlphu3tftyy27vrh79y7crx42yus5y78dsml3w0wd3k68ykk2f6469yrl8mdf6c4d5pp7qav2cahp2gaf8qedggvdqx630yea3zvkrxs99p0ahys8pwr9xrzvjl9uq49rtnwtx78ad0scpsvp0ty3y2vu7zqjq6jrwphvndkkq9al0phgc36vjj5mlzcpxj87yp94x0ysuupmmc3z054wqy5xn028hwlt37yuh8f05m95j4xeju7c5d874qguw4g3v9nkcfyusrqhj3mk4fjj84zl4ttpr02ncj49rqjf8vydtyf4d2mtw0jkr68avrs5zama43v53xw0nvy0rag9mes3f7hw7ye2hfx08jjgjwk8q6zwc653jnvzcznenc5lqw456ww0s0ffplwwqfp75c64kvu4tcc4jzmg8fcqt896zaa5tv4hpwfgnw8yx9564g4u2j43er55znwez22s8qnqa2aqxfph99qvlrzs8pmrw95x5pnf4vk56y7f9dhu33xkczf449qmtr8fttnwg5pqy7a2wuz0x5n7r6f4gnytpyuhr6xfx3q07p8ze9gl906y2nlyhjad2kx7knzcxr73texmc8v2fd225duywrunp329qr9r93xxfs80sk94qknnxgd0grqx6mssdrsayl7ygkvehw23fhg66zzldv3njyhdyrfpmxctnm5k2l4kaj5wt35xsk3cn0yz5pd8jx045kp3akks6pha0qtxzaevze88mar7umrhqxfq26sfxmk3hzw3s66yaz8gdeck4krc7kjc0vt0fvltf4msyhehwep6clwnfyxrsgwnqxxxdydm0s9j3ezeuvj267ptmnge8zvskn3ceuut957en6zyvkerrdcgs6a3g7hft4kppaqkw3ut4rl5t8reqkpqwluy7haays630hzgwuwrgqly5emapcswdy3v6tneyjc8qsd642xp0hue8dfecmd8cjh8e0ua04tmwg4n52xx4d49gw7rhq2djg2x976kyn0ukg8s2h09k7swglgw8mf9mp3dccrsfrynkrqgt2tnsr4e5k5pdet6nllmersnmcy6xd9szkfdtfyvjplq8edkvjts6zpa5l92ew6ycfwrk7c7ful4madmjtvhrjnhqcvhvczhmgp07hm74g2jfpvtrca38pvxnfllyvs4fk5eg3m426fsepfkp7d4283zz2j285vpgkxn4tgwk2wvt7wvuxc5capvmttt2x0hm78aksm7f4gzmvc5s477jhzmn5843dd43zef9xap7fyfcdww308sjdj0zryarpsltxnqzx04mcu0avdsxrnsnwly7yqf007nkelzd0twcjmytddncxr2znyhvw4d67ftkt8k48w2x8a0h5hscxew2l7z04v7duq6nlyfkczhne6hnp2ayrjrvvyepdvnwaunayl0fr4w42dkmqnj303ddu2jjrnf3p0qh4wdenx9uega42yte3cwsje6sadh3uxf25dmcpu4jh6zwrh754saa7qf52t8vrfkh54gdadnsk3yfsty3lwa5j0jl804ecgtn4j4z5rglujfzyk4ckc2q6fn37ldwtr45ys8ekc2ryy6r44fkym2npj6ma38wmxsx2ug02nmnkt6ur9rd0mrhc4qzdxutdn7wyxyfkvc9mz600qeqwt09xyvpnz5j2wnnv6wxuava5h0g2sfg38wlq8k77dqkp9xuyd09a69h2rujrw0pdq4qw26jkvjwkvp7lu9aqnhmus87pq0yt36yywlg527yq465cmfuxrl397gt7gaj4z97lfkmfz5kqlurgs6jn93rpgw7ymc7du23facsk6q5txaeez5639ewqhld8zrjwy29ld4hksmw6fpk7kr0da6w3q6wt8gdte2tl9kp3guevzh6rzd22zx7mzkgyr4u0zzq5zdyn27wl40ht5e6zpggg0r7exjh68heazhkye9jd5ant25a8hg5v3xlpmnjwzv35fw44jt76edtfa9sh0g6ylv3s3lx9ap5xea5xcxc8w5t6jnyaf8qmq73gt57v4nrhswy5t5fgp96kstc3xq49wy9fxak30ehkscqr59fxmsweqvyk4adhhqx6l73xzgv2wj6gjfl3lsqgtgcrwq3f4cm4ctzuh9adguvu0vmvc39ur42xktnkqulsmwygjpkn9e42at4phc3nn0v0cc7qya8c0053kxgqj7tdcyr09z6nv22qv309vgv9dds85hhep2mq2y95c7tvjcur0l0thz29w5vzd64afvessaw0nqaer09qmcplvgdy408me4e4kfn6zn509pyf8cetzs5n4y42wl2es0qzyjtf4fwsrjvt7el7grt8hhk3ls2pymaasrsp6mkqcmyzk9j023k8wxdkl4g6anhlwrfaenjxrt4j97g8ds0gg233zct6ewwrr6rmc5us74ypf6xpu2meg6674jk7wujrrrs8mk2n5n7vnz39dq4094uztxmvrau6pmv3w70uqhncph5hgwpfq53auhcz74cnh8wzgappnaayret7xf9dfud7gh35tesmv5z8u7e0gdmjpar35wfk6ml6ldzwnwtq7kl39c8p40txnmcyk0uhsc8hp2yhmqsghjfh5n9paz76a72a9j3nwughm7xpuvfzzry94dwfvwrdz2fkq5u9xm6v486p35mpx606qpwzp4rs5mw9rpcaa5qdt5wuggcjgc5ztg2v5c9keq3e7a7njgzxcay8ykxxg5lnsx5548fhl5etvt6vz397mrkj97s5f7xa7tg222heqjzxwlqg7fwee900znu0l4nm8jf5hqdv37j9hmrw0vj972le397qp39wphqpjfur6fl6sct037pt5hfm56ngrlgu0e6q4ggz4mrv9r0l3nyjx70dx8z542y9c", Network::Main).unwrap(), NativeCurrencyAmount::coins(500)),

            // Actual premine recipients, added 2025-01-13, in 88db6fefa150fb13cab35bee3cb5821cc6f0eded
            (ReceivingAddress::from_bech32m("nolgam125sf39wwkzc7pakked34mv74v67p6a5p8nst0st2gmgf2tsr5lejzmnrp7vp3yltjhv4wj39cw7w2zj94zc77rkdxmchrf5w7l588saeecwxtswqj4n5z22af2f4k5ls37vcpdlc34qelvqyw4nu4cztchjppc3guc30yssn0h92jnrmmqak47fgwg40yz4cezd4z38khc4km7hzw6sndfd4s7l75adu9zvvyydp6zww7h6geqspp6qhyk3h3qgmgcl4fqy6n2j85tyqwg97207zxcywpeqmrw0qq3agumx9gyuy32j880vr3x9x0ww0dvngfhdynrtlz6r5afgyycm65yrthfkn6cq48u6s4w2waslln3cynylvw8qt30n2z70dqlcht5f39dsyyh00sguhnxk0wu3dwevc2rg3q5g3fwcrlxqd9dvqxfaypkvvuw68uzm0hp2q4wa3vkfkjm85060ppax6ujf2xnulejfv2ndl66fazpvuayv5ltksdz4xzpxs6uszx5chghg3hnllm9u8vsre9zlndkcyeu44mnyutkq9tag6sq9hpd9r88ysjkccy5ch9hczrq783wa8hns0cwegvdadm30aszwxzcjfp3recp0s7xx4zvexewmqfn0qwc3u7q5qcw6xv7ac9fenfqh6j2p26p435skpzk52eyl7hf2p48dj56t9gkk7n894mcvxpk3enqduk3hm53u559dcg5823xa0ewpktdek8c3vfn48fkes50n9mf2t9k6jwts45da068acyhuw0rehanu932gem963kj0nsk0ux07k0xwzhx7ey93vchr33hc4tdwht48aly4wnf8elqeymtp463xxalruq9f4q5drfpkkwu325q7cxnvm5y5fcjy8sweq7ayfggefzp3j22ylm2k68zymp7ymwj7wp6alrzgnm4gjsppx8anu3yeapxraf9t4j39afuknu2r4h7h6d2zgunckfvd59e2522lx3qz0ffaswmznryruduwd73nqrg4re7lmcfaakz6wn2z9c6vlahhkeu4p4hejk2jh2zq2jjl4rn0y78cgcckujeenlad7zdsl2dy9972qxqmpuw8lemaqq3f97sze575m5x3vjzvctnwtkpvm9lj453337xkqul0g4umv5hdl6umy8sser076t4kda7ym5yppmnazya2ycp0dhpg07p9ylmrzf635awzdpth094wac6k7p6u9r52kstym5vhymdfk588jzzqss2e0du60k2r3qn76j66fpgkge2a4kvhd0t9uan477xha88gxt0l9cjlntzcnjtln7nxst7a6hd8vd4mg4ggd6faqqftc49t3hcvwgj2cgph72ak3wlklv2seda4exzhscm32mn8v2cqv6rpkxykhy3rm57jd9ggqa6h8hlx4nufh7n9xlx2q2w7hcw9f387pkrsqnera4dwqv9wv7a0lcdp52uw3z764y8z25msz3y6m35rxqcuyyt9e8203xm20k7f4x3dutgpjwjkr88l2rq80csy42m9wpqkc3vp2m40t0sux8p6haeze060tkcm58z9w6sr7npujsnsl3hu9mvtpdn5aaeydwujlwyy3u882ec7lkf0jecsmkhz9w3e6kc2h2fej4qcmxxddt4xwzawgnaflxmkv7qxq82aqxsyd6lgu6xz6s8q2wpp69fkc52as4d4hx7df8xqpjazn0j7j2eygfchsuexmht2zz9a3rzn40uny5mf5njlr0psj95uxe0086gt77cdnzm7vd5lxq36qs63xccg73ugudtz9np32yc3e585dsc9gfxzuujsj45gvw0f4s4ddpthmeq4v7hwkplh4ejareen8kz5xdu849z4uzkdgkpzwz0rnnvnu9zeck093pwpuh3rglx4lj0kfdwshys90n2x0c26u4tnkhuv74d4yvsr8n3ym7gegchcy9j9nlrkrfr58mq6fyrl90lkefa57u9ajajmxgu9el80m5kv9c7ne0u8c2uea4fdzckunvm8tarnc50u0t6xgg96nmc3h5a9l7acfszapj2fwcmge754992k4qsftf4z498splx2df0f2kzxjswtrk8dwnzhkvwhw345u86jffsdh7y58aklssglj3zsatdprph9jd6a8kt3w0f24m5elhyu3f6aqp5rtj5mzm4md5v88fgkl4a7lusplcyhj3kq5kq2y5ehklm9gsqscrd2nx27zma43gp403nd5wgzdclalme4ucnj7uschq73v6vhk8kvmn0remaeqxjh2pg4nqgfskd0ktjleuj573gxnkeczn26pkd86kw3qtll3djdl7rs3844dte764ms8aapmpjq76de6mcxvx9pv2xtyst4832vc2yzt6426rk7rff4tslrsunq7azyqrs59j3w6s23tdcs0fw7a2yh0s0f2rd38rzs0d5dawq5akmnqnd733dw0xjyhsqh320ecnpx68e8673d3n02axs49zwjv8t6p4ftajezqyedvpvvnm6el4c0s77pxacmgyg8capd5069djw3hvn09ugv5889tcla70yzyu95p9hxgcdw5ndv4mgr60wgqkvsquppzx5yj54sxessflvtr4vu8sk45xqkevz2jgj8r4dp5ye3wlelp7mlgjdrwls69z3nkztq70s7zjynd8x9fkxwtdjpzmhvyp5su5ekt96vngxau40zkjlp4m9lecsemw477sx4svrcjlq8932gl5fwgzspy5u9w3483f7ekuzwff72x0a589vtphn9lmdt0l3krj2pmujyvddqd7fd23zppm0az58kynt74h33r6y8atk0tua4gydh4sx0p4y72l2hrulpz3vdnvt8vklq5gtyyk05lxglyj743x869mc9gcjh6v452mpulgec3vg0kw32yrh826y9tzqadh7fsz4h7rmdl2uwuf4quu6q9xg9rz4f6v4e3h8dh8h3hyk9077fcdrgygy6tp32erqzhfmyws5w48ur346fhudztvn8428r5zc4fdmt07pwxp4mu39xf6er6g44eazy30z9ylt76amnp78494nejcups6yej0awzhdcrp078227ljcv4zgendhjknlzw9j6et2levyn88gaals93gkednyzn7dac5dkw3r3qvffe0kzgxvn8x90ulu02q980jfczyfu8xe7w9ffpq5gpcr6mprj705z8vy7ssl5k608k3z6njvtfgddmrx3kmxxz3puwfujrv9tcg98jxee0c9t9ga2nqt5yw2pv35a0ktpshmagg8srtn8phqajn4vnz3ueld8kg97tf0u526aljsnz7pgwmzd836zsr6d5k2hentxfspl0r6rpae736jhpykmg68j9j2e4xyzcee85g6jwa7m0wplgsl8e4qwtpx3j27mf9tlac9ghp2u", Network::Main).unwrap(), NativeCurrencyAmount::coins(8808)),
            (ReceivingAddress::from_bech32m("nolgam1xt6pchtatfkgr4g8gd6u5w2n2gzh4ntzm08ss30hu7dnjmsexeqs293lzel5cpatae8h5psjvhruh4vtrshuvqecg7x555qxt4k3hmpxgcunhgjacwt0glalxfsz0s62q6g3n0tm8rvcrz4pd7rx9t3rlzcv4czsft0hfnwq05z8k5305rpajp06m5hthxp96zcf567s9ujjjjhccga6yt0gm8syhsznj4twt5mchlqg0w3z6852k3956yypged7thekfvs536tvmrvvlqg0d9weu8ww0tcvs7hrnq9yh42638dl0nene3tea5wdqtknakygmcpy66uuyshes4zy0gdt3h0m2nx2f4dk4cad4hj93hfg2lhrwet934mghsrpxj60de5lr35gvlup9v9zl3xg9qxet0wly6arzguryf2mtwa7n2trjzdlleq06kna9z826xcxpf078j7450vd0cmr8yemve959qmru4vfegpcjdntzucr3ph8rd8a6hj04sdxu2smahgpguclyl7qxcklcupqugravk2qcswar0d0ycygrxyefwcvrs77s6md5gyc8acq4uanzjvplsaa2ukawlv4qrgrrsnhfld0f6zrwgns4fe56vzej26hp49ufs74tsmq5tg29357as2vgnd4hqe8g0glzh3vsed0sap3kprxnr3klmqm9yp3jzmzynq489qkep7q40d59y8khxt9ezhkmtgtmukj5tw7tnhjrnrcv6e7pmj3juyqu0kecel909tdruaw5c4mr8a5lvhu5vhauaynsz96nc3az0pwvf3h99grpxr64mxk5gw4ft2w2yxfcux9wc8td7kfxtx0x274yy7qkxetqwdsjlgemqkgp9vq05zmrg2h83rqma3qm77yhwaunpwndjsejcmaqznkvgl9grkr64d950lwfwwl8d9wk6lc2n8xdla6fklyes97pc3ql2nedhx4wuz28cwwy94vc06zu43tlwn3ducurvf6szcqknlgh55dx3umel4jr59py6exk6xs8j0mn4w8pjsjm36aqqd4n2jh6yevvdufzl4mn0kn00rgtkpgqydhzhrt40v02kuteyzjmrdrlzayjsjjm5yt9wtsrwfetv66rdvmjrh04962a3wy9ucl9y7swp5l4yxv9qnz5p0h9tghw9cglqxkth8306znjfh25u36z3fnpz83fg8905f265rjhvq9csscgv9gqfgqdgay2c6pqdaazvr2h0xntagdmtuvfpzs02san7wvyxtgqe35r39l4qykvpws43vlyrv7fyueqctapmsqnztx6s826tcv9smgx5khef02jjp6r9wkmflyskxnvvn3fkzx5rd6gx5gp7ef0hnfzhvu5w3wv8va423c7fr63tugvhzklaqzm9m4803fu6r2gks9gusp0638ye4zsfexl0t6fnepajmf6pjj6snc9s9en34l7n6tns4a9spehntfzrz0u55jlt95jz9gh9lwqwtakd2d8qqfvfq8fyugfnfq0xs9xkk7nz5gqugp6022vhjlrdkkaew9nhnl73ygrzsm9eevvqujwgzy0ukzw8e5mhsklahhmdx5gqmaa0twy9s0gvlmlcnsatv3jrk50j62x5x4rysd75aa6xt9jc6tjxahnjgskveywuxk86jh2mqqm53zn59c3mqu9tw60pdu3jkwm89mqxyve8fk85xfzfj5yzpwarel8z43y40jqgfxdukn48w2jy0ps2p7d9d2r6sl6jlqhmmrafgmlptf3pjfaw7qdqs9kprvjyv3j39a88s69vnzh48nwevmx92rjrg6xmck5tc5fayrl3khea6sx3qwnkdkflk7ejzwm3wqu7d2z2mxtk38qe8wg0982gdwaaj7td7wwa0vpqzqxy38mv0ddx6seefc8txl6u7hjz8laaf4ju78r6mr8zvtzezdqx73svtynpe3pkcqlsxe5q692dpp098s06hmgf390d3wel5r3tgud527cx5hwf0hh0yej6gs7j9dztlappmmusd4z9nqra6fa78qp9007k2q7wwlajaqgymzua8yuepkm7fag6dfuz7s276exj6g57l76wta85qytglch2akjny8f8athyagxhag9fceqmtl3rm25nm3mlvuawu4hgv53xwkya9s9nm7eqyt0h9p0f0492salddgs2zfw3ehqym7ddkpfmdzu2njptdpcgtcekz9nh98tjt34hlxvtdu49jr56cv33c5hacumald9jdlam6y7fh4f42afv70hrjyjumak6fhwpye8afk6d79j9nw9rd0pfcxjk4xeaz24p58pahs2fccvkzuuym5aamxmj2mtcp4mqrw2xycelrlrkl79xr2ylaqce3gma4zc6q6rq8843v25slx7l3ya8vclmnvwnu6vp7ldefstvek7ttplrjl3ezscjg3ynnesq4yjvax6vxfd0sdhaut0lmfefck4pwrvy53a96x7crg3fh68xesepx23qzn44d8wrjx3rzhv4sslmy4u3zu49u2m6wmcjvu3r9gredvgm2n56rsf7kxn389ftsz8g97jlnztwzlc8fcpht2apr8u0a3cz35x4zmevns0m8ph7ncrn9zjpxypkxmax8n5x3yl5h3ufek5vp68t84qmhs0udgcsx8kr3uktfhskd6sgwwdc6twzy8tldhflhahg5zgphe575fsslqdyfzwwcj5wuh7fx5393uezw4y9u5ch8xgzqy6we42xtktyk6lwzt6xnyhzemgg7c4c4n0kpgds2kgll7y2tlgkqslytlmt0ve64ze53e60ef3xzvf3wa6kn50kfksfjka7n4sptm8kf5e09azd7tnl7q3l5h3mey8zwzxx83226s38qf280yaglgx9fmdv0xrqjrexcqmp9n6aa8jqvqnlq9gxayxera7cyzcy3pjy8as53gxpfs40wsk6a03uyy2t9779zujgap6y3kje6vvncgdeutj8ke2rs8jfrltp7rl3e5snlq9phdy2ny7rn4k2qkalrt97zz2hvk7jhcj4st5hsh906qngm87vx3as85u2rfusfravtfm7yjvvwldty8uak09cjy5a2yp3v7akltgzv6j0y75x0g4zsq62e4crzzavn4x9s92wtngfyzckza492tkju8c53m0jtpm62yradzcjg3ny3kd3edp0zznneu9zh8h4wfn992y7s5l6vmvukcrt6gx4txhdmz4rksq4r2pwvpkfaywpapxyd82ajvj5cjtltdz7pa4xhkst6hyxfacpnw506gu5rn9kt9q2jk95exddgqcnzakfxfy66432y0r3ehtv72508dhksdy490uq87ekfve845a2jsret7svtu802kwzw4rgc0v5e8l9q45gqsn7ajk0ggfjcsp0k6fzf49ztc7q7pw0h", Network::Main).unwrap(), NativeCurrencyAmount::coins(384)),
        ]
    }

    pub fn premine_utxos(network: Network) -> Vec<Utxo> {
        let mut utxos = vec![];
        for (receiving_address, amount) in Self::premine_distribution() {
            // generate utxo
            let six_months = Timestamp::months(6);
            let coins = vec![
                Coin::new_native_currency(amount),
                TimeLock::until(network.launch_date() + six_months),
            ];
            let utxo = Utxo::new(receiving_address.lock_script(), coins);
            utxos.push(utxo);
        }
        utxos
    }

    pub(crate) fn new(
        header: BlockHeader,
        body: BlockBody,
        appendix: BlockAppendix,
        block_proof: BlockProof,
    ) -> Self {
        let kernel = BlockKernel::new(header, body, appendix);
        Self {
            digest: OnceLock::default(), // calc'd in hash()
            kernel,
            proof: block_proof,
        }
    }

    // /// Merge a transaction into this block's transaction.
    // /// The mutator set data must be valid in all inputs.
    // ///
    // /// note: this causes block digest to change.
    // pub async fn accumulate_transaction(
    //     &mut self,
    //     transaction: Transaction,
    //     previous_mutator_set_accumulator: &MutatorSetAccumulator,
    // ) {
    //     // merge transactions
    //     let merged_timestamp = max::<Timestamp>(
    //         self.kernel.header.timestamp,
    //         max::<Timestamp>(
    //             self.kernel.body.transaction_kernel.timestamp,
    //             transaction.kernel.timestamp,
    //         ),
    //     );
    //     let new_transaction = self
    //         .kernel
    //         .body
    //         .transaction_kernel
    //         .clone()
    //         .merge_with(transaction.clone());

    //     // accumulate mutator set updates
    //     // Can't use the current mutator sat accumulator because it is in an in-between state.
    //     let mut new_mutator_set_accumulator = previous_mutator_set_accumulator.clone();
    //     let mutator_set_update = MutatorSetUpdate::new(
    //         new_transaction.kernel.inputs.clone(),
    //         new_transaction.kernel.outputs.clone(),
    //     );

    //     // Apply the mutator set update to get the `next_mutator_set_accumulator`
    //     mutator_set_update
    //         .apply_to_accumulator(&mut new_mutator_set_accumulator)
    //         .expect("Mutator set mutation must work");

    //     let block_body: BlockBody = BlockBody {
    //         transaction_kernel: new_transaction,
    //         mutator_set_accumulator: new_mutator_set_accumulator.clone(),
    //         lock_free_mmr_accumulator: self.kernel.body.lock_free_mmr_accumulator.clone(),
    //         block_mmr_accumulator: self.kernel.body.block_mmr_accumulator.clone(),
    //         uncle_blocks: self.kernel.body.uncle_blocks.clone(),
    //     };

    //     let block_header = BlockHeader {
    //         version: self.kernel.header.version,
    //         height: self.kernel.header.height,
    //         prev_block_digest: self.kernel.header.prev_block_digest,
    //         timestamp: merged_timestamp,
    //         nonce: self.kernel.header.nonce,
    //         max_block_size: self.kernel.header.max_block_size,
    //         proof_of_work_line: self.kernel.header.proof_of_work_line,
    //         proof_of_work_family: self.kernel.header.proof_of_work_family,
    //         difficulty: self.kernel.header.difficulty,
    //     };

    //     self.kernel.body = block_body;
    //     self.kernel.header = block_header;
    //     self.unset_digest();
    // }

    /// Verify a block. It is assumed that `previous_block` is valid.
    /// Note that this function does **not** check that the block has enough
    /// proof of work; that must be done separately by the caller, for instance
    /// by calling [`Self::has_proof_of_work`].
    pub(crate) async fn is_valid(&self, previous_block: &Block, now: Timestamp) -> bool {
        self.is_valid_internal(previous_block, now, None, None)
            .await
    }

    /// Like `is_valid` but also allows specifying a custom
    /// `target_block_interval` and `minimum_block_time`. If `None` is passed,
    /// these variabes take the default values.
    async fn is_valid_internal(
        &self,
        previous_block: &Block,
        now: Timestamp,
        target_block_interval: Option<Timestamp>,
        minimum_block_time: Option<Timestamp>,
    ) -> bool {
        // What belongs here are the things that would otherwise
        // be verified by the block validity proof.

        // 0. `previous_block` is consistent with current block
        //   a) Block height is previous plus one
        //   b) Block header points to previous block
        //   c) Block mmr updated correctly
        //   d) Block timestamp is greater than (or equal to) timestamp of
        //      previous block plus minimum block time
        //   e) Target difficulty and cumulative proof-of-work were updated correctly
        //   f) Block timestamp is less than host-time (utc) + 2 hours.
        // 1. Block proof is valid
        //   a) Verify appendix contains required claims
        //   b) Block proof is valid
        //   c) Max block size is not exceeded
        // 2. The transaction is valid.
        //   a) Verify that MS removal records are valid, done against previous
        //      `mutator_set_accumulator`,
        //   b) Verify that all removal records have unique index sets
        //   c) Verify that the mutator set update induced by the block sends
        //      the old mutator set accumulator to the new one.
        //   d) transaction timestamp <= block timestamp
        //   e) transaction coinbase <= miner reward, and not negative.
        //   f) 0 <= transaction fee (also checked in block program).

        // DO NOT add explanations to the individual steps below. *All*
        // explanations belong in the recipe above and may not be duplicated or
        // elaborated on below this line.

        // 0.a)
        if previous_block.kernel.header.height.next() != self.kernel.header.height {
            warn!(
                "Block height ({}) does not match previous height plus one ({})",
                self.kernel.header.height,
                previous_block.kernel.header.height.next()
            );
            return false;
        }

        // 0.b)
        if previous_block.hash() != self.kernel.header.prev_block_digest {
            warn!("Hash digest does not match previous digest");
            return false;
        }

        // 0.c)
        let mut mmra = previous_block.kernel.body.block_mmr_accumulator.clone();
        mmra.append(previous_block.hash());
        if mmra != self.kernel.body.block_mmr_accumulator {
            warn!("Block MMRA was not updated correctly");
            return false;
        }

        // 0.d)
        let minimum_block_time = minimum_block_time.unwrap_or(MINIMUM_BLOCK_TIME);
        if previous_block.kernel.header.timestamp + minimum_block_time
            > self.kernel.header.timestamp
        {
            warn!(
                "Block's timestamp ({}) should be greater than or equal to that of previous block \
                ({}) plus minimum block time ({}) \nprevious <= current ?? {}",
                self.kernel.header.timestamp,
                previous_block.kernel.header.timestamp,
                minimum_block_time,
                previous_block.kernel.header.timestamp + minimum_block_time
                    <= self.kernel.header.timestamp
            );
            return false;
        }

        // 0.e)
        let expected_difficulty = difficulty_control(
            self.header().timestamp,
            previous_block.header().timestamp,
            previous_block.header().difficulty,
            target_block_interval,
            previous_block.header().height,
        );
        if self.kernel.header.difficulty != expected_difficulty {
            warn!(
                "Value for new difficulty is incorrect. \
                actual: {}, expected: {expected_difficulty}",
                self.kernel.header.difficulty,
            );
            return false;
        }
        let expected_cumulative_proof_of_work =
            previous_block.header().cumulative_proof_of_work + previous_block.header().difficulty;
        if self.header().cumulative_proof_of_work != expected_cumulative_proof_of_work {
            warn!(
                "Block's cumulative proof-of-work number does not match with expectation.\n\n\
                Block's pow: {}\nexpectation: {}",
                self.header().cumulative_proof_of_work,
                expected_cumulative_proof_of_work
            );
            return false;
        }

        // 0.f)
        const FUTUREDATING_LIMIT: Timestamp = Timestamp::minutes(5);
        let future_limit = now + FUTUREDATING_LIMIT;
        if self.kernel.header.timestamp >= future_limit {
            warn!(
                "block time is too far in the future.\n\nBlock timestamp: {}\nThreshold is: {}",
                self.kernel.header.timestamp, future_limit
            );
            return false;
        }

        // 1.a)
        for required_claim in BlockAppendix::consensus_claims(self.body()) {
            if !self.appendix().contains(&required_claim) {
                warn!(
                    "Block appendix does not contain required claim.\n\
                    Required claim: {required_claim:?}"
                );
                return false;
            }
        }

        // 1.b)
        let BlockProof::SingleProof(block_proof) = &self.proof else {
            warn!("Can only verify block proofs, got {:?}", self.proof);
            return false;
        };
        if !BlockProgram::verify(self.body(), self.appendix(), block_proof).await {
            warn!("Block proof invalid.");
            return false;
        }

        // 1.c)
        if self.size() > MAX_BLOCK_SIZE {
            warn!(
                "Block size exceeds limit.\n\nBlock size: {} bfes\nLimit: {} bfes",
                self.size(),
                MAX_BLOCK_SIZE
            );
            return false;
        }

        // 2.a)
        for removal_record in self.kernel.body.transaction_kernel.inputs.iter() {
            if !previous_block
                .mutator_set_accumulator_after()
                .can_remove(removal_record)
            {
                warn!("Removal record cannot be removed from mutator set");
                return false;
            }
        }

        // 2.b)
        let mut absolute_index_sets = self
            .kernel
            .body
            .transaction_kernel
            .inputs
            .iter()
            .map(|removal_record| removal_record.absolute_indices.to_vec())
            .collect_vec();
        absolute_index_sets.sort();
        absolute_index_sets.dedup();
        if absolute_index_sets.len() != self.kernel.body.transaction_kernel.inputs.len() {
            warn!("Removal records contain duplicates");
            return false;
        }

        // 2.c)
        let mutator_set_update = MutatorSetUpdate::new(
            self.body().transaction_kernel.inputs.clone(),
            self.body().transaction_kernel.outputs.clone(),
        );
        let mut msa = previous_block.mutator_set_accumulator_after();
        let ms_update_result = mutator_set_update.apply_to_accumulator(&mut msa);
        if let Err(err) = ms_update_result {
            warn!("Failed to apply mutator set update: {}", err);
            return false;
        };
        if msa.hash() != self.body().mutator_set_accumulator.hash() {
            warn!("Reported mutator set does not match calculated object.");
            debug!(
                "From Block body\n{:?}. \n\nCalculated\n{:?}",
                self.body().mutator_set_accumulator,
                msa
            );
            return false;
        }

        // 2.d)
        if self.kernel.body.transaction_kernel.timestamp > self.kernel.header.timestamp {
            warn!(
                "Transaction timestamp ({}) is is larger than that of block ({})",
                self.kernel.body.transaction_kernel.timestamp, self.kernel.header.timestamp
            );
            return false;
        }

        // 2.e)
        let block_subsidy = Self::block_subsidy(self.kernel.header.height);
        let coinbase = self.kernel.body.transaction_kernel.coinbase;
        if let Some(coinbase) = coinbase {
            if coinbase > block_subsidy {
                warn!(
                    "Coinbase exceeds block subsidy. coinbase: {coinbase}; \
                    block subsidy: {block_subsidy}."
                );
                return false;
            }

            if coinbase.is_negative() {
                warn!("Coinbase may not be negative. Got coinbase: {coinbase}.");
                return false;
            }
        }

        // 2.f)
        let fee = self.kernel.body.transaction_kernel.fee;
        if fee.is_negative() {
            warn!("Fee may not be negative when transaction is included in block. Got fee: {fee}.");
            return false;
        }

        true
    }

    /// Determine whether the the proof-of-work puzzle was solved correctly.
    ///
    /// Specifically, compare the hash of the current block against the
    /// target corresponding to the previous block;s difficulty and return true
    /// if the former is smaller. If the timestamp difference exceeds the
    /// `TARGET_BLOCK_INTERVAL` by a factor `ADVANCE_DIFFICULTY_CORRECTION_WAIT`
    /// then the effective difficulty is reduced by a factor
    /// `ADVANCE_DIFFICULTY_CORRECTION_FACTOR`.
    pub fn has_proof_of_work(&self, previous_block_header: &BlockHeader) -> bool {
        let hash = self.hash();
        let threshold = previous_block_header.difficulty.target();
        if hash <= threshold {
            return true;
        }

        let delta_t = self.header().timestamp - previous_block_header.timestamp;
        let excess_multiple = usize::try_from(
            delta_t.to_millis() / TARGET_BLOCK_INTERVAL.to_millis(),
        )
        .expect("excessive timestamp on incoming block should have been caught by peer loop");
        let shift = usize::try_from(ADVANCE_DIFFICULTY_CORRECTION_FACTOR.ilog2()).unwrap()
            * (excess_multiple
                >> usize::try_from(ADVANCE_DIFFICULTY_CORRECTION_WAIT.ilog2()).unwrap());
        let effective_difficulty = previous_block_header.difficulty >> shift;
        if hash <= effective_difficulty.target() {
            return true;
        }

        false
    }

    /// Evaluate the fork choice rule.
    ///
    /// Given two blocks, determine which one is more canonical. This function
    /// evaluates the following logic:
    ///  - if the height is different, prefer the block with more accumulated
    ///    proof-of-work;
    ///  - otherwise, if exactly one of the blocks' transactions has no inputs,
    ///    reject that one;
    ///  - otherwise, prefer the current tip.
    ///
    /// This function assumes the blocks are valid and have the self-declared
    /// accumulated proof-of-work.
    ///
    /// This function is called exclusively in
    /// [`GlobalState::incoming_block_is_more_canonical`], which is in turn
    /// called in two places:
    ///  1. In `peer_loop`, when a peer sends a block. The `peer_loop` task only
    ///     sends the incoming block to the `main_loop` if it is more canonical.
    ///  2. In `main_loop`, when it receives a block from a `peer_loop` or from
    ///     the `mine_loop`. It is possible that despite (1), race conditions
    ///     arise and they must be solved here.
    pub(crate) fn fork_choice_rule<'a>(
        current_tip: &'a Self,
        incoming_block: &'a Self,
    ) -> &'a Self {
        if current_tip.header().height != incoming_block.header().height {
            if current_tip.header().cumulative_proof_of_work
                >= incoming_block.header().cumulative_proof_of_work
            {
                current_tip
            } else {
                incoming_block
            }
        } else if current_tip.body().transaction_kernel.inputs.is_empty() {
            incoming_block
        } else {
            current_tip
        }
    }

    /// Size in number of BFieldElements of the block
    // Why defined in terms of BFieldElements and not bytes? Anticipates
    // recursive block validation, where we need to test a block's size against
    // the limit. The size is easier to calculate if it relates to a block's
    // encoding on the VM, rather than its serialization as a vector of bytes.
    pub(crate) fn size(&self) -> usize {
        self.encode().len()
    }

    /// The amount rewarded to the guesser who finds a valid nonce for this
    /// block.
    pub(crate) fn total_guesser_reward(&self) -> NativeCurrencyAmount {
        self.body().transaction_kernel.fee
    }

    /// Get the block's guesser fee UTXOs.
    ///
    /// The amounts in the UTXOs are taken from the transaction fee.
    ///
    /// The genesis block does not have a guesser reward.
    pub(crate) fn guesser_fee_utxos(&self) -> Vec<Utxo> {
        if self.header().height.is_genesis() {
            return vec![];
        }

        let lock = self.header().guesser_digest;
        let lock_script = HashLockKey::lock_script_from_after_image(lock);

        let total_guesser_reward = self.total_guesser_reward();
        let mut value_locked = total_guesser_reward;
        value_locked.div_two();
        let value_unlocked = total_guesser_reward.checked_sub(&value_locked).unwrap();

        const MINER_REWARD_TIME_LOCK_PERIOD: Timestamp = Timestamp::years(3);
        let coins = vec![
            Coin::new_native_currency(value_locked),
            TimeLock::until(self.header().timestamp + MINER_REWARD_TIME_LOCK_PERIOD),
        ];
        let locked_utxo = Utxo::new(lock_script.clone(), coins);
        let unlocked_utxo = Utxo::new_native_currency(lock_script, value_unlocked);

        vec![locked_utxo, unlocked_utxo]
    }

    /// Compute the addition records that correspond to the UTXOs generated for
    /// the block's guesser
    ///
    /// The genesis block does not have this addition record.
    pub(crate) fn guesser_fee_addition_records(&self) -> Vec<AdditionRecord> {
        self.guesser_fee_utxos()
            .into_iter()
            .map(|utxo| {
                let item = Tip5::hash(&utxo);

                // Adding the block hash to the mutator set here means that no
                // composer can start proving before solving the PoW-race;
                // production of future proofs is impossible as they depend on
                // inputs hidden behind the veil of future PoW.
                let sender_randomness = self.hash();
                let receiver_digest = self.header().guesser_digest;

                commit(item, sender_randomness, receiver_digest)
            })
            .collect_vec()
    }

    /// Create a list of [`ExpectedUtxo`]s for the guesser fee.
    pub(crate) fn guesser_fee_expected_utxos(&self, guesser_preimage: Digest) -> Vec<ExpectedUtxo> {
        self.guesser_fee_utxos()
            .into_iter()
            .map(|utxo| {
                ExpectedUtxo::new(
                    utxo,
                    self.hash(),
                    guesser_preimage,
                    UtxoNotifier::OwnMinerGuessNonce,
                )
            })
            .collect_vec()
    }

    /// Return the mutator set update corresponding to this block, which sends
    /// the mutator set accumulator after the predecessor to the mutator set
    /// accumulator after self.
    pub(crate) fn mutator_set_update(&self) -> MutatorSetUpdate {
        let mut mutator_set_update = MutatorSetUpdate::new(
            self.body().transaction_kernel.inputs.clone(),
            self.body().transaction_kernel.outputs.clone(),
        );

        let extra_addition_records = self.guesser_fee_addition_records();
        mutator_set_update.additions.extend(extra_addition_records);
        mutator_set_update
    }
}

#[cfg(test)]
pub(crate) mod block_tests {
    use rand::random;
    use rand::rngs::StdRng;
    use rand::thread_rng;
    use rand::Rng;
    use rand::SeedableRng;
    use strum::IntoEnumIterator;
    use tracing_test::traced_test;
    use twenty_first::util_types::mmr::mmr_trait::LeafMutation;

    use super::super::transaction::transaction_kernel::TransactionKernelModifier;
    use super::*;
    use crate::config_models::cli_args;
    use crate::config_models::network::Network;
    use crate::database::storage::storage_schema::SimpleRustyStorage;
    use crate::database::NeptuneLevelDb;
    use crate::models::state::tx_proving_capability::TxProvingCapability;
    use crate::models::state::wallet::transaction_output::TxOutput;
    use crate::models::state::wallet::utxo_notification::UtxoNotificationMedium;
    use crate::models::state::wallet::WalletSecret;
    use crate::tests::shared::fake_valid_successor_for_tests;
    use crate::tests::shared::invalid_block_with_transaction;
    use crate::tests::shared::make_mock_block;
    use crate::tests::shared::make_mock_transaction;
    use crate::tests::shared::mock_genesis_global_state;
    use crate::util_types::archival_mmr::ArchivalMmr;

    pub(crate) const PREMINE_MAX_SIZE: NativeCurrencyAmount = NativeCurrencyAmount::coins(831424);

    #[test]
    fn all_genesis_blocks_have_unique_mutator_set_hashes() {
        let mutator_set_hash = |network| {
            Block::genesis(network)
                .body()
                .mutator_set_accumulator
                .hash()
        };

        assert!(
            Network::iter().map(mutator_set_hash).all_unique(),
            "All genesis blocks must have unique MSA digests, else replay attacks are possible",
        );
    }

    #[test]
    fn block_subsidy_calculation_terminates() {
        Block::block_subsidy(BFieldElement::MAX.into());

        let random_height: BFieldElement = random();
        Block::block_subsidy(random_height.into());
    }

    #[tokio::test]
    async fn test_difficulty_control_matches() {
        let network = Network::Main;

        let a_wallet_secret = WalletSecret::new_random();
        let a_key = a_wallet_secret.nth_generation_spending_key_for_tests(0);

        // TODO: Can this outer-loop be parallelized?
        for multiplier in [1, 10, 100, 1_000, 10_000, 100_000, 1_000_000] {
            let mut block_prev = Block::genesis(network);
            let mut now = block_prev.kernel.header.timestamp;
            let mut rng = thread_rng();

            for i in (0..30).step_by(1) {
                let duration = i as u64 * multiplier;
                now += Timestamp::millis(duration);

                let (block, _) = make_mock_block(&block_prev, Some(now), a_key, rng.gen()).await;

                let control = difficulty_control(
                    block.kernel.header.timestamp,
                    block_prev.header().timestamp,
                    block_prev.header().difficulty,
                    None,
                    block_prev.header().height,
                );
                assert_eq!(block.kernel.header.difficulty, control);

                block_prev = block;
            }
        }
    }

    #[test]
    fn difficulty_to_threshold_test() {
        // Verify that a difficulty of 2 accepts half of the digests
        let difficulty: u32 = 2;
        let difficulty_u32s = Difficulty::from(difficulty);
        let threshold_for_difficulty_two: Digest = difficulty_u32s.target();

        for elem in threshold_for_difficulty_two.values() {
            assert_eq!(BFieldElement::MAX / u64::from(difficulty), elem.value());
        }

        // Verify that a difficulty of BFieldElement::MAX accepts all digests where the
        // last BFieldElement is zero
        let some_difficulty = Difficulty::new([1, u32::MAX, 0, 0, 0]);
        let some_threshold_actual: Digest = some_difficulty.target();

        let bfe_max_elem = BFieldElement::new(BFieldElement::MAX);
        let some_threshold_expected = Digest::new([
            bfe_max_elem,
            bfe_max_elem,
            bfe_max_elem,
            bfe_max_elem,
            BFieldElement::zero(),
        ]);

        assert_eq!(0u64, some_threshold_actual.values()[4].value());
        assert_eq!(some_threshold_actual, some_threshold_expected);
        assert_eq!(bfe_max_elem, some_threshold_actual.values()[3]);
    }

    #[tokio::test]
    async fn block_with_wrong_mmra_is_invalid() {
        let network = Network::Main;
        let genesis_block = Block::genesis(network);
        let now = genesis_block.kernel.header.timestamp + Timestamp::hours(2);
        let mut rng: StdRng = SeedableRng::seed_from_u64(2225550001);

        let mut block1 = fake_valid_successor_for_tests(&genesis_block, now, rng.gen()).await;

        let timestamp = block1.kernel.header.timestamp;
        assert!(block1.is_valid(&genesis_block, timestamp).await);

        let mut mutated_leaf = genesis_block.body().block_mmr_accumulator.clone();
        let mp = mutated_leaf.append(genesis_block.hash());
        mutated_leaf.mutate_leaf(LeafMutation::new(0, random(), mp));

        let mut extra_leaf = block1.body().block_mmr_accumulator.clone();
        extra_leaf.append(block1.hash());

        let bad_new_mmrs = [
            MmrAccumulator::new_from_leafs(vec![]),
            mutated_leaf,
            extra_leaf,
        ];

        for bad_new_mmr in bad_new_mmrs {
            block1.kernel.body.block_mmr_accumulator = bad_new_mmr;
            assert!(!block1.is_valid(&genesis_block, timestamp).await);
        }
    }

    #[tokio::test]
    async fn can_prove_block_ancestry() {
        let mut rng = thread_rng();
        let network = Network::RegTest;
        let genesis_block = Block::genesis(network);
        let mut blocks = vec![];
        blocks.push(genesis_block.clone());
        let db = NeptuneLevelDb::open_new_test_database(true, None, None, None)
            .await
            .unwrap();
        let mut storage = SimpleRustyStorage::new(db);
        let ammr_storage = storage.schema.new_vec::<Digest>("ammr-blocks-0").await;
        let mut ammr = ArchivalMmr::new(ammr_storage).await;
        ammr.append(genesis_block.hash()).await;
        let mut mmra = MmrAccumulator::new_from_leafs(vec![genesis_block.hash()]);

        for i in 0..55 {
            let wallet_secret = WalletSecret::new_random();
            let key = wallet_secret.nth_generation_spending_key_for_tests(0);
            let (new_block, _) =
                make_mock_block(blocks.last().unwrap(), None, key, rng.gen()).await;
            if i != 54 {
                ammr.append(new_block.hash()).await;
                mmra.append(new_block.hash());
                assert_eq!(
                    ammr.to_accumulator_async().await.bag_peaks(),
                    mmra.bag_peaks()
                );
            }
            blocks.push(new_block);
        }

        let last_block_mmra = blocks.last().unwrap().body().block_mmr_accumulator.clone();
        assert_eq!(mmra, last_block_mmra);

        let index = thread_rng().gen_range(0..blocks.len() - 1);
        let block_digest = blocks[index].hash();

        let leaf_index = index as u64;
        let membership_proof = ammr.prove_membership_async(leaf_index).await;
        let v = membership_proof.verify(
            leaf_index,
            block_digest,
            &last_block_mmra.peaks(),
            last_block_mmra.num_leafs(),
        );
        assert!(
            v,
            "peaks: {} ({}) leaf count: {} index: {} path: {} number of blocks: {}",
            last_block_mmra.peaks().iter().join(","),
            last_block_mmra.peaks().len(),
            last_block_mmra.num_leafs(),
            leaf_index,
            membership_proof.authentication_path.iter().join(","),
            blocks.len(),
        );
        assert_eq!(last_block_mmra.num_leafs(), blocks.len() as u64 - 1);
    }

    #[test]
    fn test_premine_size() {
        // 831424 = 42000000 * 0.01979581
        // where 42000000 is the asymptotical limit of the token supply
        // and 0.01979581...% is the relative size of the premine
        let asymptotic_total_cap = NativeCurrencyAmount::coins(42_000_000);
        let premine_max_size = PREMINE_MAX_SIZE;
        let total_premine = Block::premine_distribution()
            .iter()
            .map(|(_receiving_address, amount)| *amount)
            .sum::<NativeCurrencyAmount>();

        assert!(total_premine <= premine_max_size);
        assert!(
            premine_max_size.to_nau_f64() / asymptotic_total_cap.to_nau_f64() < 0.0198f64,
            "Premine must be less than or equal to promised"
        )
    }

    mod block_is_valid {
        use rand::rngs::StdRng;
        use rand::SeedableRng;

        use super::*;
        use crate::job_queue::triton_vm::TritonVmJobPriority;
        use crate::mine_loop::mine_loop_tests::make_coinbase_transaction_from_state;
        use crate::models::state::wallet::address::KeyType;
        use crate::tests::shared::fake_valid_successor_for_tests;

        #[traced_test]
        #[tokio::test]
        async fn blocks_with_0_to_10_inputs_and_successors_are_valid() {
            // Scenario: Build different blocks of height 2, with varying number
            // of inputs. Verify all are valid. The build a block of height 3
            // with non-zero inputs and verify validity. This should ensure that
            // at least one of block 2's guesser fee UTXOs shift the active
            // window of the mutator set's Bloom filter, ensuring that the
            // validity-check of a block handles guesser fee UTXOs correctly
            // when calculating the expected state of the new mutator set.
            // Cf., the bug fixed in 4d6b7013624e593c40e76ce93cb6b288b6b3f48b.

            let network = Network::Main;
            let genesis_block = Block::genesis(network);
            let plus_seven_months = genesis_block.kernel.header.timestamp + Timestamp::months(7);
            let mut rng: StdRng = SeedableRng::seed_from_u64(2225550001);
            let block1 =
                fake_valid_successor_for_tests(&genesis_block, plus_seven_months, rng.gen()).await;

            let alice_wallet = WalletSecret::devnet_wallet();
            let mut alice = mock_genesis_global_state(
                network,
                3,
                alice_wallet.clone(),
                cli_args::Args::default(),
            )
            .await;
            alice.set_new_tip(block1.clone()).await.unwrap();
            let alice_key = alice
                .lock_guard()
                .await
                .wallet_state
                .nth_spending_key(KeyType::Generation, 0)
                .unwrap();
            let output_to_self = TxOutput::onchain_native_currency(
                NativeCurrencyAmount::coins(1),
                rng.gen(),
                alice_key.to_address().unwrap(),
                true,
            );

            let plus_eight_months = plus_seven_months + Timestamp::months(1);
            let (coinbase_for_block2, _) = make_coinbase_transaction_from_state(
                &block1,
                &alice,
                0.5f64,
                plus_eight_months,
                TxProvingCapability::SingleProof,
                (TritonVmJobPriority::Normal, None).into(),
            )
            .await
            .unwrap();
            let fee = NativeCurrencyAmount::coins(1);
            let plus_nine_months = plus_eight_months + Timestamp::months(1);
            for i in 0..10 {
                println!("i: {i}");
                alice = mock_genesis_global_state(
                    network,
                    3,
                    alice_wallet.clone(),
                    cli_args::Args::default(),
                )
                .await;
                alice.set_new_tip(block1.clone()).await.unwrap();
                let outputs = vec![output_to_self.clone(); i];
                let (tx2, _) = alice
                    .lock_guard_mut()
                    .await
                    .create_transaction_with_prover_capability(
                        outputs.into(),
                        alice_key,
                        UtxoNotificationMedium::OnChain,
                        fee,
                        plus_eight_months,
                        TxProvingCapability::SingleProof,
                        &TritonVmJobQueue::dummy(),
                    )
                    .await
                    .unwrap();
                let block2_tx = coinbase_for_block2
                    .clone()
                    .merge_with(
                        tx2,
                        rng.gen(),
                        &TritonVmJobQueue::dummy(),
                        TritonVmProofJobOptions::default(),
                    )
                    .await
                    .unwrap();
                let block2_without_valid_pow = Block::compose(
                    &block1,
                    block2_tx,
                    plus_eight_months,
                    None,
                    &TritonVmJobQueue::dummy(),
                    TritonVmProofJobOptions::default(),
                )
                .await
                .unwrap();

                assert!(
                    block2_without_valid_pow
                        .is_valid(&block1, plus_eight_months)
                        .await,
                    "Block with {i} inputs must be valid"
                );

                alice
                    .set_new_tip(block2_without_valid_pow.clone())
                    .await
                    .unwrap();
                let (coinbase_for_block3, _) = make_coinbase_transaction_from_state(
                    &block2_without_valid_pow,
                    &alice,
                    0.5f64,
                    plus_nine_months,
                    TxProvingCapability::SingleProof,
                    (TritonVmJobPriority::Normal, None).into(),
                )
                .await
                .unwrap();
                let (tx3, _) = alice
                    .lock_guard_mut()
                    .await
                    .create_transaction_with_prover_capability(
                        vec![output_to_self.clone()].into(),
                        alice_key,
                        UtxoNotificationMedium::OnChain,
                        fee,
                        plus_nine_months,
                        TxProvingCapability::SingleProof,
                        &TritonVmJobQueue::dummy(),
                    )
                    .await
                    .unwrap();
                let block3_tx = coinbase_for_block3
                    .clone()
                    .merge_with(
                        tx3,
                        rng.gen(),
                        &TritonVmJobQueue::dummy(),
                        TritonVmProofJobOptions::default(),
                    )
                    .await
                    .unwrap();
                assert!(
                    !block3_tx.kernel.inputs.len().is_zero(),
                    "block transaction 3 must have inputs"
                );
                let block3_without_valid_pow = Block::compose(
                    &block2_without_valid_pow,
                    block3_tx,
                    plus_nine_months,
                    None,
                    &TritonVmJobQueue::dummy(),
                    TritonVmProofJobOptions::default(),
                )
                .await
                .unwrap();

                assert!(
                    block3_without_valid_pow
                        .is_valid(&block2_without_valid_pow, plus_nine_months)
                        .await,
                    "Block of height 3 after block 2 with {i} inputs must be valid"
                );
            }
        }

        #[traced_test]
        #[tokio::test]
        async fn block_with_far_future_timestamp_is_invalid() {
            let network = Network::Main;
            let genesis_block = Block::genesis(network);
            let mut now = genesis_block.kernel.header.timestamp + Timestamp::hours(2);
            let mut rng: StdRng = SeedableRng::seed_from_u64(2225550001);

            let mut block1 = fake_valid_successor_for_tests(&genesis_block, now, rng.gen()).await;

            // Set block timestamp 4 minutes in the future.  (is valid)
            let future_time1 = now + Timestamp::minutes(4);
            block1.kernel.header.timestamp = future_time1;
            assert!(block1.is_valid(&genesis_block, now).await);

            now = block1.kernel.header.timestamp;

            // Set block timestamp 5 minutes - 1 sec in the future.  (is valid)
            let future_time2 = now + Timestamp::minutes(5) - Timestamp::seconds(1);
            block1.kernel.header.timestamp = future_time2;
            assert!(block1.is_valid(&genesis_block, now).await);

            // Set block timestamp 5 minutes in the future. (not valid)
            let future_time3 = now + Timestamp::minutes(5);
            block1.kernel.header.timestamp = future_time3;
            assert!(!block1.is_valid(&genesis_block, now).await);

            // Set block timestamp 5 minutes + 1 sec in the future. (not valid)
            let future_time4 = now + Timestamp::minutes(5) + Timestamp::seconds(1);
            block1.kernel.header.timestamp = future_time4;
            assert!(!block1.is_valid(&genesis_block, now).await);

            // Set block timestamp 2 days in the future. (not valid)
            let future_time5 = now + Timestamp::seconds(86400 * 2);
            block1.kernel.header.timestamp = future_time5;
            assert!(!block1.is_valid(&genesis_block, now).await);
        }
    }

    /// This module has tests that verify a block's digest
    /// is always in a correct state.
    ///
    /// All operations that create or modify a Block should
    /// have a test here.
    mod digest_encapsulation {

        use super::*;

        // test: verify clone + modify does not change original.
        //
        // note: a naive impl that derives Clone on `Block` containing
        //       Arc<Mutex<Option<Digest>>> would link the digest in the clone
        #[test]
        fn clone_and_modify() {
            let gblock = Block::genesis(Network::RegTest);
            let g_hash = gblock.hash();

            let mut g2 = gblock.clone();
            assert_eq!(gblock.hash(), g_hash);
            assert_eq!(gblock.hash(), g2.hash());

            g2.set_header_nonce(Digest::new(bfe_array![1u64, 1u64, 1u64, 1u64, 1u64]));
            assert_ne!(gblock.hash(), g2.hash());
            assert_eq!(gblock.hash(), g_hash);
        }

        // test: verify digest is correct after Block::new().
        #[test]
        fn new() {
            let gblock = Block::genesis(Network::RegTest);
            let g2 = gblock.clone();

            let block = Block::new(
                g2.kernel.header,
                g2.kernel.body,
                g2.kernel.appendix,
                g2.proof,
            );
            assert_eq!(gblock.hash(), block.hash());
        }

        // test: verify digest changes after nonce is updated.
        #[test]
        fn set_header_nonce() {
            let gblock = Block::genesis(Network::RegTest);
            let mut rng = thread_rng();

            let mut new_block = gblock.clone();
            new_block.set_header_nonce(rng.gen());
            assert_ne!(gblock.hash(), new_block.hash());
        }

        // test: verify set_block() copies source digest
        #[test]
        fn set_block() {
            let gblock = Block::genesis(Network::RegTest);
            let mut rng = thread_rng();

            let mut unique_block = gblock.clone();
            unique_block.set_header_nonce(rng.gen());

            let mut block = gblock.clone();
            block.set_block(unique_block.clone());

            assert_eq!(unique_block.hash(), block.hash());
            assert_ne!(unique_block.hash(), gblock.hash());
        }

        // test: verify digest is correct after deserializing
        #[test]
        fn deserialize() {
            let gblock = Block::genesis(Network::RegTest);

            let bytes = bincode::serialize(&gblock).unwrap();
            let block: Block = bincode::deserialize(&bytes).unwrap();

            assert_eq!(gblock.hash(), block.hash());
        }

        // test: verify block digest matches after BFieldCodec encode+decode
        //       round trip.
        #[test]
        fn bfieldcodec_encode_and_decode() {
            let gblock = Block::genesis(Network::RegTest);

            let encoded: Vec<BFieldElement> = gblock.encode();
            let decoded: Block = *Block::decode(&encoded).unwrap();

            assert_eq!(gblock, decoded);
            assert_eq!(gblock.hash(), decoded.hash());
        }
    }

    mod guesser_fee_utxos {
        use super::*;
        use crate::models::state::wallet::address::generation_address::GenerationSpendingKey;
        use crate::tests::shared::make_mock_block_guesser_preimage_and_guesser_fraction;

        #[tokio::test]
        async fn guesser_fee_addition_records_are_consistent() {
            // Ensure that multiple ways of deriving guesser-fee addition
            // records are consistent.

            let mut rng = thread_rng();
            let genesis_block = Block::genesis(Network::Main);
            let a_key = GenerationSpendingKey::derive_from_seed(rng.gen());
            let guesser_preimage = rng.gen();
            let (block1, _) = make_mock_block_guesser_preimage_and_guesser_fraction(
                &genesis_block,
                None,
                a_key,
                rng.gen(),
                0.4,
                guesser_preimage,
            )
            .await;
            let ars = block1.guesser_fee_addition_records();
            let ars_from_eus = block1
                .guesser_fee_expected_utxos(guesser_preimage)
                .iter()
                .map(|x| x.addition_record)
                .collect_vec();
            assert_eq!(ars, ars_from_eus);

            let MutatorSetUpdate {
                removals: _,
                additions,
            } = block1.mutator_set_update();
            assert!(
                ars.iter().all(|ar| additions.contains(ar)),
                "All addition records must be present in block's mutator set update"
            );
        }

        #[test]
        fn guesser_can_unlock_guesser_fee_utxo() {
            let genesis_block = Block::genesis(Network::Main);
            let mut transaction = make_mock_transaction(vec![], vec![]);

            transaction.kernel = TransactionKernelModifier::default()
                .fee(
                    NativeCurrencyAmount::from_nau(1337.into())
                        .expect("given number should be valid NativeCurrencyAmount amount"),
                )
                .modify(transaction.kernel);

            let mut block = invalid_block_with_transaction(&genesis_block, transaction);

            let preimage = thread_rng().gen::<Digest>();
            block.set_header_guesser_digest(preimage.hash());

            let guesser_fee_utxos = block.guesser_fee_utxos();

            let lock_script_and_witness =
                HashLockKey::from_preimage(preimage).lock_script_and_witness();
            assert!(guesser_fee_utxos
                .iter()
                .all(|guesser_fee_utxo| lock_script_and_witness.can_unlock(guesser_fee_utxo)));
        }

        #[traced_test]
        #[tokio::test]
        async fn guesser_fees_are_added_to_mutator_set() {
            // Mine two blocks on top of the genesis block. Verify that the guesser
            // fee for the 1st block was added to the mutator set. The genesis
            // block awards no guesser fee.

            // This test must live in block/mod.rs because it relies on access to
            // private fields on `BlockBody`.

            let mut rng = thread_rng();
            let network = Network::Main;
            let genesis_block = Block::genesis(network);
            assert!(
                genesis_block.guesser_fee_utxos().is_empty(),
                "Genesis block has no guesser fee UTXOs"
            );

            let launch_date = genesis_block.header().timestamp;
            let in_seven_months = launch_date + Timestamp::months(7);
            let in_eight_months = launch_date + Timestamp::months(8);
            let alice_wallet = WalletSecret::devnet_wallet();
            let alice_key = alice_wallet.nth_generation_spending_key(0);
            let alice_address = alice_key.to_address();
            let mut alice =
                mock_genesis_global_state(network, 0, alice_wallet, cli_args::Args::default())
                    .await;

            let output = TxOutput::offchain_native_currency(
                NativeCurrencyAmount::coins(4),
                rng.gen(),
                alice_address.into(),
                true,
            );
            let fee = NativeCurrencyAmount::coins(1);
            let (tx1, _) = alice
                .lock_guard()
                .await
                .create_transaction_with_prover_capability(
                    vec![output.clone()].into(),
                    alice_key.into(),
                    UtxoNotificationMedium::OnChain,
                    fee,
                    in_seven_months,
                    TxProvingCapability::PrimitiveWitness,
                    &TritonVmJobQueue::dummy(),
                )
                .await
                .unwrap();

            let block1 =
                Block::block_template_invalid_proof(&genesis_block, tx1, in_seven_months, None);
            alice.set_new_tip(block1.clone()).await.unwrap();

            let (tx2, _) = alice
                .lock_guard()
                .await
                .create_transaction_with_prover_capability(
                    vec![output].into(),
                    alice_key.into(),
                    UtxoNotificationMedium::OnChain,
                    fee,
                    in_eight_months,
                    TxProvingCapability::PrimitiveWitness,
                    &TritonVmJobQueue::dummy(),
                )
                .await
                .unwrap();

            let block2 = Block::block_template_invalid_proof(&block1, tx2, in_eight_months, None);

            let mut ms = block1.body().mutator_set_accumulator.clone();

            let mutator_set_update_guesser_fees =
                MutatorSetUpdate::new(vec![], block1.guesser_fee_addition_records());
            let mut mutator_set_update_tx = MutatorSetUpdate::new(
                block2.body().transaction_kernel.inputs.clone(),
                block2.body().transaction_kernel.outputs.clone(),
            );

            let reason = "applying mutator set update derived from block 2 \
                          to mutator set from block 1 should work";
            mutator_set_update_guesser_fees
                .apply_to_accumulator_and_records(
                    &mut ms,
                    &mut mutator_set_update_tx.removals.iter_mut().collect_vec(),
                )
                .expect(reason);
            mutator_set_update_tx
                .apply_to_accumulator(&mut ms)
                .expect(reason);

            assert_eq!(ms.hash(), block2.body().mutator_set_accumulator.hash());
        }
    }

    #[test]
    fn premine_distribution_does_not_crash() {
        Block::premine_distribution();
    }
}
