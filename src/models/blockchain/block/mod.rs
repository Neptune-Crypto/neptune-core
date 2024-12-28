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
use block_header::BLOCK_HEADER_VERSION;
use block_header::MINIMUM_BLOCK_TIME;
use block_header::TARGET_BLOCK_INTERVAL;
use block_height::BlockHeight;
use block_kernel::BlockKernel;
use difficulty_control::Difficulty;
use difficulty_control::ProofOfWork;
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

use super::transaction::lock_script::LockScript;
use super::transaction::transaction_kernel::TransactionKernelProxy;
use super::transaction::utxo::Utxo;
use super::transaction::Transaction;
use super::type_scripts::neptune_coins::NeptuneCoins;
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
use crate::models::proof_abstractions::SecretWitness;
use crate::models::state::wallet::address::ReceivingAddress;
use crate::models::state::wallet::expected_utxo::ExpectedUtxo;
use crate::models::state::wallet::expected_utxo::UtxoNotifier;
use crate::prelude::twenty_first;
use crate::triton_vm;
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
///
/// let mut block = Block::genesis_block(Network::RegTest);
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
    fn template_header(
        predecessor_header: &BlockHeader,
        predecessor_digest: Digest,
        timestamp: Timestamp,
        nonce: Digest,
        target_block_interval: Option<Timestamp>,
    ) -> BlockHeader {
        let difficulty = difficulty_control(
            timestamp,
            predecessor_header.timestamp,
            predecessor_header.difficulty,
            target_block_interval,
            predecessor_header.height,
        );

        let new_cumulative_proof_of_work: ProofOfWork =
            predecessor_header.cumulative_proof_of_work + predecessor_header.difficulty;
        BlockHeader {
            version: BLOCK_HEADER_VERSION,
            height: predecessor_header.height.next(),
            prev_block_digest: predecessor_digest,
            timestamp,
            nonce,
            cumulative_proof_of_work: new_cumulative_proof_of_work,
            difficulty,
        }
    }

    /// Create a block template with an invalid block proof.
    ///
    /// To be used in tests where you don't care about block validity.
    #[cfg(test)]
    pub(crate) fn block_template_invalid_proof(
        predecessor: &Block,
        transaction: Transaction,
        block_timestamp: Timestamp,
        nonce_preimage: Digest,
        target_block_interval: Option<Timestamp>,
    ) -> Block {
        let primitive_witness = BlockPrimitiveWitness::new(predecessor.to_owned(), transaction);
        let body = primitive_witness.body().to_owned();
        let header = primitive_witness.header(
            block_timestamp,
            nonce_preimage.hash(),
            target_block_interval,
        );
        let proof = BlockProof::Invalid;
        let appendix = BlockAppendix::default();
        Block::new(header, body, appendix, proof)
    }

    pub(crate) async fn block_template_from_block_primitive_witness(
        primitive_witness: BlockPrimitiveWitness,
        timestamp: Timestamp,
        nonce_preimage: Digest,
        target_block_interval: Option<Timestamp>,
        triton_vm_job_queue: &TritonVmJobQueue,
        proof_job_options: TritonVmProofJobOptions,
    ) -> anyhow::Result<Block> {
        let body = primitive_witness.body().to_owned();
        let header =
            primitive_witness.header(timestamp, nonce_preimage.hash(), target_block_interval);
        let (appendix, proof) = {
            let block_proof_witness =
                BlockProofWitness::produce(primitive_witness, triton_vm_job_queue).await?;
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
        nonce_preimage: Digest,
        target_block_interval: Option<Timestamp>,
        triton_vm_job_queue: &TritonVmJobQueue,
        proof_job_options: TritonVmProofJobOptions,
    ) -> anyhow::Result<Block> {
        let tx_claim = SingleProof::claim(transaction.kernel.mast_hash());
        assert!(
            triton_vm::verify(
                Stark::default(),
                &tx_claim,
                &transaction.proof.clone().into_single_proof()
            ),
            "Transaction proof must be valid to generate a block"
        );
        let primitive_witness = BlockPrimitiveWitness::new(predecessor.to_owned(), transaction);
        Self::block_template_from_block_primitive_witness(
            primitive_witness,
            block_timestamp,
            nonce_preimage,
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
        nonce_preimage: Digest,
        target_block_interval: Option<Timestamp>,
        triton_vm_job_queue: &TritonVmJobQueue,
        proof_job_options: TritonVmProofJobOptions,
    ) -> anyhow::Result<Block> {
        Self::make_block_template_with_valid_proof(
            predecessor,
            transaction,
            block_timestamp,
            nonce_preimage,
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
    pub fn block_subsidy(block_height: BlockHeight) -> NeptuneCoins {
        let mut reward: NeptuneCoins = NeptuneCoins::new(128);
        let generation = block_height.get_generation();

        if generation > 128 {
            return NeptuneCoins::zero();
        }

        for _ in 0..generation {
            reward.div_two()
        }

        reward
    }

    /// returns coinbase reward amount for this block.
    ///
    /// note that this amount may differ from self::block_subsidy(self.height)
    /// because a miner can choose to accept less than the calculated reward amount.
    pub fn coinbase_amount(&self) -> NeptuneCoins {
        // A block must always have a Coinbase.
        // we impl this method in part to cement that guarantee.
        self.body()
            .transaction_kernel
            .coinbase
            .unwrap_or_else(NeptuneCoins::zero)
    }

    pub fn genesis_block(network: Network) -> Self {
        let premine_distribution = Self::premine_distribution(network);
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
            fee: NeptuneCoins::new(0),
            timestamp: network.launch_date(),
            public_announcements: vec![],
            coinbase: Some(total_premine_amount),
            mutator_set_hash: MutatorSetAccumulator::default().hash(),
        }
        .into_kernel();

        let body: BlockBody = BlockBody::new(
            genesis_txk,
            genesis_mutator_set.clone(),
            MmrAccumulator::new_from_leafs(vec![]),
            MmrAccumulator::new_from_leafs(vec![]),
        );

        let header: BlockHeader = BlockHeader {
            version: BFieldElement::zero(),
            height: BFieldElement::zero().into(),
            prev_block_digest: Default::default(),
            timestamp: network.launch_date(),

            // TODO: to be set to something difficult to predict ahead of time
            nonce: Digest::new(bfe_array![0, 0, 0, 0, 0]),
            cumulative_proof_of_work: ProofOfWork::zero(),
            difficulty: Difficulty::MINIMUM,
        };

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

    #[cfg(not(test))]
    fn premine_distribution(network: Network) -> Vec<(ReceivingAddress, NeptuneCoins)> {
        match network {
            Network::Main => {
                vec![
                    // The premine UTXOs can be hardcoded here.
                    (ReceivingAddress::from_bech32m("nolgam1v0j838fvl7ud8q964x7urcyetufmy9nfllmy0xej9837lanjl2vfmsar7w2ncraxhgpxg4d4pntd6kmjxhgvhjcdelr75zj4fqvws88dfunsn6fj0fnkxlch3rqcdstmpv28v732tvcvvctcjxw3drn5gpygmflhasj5zu043vzr6hmjpt4tedn94p4mzerp69xp9d8cx9u697f8ds4vrw7rmpk74lk06pt4q0lx4d5e7el5r0fywqxk3s8dvgxtehlvpde9kkt7y654ddpusmn0yhr4whgvh4nvffp2eahnvmslhruwymzpqdf5c99l9redvtuk9kg32zfenwjqkere2xltvfhqfpm54cxltcj8lfr5ttcakytztwcr457jyx6yuam6dma7khjkspx0nu0m5kut2neja956hkj3p3ej8hutavv2zkmygff4gca55hd6apyhhslsyfs24s60ldzktd7hj7gkdtgfm2l8vdd8pkuh02q0k3ce6utpltzpw6anx8zk8jn3f8kuansk3fs98zlxxpvqrl9w2ayq9axuc64lfvp9teluwhvwc7w2veujpqk3jxdag4d9uav7tt9lc02pnejw8v2fvl03a50jra8mf82j879z3wklw8n357fmtaaf48e8xaak7jfz6a6lmele0h8yhv6f9kf79ashn3sggh35kfqpx8wevnku7kz2kdrj4x5m3y4wze47g3rp3xvjpmlqx6yl7plxg8a33ljm0c09p2v5t36j2ym7t5u2fpcjvvy92vj3dnew8729u9lslrzuxa5yrmf3qntdegeq3hygru2uee5xya3mam2aejf285eh843vxkdvg8xeqg9lfyjkdgamchweg40srfju6aef0v3ads4wswyw6fyrnz8ltdhnd7cn0t7ucpwtdhfy8jcw94fygks8pxcuuerk0smkwrr6wvqegtdprtfzpya8c8gx9n8weaxjtfag7h7vqw957ncwkmfj27j7jvjewcapfef43ujgu4clyj8jhzkuyrlvgxz3vf2wdx4atl7l89q9qhwvtltqne4a0t64zwpx87aqkcvjysnuf6ct9h5uxyp3768fglzc6arvs00f3lznppgnuakzy0k7aw5620eddfu7eq0gusc7c348ng3yl85hm42y54leyshyfh4lhadzj927wl3sw4l5k00l4cwamfjxmaklp4e7qny3jvjvzkzs33c346prn4reljyn2rjpurms9ha2jcj55dfpwa33cj73nananj5mvy6s2w8ec0sftwzu2w0w3smjv3mvvf3glclwswvzrghy6jd7a2vtdr4dtrrw2tdfssvpa6qc2955f27rgrqt2yg2h3xs5qy94xtsz6ufjqtafl7cffhja6e0wznf8qnt9wd6ng062x9pgztrh5pvhqjcud9nqdsmydumz9h6lzneawln3ds4y8zfvjcnq4h654ypnts7wfwty9tr65nnmjvprqqrss9js325p94kh5yctshlkhuqt4705r5etgzavazw0w6l9yra56z9kxzwjxfcar407tfaw4l0elk3ddr54c4e8uqnnlg8gwuzsd84dmefvk958hmzdxvg2x5r995ez6y4wkqn08gyrwejf9z3unjtx097zehntjlklsfmfk2gw4v0eh9jd6jr0ztz8m22t7ajse3w8yyl6ht34hp8pdzr0qa0vvqyx4ulft6enutr3axjh9kdrcjzh28ky00vxkln7nmqp8xe9hvyqt2s2qgp8g5lu6tkmzav9vy7nq0ww5vp2x56gf6y9he6nm7f4xzqarwy52nan8m479h6drvmdnaxw5scddgwv669gpjwg7zd352tagdgwxz5gl9pvdcztzjur64jkg0hed60vws3al2dt3az4gfn00txe4c4s8djvzmml06degdccsuxnmxh3vrphjqeekqrgszu8w9jwksfrayeyhhlzxtzejgxy4c2apv4rknp0dq7rf6us2ns6zlkwpmul70fj3xv30uv9edcn87ggy55trph5plhzvf0vp0pz5yvq8p9hgrq3pl75wnvv074v9uldnn5tej0aewedvulv499mamxu88g3z4spactyzhl8jtgrypquasfvv2ucucg90lslzvsnxg5q2wgwc9c30ru6jf5ktmjfa3jm4whead4ln0l49y6z9l3p0eu4ax4qpns3kfuc5a6er5lltf65pxe46yaxcwf893wdqtaj8uz67t50nkwztwmp427auy65ck7506qf9ullc23vqy74sj2lnpgq84vtfyz74ywxza5kxzs4a3xtkvgg7a07u08dnlwqkkhkx6jj2srvsxk49nkutd3cd526n62fe6a9acmpah4l3uapzaja2y9cx3ncdmkpry7e869svyz7m0scm6vsyj9amxpctswkdft0tqp68fgyheluuy95x07m64pe45avnjcchtgulef7yrjqzmauhpx2j8xe9d529kx5j8wnpsnwyycduz59588hn75zzg09skrpjhe8mxj3ljds6k3p563n2n2v7w3d86amphe2fvu0ay25qcfqq39znjk34l85pxnv3q7ftl4x2cmkkr7gr3tz3jn72jkcj4xa92lzu0pp58mrp06gr8dual30y0r9pn5aeasggymtmswgpeyxqur8yqck75pfykz8lzzavwgv0fg43uly70tt4hs5e64hvn0t88w3j0wq3p34scwc5kdl79yj0xyz8zlelhr0yzn4fnwgs6c0te55v22eef7kzc32m8edu8rs5wymk6r9whnwkhy9lh0r5z8xssw7tel9nvsf7fjs8f9pjuxwe8s5nw7xhgh5s4rpfy3jg0kg6asjxrjcjts30436eud4ctrenesptz2x7ngv52h74dy7gaymvujxnxz7xmsl69v24lwj5580ndtrl5uqavt4v6nr85gh7ectvq0mpsyrcy3qaq6pwgkjy62uypwshegzrllcsre9wkau4v4ttv385qzgxt773pqxefs2nyd0wnpd5fk35uewa7gzghn5vwey07rlea2v5amd90njt95zm7umrdsp7l5q92gywjfuzyhmzup75pjxm067eym43vkxp03dcsv0tjsr253yz9kfpe3uw9j9v8tnlhhnrjgywzd88sqagsrdasm6prxzwf4qt4vp7r5f2vzswzdk94gk0mu5gzhnr4se47wykyyvs6ugvc8gg6n3sv5f4vvht0m2r9av296cmf2jdfs52jw8r05k3wqmvy7xn8frz0x2vc6wa66cmll68k9kxh9hj8dv59x96d020fgt004wwxpgquwl8mgsxm9tpcdqr55mce3ep3ckhmvjqzyzplm69xza2nrfjjcc82gp6y72s6e0cmwvw2x4qhjfp32l8jnr7njckl2yacscqffkmmtud7e2ttqrppte6v79rm0chzqpyv", Network::Main).unwrap(), NeptuneCoins::new(2000)),
                    (ReceivingAddress::from_bech32m("nolgam1u9r0el5lvaz4883zzf588t0rgcm87anaxvgqq5e3ptzzzxh6da546lf2vhtwkfm29thvz6m94u6twxvzvve9m2ucda53fd8z80xt29wplnuq40u5r4pzw9k7eyexps2q3hsdqu5hhzpnpq2wmpq4lcfj4deqh09tdgmkuvw5y7ay2xqaaj0xc0aclnwd7qs7asclsvgr9r225alnfyf9x09xutyp629s2mfts2un2cmq9s07xwllw8cvsufulxmacruzfyxx9w0jkksys39w47vvgehlv6ncuzhl7tzrvj79xla9rfy20f2da5nptw9h5h6ua8dsn8q0qz0d7y5ndlcqz3whr7h40mjxgg3ueycs7zz9r0rc3znu8vph74nw22y38h89zy20lv82mekq3xu9cumytxqlsnugjs5tp78mgm3prpcmtzezgwzl8vntm00n3x99hhdvsp8lkjuvnjndxyczmgl554xl96x55djrjnv4mxvqlswzvxnw8lkw87f959v2pktmeg3yx86ku23fsfp0x8jh2te94vuk9ahwp7zkaw4njjsjp6a79qvxfcujwr89xhwgzzfjffnj5vusye7907s6vzgfms6xfzu07ugwr3dskakjazre2mn4xvxpzznjaatnztfla69c43x7un4er2c8x06ucwe72gzt9xvh487q6l8dq2ejwamfpllw5mrarrrvf9wu36r8pvwa45ck8005060lk67y74f09dz2h780ddruq79a5racn05gepc2qr0s85n8550ulvcmqzv8nmwxetaj7hl78mg8nx9ftju3ak2uf5ur45s26yle02s5netsdaukx7thfkalnr83f8kp7grajgx4glcknxzkc7326rttl34up9h7c7f7k76n43zgwjg8mwx22cyf0mc0g67kcf3637urst5fl2ez9ja2at7nhr00hug999e7g7e02nu7jxesq07zqdmpwta64zzxfvpwqy4lfd35qmyvm4ftjfdnw8mvglfmsflan5vz466svsq298pm748kc22cvyn35xfy6rzzq73dl8cytj7kchcx6mjj58ll2xdhk2kf0a25ea5quktkep8t9awrww6x6ynnepc8chgnvvtg90ueu7tgr0t25pnurcn6csukvpyvn988ynpmry2lrd8e6q6ur4k9nd3rd4xsrge6nlu5hcjrv2xhv5vmcavts8rapxrr4773u0dthe08pd3yu2vnetkk28k08ae6t3dchr2hlfq6tlmnq20taj6xz7uq7wccx30ntrf9h7r2r5tgmpd6c7m3vgq69qtft3xlw8qs8tc00j4vslhudmv2cgd0mgncgvzrmvetrnt0zmwft9c6xkeyt609cmxc405jzwt3ysj249vmhh7heq2j7524qthgsu3d0ns9rc9amslk2anscy67rrn456pe5kjcrr9ft9javak5gl49qtyegnyuh6r7jgsfv3w6v8zl6zy2qww7v7e3yyvdmwvfhfusuj9kvacrtwpa55fm283ez4jyz5t59esyj4df0qnly0vn7j4h03zyhquw6psxcu8zwz3edylauq922j6ggrztsyemaj6wm6887saw329kg6gpa78zp89z5vwthawkagh9tf5usjsdqqdlj3v0047ecwshruz2u9mr2fnnc8m0as0qj7unpvyhlyem3ud4refpwx233hg2gtnj28duea985zmr4hmq6dzq03sp7jglgvx427s75u8czzxmsj9uyasq4qke6nanxmr67xekf60p3wgakd339ry2z5nkrey5qwtewknrvzaelnzl0nfwzlvkaws3mgng8dzy6nx5y097algffhh7ln7qt9uetuz6jehtctc9q6jevdvee2g73lsqxmel8decsqephv3cdtrly0q63ztrjx7hr0tudfuhy402zjd9yg8227x2ve2eda8qw9hcw5lv7ec77t77fqdjpu3stn6rzlvavupd6vxdf4nkm743xtdu2c5kuqhl8z449njj3vqu8q3x3t60lc2cppedllv2wy6xdfjlnk7mjuupesl5z67f7qcjr349wj4e9zg5fxy7qax2j4sgef86khhvnhjec9u0v79n29ah79eynj5utvksvuwp4zreceq6fke7x0pcte8s2506u3kzd46ps06znwydz9z727vsdvalnxlj4v7rdeqnrvw8ckl9pjt8fpv0773lydy3n6te63s37729j897d2emfyk0f45xmjgzdrsmtvpf6ejc0mljque390su0lf8yvd3lsducr6cvnagkkketfxxha45rvh9dw84wpl3x8skzjh54ht2u7ljv8mxww67lrfgq6lmx7vx0qdfwufz33mpuychkpz2hr00ptsshuukp4yrn95v2qg0ldumvx07lz8864kq4rwmhedcd8g6f7sqyewqqxz38drudukyytany97t3m7sp2zucntlqpk860kggcf0nydppvw46gyrg2f8rwq4f03y5w560mqgf4eaumkq74qzzh332p724pap7lhqv2tru2562aadlvyfaqj433zmqt2qjerz6c6p8aqq55wm98xsjp8d6vzsvuj07k5tlqqjdjanwecq9z3k86dcjc38hdgkurjnhmtux5nr3u84cjkzp5qxv6k86z4jvl73zxcc66uk2278jw5tvkr36j7pqnkdy9xkhdnycu8vlp4sne084e9r37n34xt238a95ntws0knuxlx5xkw3g3p7x8qvn2a9xey5yxk9zrupr4tf42lc7qx0thwh4mga63ucgkwffkc06kw58rh5zx2vf4yhdpx72lq9nwyvg0vkuhpjyswfuulesdldsrym0jm66zh4qyw96zc26xnk9ltd3zlpyj8ql9r3wq8sn8ww9w7andwx0kgqa3d69mnkz5mvydqls4zsm8npk8s75fgf4h3n666sghn72ryfn9xpdvyqk847g7w68mxu6rq7kvfrwsq4y7a3gt84rfk2cfkdvrraxecuzp3lmr6kde8gz92f2khrhynwe4dkjwrs9lhs9xkpew0jl6drfh945h9ejev8l8s4scrnc5qu4g94hvpswk7a69x6wmz3hv3h6s6udz2akjdpq2gmm0zq9r7llprzan7ls3l3wpcmjh9dlzg0e9tjvqngvzptksl9vzjrnfhperw5xkvaaaum50062a5wpz7uhrjxesrxa97r4vpv5hmuywrtwwlpzavgfacql6s6d5upvy8506ma8kddtmak0hwm55cxj0xw7ntukq20x076krwkcsp94hrq9k5uxp9ppdeyzdju7r9alushp0q0pw47lj99ah74g9y7d67ndw266xwlkar5zukztf6ffzcaza2p23nlqpgcsv7fpgvu86029wlfv6ke9hvcwqkw3ddn0rul6h9trcs04nnvnzukzfpf4nkz87dqw2", Network::Main).unwrap(), NeptuneCoins::new(250)),
                    (ReceivingAddress::from_bech32m("nolgam1jv5eueyvcq0eyej64h20j2k56r33rev830gmdxe038kwqjrcr3n889wu7at7njguhfkzahe6fc7jzpjrv5v6q4mak0hmtwsuj2g272e9yjshvwqlhuj4tsfhy9kkepa3068lxye9ta5l48zck5wkx5zj2ww3zfr3gk7pfrx2mv8zc2gdx2qwh43wjv2ztpcs5w0kfkalt950eupzx3jd0xu56aaumeg5try2vfdy49l96pzsetre9zt97skm6dqrckm8543suas4udnlh0l8a98rdxyljuhyk4zg29pculzdjr484xfeg9dfcf4l2ans3rkglug2hd3khczkwlgejv4wu8rxxuxcmg38f2qyn7rnjm278npfeh0fzn2q8me9tmxx4vg9tn9j36zv522fdg4uqvncn635v9k6hegwf48xffh5r3tdz0cm4hz2tatamfw4qtsc8mhnnsvwq4zv795kvv3xvms92w22trar6c2xsxsk9cvlpnq0aje7gq90h979v5vlt6u240yhck5mlphu3tftyy27vrh79y7crx42yus5y78dsml3w0wd3k68ykk2f6469yrl8mdf6c4d5pp7qav2cahp2gaf8qedggvdqx630yea3zvkrxs99p0ahys8pwr9xrzvjl9uq49rtnwtx78ad0scpsvp0ty3y2vu7zqjq6jrwphvndkkq9al0phgc36vjj5mlzcpxj87yp94x0ysuupmmc3z054wqy5xn028hwlt37yuh8f05m95j4xeju7c5d874qguw4g3v9nkcfyusrqhj3mk4fjj84zl4ttpr02ncj49rqjf8vydtyf4d2mtw0jkr68avrs5zama43v53xw0nvy0rag9mes3f7hw7ye2hfx08jjgjwk8q6zwc653jnvzcznenc5lqw456ww0s0ffplwwqfp75c64kvu4tcc4jzmg8fcqt896zaa5tv4hpwfgnw8yx9564g4u2j43er55znwez22s8qnqa2aqxfph99qvlrzs8pmrw95x5pnf4vk56y7f9dhu33xkczf449qmtr8fttnwg5pqy7a2wuz0x5n7r6f4gnytpyuhr6xfx3q07p8ze9gl906y2nlyhjad2kx7knzcxr73texmc8v2fd225duywrunp329qr9r93xxfs80sk94qknnxgd0grqx6mssdrsayl7ygkvehw23fhg66zzldv3njyhdyrfpmxctnm5k2l4kaj5wt35xsk3cn0yz5pd8jx045kp3akks6pha0qtxzaevze88mar7umrhqxfq26sfxmk3hzw3s66yaz8gdeck4krc7kjc0vt0fvltf4msyhehwep6clwnfyxrsgwnqxxxdydm0s9j3ezeuvj267ptmnge8zvskn3ceuut957en6zyvkerrdcgs6a3g7hft4kppaqkw3ut4rl5t8reqkpqwluy7haays630hzgwuwrgqly5emapcswdy3v6tneyjc8qsd642xp0hue8dfecmd8cjh8e0ua04tmwg4n52xx4d49gw7rhq2djg2x976kyn0ukg8s2h09k7swglgw8mf9mp3dccrsfrynkrqgt2tnsr4e5k5pdet6nllmersnmcy6xd9szkfdtfyvjplq8edkvjts6zpa5l92ew6ycfwrk7c7ful4madmjtvhrjnhqcvhvczhmgp07hm74g2jfpvtrca38pvxnfllyvs4fk5eg3m426fsepfkp7d4283zz2j285vpgkxn4tgwk2wvt7wvuxc5capvmttt2x0hm78aksm7f4gzmvc5s477jhzmn5843dd43zef9xap7fyfcdww308sjdj0zryarpsltxnqzx04mcu0avdsxrnsnwly7yqf007nkelzd0twcjmytddncxr2znyhvw4d67ftkt8k48w2x8a0h5hscxew2l7z04v7duq6nlyfkczhne6hnp2ayrjrvvyepdvnwaunayl0fr4w42dkmqnj303ddu2jjrnf3p0qh4wdenx9uega42yte3cwsje6sadh3uxf25dmcpu4jh6zwrh754saa7qf52t8vrfkh54gdadnsk3yfsty3lwa5j0jl804ecgtn4j4z5rglujfzyk4ckc2q6fn37ldwtr45ys8ekc2ryy6r44fkym2npj6ma38wmxsx2ug02nmnkt6ur9rd0mrhc4qzdxutdn7wyxyfkvc9mz600qeqwt09xyvpnz5j2wnnv6wxuava5h0g2sfg38wlq8k77dqkp9xuyd09a69h2rujrw0pdq4qw26jkvjwkvp7lu9aqnhmus87pq0yt36yywlg527yq465cmfuxrl397gt7gaj4z97lfkmfz5kqlurgs6jn93rpgw7ymc7du23facsk6q5txaeez5639ewqhld8zrjwy29ld4hksmw6fpk7kr0da6w3q6wt8gdte2tl9kp3guevzh6rzd22zx7mzkgyr4u0zzq5zdyn27wl40ht5e6zpggg0r7exjh68heazhkye9jd5ant25a8hg5v3xlpmnjwzv35fw44jt76edtfa9sh0g6ylv3s3lx9ap5xea5xcxc8w5t6jnyaf8qmq73gt57v4nrhswy5t5fgp96kstc3xq49wy9fxak30ehkscqr59fxmsweqvyk4adhhqx6l73xzgv2wj6gjfl3lsqgtgcrwq3f4cm4ctzuh9adguvu0vmvc39ur42xktnkqulsmwygjpkn9e42at4phc3nn0v0cc7qya8c0053kxgqj7tdcyr09z6nv22qv309vgv9dds85hhep2mq2y95c7tvjcur0l0thz29w5vzd64afvessaw0nqaer09qmcplvgdy408me4e4kfn6zn509pyf8cetzs5n4y42wl2es0qzyjtf4fwsrjvt7el7grt8hhk3ls2pymaasrsp6mkqcmyzk9j023k8wxdkl4g6anhlwrfaenjxrt4j97g8ds0gg233zct6ewwrr6rmc5us74ypf6xpu2meg6674jk7wujrrrs8mk2n5n7vnz39dq4094uztxmvrau6pmv3w70uqhncph5hgwpfq53auhcz74cnh8wzgappnaayret7xf9dfud7gh35tesmv5z8u7e0gdmjpar35wfk6ml6ldzwnwtq7kl39c8p40txnmcyk0uhsc8hp2yhmqsghjfh5n9paz76a72a9j3nwughm7xpuvfzzry94dwfvwrdz2fkq5u9xm6v486p35mpx606qpwzp4rs5mw9rpcaa5qdt5wuggcjgc5ztg2v5c9keq3e7a7njgzxcay8ykxxg5lnsx5548fhl5etvt6vz397mrkj97s5f7xa7tg222heqjzxwlqg7fwee900znu0l4nm8jf5hqdv37j9hmrw0vj972le397qp39wphqpjfur6fl6sct037pt5hfm56ngrlgu0e6q4ggz4mrv9r0l3nyjx70dx8z542y9c", Network::Main).unwrap(), NeptuneCoins::new(500)),
                ]
            }
            _ => {
                vec![]
            }
        }
    }

    #[cfg(test)]
    fn premine_distribution(network: Network) -> Vec<(ReceivingAddress, NeptuneCoins)> {
        let authority_receiving_address = crate::WalletSecret::devnet_wallet()
            .nth_generation_spending_key_for_tests(0)
            .to_address()
            .into();

        let mut addrs = vec![
            // chiefly for testing; anyone can access these coins by generating
            // the devnet wallet as above
            (authority_receiving_address, NeptuneCoins::new(20)),
        ];

        match network {
            Network::Alpha => {
                addrs.append(&mut vec![
                    // also for testing, but for internal use only
                    (ReceivingAddress::from_bech32m("nolgam1t6h52ck34mkvvmkk8nnzesf5sdcks3mlj23k8hgp5gc39qaxx76qnltllx465np340n0mf9zrv2e04425q69xlhjgy35v3zu7jmnljev9n38t2a86d9sqq84g8y9egy23etpkewp4ad64s66qq9cruyp0r0vz50urcalgxerv6xcuet6j5tcdx6tqm6d772dxu29r6kq8mkzkyrc07072rlvkx4tkmwy29aqq8qmwwd0n4at3qllgvd427um3jsjed696rddert6dzlamqtn66mz997xt8nslrq8dqvl2nx4k7vu50ul7584m7243pdzdczgnxcd0a8q8aspfd66s5spaa5nk8sqfh29htak8lzf853edgqw99fu4v4ess3d9z0gcqjpclks9p2w5srta9n65r5w2rj89jmagtuklz838lj726frzdvlfj7t992hz8n355raxy2xnm4fpfr20zvk38caatsd74lzx370mfhqrakf6achx5fv858wpchjlmu3h55s5kqkmfu0zhw05wfx7meu33fnmw0fju6p0m940nfrsqkv0e8q25g3sgjk4t0qfun0st7h2k4ef6cau3zyrc5dsqukvzwd85kxxf9ksk6jw7k5ny7wku6wf90mx5xyd7p6q5w6eu4wxxfeqryyfw2rdprr7fkzg9hrt97s4hn9cgpr6qz8x0j59gm885ekde9czanpksqq0c0kmefzfha3lqw8v2xeme5nmf93u59z8luq4wprlxj6v7mpp80t3sjvmv3a6t2kxsh9qaw9spj789ft8jswzm2kmfywxn80caccqf4d38kkjg5ahdrkmfvec242rg47ewzwsfy590hxyvz5v3dpg2a99vwc20a749rmygj74k2uw794t66dz0n9chmhd47gg84y8qc62jvjl8num4j7s2c0gtc88t3pun4zwuq55vf66mg4n8urn50lm7ww4he5x5ya4yyaqlrn2ag5sdnqt46magvw90hh9chyq3q9qc36pq4tattn6lvzfjp9trxuske84yttf6pa3le9z0z8y06gv7925dshhfjn4y5y3aykfg2g7ujrlly8dgpk3srlvq0zmdvgu5jsxwqvngvp6fh6he8fyrlqgrs58qklrg3zyu2jl9nrp2hdvj3hwh29fk5mjl9tpjx0tnyys5gkqlvxxhel4yh53ms0rxpkw3sa6teqgpe4yej5sk7edyqn7w8xr4mgm2asww53gzv95fwpud7mzg4rrnpvdk40m0vna8w8y0w9y240r6m7ja58gfk3stfra9qsm0lt7npkv4w0ghzypdrrg04kp7kkepnm4qmwmjxdg2tx3ejtdmzp0w08alv7x3zxgxsu35yhlvrnkpl9mxgejkfcxdgccper4f7llaaux9hcpul5uy47lhr065qwkgxc6jfylq5raqeczryz089syr4aj7z908e4e3t49qd40x3ueyrgxcdj37dkd5ysezj45kgtv546e7m3fj8ga920lztrgmmx0a98qwnk2ep5k9qh2x05mm5snu5d88lm4lrad8hc639jx97hrx9mywkw6c7yvj9jv0mjmsq0xqpqt0kc4hsh24kndhtsc0ezfzw9h79mjw239s804t2f4jucd3x57mvvnsyp82xy9jvp4yzlq5qhrpu87frkfwkx62r8rjsdkdlx4yhss2ly4q8425ta3je6rym35lapxesd9dhsj44pfhmq92g4tmfr8qnajpn2cgj8ngtzrkc9ygsvx76633p8ksru7g8cda5dfnhf50ax47rde5fhnk8dt7k5sltkhknha697gyqsjg4hytslxmaazdjqj4earaf098uz6gpcgu27zsy4v5arc3vjmum90ngf8e00exjr4nsqs3wr4w93h42ucnllyu5ck09yundjkjqsqetrhzvc3q0smssg6vcw9hlns363grqyt92azpvml632wffpuq5wtsh9vxwdse0g0w0wl3e320hnp3vlmzde3c8xa42yye90gnmmyjdq5atmlnulga4pcapk4t6ut82w057ed3rawx42vn7rl5kzyg84cvulg8yfjeu3ff0wprytkhk85dr63u9elq5ju0c9vd2yyjkqnhxh6xwxnt4nw32pefm9aengdasjn7lsyaeldz93spfnn02uke83xkwytj0wkxhgknde5jnjgg6yegwuw8rklvh6cvyvzqkgwaj857cz7xt3u8mhxlh8xevud3vj5dvq6kpxqd4jftt5h4gcmf9qpj3e2nw87j9une3vu75ahewdrqg7avfquw79fva59f8f3xpmk6lpmlkx9x7ejaw97f8nu86r2yhaepr50cdew82c3fmpnma2gr5vatjy3luqsyf8fpqp2zrjzcymemt3f3t99rn689ucyaj8vc2eapgw4knjyaque29hk3t7swcdvrwcf5myg33ghmg2s8xrqjwzeghzmqq68278lrw5rxn4jf3y93z7ztuwz67s0qa5lldcqe44qsshpuxx36dmna5cn7yy5v5f449gf26hygmj6qk8hm7rkvv44w3cu9fdv7sq0hqy67p3tvyxc8fl640z7pdsjfraznvqpnvcepggdnf3qypgs8vu82wsj2yd8nkhfv6sv6xs3wf5d7nkqsd5k8ehk7dtfqnsvcz26yazc32cv669qn7dhxr25j0etmmz7xh8azj7dn0d4u309m0rc2yhfegds60smuqtxn4l4nhmdqj9x6se4sultl5cwy4qja66cvnjz6mqwqet4n5zcswywqd6gcpec4q2vek9g4086ys4x35hwa47dk3zj2m03yuqz7ap66dah3r73j96q00cwmqw0lxvvqq4u0kvt6vrc0urd2hfhrxkrkmr9yx48uw94vmnjyq7sgyc0szkyuq07cjhg0fhx5z5mr9ua24wx9qnh32cjult3mu8kzhlj7se2nm4jr937j64656q7vp98dh9dhvlge8p02ejse5r0nsk22aa5cexvuqcaulnxw690vm3vdagdckfwps06jjd49kd4ls4jkf0nxkhqx2rm73pcepr4u6xjxw2fhjptk95tt0rq2ramq57lfg3sw3tsee2af355lt53w4f5wmpcvctsntyl2sp8m04l3nds7acv4uqnznudmkasgdf7l9df4484ym2njjzy0c26v2zv7pkv30f06uuptdvuxmgnuqcgd4els7gehp0fwxam0vskt34e3z3kfft6kkdz2c7ftn3dcvz5wvpwqf8458ade6995vdkxkalqzfs5epjfnn3c27mnzlx6cv5fhlephxpa3mj3hu6wafd8em8jhzcguru797p6m2fes55ha23putxrtly4wufl6rpp3ydta57zcxl40pvhpps7sgr7zc2cvz57xdlxpvclsjdgp5q3up9tu5csfdkaa762mk7zrqad93506l0kj", Network::Alpha).unwrap(), NeptuneCoins::new(1337)),
                    (ReceivingAddress::from_bech32m("nolgam1hfgnle0202fgz75wh5cqpxkzz29775pqudt9z9v0s6h2e3gkfqkgv3xqn4xfq809k880cspd4dw4mmmcy3dus2pyxwcfysle3hsw2qc62qk3d4hesv56q45d539s28e267mzdvcgyrnwuz358edzjcpzwkep3wxccxrss7qqj0806uff26waqg2z37g7g8erew0eyaq83lv4wuqhql89rsmz8gxhwna4r2s48vww94vyvw9xllydqfygc8890qhhxa2sr3p70p3rdkgt7xuulh66uarnd3l0e0wl2ld7hw4klalacw6yk0u29g0eqx2vsvz29krw9s5n8vfckazhmx4f7393lxwp8aje47j9fpnvlgqr9p990qrmhx9vk8pvfc70wec3fn2c7sz9mttpzv74084pzcmrycqwd5c6qv95ks8duxv325yay48xs9zlgtf9d0zleneemhwzwknsct7ea7quj00359urmuvsvrftvht9wmhtkdzwe6jr6jqvjyn8ew8artcme97smx5dxy4m8yug67xcpfz8chtx0t7eerce7gtpfdn0cryx4s2erhedxk883jykck9ryj3akv7pqrvyldy3ruckgpcm9g6w6fc75yt9g466wemkhftx7tp6uskcvjnvrpn6wzadp44qmua3c23c3pylpdcx0wsv5vl3rspn36zwuzmzpma9ndpppa4dluqag8kfw7xj055szhrf4lsyquxmxq2efp74y75e535y3mgvhqgultm2f7m33hc6vk8ztymz59efth64msyqkmqx5mshm42kqwhqvznkw0ezmh22lfcd6fsh0l4gdujnmz7yfvyfdajkx80j87zmz2nhnv50qdpqjkrhem9ankxw3f06yhc6m5ltfeyhm7nq98glcgtljwss2r7m0gl8d8p2hlesa6cm0ld2y8s7prhz8gywl20dh89ve7qknljygdd5w7l5ueykmz736atgg5vevludsdut9xamwmtsye0fca6c2tl0ne8wpnsdljttt97qrf0mxemdm90v44v9wqet0utf4x0ahqqrlhf647rytaesj6j7dzqpan03za3lkqfcx7pymngzwl29rm62yklh3p884e5hz6qdwfaz98lsq9lke5ntmg2w55xvraleegkn6nftdr2ztgs58zfndpzafqs6v7tcm75hapw6hptzqwnpfwcvw38ghru55y003xm76tsd2fe6565fv5snakw74act2k2lsfg8ntaxf62ksgusdt9a6pw7mfypv2n2y9phddpj62yg93fxyqcujxw7vjced4eteendff28nmwmr3mtclyqhrry8palcsekavj8dstmkgezw6l3vq98p254mkxxye2uumaw8zh2mzvuqsgn0jfkymq76rlvx2d8e2xe6tv34vtpr09lhlehh4cwl48mjq7h0pnwlkrxyf0k0scw3szrc6wqg4hnc9whpx3whmdd2neme9j8lzauzyq45fqks6qt5vmq7lqx0a0flurpleyaq5466dzajma5vlqlgaggxxs3r3glumrpqtu6pd5mnemnuuc6f4gdjr65jdy3em8whcxwjnex6smkrxv5kjdag7cx0j8m8cg26hkkwyra9a0xqauzu0vaxd5qnx6cpm0w68evt4v960axzzuaevkagsyft9df6tnq0g2yqm7w7frht8wsxy4s0p227psd92d3vd5t45zesrvny4lvfvkn0cnwyf7p60gtx3er45xs4u4zy2ntrkx64elmp8k4v6kv0w8sh76ychxn384m4hhrrg523ex6ux0fhs63fkk7r68p3jlm4wcmxvxt872gg930m30l5v9vw6g4txy84w2wvvh7vxdu7tq50we9yp7x0wv2f6kfe4dthcmp2sjxf5l2myhegj3u8uz0m652flmsdyu57f8ncszjtkzh44afw4quw4j7dx6m322p6q2nkcw2x0n5lxwr3u2qd7t2rc28c4wgzdfgl2qvqpf95z0uv5m7p9crhl2hjzje3zqgyzgxxd4zku3yuhmj4saqeff78r78fth39p6mryyk95m4r76x30etzf7mcaudthhzrw3ae2fts576kh0c5ksnnzamtyr8ak6t4dn86a5zupn4kv426wwy7j688aasxupw7nu9qvkagm2a44ssk88ffyjxznrjtdln45vejx5ghaewzju6qze507shwtmu8evxcxv7h4axwqyvufxrvsmw3n88600af973r3k3nn3crs063j7ncc36luckfgajmqu6qtxt5emyzzmfy4pp9u4swfqtacaqgqmfjmmzansw9qv7zmhzz0wzllcv8a82f6apyt5kgrkdxg58a854rc4940gq2wy6y8lwtrkp3uf9fgms64d5d6990jzrfcr7xdkwp3fh8p66q7mfu03wpk0jzulqnu7dt6qppal3gkxhk384dvh8makve69vht6lcn032f2pavs0x4uq94s2lycmuvrevv6jrf76c90e6juz0q5w3744me7xagrunr3qpg4p8pqmyae4d7gzz8wr2znqg8wp32n2zdegz3qsmct9rhc4w5ne97epn5xdzzfa3rnqqllfqdu2672pk9a5uqldewz3v5haxnrxdhl3h52srthlv3c8ythj4m692rp74mzl2wx3svw864weq8437gqq9ejkhmkqnpzwzq7mtgp6c9r6sw2qqz4u2688wqet3yxf8rdqe0l9r9glhl5jq4arrx5f45k6l79mn9x44mmersqcrk3kmyfnptqe023rk5349a878n6qymd36tp6pvpxyxnuksyvw6yetyk4kvth6yqx5ke0q2v5ka49ewh787pgz4cnsvc2plyjwky8nurldynf44e9h0vaeukdk7xhs3slfydmmy2y84lez9uwqkj76e68fsws4g4jjlck902hs6ymmuhw52th2e82myf77wcxph7ka75qhhd4x35gd2lz8rajhjnfnns65gp3kqmwmq52st273jx7xs0xpper2s0jawgs38s3x8ggn3nk7a8k3dwlr7hry38xgyyjpvm6qlwvdyv5sau6a0rdyumrmut6uuxk90jqm2s4mp9u5rnyasedzeugegcygj72u29t7t2swvdr4mwrynryusp24d4s3l8ppj7tpks2nj8a3tlwzqh2feew6swzkf839lczs5rq4pcvmsgcy5ck5x0p759vwzqxwn7trtg0x7grfzpdc50x8zudrwad7fye8ca2zc7f8m689e34u003wc5dzs32cd8mxljkdpt4elasxcxse08948zeq239k8c442yffxz85uyqzcjyc86rfw3g79x5h3zkjq35t9v8vwskawag2vzmjtrmn4knst75kf3pfgt3mnkavs3fgyq9nfut343nmne8cct4uhj8zp0hrplpwf65kjvw8gqwstyg0gqejy4aur5", Network::Alpha).unwrap(), NeptuneCoins::new(42)),
                ]);
            }
            Network::Main => {
                addrs.append(&mut vec![
                    // Actual premine recipients
                    (ReceivingAddress::from_bech32m("nolgam1v0j838fvl7ud8q964x7urcyetufmy9nfllmy0xej9837lanjl2vfmsar7w2ncraxhgpxg4d4pntd6kmjxhgvhjcdelr75zj4fqvws88dfunsn6fj0fnkxlch3rqcdstmpv28v732tvcvvctcjxw3drn5gpygmflhasj5zu043vzr6hmjpt4tedn94p4mzerp69xp9d8cx9u697f8ds4vrw7rmpk74lk06pt4q0lx4d5e7el5r0fywqxk3s8dvgxtehlvpde9kkt7y654ddpusmn0yhr4whgvh4nvffp2eahnvmslhruwymzpqdf5c99l9redvtuk9kg32zfenwjqkere2xltvfhqfpm54cxltcj8lfr5ttcakytztwcr457jyx6yuam6dma7khjkspx0nu0m5kut2neja956hkj3p3ej8hutavv2zkmygff4gca55hd6apyhhslsyfs24s60ldzktd7hj7gkdtgfm2l8vdd8pkuh02q0k3ce6utpltzpw6anx8zk8jn3f8kuansk3fs98zlxxpvqrl9w2ayq9axuc64lfvp9teluwhvwc7w2veujpqk3jxdag4d9uav7tt9lc02pnejw8v2fvl03a50jra8mf82j879z3wklw8n357fmtaaf48e8xaak7jfz6a6lmele0h8yhv6f9kf79ashn3sggh35kfqpx8wevnku7kz2kdrj4x5m3y4wze47g3rp3xvjpmlqx6yl7plxg8a33ljm0c09p2v5t36j2ym7t5u2fpcjvvy92vj3dnew8729u9lslrzuxa5yrmf3qntdegeq3hygru2uee5xya3mam2aejf285eh843vxkdvg8xeqg9lfyjkdgamchweg40srfju6aef0v3ads4wswyw6fyrnz8ltdhnd7cn0t7ucpwtdhfy8jcw94fygks8pxcuuerk0smkwrr6wvqegtdprtfzpya8c8gx9n8weaxjtfag7h7vqw957ncwkmfj27j7jvjewcapfef43ujgu4clyj8jhzkuyrlvgxz3vf2wdx4atl7l89q9qhwvtltqne4a0t64zwpx87aqkcvjysnuf6ct9h5uxyp3768fglzc6arvs00f3lznppgnuakzy0k7aw5620eddfu7eq0gusc7c348ng3yl85hm42y54leyshyfh4lhadzj927wl3sw4l5k00l4cwamfjxmaklp4e7qny3jvjvzkzs33c346prn4reljyn2rjpurms9ha2jcj55dfpwa33cj73nananj5mvy6s2w8ec0sftwzu2w0w3smjv3mvvf3glclwswvzrghy6jd7a2vtdr4dtrrw2tdfssvpa6qc2955f27rgrqt2yg2h3xs5qy94xtsz6ufjqtafl7cffhja6e0wznf8qnt9wd6ng062x9pgztrh5pvhqjcud9nqdsmydumz9h6lzneawln3ds4y8zfvjcnq4h654ypnts7wfwty9tr65nnmjvprqqrss9js325p94kh5yctshlkhuqt4705r5etgzavazw0w6l9yra56z9kxzwjxfcar407tfaw4l0elk3ddr54c4e8uqnnlg8gwuzsd84dmefvk958hmzdxvg2x5r995ez6y4wkqn08gyrwejf9z3unjtx097zehntjlklsfmfk2gw4v0eh9jd6jr0ztz8m22t7ajse3w8yyl6ht34hp8pdzr0qa0vvqyx4ulft6enutr3axjh9kdrcjzh28ky00vxkln7nmqp8xe9hvyqt2s2qgp8g5lu6tkmzav9vy7nq0ww5vp2x56gf6y9he6nm7f4xzqarwy52nan8m479h6drvmdnaxw5scddgwv669gpjwg7zd352tagdgwxz5gl9pvdcztzjur64jkg0hed60vws3al2dt3az4gfn00txe4c4s8djvzmml06degdccsuxnmxh3vrphjqeekqrgszu8w9jwksfrayeyhhlzxtzejgxy4c2apv4rknp0dq7rf6us2ns6zlkwpmul70fj3xv30uv9edcn87ggy55trph5plhzvf0vp0pz5yvq8p9hgrq3pl75wnvv074v9uldnn5tej0aewedvulv499mamxu88g3z4spactyzhl8jtgrypquasfvv2ucucg90lslzvsnxg5q2wgwc9c30ru6jf5ktmjfa3jm4whead4ln0l49y6z9l3p0eu4ax4qpns3kfuc5a6er5lltf65pxe46yaxcwf893wdqtaj8uz67t50nkwztwmp427auy65ck7506qf9ullc23vqy74sj2lnpgq84vtfyz74ywxza5kxzs4a3xtkvgg7a07u08dnlwqkkhkx6jj2srvsxk49nkutd3cd526n62fe6a9acmpah4l3uapzaja2y9cx3ncdmkpry7e869svyz7m0scm6vsyj9amxpctswkdft0tqp68fgyheluuy95x07m64pe45avnjcchtgulef7yrjqzmauhpx2j8xe9d529kx5j8wnpsnwyycduz59588hn75zzg09skrpjhe8mxj3ljds6k3p563n2n2v7w3d86amphe2fvu0ay25qcfqq39znjk34l85pxnv3q7ftl4x2cmkkr7gr3tz3jn72jkcj4xa92lzu0pp58mrp06gr8dual30y0r9pn5aeasggymtmswgpeyxqur8yqck75pfykz8lzzavwgv0fg43uly70tt4hs5e64hvn0t88w3j0wq3p34scwc5kdl79yj0xyz8zlelhr0yzn4fnwgs6c0te55v22eef7kzc32m8edu8rs5wymk6r9whnwkhy9lh0r5z8xssw7tel9nvsf7fjs8f9pjuxwe8s5nw7xhgh5s4rpfy3jg0kg6asjxrjcjts30436eud4ctrenesptz2x7ngv52h74dy7gaymvujxnxz7xmsl69v24lwj5580ndtrl5uqavt4v6nr85gh7ectvq0mpsyrcy3qaq6pwgkjy62uypwshegzrllcsre9wkau4v4ttv385qzgxt773pqxefs2nyd0wnpd5fk35uewa7gzghn5vwey07rlea2v5amd90njt95zm7umrdsp7l5q92gywjfuzyhmzup75pjxm067eym43vkxp03dcsv0tjsr253yz9kfpe3uw9j9v8tnlhhnrjgywzd88sqagsrdasm6prxzwf4qt4vp7r5f2vzswzdk94gk0mu5gzhnr4se47wykyyvs6ugvc8gg6n3sv5f4vvht0m2r9av296cmf2jdfs52jw8r05k3wqmvy7xn8frz0x2vc6wa66cmll68k9kxh9hj8dv59x96d020fgt004wwxpgquwl8mgsxm9tpcdqr55mce3ep3ckhmvjqzyzplm69xza2nrfjjcc82gp6y72s6e0cmwvw2x4qhjfp32l8jnr7njckl2yacscqffkmmtud7e2ttqrppte6v79rm0chzqpyv", Network::Main).unwrap(), NeptuneCoins::new(2000)),
                    (ReceivingAddress::from_bech32m("nolgam1u9r0el5lvaz4883zzf588t0rgcm87anaxvgqq5e3ptzzzxh6da546lf2vhtwkfm29thvz6m94u6twxvzvve9m2ucda53fd8z80xt29wplnuq40u5r4pzw9k7eyexps2q3hsdqu5hhzpnpq2wmpq4lcfj4deqh09tdgmkuvw5y7ay2xqaaj0xc0aclnwd7qs7asclsvgr9r225alnfyf9x09xutyp629s2mfts2un2cmq9s07xwllw8cvsufulxmacruzfyxx9w0jkksys39w47vvgehlv6ncuzhl7tzrvj79xla9rfy20f2da5nptw9h5h6ua8dsn8q0qz0d7y5ndlcqz3whr7h40mjxgg3ueycs7zz9r0rc3znu8vph74nw22y38h89zy20lv82mekq3xu9cumytxqlsnugjs5tp78mgm3prpcmtzezgwzl8vntm00n3x99hhdvsp8lkjuvnjndxyczmgl554xl96x55djrjnv4mxvqlswzvxnw8lkw87f959v2pktmeg3yx86ku23fsfp0x8jh2te94vuk9ahwp7zkaw4njjsjp6a79qvxfcujwr89xhwgzzfjffnj5vusye7907s6vzgfms6xfzu07ugwr3dskakjazre2mn4xvxpzznjaatnztfla69c43x7un4er2c8x06ucwe72gzt9xvh487q6l8dq2ejwamfpllw5mrarrrvf9wu36r8pvwa45ck8005060lk67y74f09dz2h780ddruq79a5racn05gepc2qr0s85n8550ulvcmqzv8nmwxetaj7hl78mg8nx9ftju3ak2uf5ur45s26yle02s5netsdaukx7thfkalnr83f8kp7grajgx4glcknxzkc7326rttl34up9h7c7f7k76n43zgwjg8mwx22cyf0mc0g67kcf3637urst5fl2ez9ja2at7nhr00hug999e7g7e02nu7jxesq07zqdmpwta64zzxfvpwqy4lfd35qmyvm4ftjfdnw8mvglfmsflan5vz466svsq298pm748kc22cvyn35xfy6rzzq73dl8cytj7kchcx6mjj58ll2xdhk2kf0a25ea5quktkep8t9awrww6x6ynnepc8chgnvvtg90ueu7tgr0t25pnurcn6csukvpyvn988ynpmry2lrd8e6q6ur4k9nd3rd4xsrge6nlu5hcjrv2xhv5vmcavts8rapxrr4773u0dthe08pd3yu2vnetkk28k08ae6t3dchr2hlfq6tlmnq20taj6xz7uq7wccx30ntrf9h7r2r5tgmpd6c7m3vgq69qtft3xlw8qs8tc00j4vslhudmv2cgd0mgncgvzrmvetrnt0zmwft9c6xkeyt609cmxc405jzwt3ysj249vmhh7heq2j7524qthgsu3d0ns9rc9amslk2anscy67rrn456pe5kjcrr9ft9javak5gl49qtyegnyuh6r7jgsfv3w6v8zl6zy2qww7v7e3yyvdmwvfhfusuj9kvacrtwpa55fm283ez4jyz5t59esyj4df0qnly0vn7j4h03zyhquw6psxcu8zwz3edylauq922j6ggrztsyemaj6wm6887saw329kg6gpa78zp89z5vwthawkagh9tf5usjsdqqdlj3v0047ecwshruz2u9mr2fnnc8m0as0qj7unpvyhlyem3ud4refpwx233hg2gtnj28duea985zmr4hmq6dzq03sp7jglgvx427s75u8czzxmsj9uyasq4qke6nanxmr67xekf60p3wgakd339ry2z5nkrey5qwtewknrvzaelnzl0nfwzlvkaws3mgng8dzy6nx5y097algffhh7ln7qt9uetuz6jehtctc9q6jevdvee2g73lsqxmel8decsqephv3cdtrly0q63ztrjx7hr0tudfuhy402zjd9yg8227x2ve2eda8qw9hcw5lv7ec77t77fqdjpu3stn6rzlvavupd6vxdf4nkm743xtdu2c5kuqhl8z449njj3vqu8q3x3t60lc2cppedllv2wy6xdfjlnk7mjuupesl5z67f7qcjr349wj4e9zg5fxy7qax2j4sgef86khhvnhjec9u0v79n29ah79eynj5utvksvuwp4zreceq6fke7x0pcte8s2506u3kzd46ps06znwydz9z727vsdvalnxlj4v7rdeqnrvw8ckl9pjt8fpv0773lydy3n6te63s37729j897d2emfyk0f45xmjgzdrsmtvpf6ejc0mljque390su0lf8yvd3lsducr6cvnagkkketfxxha45rvh9dw84wpl3x8skzjh54ht2u7ljv8mxww67lrfgq6lmx7vx0qdfwufz33mpuychkpz2hr00ptsshuukp4yrn95v2qg0ldumvx07lz8864kq4rwmhedcd8g6f7sqyewqqxz38drudukyytany97t3m7sp2zucntlqpk860kggcf0nydppvw46gyrg2f8rwq4f03y5w560mqgf4eaumkq74qzzh332p724pap7lhqv2tru2562aadlvyfaqj433zmqt2qjerz6c6p8aqq55wm98xsjp8d6vzsvuj07k5tlqqjdjanwecq9z3k86dcjc38hdgkurjnhmtux5nr3u84cjkzp5qxv6k86z4jvl73zxcc66uk2278jw5tvkr36j7pqnkdy9xkhdnycu8vlp4sne084e9r37n34xt238a95ntws0knuxlx5xkw3g3p7x8qvn2a9xey5yxk9zrupr4tf42lc7qx0thwh4mga63ucgkwffkc06kw58rh5zx2vf4yhdpx72lq9nwyvg0vkuhpjyswfuulesdldsrym0jm66zh4qyw96zc26xnk9ltd3zlpyj8ql9r3wq8sn8ww9w7andwx0kgqa3d69mnkz5mvydqls4zsm8npk8s75fgf4h3n666sghn72ryfn9xpdvyqk847g7w68mxu6rq7kvfrwsq4y7a3gt84rfk2cfkdvrraxecuzp3lmr6kde8gz92f2khrhynwe4dkjwrs9lhs9xkpew0jl6drfh945h9ejev8l8s4scrnc5qu4g94hvpswk7a69x6wmz3hv3h6s6udz2akjdpq2gmm0zq9r7llprzan7ls3l3wpcmjh9dlzg0e9tjvqngvzptksl9vzjrnfhperw5xkvaaaum50062a5wpz7uhrjxesrxa97r4vpv5hmuywrtwwlpzavgfacql6s6d5upvy8506ma8kddtmak0hwm55cxj0xw7ntukq20x076krwkcsp94hrq9k5uxp9ppdeyzdju7r9alushp0q0pw47lj99ah74g9y7d67ndw266xwlkar5zukztf6ffzcaza2p23nlqpgcsv7fpgvu86029wlfv6ke9hvcwqkw3ddn0rul6h9trcs04nnvnzukzfpf4nkz87dqw2", Network::Main).unwrap(), NeptuneCoins::new(250)),
                    (ReceivingAddress::from_bech32m("nolgam1jv5eueyvcq0eyej64h20j2k56r33rev830gmdxe038kwqjrcr3n889wu7at7njguhfkzahe6fc7jzpjrv5v6q4mak0hmtwsuj2g272e9yjshvwqlhuj4tsfhy9kkepa3068lxye9ta5l48zck5wkx5zj2ww3zfr3gk7pfrx2mv8zc2gdx2qwh43wjv2ztpcs5w0kfkalt950eupzx3jd0xu56aaumeg5try2vfdy49l96pzsetre9zt97skm6dqrckm8543suas4udnlh0l8a98rdxyljuhyk4zg29pculzdjr484xfeg9dfcf4l2ans3rkglug2hd3khczkwlgejv4wu8rxxuxcmg38f2qyn7rnjm278npfeh0fzn2q8me9tmxx4vg9tn9j36zv522fdg4uqvncn635v9k6hegwf48xffh5r3tdz0cm4hz2tatamfw4qtsc8mhnnsvwq4zv795kvv3xvms92w22trar6c2xsxsk9cvlpnq0aje7gq90h979v5vlt6u240yhck5mlphu3tftyy27vrh79y7crx42yus5y78dsml3w0wd3k68ykk2f6469yrl8mdf6c4d5pp7qav2cahp2gaf8qedggvdqx630yea3zvkrxs99p0ahys8pwr9xrzvjl9uq49rtnwtx78ad0scpsvp0ty3y2vu7zqjq6jrwphvndkkq9al0phgc36vjj5mlzcpxj87yp94x0ysuupmmc3z054wqy5xn028hwlt37yuh8f05m95j4xeju7c5d874qguw4g3v9nkcfyusrqhj3mk4fjj84zl4ttpr02ncj49rqjf8vydtyf4d2mtw0jkr68avrs5zama43v53xw0nvy0rag9mes3f7hw7ye2hfx08jjgjwk8q6zwc653jnvzcznenc5lqw456ww0s0ffplwwqfp75c64kvu4tcc4jzmg8fcqt896zaa5tv4hpwfgnw8yx9564g4u2j43er55znwez22s8qnqa2aqxfph99qvlrzs8pmrw95x5pnf4vk56y7f9dhu33xkczf449qmtr8fttnwg5pqy7a2wuz0x5n7r6f4gnytpyuhr6xfx3q07p8ze9gl906y2nlyhjad2kx7knzcxr73texmc8v2fd225duywrunp329qr9r93xxfs80sk94qknnxgd0grqx6mssdrsayl7ygkvehw23fhg66zzldv3njyhdyrfpmxctnm5k2l4kaj5wt35xsk3cn0yz5pd8jx045kp3akks6pha0qtxzaevze88mar7umrhqxfq26sfxmk3hzw3s66yaz8gdeck4krc7kjc0vt0fvltf4msyhehwep6clwnfyxrsgwnqxxxdydm0s9j3ezeuvj267ptmnge8zvskn3ceuut957en6zyvkerrdcgs6a3g7hft4kppaqkw3ut4rl5t8reqkpqwluy7haays630hzgwuwrgqly5emapcswdy3v6tneyjc8qsd642xp0hue8dfecmd8cjh8e0ua04tmwg4n52xx4d49gw7rhq2djg2x976kyn0ukg8s2h09k7swglgw8mf9mp3dccrsfrynkrqgt2tnsr4e5k5pdet6nllmersnmcy6xd9szkfdtfyvjplq8edkvjts6zpa5l92ew6ycfwrk7c7ful4madmjtvhrjnhqcvhvczhmgp07hm74g2jfpvtrca38pvxnfllyvs4fk5eg3m426fsepfkp7d4283zz2j285vpgkxn4tgwk2wvt7wvuxc5capvmttt2x0hm78aksm7f4gzmvc5s477jhzmn5843dd43zef9xap7fyfcdww308sjdj0zryarpsltxnqzx04mcu0avdsxrnsnwly7yqf007nkelzd0twcjmytddncxr2znyhvw4d67ftkt8k48w2x8a0h5hscxew2l7z04v7duq6nlyfkczhne6hnp2ayrjrvvyepdvnwaunayl0fr4w42dkmqnj303ddu2jjrnf3p0qh4wdenx9uega42yte3cwsje6sadh3uxf25dmcpu4jh6zwrh754saa7qf52t8vrfkh54gdadnsk3yfsty3lwa5j0jl804ecgtn4j4z5rglujfzyk4ckc2q6fn37ldwtr45ys8ekc2ryy6r44fkym2npj6ma38wmxsx2ug02nmnkt6ur9rd0mrhc4qzdxutdn7wyxyfkvc9mz600qeqwt09xyvpnz5j2wnnv6wxuava5h0g2sfg38wlq8k77dqkp9xuyd09a69h2rujrw0pdq4qw26jkvjwkvp7lu9aqnhmus87pq0yt36yywlg527yq465cmfuxrl397gt7gaj4z97lfkmfz5kqlurgs6jn93rpgw7ymc7du23facsk6q5txaeez5639ewqhld8zrjwy29ld4hksmw6fpk7kr0da6w3q6wt8gdte2tl9kp3guevzh6rzd22zx7mzkgyr4u0zzq5zdyn27wl40ht5e6zpggg0r7exjh68heazhkye9jd5ant25a8hg5v3xlpmnjwzv35fw44jt76edtfa9sh0g6ylv3s3lx9ap5xea5xcxc8w5t6jnyaf8qmq73gt57v4nrhswy5t5fgp96kstc3xq49wy9fxak30ehkscqr59fxmsweqvyk4adhhqx6l73xzgv2wj6gjfl3lsqgtgcrwq3f4cm4ctzuh9adguvu0vmvc39ur42xktnkqulsmwygjpkn9e42at4phc3nn0v0cc7qya8c0053kxgqj7tdcyr09z6nv22qv309vgv9dds85hhep2mq2y95c7tvjcur0l0thz29w5vzd64afvessaw0nqaer09qmcplvgdy408me4e4kfn6zn509pyf8cetzs5n4y42wl2es0qzyjtf4fwsrjvt7el7grt8hhk3ls2pymaasrsp6mkqcmyzk9j023k8wxdkl4g6anhlwrfaenjxrt4j97g8ds0gg233zct6ewwrr6rmc5us74ypf6xpu2meg6674jk7wujrrrs8mk2n5n7vnz39dq4094uztxmvrau6pmv3w70uqhncph5hgwpfq53auhcz74cnh8wzgappnaayret7xf9dfud7gh35tesmv5z8u7e0gdmjpar35wfk6ml6ldzwnwtq7kl39c8p40txnmcyk0uhsc8hp2yhmqsghjfh5n9paz76a72a9j3nwughm7xpuvfzzry94dwfvwrdz2fkq5u9xm6v486p35mpx606qpwzp4rs5mw9rpcaa5qdt5wuggcjgc5ztg2v5c9keq3e7a7njgzxcay8ykxxg5lnsx5548fhl5etvt6vz397mrkj97s5f7xa7tg222heqjzxwlqg7fwee900znu0l4nm8jf5hqdv37j9hmrw0vj972le397qp39wphqpjfur6fl6sct037pt5hfm56ngrlgu0e6q4ggz4mrv9r0l3nyjx70dx8z542y9c", Network::Main).unwrap(), NeptuneCoins::new(500)),
                ]);
            }
            _ => {}
        }

        addrs
    }

    pub fn premine_utxos(network: Network) -> Vec<Utxo> {
        let mut utxos = vec![];
        for (receiving_address, amount) in Self::premine_distribution(network) {
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
    pub(crate) fn is_valid(&self, previous_block: &Block, now: Timestamp) -> bool {
        self.is_valid_internal(previous_block, now, None, None)
    }

    /// Like `is_valid` but also allows specifying a custom
    /// `target_block_interval` and `minimum_block_time`. If `None` is passed,
    /// these variabes take the default values.
    fn is_valid_internal(
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
        const FUTUREDATING_LIMIT: Timestamp = Timestamp::hours(2);
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
        if !BlockProgram::verify(self.body(), self.appendix(), block_proof) {
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
                .kernel
                .body
                .mutator_set_accumulator
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
            [
                previous_block.guesser_fee_addition_records(),
                self.body().transaction_kernel.outputs.clone(),
            ]
            .concat(),
        );
        let mut msa = previous_block.body().mutator_set_accumulator.clone();
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
    pub fn has_proof_of_work(&self, previous_block: &Block) -> bool {
        let hash = self.hash();
        let threshold = previous_block.kernel.header.difficulty.target();
        if hash <= threshold {
            return true;
        }

        let delta_t = self.header().timestamp - previous_block.header().timestamp;
        let excess_multiple = usize::try_from(
            delta_t.to_millis() / TARGET_BLOCK_INTERVAL.to_millis(),
        )
        .expect("excessive timestamp on incoming block should have been caught by peer loop");
        let shift = usize::try_from(ADVANCE_DIFFICULTY_CORRECTION_FACTOR.ilog2()).unwrap()
            * (excess_multiple
                >> usize::try_from(ADVANCE_DIFFICULTY_CORRECTION_WAIT.ilog2()).unwrap());
        let effective_difficulty = previous_block.header().difficulty >> shift;
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
    pub(crate) fn total_guesser_reward(&self) -> NeptuneCoins {
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

        let lock = self.header().nonce;
        let lock_script = LockScript::hash_lock(lock);

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
                let sender_randomness = self.hash();
                let receiver_digest = self.header().nonce;

                commit(item, sender_randomness, receiver_digest)
            })
            .collect_vec()
    }

    /// Create a list of [`ExpectedUtxo`]s for the guesser fee.
    pub(crate) fn guesser_fee_expected_utxos(&self, nonce_preimage: Digest) -> Vec<ExpectedUtxo> {
        self.guesser_fee_utxos()
            .into_iter()
            .map(|utxo| {
                ExpectedUtxo::new(
                    utxo,
                    self.hash(),
                    nonce_preimage,
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
mod block_tests {
    use rand::thread_rng;
    use rand::Rng;
    use rayon::iter::IntoParallelRefIterator;
    use rayon::iter::ParallelIterator;
    use strum::IntoEnumIterator;
    use tracing_test::traced_test;

    use super::super::transaction::transaction_kernel::TransactionKernelModifier;
    use super::*;
    use crate::config_models::cli_args;
    use crate::config_models::network::Network;
    use crate::database::storage::storage_schema::SimpleRustyStorage;
    use crate::database::NeptuneLevelDb;
    use crate::mine_loop::make_coinbase_transaction;
    use crate::models::blockchain::transaction::lock_script::LockScriptAndWitness;
    use crate::models::state::tx_proving_capability::TxProvingCapability;
    use crate::models::state::wallet::transaction_output::TxOutput;
    use crate::models::state::wallet::utxo_notification::UtxoNotificationMedium;
    use crate::models::state::wallet::WalletSecret;
    use crate::tests::shared::invalid_block_with_transaction;
    use crate::tests::shared::make_mock_block;
    use crate::tests::shared::make_mock_block_with_valid_pow;
    use crate::tests::shared::make_mock_transaction;
    use crate::tests::shared::mock_genesis_global_state;
    use crate::util_types::mutator_set::archival_mmr::ArchivalMmr;

    #[test]
    fn all_genesis_blocks_have_unique_mutator_set_hashes() {
        let mutator_set_hash = |network| {
            Block::genesis_block(network)
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
    fn test_difficulty_control_matches() {
        let network = Network::Main;

        let a_wallet_secret = WalletSecret::new_random();
        let a_recipient_address = a_wallet_secret
            .nth_generation_spending_key_for_tests(0)
            .to_address();

        // parallelized since this is a slow test.
        [1, 10, 100, 1_000, 10_000, 100_000, 1_000_000]
            .par_iter()
            .for_each(|multiplier| {
                let mut block_prev = Block::genesis_block(network);
                let mut now = block_prev.kernel.header.timestamp;
                let mut rng = thread_rng();

                for i in (0..30).step_by(1) {
                    let duration = i as u64 * multiplier;
                    now += Timestamp::millis(duration);

                    let (block, _, _) =
                        make_mock_block(&block_prev, Some(now), a_recipient_address, rng.gen());

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
            });
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

    #[test]
    fn block_with_wrong_mmra_is_invalid() {
        let mut rng = thread_rng();
        let network = Network::RegTest;
        let genesis_block = Block::genesis_block(network);

        let a_wallet_secret = WalletSecret::new_random();
        let a_recipient_address = a_wallet_secret
            .nth_generation_spending_key_for_tests(0)
            .to_address();
        let (mut block_1, _, _) =
            make_mock_block_with_valid_pow(&genesis_block, None, a_recipient_address, rng.gen());

        block_1.kernel.body.block_mmr_accumulator = MmrAccumulator::new_from_leafs(vec![]);
        let timestamp = genesis_block.kernel.header.timestamp;

        assert!(!block_1.is_valid(&genesis_block, timestamp));
    }

    #[tokio::test]
    async fn can_prove_block_ancestry() {
        let mut rng = thread_rng();
        let network = Network::RegTest;
        let genesis_block = Block::genesis_block(network);
        let mut blocks = vec![];
        blocks.push(genesis_block.clone());
        let db = NeptuneLevelDb::open_new_test_database(true, None, None, None)
            .await
            .unwrap();
        let mut storage = SimpleRustyStorage::new(db);
        let ammr_storage = storage.schema.new_vec::<Digest>("ammr-blocks-0").await;
        let mut ammr: ArchivalMmr<_> = ArchivalMmr::new(ammr_storage).await;
        ammr.append(genesis_block.hash()).await;
        let mut mmra = MmrAccumulator::new_from_leafs(vec![genesis_block.hash()]);

        for i in 0..55 {
            let wallet_secret = WalletSecret::new_random();
            let recipient_address = wallet_secret
                .nth_generation_spending_key_for_tests(0)
                .to_address();
            let (new_block, _, _) =
                make_mock_block(blocks.last().unwrap(), None, recipient_address, rng.gen());
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
        // 831488 = 42000000 * 0.019797333333333333
        // where 42000000 is the asymptotical limit of the token supply
        // and 1.9797333...% is the relative size of the premine
        let asymptotic_total_cap = NeptuneCoins::new(42_000_000);
        let premine_max_size = NeptuneCoins::new(831488);
        let total_premine = Block::premine_distribution(Network::Alpha)
            .iter()
            .map(|(_receiving_address, amount)| *amount)
            .sum::<NeptuneCoins>();

        assert!(total_premine <= premine_max_size);
        assert!(
            premine_max_size.to_nau_f64() / asymptotic_total_cap.to_nau_f64() < 0.0198f64,
            "Premine must be less than or equal to promised"
        )
    }

    mod block_is_valid {
        use super::*;
        use crate::config_models::cli_args;
        use crate::job_queue::triton_vm::TritonVmJobPriority;

        #[traced_test]
        #[tokio::test]
        async fn block_with_far_future_timestamp_is_invalid() {
            let network = Network::Main;
            let genesis_block = Block::genesis_block(network);
            let mut now = genesis_block.kernel.header.timestamp + Timestamp::hours(2);
            let wallet = WalletSecret::devnet_wallet();
            let genesis_state =
                mock_genesis_global_state(network, 0, wallet, cli_args::Args::default()).await;

            let guesser_fraction = 0f64;
            let (block_tx, _expected_utxo) = make_coinbase_transaction(
                &genesis_block,
                &genesis_state,
                guesser_fraction,
                now,
                TxProvingCapability::SingleProof,
            )
            .await
            .unwrap();
            let mut block1 = Block::make_block_template_with_valid_proof(
                &genesis_block,
                block_tx,
                now,
                Digest::default(),
                None,
                &TritonVmJobQueue::dummy(),
                TritonVmJobPriority::default().into(),
            )
            .await
            .unwrap();

            // Set block timestamp 1 hour in the future.  (is valid)
            let future_time1 = now + Timestamp::hours(1);
            block1.kernel.header.timestamp = future_time1;
            assert!(block1.is_valid(&genesis_block, now));

            now = block1.kernel.header.timestamp;

            // Set block timestamp 2 hours - 1 sec in the future.  (is valid)
            let future_time2 = now + Timestamp::hours(2) - Timestamp::seconds(1);
            block1.kernel.header.timestamp = future_time2;
            assert!(block1.is_valid(&genesis_block, now));

            // Set block timestamp 2 hours + 10 secs in the future. (not valid)
            let future_time3 = now + Timestamp::hours(2) + Timestamp::seconds(10);
            block1.kernel.header.timestamp = future_time3;
            assert!(!block1.is_valid(&genesis_block, now));

            // Set block timestamp 2 days in the future. (not valid)
            let future_time4 = now + Timestamp::seconds(86400 * 2);
            block1.kernel.header.timestamp = future_time4;
            assert!(!block1.is_valid(&genesis_block, now));
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
            let gblock = Block::genesis_block(Network::RegTest);
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
            let gblock = Block::genesis_block(Network::RegTest);
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
            let gblock = Block::genesis_block(Network::RegTest);
            let mut rng = thread_rng();

            let mut new_block = gblock.clone();
            new_block.set_header_nonce(rng.gen());
            assert_ne!(gblock.hash(), new_block.hash());
        }

        // test: verify set_block() copies source digest
        #[test]
        fn set_block() {
            let gblock = Block::genesis_block(Network::RegTest);
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
            let gblock = Block::genesis_block(Network::RegTest);

            let bytes = bincode::serialize(&gblock).unwrap();
            let block: Block = bincode::deserialize(&bytes).unwrap();

            assert_eq!(gblock.hash(), block.hash());
        }

        // test: verify block digest matches after BFieldCodec encode+decode
        //       round trip.
        #[test]
        fn bfieldcodec_encode_and_decode() {
            let gblock = Block::genesis_block(Network::RegTest);

            let encoded: Vec<BFieldElement> = gblock.encode();
            let decoded: Block = *Block::decode(&encoded).unwrap();

            assert_eq!(gblock, decoded);
            assert_eq!(gblock.hash(), decoded.hash());
        }
    }

    #[test]
    fn guesser_can_unlock_guesser_fee_utxo() {
        let genesis_block = Block::genesis_block(Network::Main);
        let mut transaction = make_mock_transaction(vec![], vec![]);

        transaction.kernel = TransactionKernelModifier::default()
            .fee(
                NeptuneCoins::from_nau(1337.into())
                    .expect("given number should be valid NeptuneCoins amount"),
            )
            .modify(transaction.kernel);

        let mut block = invalid_block_with_transaction(&genesis_block, transaction);

        let preimage = thread_rng().gen::<Digest>();
        block.set_header_nonce(preimage.hash());

        let guesser_fee_utxos = block.guesser_fee_utxos();

        let lock_script_and_witness = LockScriptAndWitness::hash_lock(preimage);
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
        let genesis_block = Block::genesis_block(network);
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
            mock_genesis_global_state(network, 0, alice_wallet, cli_args::Args::default()).await;

        let output = TxOutput::offchain_native_currency(
            NeptuneCoins::new(4),
            rng.gen(),
            alice_address.into(),
            true,
        );
        let fee = NeptuneCoins::new(1);
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

        let block1 = Block::block_template_invalid_proof(
            &genesis_block,
            tx1,
            in_seven_months,
            Digest::default(),
            None,
        );
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

        let block2 =
            Block::block_template_invalid_proof(&block1, tx2, in_eight_months, rng.gen(), None);

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

    #[test]
    fn premine_distribution_does_not_crash() {
        Block::premine_distribution(Network::Alpha);
    }
}
