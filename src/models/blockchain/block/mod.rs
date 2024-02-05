use crate::config_models::network::Network;
use crate::models::consensus::mast_hash::MastHash;
use crate::prelude::twenty_first;

use get_size::GetSize;
use itertools::Itertools;
use num_bigint::BigUint;
use num_traits::{abs, Zero};

use serde::{Deserialize, Serialize};
use std::cmp::max;
use tasm_lib::triton_vm::proof::Proof;
use tasm_lib::twenty_first::util_types::mmr::mmr_accumulator::MmrAccumulator;
use tasm_lib::twenty_first::util_types::mmr::mmr_trait::Mmr;
use twenty_first::shared_math::bfield_codec::BFieldCodec;

use tracing::{debug, error, warn};

use twenty_first::amount::u32s::U32s;
use twenty_first::shared_math::b_field_element::BFieldElement;
use twenty_first::shared_math::digest::Digest;
use twenty_first::shared_math::tip5::DIGEST_LENGTH;
use twenty_first::util_types::algebraic_hasher::AlgebraicHasher;

pub mod block_body;
pub mod block_header;
pub mod block_height;
pub mod block_kernel;
pub mod mutator_set_update;
pub mod transfer_block;
pub mod validity;

use self::block_body::BlockBody;
use self::block_header::{
    BlockHeader, MINIMUM_DIFFICULTY, TARGET_BLOCK_INTERVAL, TARGET_DIFFICULTY_U32_SIZE,
};
use self::block_height::BlockHeight;
use self::block_kernel::BlockKernel;
use self::mutator_set_update::MutatorSetUpdate;
use self::transfer_block::TransferBlock;
use super::transaction::transaction_kernel::TransactionKernel;
use super::transaction::utxo::Utxo;
use super::transaction::{neptune_coins::NeptuneCoins, Transaction};
use crate::models::blockchain::shared::Hash;
use crate::models::consensus::Witness;
use crate::models::state::wallet::address::generation_address::{self, ReceivingAddress};
use crate::models::state::wallet::WalletSecret;
use crate::util_types::mutator_set::mutator_set_accumulator::MutatorSetAccumulator;
use crate::util_types::mutator_set::mutator_set_trait::{commit, MutatorSet};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, BFieldCodec, GetSize)]
pub struct Block {
    /// Everything but the proof
    pub kernel: BlockKernel,

    /// All blocks have proofs except:
    ///  - the genesis block
    ///  - blocks being generated
    pub proof: Option<Proof>,
}

impl From<TransferBlock> for Block {
    fn from(t_block: TransferBlock) -> Self {
        Self {
            kernel: BlockKernel {
                header: t_block.header,
                body: t_block.body,
            },
            proof: Some(t_block.proof),
        }
    }
}

impl From<Block> for TransferBlock {
    fn from(block: Block) -> Self {
        let proof = match block.proof {
            Some(p) => p,
            None => {
                error!("In order to be transferred, a Block must have a non-None proof field.");
                panic!()
            }
        };
        Self {
            header: block.kernel.header,
            body: block.kernel.body,
            proof,
        }
    }
}

impl Block {
    #[inline]
    pub fn hash(&self) -> Digest {
        self.kernel.mast_hash()
    }

    #[inline]
    pub fn header(&self) -> &BlockHeader {
        &self.kernel.header
    }

    #[inline]
    pub fn body(&self) -> &BlockBody {
        &self.kernel.body
    }

    #[inline]
    pub fn set_block(&mut self, block: Block) {
        self.kernel.header = block.kernel.header;
        self.kernel.body = block.kernel.body;
    }

    pub fn get_mining_reward(block_height: BlockHeight) -> NeptuneCoins {
        let mut reward: NeptuneCoins = NeptuneCoins::new(100);
        let generation = block_height.get_generation();
        for _ in 0..generation {
            reward.div_two()
        }

        reward
    }

    pub fn genesis_block() -> Self {
        let mut genesis_mutator_set = MutatorSetAccumulator::<Hash>::default();
        let mut ms_update = MutatorSetUpdate::default();

        let premine_distribution = Self::premine_distribution();
        let total_premine_amount = premine_distribution
            .iter()
            .map(|(_receiving_address, amount)| *amount)
            .sum();

        // This is the UNIX timestamp in ms when this code was written the 1st time
        let timestamp: BFieldElement = BFieldElement::new(1655916990000u64);

        let mut genesis_coinbase_tx = Transaction {
            kernel: TransactionKernel {
                inputs: vec![],
                outputs: vec![],
                fee: NeptuneCoins::new(0),
                timestamp,
                public_announcements: vec![],
                coinbase: Some(total_premine_amount),
                mutator_set_hash: MutatorSetAccumulator::<Hash>::new().hash(),
            },
            witness: Witness::Faith,
        };

        for (receiving_address, amount) in premine_distribution {
            // generate utxo
            let utxo = Utxo::new_native_coin(receiving_address.lock_script(), amount);
            let utxo_digest = Hash::hash(&utxo);

            // generate randomness for mutator set commitment
            // Sender randomness cannot be random because there is no sender.
            let bad_randomness = Digest::default();
            let receiver_digest = receiving_address.privacy_digest;

            // Add pre-mine UTXO to MutatorSet
            let addition_record = commit::<Hash>(utxo_digest, bad_randomness, receiver_digest);
            ms_update.additions.push(addition_record);
            genesis_mutator_set.add(&addition_record);

            // Add pre-mine UTXO + commitment to coinbase transaction
            genesis_coinbase_tx.kernel.outputs.push(addition_record)
        }

        let body: BlockBody = BlockBody {
            transaction: genesis_coinbase_tx,
            mutator_set_accumulator: genesis_mutator_set.clone(),
            block_mmr_accumulator: MmrAccumulator::new(vec![]),
            lock_free_mmr_accumulator: MmrAccumulator::new(vec![]),
            uncle_blocks: vec![],
        };

        let header: BlockHeader = BlockHeader {
            version: BFieldElement::zero(),
            height: BFieldElement::zero().into(),
            prev_block_digest: Digest::default(),
            timestamp,
            nonce: [
                BFieldElement::zero(),
                BFieldElement::zero(),
                BFieldElement::zero(),
            ],
            max_block_size: 10_000,
            proof_of_work_line: U32s::zero(),
            proof_of_work_family: U32s::zero(),
            difficulty: MINIMUM_DIFFICULTY.into(),
        };

        Self::new(header, body, None)
    }

    pub fn premine_distribution() -> Vec<(generation_address::ReceivingAddress, NeptuneCoins)> {
        // The premine UTXOs can be hardcoded here.
        let authority_wallet = WalletSecret::devnet_wallet();
        let authority_receiving_address =
            authority_wallet.nth_generation_spending_key(0).to_address();
        vec![
            // chiefly for testing; anyone can access these coins by generating the devnet wallet as above
            (authority_receiving_address, NeptuneCoins::new(20000)),

            // also for testing, but for internal use only
            (ReceivingAddress::from_bech32m("nolgam1t6h52ck34mkvvmkk8nnzesf5sdcks3mlj23k8hgp5gc39qaxx76qnltllx465np340n0mf9zrv2e04425q69xlhjgy35v3zu7jmnljev9n38t2a86d9sqq84g8y9egy23etpkewp4ad64s66qq9cruyp0r0vz50urcalgxerv6xcuet6j5tcdx6tqm6d772dxu29r6kq8mkzkyrc07072rlvkx4tkmwy29aqq8qmwwd0n4at3qllgvd427um3jsjed696rddert6dzlamqtn66mz997xt8nslrq8dqvl2nx4k7vu50ul7584m7243pdzdczgnxcd0a8q8aspfd66s5spaa5nk8sqfh29htak8lzf853edgqw99fu4v4ess3d9z0gcqjpclks9p2w5srta9n65r5w2rj89jmagtuklz838lj726frzdvlfj7t992hz8n355raxy2xnm4fpfr20zvk38caatsd74lzx370mfhqrakf6achx5fv858wpchjlmu3h55s5kqkmfu0zhw05wfx7meu33fnmw0fju6p0m940nfrsqkv0e8q25g3sgjk4t0qfun0st7h2k4ef6cau3zyrc5dsqukvzwd85kxxf9ksk6jw7k5ny7wku6wf90mx5xyd7p6q5w6eu4wxxfeqryyfw2rdprr7fkzg9hrt97s4hn9cgpr6qz8x0j59gm885ekde9czanpksqq0c0kmefzfha3lqw8v2xeme5nmf93u59z8luq4wprlxj6v7mpp80t3sjvmv3a6t2kxsh9qaw9spj789ft8jswzm2kmfywxn80caccqf4d38kkjg5ahdrkmfvec242rg47ewzwsfy590hxyvz5v3dpg2a99vwc20a749rmygj74k2uw794t66dz0n9chmhd47gg84y8qc62jvjl8num4j7s2c0gtc88t3pun4zwuq55vf66mg4n8urn50lm7ww4he5x5ya4yyaqlrn2ag5sdnqt46magvw90hh9chyq3q9qc36pq4tattn6lvzfjp9trxuske84yttf6pa3le9z0z8y06gv7925dshhfjn4y5y3aykfg2g7ujrlly8dgpk3srlvq0zmdvgu5jsxwqvngvp6fh6he8fyrlqgrs58qklrg3zyu2jl9nrp2hdvj3hwh29fk5mjl9tpjx0tnyys5gkqlvxxhel4yh53ms0rxpkw3sa6teqgpe4yej5sk7edyqn7w8xr4mgm2asww53gzv95fwpud7mzg4rrnpvdk40m0vna8w8y0w9y240r6m7ja58gfk3stfra9qsm0lt7npkv4w0ghzypdrrg04kp7kkepnm4qmwmjxdg2tx3ejtdmzp0w08alv7x3zxgxsu35yhlvrnkpl9mxgejkfcxdgccper4f7llaaux9hcpul5uy47lhr065qwkgxc6jfylq5raqeczryz089syr4aj7z908e4e3t49qd40x3ueyrgxcdj37dkd5ysezj45kgtv546e7m3fj8ga920lztrgmmx0a98qwnk2ep5k9qh2x05mm5snu5d88lm4lrad8hc639jx97hrx9mywkw6c7yvj9jv0mjmsq0xqpqt0kc4hsh24kndhtsc0ezfzw9h79mjw239s804t2f4jucd3x57mvvnsyp82xy9jvp4yzlq5qhrpu87frkfwkx62r8rjsdkdlx4yhss2ly4q8425ta3je6rym35lapxesd9dhsj44pfhmq92g4tmfr8qnajpn2cgj8ngtzrkc9ygsvx76633p8ksru7g8cda5dfnhf50ax47rde5fhnk8dt7k5sltkhknha697gyqsjg4hytslxmaazdjqj4earaf098uz6gpcgu27zsy4v5arc3vjmum90ngf8e00exjr4nsqs3wr4w93h42ucnllyu5ck09yundjkjqsqetrhzvc3q0smssg6vcw9hlns363grqyt92azpvml632wffpuq5wtsh9vxwdse0g0w0wl3e320hnp3vlmzde3c8xa42yye90gnmmyjdq5atmlnulga4pcapk4t6ut82w057ed3rawx42vn7rl5kzyg84cvulg8yfjeu3ff0wprytkhk85dr63u9elq5ju0c9vd2yyjkqnhxh6xwxnt4nw32pefm9aengdasjn7lsyaeldz93spfnn02uke83xkwytj0wkxhgknde5jnjgg6yegwuw8rklvh6cvyvzqkgwaj857cz7xt3u8mhxlh8xevud3vj5dvq6kpxqd4jftt5h4gcmf9qpj3e2nw87j9une3vu75ahewdrqg7avfquw79fva59f8f3xpmk6lpmlkx9x7ejaw97f8nu86r2yhaepr50cdew82c3fmpnma2gr5vatjy3luqsyf8fpqp2zrjzcymemt3f3t99rn689ucyaj8vc2eapgw4knjyaque29hk3t7swcdvrwcf5myg33ghmg2s8xrqjwzeghzmqq68278lrw5rxn4jf3y93z7ztuwz67s0qa5lldcqe44qsshpuxx36dmna5cn7yy5v5f449gf26hygmj6qk8hm7rkvv44w3cu9fdv7sq0hqy67p3tvyxc8fl640z7pdsjfraznvqpnvcepggdnf3qypgs8vu82wsj2yd8nkhfv6sv6xs3wf5d7nkqsd5k8ehk7dtfqnsvcz26yazc32cv669qn7dhxr25j0etmmz7xh8azj7dn0d4u309m0rc2yhfegds60smuqtxn4l4nhmdqj9x6se4sultl5cwy4qja66cvnjz6mqwqet4n5zcswywqd6gcpec4q2vek9g4086ys4x35hwa47dk3zj2m03yuqz7ap66dah3r73j96q00cwmqw0lxvvqq4u0kvt6vrc0urd2hfhrxkrkmr9yx48uw94vmnjyq7sgyc0szkyuq07cjhg0fhx5z5mr9ua24wx9qnh32cjult3mu8kzhlj7se2nm4jr937j64656q7vp98dh9dhvlge8p02ejse5r0nsk22aa5cexvuqcaulnxw690vm3vdagdckfwps06jjd49kd4ls4jkf0nxkhqx2rm73pcepr4u6xjxw2fhjptk95tt0rq2ramq57lfg3sw3tsee2af355lt53w4f5wmpcvctsntyl2sp8m04l3nds7acv4uqnznudmkasgdf7l9df4484ym2njjzy0c26v2zv7pkv30f06uuptdvuxmgnuqcgd4els7gehp0fwxam0vskt34e3z3kfft6kkdz2c7ftn3dcvz5wvpwqf8458ade6995vdkxkalqzfs5epjfnn3c27mnzlx6cv5fhlephxpa3mj3hu6wafd8em8jhzcguru797p6m2fes55ha23putxrtly4wufl6rpp3ydta57zcxl40pvhpps7sgr7zc2cvz57xdlxpvclsjdgp5q3up9tu5csfdkaa762mk7zrqad93506l0kj".to_string(), Network::Alpha).unwrap(), NeptuneCoins::new(1337)),
        ]
    }

    pub fn new(header: BlockHeader, body: BlockBody, proof: Option<Proof>) -> Self {
        Self {
            kernel: BlockKernel { body, header },
            proof,
        }
    }

    /// Merge a transaction into this block's transaction.
    /// The mutator set data must be valid in all inputs.
    pub fn accumulate_transaction(&mut self, transaction: Transaction) {
        // merge
        let merged_timestamp = BFieldElement::new(max(
            self.kernel.header.timestamp.value(),
            max(
                self.kernel.body.transaction.kernel.timestamp.value(),
                transaction.kernel.timestamp.value(),
            ),
        ));

        // accumulate
        let mut next_mutator_set_accumulator = self.kernel.body.mutator_set_accumulator.clone();

        let mutator_set_update = MutatorSetUpdate::new(
            transaction.kernel.inputs.clone(),
            transaction.kernel.outputs.clone(),
        );

        let new_transaction = self.kernel.body.transaction.clone().merge_with(transaction);
        // Apply the mutator set update to get the `next_mutator_set_accumulator`
        mutator_set_update
            .apply(&mut next_mutator_set_accumulator)
            .expect("Mutator set mutation must work");

        let block_body: BlockBody = BlockBody {
            transaction: new_transaction,
            mutator_set_accumulator: next_mutator_set_accumulator.clone(),
            lock_free_mmr_accumulator: self.kernel.body.lock_free_mmr_accumulator.clone(),
            block_mmr_accumulator: self.kernel.body.block_mmr_accumulator.clone(),
            uncle_blocks: self.kernel.body.uncle_blocks.clone(),
        };

        let block_header = BlockHeader {
            version: self.kernel.header.version,
            height: self.kernel.header.height,
            prev_block_digest: self.kernel.header.prev_block_digest,
            timestamp: merged_timestamp,
            nonce: self.kernel.header.nonce,
            max_block_size: self.kernel.header.max_block_size,
            proof_of_work_line: self.kernel.header.proof_of_work_line,
            proof_of_work_family: self.kernel.header.proof_of_work_family,
            difficulty: self.kernel.header.difficulty,
        };

        self.kernel.body = block_body;
        self.kernel.header = block_header;
    }

    /// Verify a block. It is assumed that `previous_block` is valid.
    /// Note that this function does **not** check that the PoW digest is below the threshold.
    /// That must be done separately by the caller.
    pub(crate) fn is_valid(&self, previous_block: &Block) -> bool {
        // The block value doesn't actually change. Some function calls just require
        // mutable references because that's how the interface was defined for them.
        let block_copy = self.to_owned();
        // What belongs here are the things that would otherwise
        // be verified by the block validity proof.

        // 0. `previous_block` is consistent with current block
        //   a) Block height is previous plus one
        //   b) Block header points to previous block
        //   d) Block timestamp is greater than previous block timestamp
        //   e) Target difficulty, and other control parameters, were adjusted correctly
        // 1. The transaction is valid.
        // 1'. All transactions are valid.
        //   a) verify that MS membership proof is valid, done against previous `mutator_set_accumulator`,
        //   b) Verify that MS removal record is valid, done against previous `mutator_set_accumulator`,
        //   c) Verify that all removal records have unique index sets
        //   d) verify that adding `mutator_set_update` to previous `mutator_set_accumulator`
        //      gives `next_mutator_set_accumulator`,
        //   e) transaction timestamp <= block timestamp
        //   f) transaction coinbase <= miner reward
        //   g) transaction is valid (internally consistent)

        // 0.a) Block height is previous plus one
        if previous_block.kernel.header.height.next() != block_copy.kernel.header.height {
            warn!("Height does not match previous height");
            return false;
        }

        // 0.b) Block header points to previous block
        if previous_block.kernel.mast_hash() != block_copy.kernel.header.prev_block_digest {
            warn!("Hash digest does not match previous digest");
            return false;
        }

        // 0.c) Verify correct addition to block MMR
        let mut mmra = previous_block.kernel.body.block_mmr_accumulator.clone();
        mmra.append(previous_block.hash());
        if mmra != self.kernel.body.block_mmr_accumulator {
            warn!("Block MMRA was not updated correctly");
            return false;
        }

        // 0.d) Block timestamp is greater than that of previuos block
        if previous_block.kernel.header.timestamp.value()
            >= block_copy.kernel.header.timestamp.value()
        {
            warn!("Block does not have greater timestamp than that of previous block");
            return false;
        }

        // 0.e) Target difficulty, and other control parameters, were updated correctly
        if block_copy.kernel.header.difficulty
            != Self::difficulty_control(previous_block, block_copy.kernel.header.timestamp.value())
        {
            warn!("Value for new difficulty is incorrect.");
            return false;
        }

        // 1.b) Verify validity of removal records: That their MMR MPs match the SWBF, and
        // that at least one of their listed indices is absent.
        for removal_record in block_copy.kernel.body.transaction.kernel.inputs.iter() {
            if !previous_block
                .kernel
                .body
                .mutator_set_accumulator
                .kernel
                .can_remove(removal_record)
            {
                warn!("Removal record cannot be removed from mutator set");
                return false;
            }
        }

        // 1.c) Verify that the removal records do not contain duplicate `AbsoluteIndexSet`s
        let mut absolute_index_sets = block_copy
            .kernel
            .body
            .transaction
            .kernel
            .inputs
            .iter()
            .map(|removal_record| removal_record.absolute_indices.to_vec())
            .collect_vec();
        absolute_index_sets.sort();
        absolute_index_sets.dedup();
        if absolute_index_sets.len() != block_copy.kernel.body.transaction.kernel.inputs.len() {
            warn!("Removal records contain duplicates");
            return false;
        }

        // 1.d) Verify that the two mutator sets, the one from the current block and the
        // one from the previous, are consistent with the transactions.
        // Construct all the addition records for all the transaction outputs. Then
        // use these addition records to insert into the mutator set.
        let mutator_set_update = MutatorSetUpdate::new(
            block_copy.kernel.body.transaction.kernel.inputs.clone(),
            block_copy.kernel.body.transaction.kernel.outputs.clone(),
        );
        let mut ms = previous_block.kernel.body.mutator_set_accumulator.clone();
        let ms_update_result = mutator_set_update.apply(&mut ms);
        match ms_update_result {
            Ok(()) => (),
            Err(err) => {
                warn!("Failed to apply mutator set update: {}", err);
                return false;
            }
        };

        // Verify that the locally constructed mutator set matches that in the received
        // block's body.
        if ms.hash() != block_copy.kernel.body.mutator_set_accumulator.hash() {
            warn!("Reported mutator set does not match calculated object.");
            debug!(
                "From Block\n{:?}. \n\n\nCalculated\n{:?}",
                block_copy.kernel.body.mutator_set_accumulator, ms
            );
            return false;
        }

        // 1.e) verify that the transaction timestamp is less than or equal to the block's timestamp.
        if block_copy.kernel.body.transaction.kernel.timestamp.value()
            > block_copy.kernel.header.timestamp.value()
        {
            warn!("Transaction with invalid timestamp found");
            return false;
        }

        // 1.f) Verify that the coinbase claimed by the transaction does not exceed
        // the allowed coinbase based on block height, epoch, etc., and fee
        let miner_reward: NeptuneCoins = Self::get_mining_reward(block_copy.kernel.header.height)
            + self.kernel.body.transaction.kernel.fee;
        if let Some(claimed_reward) = block_copy.kernel.body.transaction.kernel.coinbase {
            if claimed_reward > miner_reward {
                warn!("Block is invalid because the claimed miner reward is too high relative to current network parameters.");
                return false;
            }
        }

        // 1.g) Verify transaction, but without relating it to the blockchain tip (that was done above).
        if !block_copy.kernel.body.transaction.is_valid() {
            warn!("Invalid transaction found in block");
            return false;
        }

        // 2. accumulated proof-of-work was computed correctly
        //  - look two blocks back, take proof_of_work_line
        //  - look 1 block back, estimate proof-of-work
        //  - add -> new proof_of_work_line
        //  - look two blocks back, take proof_of_work_family
        //  - look at all uncles, estimate proof-of-work
        //  - add -> new proof_of_work_family

        // 3. variable network parameters are computed correctly
        // 3.a) target_difficulty <- pow_line
        // 3.b) max_block_size <- difference between `pow_family[n-2] - pow_line[n-2] - (pow_family[n] - pow_line[n])`

        // 4. for every uncle
        //  4.1. verify that uncle's prev_block_digest matches with parent's prev_block_digest
        //  4.2. verify that all uncles' hash are below parent's target_difficulty

        true
    }

    /// Determine if the the proof-of-work puzzle was solved correctly. Specifically,
    /// compare the hash of the current block against the difficulty determined by
    /// the previous.
    pub fn has_proof_of_work(&self, previous_block: &Block) -> bool {
        // check that hash is below threshold
        if self.hash()
            > Self::difficulty_to_digest_threshold(previous_block.kernel.header.difficulty)
        {
            warn!("Block digest exceeds target difficulty");
            return false;
        }

        true
    }

    /// Converts `difficulty` to type `Digest` so that the hash of a block can be
    /// tested against the target difficulty using `<`. The unit of `difficulty`
    /// is expected number of hashes for solving the proof-of-work puzzle.
    pub fn difficulty_to_digest_threshold(difficulty: U32s<5>) -> Digest {
        assert!(!difficulty.is_zero(), "Difficulty cannot be less than 1");

        let difficulty_as_bui: BigUint = difficulty.into();
        let max_threshold_as_bui: BigUint =
            Digest([BFieldElement::new(BFieldElement::MAX); DIGEST_LENGTH]).into();
        let threshold_as_bui: BigUint = max_threshold_as_bui / difficulty_as_bui;

        threshold_as_bui.try_into().unwrap()
    }

    /// Control system for block difficulty. This function computes the new block's
    /// difficulty from its timestamp and the previous block. It is a PID controller
    /// (with i=d=0) regulating the block interval by tuning the difficulty.
    /// We assume that the block timestamp is valid.
    pub fn difficulty_control(
        old_block: &Block,
        new_timestamp: u64,
    ) -> U32s<TARGET_DIFFICULTY_U32_SIZE> {
        // no adjustment if the previous block is the genesis block
        if old_block.kernel.header.height.is_genesis() {
            return old_block.kernel.header.difficulty;
        }

        // otherwise, compute PID control signal
        let t = new_timestamp - old_block.kernel.header.timestamp.value();

        let new_error = t as i64 - TARGET_BLOCK_INTERVAL as i64;

        let adjustment = -new_error / 100;
        let absolute_adjustment = abs(adjustment) as u64;
        let adjustment_is_positive = adjustment >= 0;
        let adj_hi = (absolute_adjustment >> 32) as u32;
        let adj_lo = absolute_adjustment as u32;
        let adjustment_u32s =
            U32s::<TARGET_DIFFICULTY_U32_SIZE>::new([adj_lo, adj_hi, 0u32, 0u32, 0u32]);
        if adjustment_is_positive {
            old_block.kernel.header.difficulty + adjustment_u32s
        } else if adjustment_u32s > old_block.kernel.header.difficulty - MINIMUM_DIFFICULTY.into() {
            MINIMUM_DIFFICULTY.into()
        } else {
            old_block.kernel.header.difficulty - adjustment_u32s
        }
    }
}

#[cfg(test)]
mod block_tests {
    use crate::{
        config_models::network::Network,
        models::{
            blockchain::transaction::PublicAnnouncement, state::wallet::WalletSecret,
            state::UtxoReceiverData,
        },
        tests::shared::{get_mock_global_state, make_mock_block, make_mock_block_with_valid_pow},
    };
    use tasm_lib::twenty_first::{
        storage::level_db::DB,
        util_types::{
            emojihash_trait::Emojihash,
            mmr::archival_mmr::ArchivalMmr,
            storage_schema::{SimpleRustyStorage, StorageWriter},
        },
    };

    use super::*;

    use rand::{random, thread_rng, Rng};
    use tracing_test::traced_test;

    #[traced_test]
    #[tokio::test]
    async fn merge_transaction_test() {
        // We need the global state to construct a transaction. This global state
        // has a wallet which receives a premine-UTXO.
        let network = Network::Alpha;
        let global_state_lock = get_mock_global_state(network, 2, None).await;
        let spending_key = global_state_lock
            .lock_guard()
            .await
            .wallet_state
            .wallet_secret
            .nth_generation_spending_key(0);
        let address = spending_key.to_address();
        let other_wallet_secret = WalletSecret::new_random();
        let other_address = other_wallet_secret
            .nth_generation_spending_key(0)
            .to_address();
        let genesis_block = Block::genesis_block();

        let (mut block_1, _, _) = make_mock_block(&genesis_block, None, address);
        assert!(
            block_1.is_valid(&genesis_block),
            "Block 1 must be valid with only coinbase output"
        );

        // create a new transaction, merge it into block 1 and check that block 1 is still valid
        let new_utxo = Utxo::new_native_coin(other_address.lock_script(), NeptuneCoins::new(10));
        let reciever_data = UtxoReceiverData {
            public_announcement: PublicAnnouncement::default(),
            receiver_privacy_digest: other_address.privacy_digest,
            sender_randomness: random(),
            utxo: new_utxo,
        };
        let new_tx = global_state_lock
            .lock_guard_mut()
            .await
            .create_transaction(vec![reciever_data], NeptuneCoins::new(1))
            .await
            .unwrap();
        assert!(new_tx.is_valid(), "Created tx must be valid");

        block_1.accumulate_transaction(new_tx);
        assert!(
            block_1.is_valid(&genesis_block),
            "Block 1 must be valid after adding a transaction; previous mutator set hash: {} and next mutator set hash: {}",
            genesis_block.kernel
                .body
                .mutator_set_accumulator
                .hash()
                .emojihash(),
                block_1.kernel
                    .body
                    .mutator_set_accumulator
                    .hash()
                    .emojihash()
        );

        // Sanity checks
        assert_eq!(
            3,
            block_1.kernel.body.transaction.kernel.outputs.len(),
            "New block must have three outputs: coinbase, transaction, and change"
        );
        assert_eq!(
            1,
            block_1.kernel.body.transaction.kernel.inputs.len(),
            "New block must have one input: spending of genesis UTXO"
        );
    }

    #[test]
    fn difficulty_to_threshold_test() {
        // Verify that a difficulty of 2 accepts half of the digests
        let difficulty: u32 = 2;
        let difficulty_u32s = U32s::<5>::from(difficulty);
        let threshold_for_difficulty_two: Digest =
            Block::difficulty_to_digest_threshold(difficulty_u32s);

        for elem in threshold_for_difficulty_two.values() {
            assert_eq!(BFieldElement::MAX / u64::from(difficulty), elem.value());
        }

        // Verify that a difficulty of BFieldElement::MAX accepts all digests where the last BFieldElement is zero
        let some_difficulty = U32s::<5>::new([1, u32::MAX, 0, 0, 0]);
        let some_threshold_actual: Digest = Block::difficulty_to_digest_threshold(some_difficulty);

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
        let genesis_block = Block::genesis_block();

        let a_wallet_secret = WalletSecret::new_random();
        let a_recipient_address = a_wallet_secret.nth_generation_spending_key(0).to_address();
        let (mut block_1, _, _) =
            make_mock_block_with_valid_pow(&genesis_block, None, a_recipient_address);

        block_1.kernel.body.block_mmr_accumulator = MmrAccumulator::new(vec![]);

        assert!(!block_1.is_valid(&genesis_block));
    }

    #[test]
    fn can_prove_block_ancestry() {
        let genesis_block = Block::genesis_block();
        let mut blocks = vec![];
        blocks.push(genesis_block.clone());
        let db = DB::open_new_test_database(true, None, None, None).unwrap();
        let mut storage = SimpleRustyStorage::new(db);
        storage.restore_or_new();
        let ammr_storage = storage.schema.new_vec::<Digest>("ammr-blocks-0");
        let mut ammr: ArchivalMmr<Hash, _> = ArchivalMmr::new(ammr_storage);
        ammr.append(genesis_block.hash());
        let mut mmra = MmrAccumulator::new(vec![genesis_block.hash()]);

        for i in 0..55 {
            let wallet_secret = WalletSecret::new_random();
            let recipient_address = wallet_secret.nth_generation_spending_key(0).to_address();
            let (new_block, _, _) =
                make_mock_block(blocks.last().unwrap(), None, recipient_address);
            if i != 54 {
                ammr.append(new_block.hash());
                mmra.append(new_block.hash());
                assert_eq!(ammr.to_accumulator().bag_peaks(), mmra.bag_peaks());
            }
            blocks.push(new_block);
        }

        let last_block_mmra = blocks.last().unwrap().body().block_mmr_accumulator.clone();
        assert_eq!(mmra, last_block_mmra);

        let index = thread_rng().gen_range(0..blocks.len() - 1);
        let block_digest = blocks[index].hash();
        let (membership_proof, _) = ammr.prove_membership(index as u64);
        let (v, _) = membership_proof.verify(
            &last_block_mmra.get_peaks(),
            block_digest,
            last_block_mmra.count_leaves(),
        );
        assert!(
            v,
            "peaks: {} ({}) leaf count: {} index: {} path: {} number of blocks: {} leaf index: {}",
            last_block_mmra
                .get_peaks()
                .iter()
                .map(|d| d.emojihash())
                .join(","),
            last_block_mmra.get_peaks().len(),
            last_block_mmra.count_leaves(),
            membership_proof.leaf_index,
            membership_proof
                .authentication_path
                .iter()
                .map(|d| d.emojihash())
                .join(","),
            blocks.len(),
            membership_proof.leaf_index
        );
        assert_eq!(last_block_mmra.count_leaves(), blocks.len() as u64 - 1);
    }

    #[test]
    fn test_premine_size() {
        // 831600 = 42000000 * 0.0198
        // where 42000000 is the asymptotical limit of the token supply
        // and 1.98% is the relative size of the premine
        let premine_max_size = NeptuneCoins::new(831600);

        let total_premine = Block::premine_distribution()
            .iter()
            .map(|(_receiving_address, amount)| *amount)
            .sum::<NeptuneCoins>();

        assert!(total_premine <= premine_max_size);
    }
}
