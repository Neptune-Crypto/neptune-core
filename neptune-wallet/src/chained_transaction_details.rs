//! Information necessary to construct a chained (link) transaction: the
//! chain-pipeline analog of [`TransactionDetails`](crate::transaction_details::TransactionDetails).

use neptune_consensus::chaintx::link_kernel::LinkKernel;
use neptune_consensus::chaintx::link_primitive_witness::LinkPrimitiveWitness;
use neptune_consensus::transaction::lock_script::LockScriptAndWitness;
use neptune_consensus::transaction::primitive_witness::SaltedUtxos;
use neptune_consensus::transaction::transaction_kernel::TransactionKernel;
use neptune_consensus::transaction::transaction_kernel::TransactionKernelProxy;
use neptune_consensus::transaction::utxo::Utxo;
use neptune_consensus::type_scripts::known_type_scripts::match_type_script_and_generate_witness;
use neptune_consensus::type_scripts::native_currency_amount::NativeCurrencyAmount;
use neptune_mutator_set::mutator_set_accumulator::MutatorSetAccumulator;
use neptune_primitives::network::Network;
use neptune_primitives::timestamp::Timestamp;
use rand::rngs::StdRng;
use rand::SeedableRng;
use tasm_lib::prelude::Digest;
use tasm_lib::prelude::Tip5;
use tasm_lib::twenty_first::math::bfield_codec::BFieldCodec;

use crate::incoming_utxo::IncomingUtxo;
use crate::transaction_output::TxOutputList;

/// An unconfirmed UTXO consumed as a thruput, together with the witness that
/// unlocks it.
///
/// The chain-pipeline analog of
/// [`UnlockedUtxo`](crate::unlocked_utxo::UnlockedUtxo): a thruput has no
/// mutator-set membership proof -- it is not in the mutator set yet -- and is
/// instead identified by the addition record its creating transaction
/// carries.
#[derive(Debug, Clone)]
pub struct ThruputInput {
    pub incoming_utxo: IncomingUtxo,
    pub lock_script_and_witness: LockScriptAndWitness,
}

/// Information necessary to construct a chained (link) transaction.
///
/// Unlike [`TransactionDetails`](crate::transaction_details::TransactionDetails),
/// the inputs are *thruputs*: unconfirmed UTXOs created by transactions that
/// sit in the mempool, spent before any block confirms them. Confirmed inputs
/// are not supported yet.
#[derive(Debug, Clone)]
pub struct ChainedTransactionDetails {
    pub thruput_inputs: Vec<ThruputInput>,
    pub tx_outputs: TxOutputList,
    pub fee: NativeCurrencyAmount,
    pub timestamp: Timestamp,
    pub mutator_set_accumulator: MutatorSetAccumulator,
    pub network: Network,
}

impl ChainedTransactionDetails {
    /// The total amount the thruputs bring in.
    pub fn total_thruput_amount(&self) -> NativeCurrencyAmount {
        self.thruput_inputs
            .iter()
            .map(|thruput| thruput.incoming_utxo.utxo.get_native_currency_amount())
            .sum()
    }

    /// The wrapped transaction kernel: no confirmed inputs, the outputs'
    /// addition records, and the outputs' notification announcements.
    fn inner_kernel(&self) -> TransactionKernel {
        TransactionKernelProxy {
            inputs: vec![],
            outputs: self.tx_outputs.addition_records(),
            announcements: self.tx_outputs.announcements(),
            fee: self.fee,
            coinbase: None,
            timestamp: self.timestamp,
            mutator_set_hash: self.mutator_set_accumulator.hash(),
            merge_bit: false,
        }
        .into_kernel()
    }

    /// The [`LinkKernel`] of the link transaction under construction.
    pub fn link_kernel(&self) -> LinkKernel {
        LinkKernel {
            kernel: self.inner_kernel(),
            thruputs: self
                .thruput_inputs
                .iter()
                .map(|thruput| thruput.incoming_utxo.addition_record())
                .collect(),
        }
    }

    /// Assemble the [`LinkPrimitiveWitness`] to forge.
    ///
    /// The analog of
    /// [`TransactionDetails::primitive_witness`](crate::transaction_details::TransactionDetails::primitive_witness),
    /// with the same deterministic salt derivation.
    pub fn link_primitive_witness(&self) -> LinkPrimitiveWitness {
        let input_utxos: Vec<Utxo> = self
            .thruput_inputs
            .iter()
            .map(|thruput| thruput.incoming_utxo.utxo.clone())
            .collect();
        let output_utxos = self.tx_outputs.utxos();
        let output_sender_randomnesses = self.tx_outputs.sender_randomnesses();
        let output_receiver_digests = self.tx_outputs.receiver_digests();

        let salt_seed_preimage = [
            input_utxos.encode(),
            output_utxos.encode(),
            output_sender_randomnesses.encode(),
        ]
        .concat();
        let salt_seed: [u8; Digest::BYTES] = Tip5::hash_varlen(&salt_seed_preimage).into();
        let mut rng = StdRng::from_seed(salt_seed[0..32].try_into().unwrap());
        let salted_output_utxos = SaltedUtxos::new_with_rng(output_utxos.clone(), &mut rng);
        let salted_input_utxos = SaltedUtxos::new_with_rng(input_utxos.clone(), &mut rng);

        let kernel = self.link_kernel();
        let type_scripts_and_witnesses =
            Utxo::type_script_hashes(input_utxos.iter().chain(output_utxos.iter()))
                .into_iter()
                .map(|type_script_hash| {
                    match_type_script_and_generate_witness(
                        type_script_hash,
                        kernel.kernel.clone(),
                        salted_input_utxos.clone(),
                        salted_output_utxos.clone(),
                    )
                    .expect("type script must be known")
                })
                .collect();

        LinkPrimitiveWitness {
            input_utxos: salted_input_utxos,
            input_membership_proofs: vec![],
            thruput_sender_randomnesses: self
                .thruput_inputs
                .iter()
                .map(|thruput| thruput.incoming_utxo.sender_randomness)
                .collect(),
            thruput_receiver_digests: self
                .thruput_inputs
                .iter()
                .map(|thruput| thruput.incoming_utxo.receiver_preimage.hash())
                .collect(),
            lock_scripts_and_witnesses: self
                .thruput_inputs
                .iter()
                .map(|thruput| thruput.lock_script_and_witness.clone())
                .collect(),
            type_scripts_and_witnesses,
            output_utxos: salted_output_utxos,
            output_sender_randomnesses,
            output_receiver_digests,
            mutator_set_accumulator: self.mutator_set_accumulator.clone(),
            kernel,
        }
    }
}
