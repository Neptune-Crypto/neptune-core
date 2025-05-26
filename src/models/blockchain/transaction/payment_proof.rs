use crate::{job_queue::triton_vm::TritonVmJobQueue, models::{blockchain::type_scripts::native_currency::NativeCurrency, state::{transaction_kernel_id::TransactionKernelId, wallet::address::ReceivingAddress}}, util_types::mutator_set::addition_record::AdditionRecord};
use tasm_lib::triton_vm::proof::{Claim, Proof};
use twenty_first::math::digest::Digest;

use super::validity::proof_collection::ProofCollection;

/// This struct allow the creation of a payement proof.
/// A payement proof is a cryptographic proof that a payment has been made.
/// Since the transaction was made on a privacy blockchain, the prof is the
/// only way to prove that the payment has been made.
///
/// To create a payment proof, the user must provide the transaction hash,
/// the amount of the payment, the receiver address as well as the sender address.
///
/// The payment proof is then created and can be shared to the receiver in a text format
/// for them to verify the payment.
struct PaymentProofParams {
    txid : TransactionKernelId,
    sender_randomness: SenderRandomness,
    addition_record: AdditionRecord,
    amount: NativeCurrency,
    receiving_address: ReceivingAddress,
}

impl PaymentProofParams{
    // Payment proof params initialization 
    pub fn from(txid : TransactionKernelId, sender_randomness : Digest, addition_record : AdditionRecord, amount : NativeCurrency, receiving_address : ReceivingAddress) -> Self {
        Self {
            txid,
            sender_randomness,
            addition_record,
            amount,
            receiving_address,
        }
    }
}

pub struct PaymentClaim{
    pub claim : Claim
}

impl PaymentClaim{
    pub fn init() -> Self {
        Self {
            claim: Claim::default(),
        }
    }
}

pub struct PaymentProof {
    pub proof: Proof,
}


impl PaymentProof {
    fn initialize_payment_proof(payment_proof_params : PaymentProofParams){
        let mut proof : SingleProof;
        
    }

    async fn create_proof(&self, params: PaymentProofParams, triton_vm_job_queue : &TritonVmJobQueue) -> PaymentProof {
        // Get the params :
        // We need to prove that the addition_record digest corresponds to the utxo having the amount locked by the receiving address

        // Is it possible to reconstruct UtxoRecoveryData here?



        // check if UtxoDigest is equal to 
        
    }
}
