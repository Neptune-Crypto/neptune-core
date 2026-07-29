use neptune_primitives::network::Network;
use tasm_lib::triton_vm;
use tasm_lib::triton_vm::proof::Claim;
use tasm_lib::triton_vm::proof::Proof as VmProof;
use tasm_lib::triton_vm::proof_stream::ProofStream;
use tasm_lib::triton_vm::stark::Stark;
use tokio::task;
use tracing::warn;

use crate::transaction::validity::neptune_proof::Proof;

/// Historical block claims that define the main-net checkpoint: one hex-encoded,
/// bincode-serialized [`Claim`] per line, each prefixed by its block height.
/// Feeding these into [`cache_true_claims`] marks the corresponding historical
/// blocks as valid without re-verifying their proofs.
pub const CHECKPOINT_MAIN: &str = include_str!("../assets/main/checkpoint.dat");

/// Historical block claims that define the testnet-0 checkpoint; see
/// [`CHECKPOINT_MAIN`] for the format.
pub const CHECKPOINT_TESTNET_0: &str = include_str!("../assets/testnet-0/checkpoint.dat");

/// This claims-cache contains claims that are simply defined to be true.
///
/// If the claim is in the cache, then the Triton VM verifier is by-passed
/// without reading the proof.
///
/// Besides tests, it is used for *checkpoints*, where we define historical
/// blocks to be valid.
static CLAIMS_CACHE: std::sync::LazyLock<tokio::sync::Mutex<std::collections::HashSet<Claim>>> =
    std::sync::LazyLock::new(|| tokio::sync::Mutex::new(std::collections::HashSet::new()));

static CLAIMS_CACHE_ENABLED: std::sync::LazyLock<tokio::sync::Mutex<bool>> =
    std::sync::LazyLock::new(|| tokio::sync::Mutex::new(true));

/// Whether to reject proofs that carry more proof items than the verifier reads.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SuperfluousProofItems {
    Reject,
    Tolerate,
}

/// The number of proof items that Triton VM's verifier reads from a proof of
/// the padded height indicated by the proof.
///
/// Returns `None` if the proof does not encode a padded height, or if no FRI
/// parameters exist for that padded height.
fn expected_num_proof_items(stark: Stark, proof: &VmProof) -> Option<usize> {
    /// Items read outside of FRI: the padded height, three Merkle roots, four
    /// out-of-domain rows, the out-of-domain quotient segments, and, for each of
    /// the three tables, the revealed rows plus their authentication structure.
    const NUM_ITEMS_OUTSIDE_FRI: usize = 15;

    /// Items read by FRI independently of the number of rounds: the Merkle root
    /// of the first round, the last round's codeword and polynomial, and the
    /// first round's revealed leafs.
    const NUM_ROUND_INDEPENDENT_FRI_ITEMS: usize = 4;

    /// Items read by FRI for every round: a Merkle root, and the revealed leafs
    /// of the round's partial codeword.
    const NUM_FRI_ITEMS_PER_ROUND: usize = 2;

    let padded_height = proof.padded_height().ok()?;
    let num_fri_rounds = stark.fri(padded_height).ok()?.num_rounds();

    Some(
        NUM_ITEMS_OUTSIDE_FRI
            + NUM_ROUND_INDEPENDENT_FRI_ITEMS
            + NUM_FRI_ITEMS_PER_ROUND * num_fri_rounds,
    )
}

/// Determine whether the proof holds exactly those proof items that Triton VM's
/// verifier reads, and no others.
///
/// Triton VM's native verifier ignores any items beyond the ones it reads,
/// whereas the verifier running *inside* the VM rejects them. A transaction
/// carrying such a proof would therefore be relayed by every node but could
/// never be merged into a block transaction.
fn has_expected_num_proof_items(proof: &VmProof) -> bool {
    let Some(expected_num_items) = expected_num_proof_items(Stark::default(), proof) else {
        return false;
    };
    let Ok(proof_stream) = ProofStream::try_from(proof) else {
        return false;
    };

    proof_stream.items.len() == expected_num_items
}

/// Verify a Triton VM (claim, proof) pair for default STARK parameters.
///
/// When the test flag is set, this function checks whether the claim is present
/// in the `CLAIMS_CACHE` and if so returns true early (*i.e.*, without running
/// the verifier). When the test flag is set and the cache does not contain the
/// claim and verification succeeds, the claim is added to the cache. The only
/// other way to populate the cache is through method `cache_true_claim`.
pub async fn verify(claim: Claim, proof: Proof, network: Network) -> bool {
    verify_inner(claim, proof, network, SuperfluousProofItems::Tolerate).await
}

/// Verify a Triton VM (claim, proof) pair belonging to a transaction.
///
/// Behaves like [`verify`], except that proofs holding more proof items than
/// the verifier reads are rejected. Such proofs are accepted by Triton VM's
/// native verifier but rejected by the verifier running inside the VM, so a
/// transaction backed by one could be relayed but never confirmed. Rejecting
/// them here keeps them out of the mempool; see `has_expected_num_proof_items`.
pub async fn verify_transaction_proof(claim: Claim, proof: Proof, network: Network) -> bool {
    verify_inner(claim, proof, network, SuperfluousProofItems::Reject).await
}

async fn verify_inner(
    claim: Claim,
    proof: Proof,
    network: Network,
    superfluous_proof_items: SuperfluousProofItems,
) -> bool {
    // security: we do not accept mock proofs unless we ourselves
    // are running a network that accepts mock-proofs, eg regtest.
    if network.use_mock_proof() {
        return proof.is_valid_mock();
    }

    {
        let is_enabled = *CLAIMS_CACHE_ENABLED.lock().await;
        if is_enabled && CLAIMS_CACHE.lock().await.contains(&claim) {
            return true;
        }
    }

    if superfluous_proof_items == SuperfluousProofItems::Reject
        && !has_expected_num_proof_items(&proof)
    {
        warn!("rejecting proof that holds an unexpected number of proof items");
        return false;
    }

    #[cfg(test)]
    let claim_clone = claim.clone();

    let verdict =
        task::spawn_blocking(move || triton_vm::verify(Stark::default(), &claim, &proof.into()))
            .await
            .expect("should be able to verify proof in new tokio task");

    // tbd: we might want to enable a cache for mainnet usage.
    // but we should probably use a cache that has a configurable max
    // size, so we don't blow up RAM.
    #[cfg(test)]
    if verdict {
        cache_true_claims([claim_clone]).await;
    }

    verdict
}

/// Add claims to the `CLAIMS_CACHE`.
pub async fn cache_true_claims<IterClaims: IntoIterator<Item = Claim>>(claims: IterClaims) {
    let mut cache = CLAIMS_CACHE.lock().await;
    for claim in claims {
        cache.insert(claim);
    }
}

/// Disable the true `CLAIMS_CACHE`.
#[cfg(any(test, feature = "test-helpers"))]
pub async fn disable_true_claims_cache() {
    *CLAIMS_CACHE_ENABLED.lock().await = false;
}

/// Enable the true `CLAIMS_CACHE`.
#[cfg(any(test, feature = "test-helpers"))]
pub async fn enable_true_claims_cache() {
    *CLAIMS_CACHE_ENABLED.lock().await = true;
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
pub(crate) mod tests {
    use std::collections::HashSet;

    use itertools::Itertools;
    use macro_rules_attr::apply;
    use rand::Rng;
    use tasm_lib::prelude::Tip5;
    use tasm_lib::triton_vm::isa::triton_asm;
    use tasm_lib::triton_vm::isa::triton_program;
    use tasm_lib::triton_vm::proof_item::ProofItem;
    use tasm_lib::triton_vm::vm::NonDeterminism;
    use triton_vm::prelude::BFieldCodec;

    use super::*;
    use crate::proof_abstractions::test_runtime::shared_tokio_runtime;

    pub(crate) fn bogus_proof(claim: &Claim) -> Proof {
        Proof::from(Tip5::hash_varlen(&claim.encode()).values().to_vec())
    }

    /// An honestly produced (claim, proof) pair for a program of the given
    /// length. Longer programs have larger padded heights, and thus more FRI
    /// rounds.
    fn honest_claim_and_proof(num_instructions: usize) -> (Claim, VmProof) {
        let program = triton_program!({&triton_asm![nop; num_instructions]} halt);
        let claim = Claim::about_program(&program);
        let proof = triton_vm::prove(Stark::default(), &claim, program, NonDeterminism::default())
            .expect("should be able to prove trivial program");

        (claim, proof)
    }

    /// The conformance test tying [`expected_num_proof_items`] to the number of
    /// proof items that Triton VM's prover actually emits. If Triton VM changes
    /// how many items a proof holds, this test must fail, since the count is
    /// hard-coded here but only implied over there.
    #[test]
    fn expected_num_proof_items_matches_honest_proofs() {
        let mut observed_num_fri_rounds = HashSet::new();
        for num_instructions in [0, 200, 2000] {
            let (_, proof) = honest_claim_and_proof(num_instructions);
            let actual_num_items = ProofStream::try_from(&proof).unwrap().items.len();
            assert_eq!(
                Some(actual_num_items),
                expected_num_proof_items(Stark::default(), &proof),
                "expected number of proof items must match actual number for a \
                 program of {num_instructions} instructions"
            );

            let padded_height = proof.padded_height().unwrap();
            observed_num_fri_rounds
                .insert(Stark::default().fri(padded_height).unwrap().num_rounds());
        }

        assert!(
            observed_num_fri_rounds.len() > 1,
            "test assumption: proofs must span more than one FRI round count, \
             otherwise the per-round term goes untested. Observed: {observed_num_fri_rounds:?}"
        );
    }

    #[test]
    fn superfluous_proof_items_are_detected() {
        let (claim, proof) = honest_claim_and_proof(200);
        assert!(
            has_expected_num_proof_items(&proof),
            "honest proof must hold exactly the expected number of proof items"
        );

        let mut appended_proof_stream = ProofStream::try_from(&proof).unwrap();
        appended_proof_stream
            .items
            .push(ProofItem::Log2PaddedHeight(8));
        let appended_proof = VmProof::from(appended_proof_stream);

        assert!(
            !has_expected_num_proof_items(&appended_proof),
            "proof with a trailing proof item must be detected"
        );

        // The divergence this check compensates for: Triton VM's native
        // verifier accepts the padded proof, while the verifier running inside
        // the VM rejects it. Should this assertion ever fail, Triton VM itself
        // rejects superfluous proof items and the check above is redundant.
        assert!(
            triton_vm::verify(Stark::default(), &claim, &appended_proof),
            "native verifier is expected to accept a proof with trailing items"
        );
    }

    #[apply(shared_tokio_runtime)]
    async fn transaction_proofs_with_superfluous_items_are_rejected() {
        let network = Network::Main;
        let (claim, proof) = honest_claim_and_proof(200);

        let mut appended_proof_stream = ProofStream::try_from(&proof).unwrap();
        appended_proof_stream
            .items
            .push(ProofItem::Log2PaddedHeight(8));
        let appended_proof = Proof::from(VmProof::from(appended_proof_stream));

        // Must precede the `verify` call below, which caches the claim as true
        // in test builds.
        assert!(
            !verify_transaction_proof(claim.clone(), appended_proof.clone(), network).await,
            "transaction proof with trailing proof item must be rejected"
        );
        assert!(
            verify(claim, appended_proof, network).await,
            "block proofs are exempt from the proof item count check, for now"
        );
    }

    #[apply(shared_tokio_runtime)]
    async fn test_claims_cache() {
        let network = Network::Main;

        // generate random claim and bogus proof
        let mut rng = rand::rng();
        let some_claim = Claim::new(rng.random())
            .with_input((0..10).map(|_| rng.random()).collect_vec())
            .with_output((0..10).map(|_| rng.random()).collect_vec());
        let some_proof = bogus_proof(&some_claim);

        // verification must fail
        assert!(!verify(some_claim.clone(), some_proof.clone(), network).await);

        // put claim into cache
        cache_true_claims(vec![some_claim.clone()]).await;

        // verification must succeed
        assert!(verify(some_claim, some_proof, network).await);
    }
}
