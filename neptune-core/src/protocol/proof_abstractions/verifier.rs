use tasm_lib::triton_vm;
use tasm_lib::triton_vm::proof::Claim;
use tasm_lib::triton_vm::stark::Stark;
use tokio::task;

use crate::application::config::network::Network;
use crate::protocol::consensus::transaction::validity::neptune_proof::Proof;

// This claims-cache stores mock proof-claims that are simply asserted to be valid.
//
// The cache is only used for tests and regtest mode!!
//
// The cache enables mock proofs to be generated and validated immediately
// which enables mock blocks and transactions.
//
// important:  for regtest mode to work properly, peers must be able to
// verify eachother's proofs. There is presently no mechanism to sync
// the cache between peers, though that could be a possibility.
//
// HOWEVER: given that this is a process-wide cache, it is actually shared
// between in-process peers such as when executing integration tests.
//
// In other words, distributed proving works for integration tests, but not
// yet in a "real" regtest multi-node network.
//
// RAM Usage:
//
// Presently claims are never expired. So there is a very real chance of
// blowing up RAM.  Maybe not so problematic since regtest is generally started
// from genesis block anyway.
//
// see: https://github.com/Neptune-Crypto/neptune-core/issues/539
#[cfg(test)]
static CLAIMS_CACHE: std::sync::LazyLock<tokio::sync::Mutex<std::collections::HashSet<Claim>>> =
    std::sync::LazyLock::new(|| tokio::sync::Mutex::new(std::collections::HashSet::new()));

/// Verify a Triton VM (claim, proof) pair for default STARK parameters.
///
/// When the test flag is set, this function checks whether the claim is present
/// in the `CLAIMS_CACHE` and if so returns true early (*i.e.*, without running
/// the verifier). When the test flag is set and the cache does not contain the
/// claim and verification succeeds, the claim is added to the cache. The only
/// other way to populate the cache is through method `cache_true_claim`.
pub(crate) async fn verify(claim: Claim, proof: Proof, network: Network) -> bool {
    // security: we do not accept mock proofs unless we ourselves
    // are running a network that accepts mock-proofs, eg regtest.
    if network.use_mock_proof() {
        return proof.is_valid_mock();
    }

    // presently this is used by certain unit tests.
    #[cfg(test)]
    if CLAIMS_CACHE.lock().await.contains(&claim) {
        return true;
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
        cache_true_claim(claim_clone).await;
    }

    verdict
}

/// Add a claim to the [`CLAIMS_CACHE`].
/// only used for tests at present.
#[cfg(test)]
pub(crate) async fn cache_true_claim(claim: Claim) {
    CLAIMS_CACHE.lock().await.insert(claim);
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
pub(crate) mod tests {
    use itertools::Itertools;
    use macro_rules_attr::apply;
    use rand::Rng;
    use tasm_lib::prelude::Tip5;
    use triton_vm::prelude::BFieldCodec;

    use super::*;
    use crate::tests::shared_tokio_runtime;

    pub(crate) fn bogus_proof(claim: &Claim) -> Proof {
        Proof::from(Tip5::hash_varlen(&claim.encode()).values().to_vec())
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
        cache_true_claim(some_claim.clone()).await;

        // verification must succeed
        assert!(verify(some_claim, some_proof, network).await);
    }
}
