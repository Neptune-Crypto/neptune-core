use tasm_lib::triton_vm;
use tasm_lib::triton_vm::proof::Claim;
use tasm_lib::triton_vm::proof::Proof;
use tasm_lib::triton_vm::stark::Stark;
use tokio::task;

#[cfg(test)]
static CLAIMS_CACHE: std::sync::LazyLock<tokio::sync::Mutex<std::collections::HashSet<Claim>>> =
    std::sync::LazyLock::new(|| tokio::sync::Mutex::new(std::collections::HashSet::new()));

/// Verify a Triton VM (claim,proof) pair for default STARK parameters.
///
/// When the test flag is set, this function checks whether the claim is present
/// in the `CLAIMS_CACHE` and if so returns true early (*i.e.*, without running
/// the verifier). When the test flag is set and the cache does not contain the
/// claim and verification succeeds, the claim is added to the cache. The only
/// other way to populate the cache is through method [`cache_true_claim`].
pub(crate) async fn verify(claim: Claim, proof: Proof) -> bool {
    #[cfg(test)]
    if CLAIMS_CACHE.lock().await.contains(&claim) {
        return true;
    }

    let claim_clone = claim.clone();
    let verdict =
        task::spawn_blocking(move || triton_vm::verify(Stark::default(), &claim_clone, &proof))
            .await
            .expect("should be able to verify proof in new tokio task");

    #[cfg(test)]
    if verdict {
        cache_true_claim(claim).await;
    }

    verdict
}

/// Add a claim to the `CLAIMS_CACHE`.
#[cfg(test)]
pub(crate) async fn cache_true_claim(claim: Claim) {
    CLAIMS_CACHE.lock().await.insert(claim);
}

#[cfg(test)]
pub(crate) mod test {
    use itertools::Itertools;
    use rand::Rng;
    use tasm_lib::prelude::Tip5;
    use triton_vm::prelude::BFieldCodec;

    use super::*;

    pub(crate) fn bogus_proof(claim: &Claim) -> Proof {
        Proof(Tip5::hash_varlen(&claim.encode()).values().to_vec())
    }

    #[tokio::test]
    async fn test_claims_cache() {
        // generate random claim and bogus proof
        let mut rng = rand::rng();
        let some_claim = Claim::new(rng.random())
            .with_input((0..10).map(|_| rng.random()).collect_vec())
            .with_output((0..10).map(|_| rng.random()).collect_vec());
        let some_proof = bogus_proof(&some_claim);

        // verification must fail
        assert!(!verify(some_claim.clone(), some_proof.clone()).await);

        // put claim into cache
        cache_true_claim(some_claim.clone()).await;

        // verification must succeed
        assert!(verify(some_claim, some_proof).await);
    }
}
