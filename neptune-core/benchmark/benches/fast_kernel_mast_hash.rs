use divan::Bencher;
use rand::random;

fn main() {
    divan::main();
}

mod fast_kernel_mast_hash_bench {
    use neptune_cash::protocol::consensus::block::block_header::BlockPow;
    use neptune_cash::protocol::consensus::block::pow::PowMastPaths;
    use rayon::iter::IntoParallelIterator;
    use rayon::iter::ParallelIterator;

    use super::*;

    /// Only benches the `fast_mast_hash` part of the guessing, not the index
    /// calculation, nor the memory lookup. Expect maximum half the hash rate
    /// this function reports, almost certainly less.
    #[divan::bench]
    fn guess_bench_partial_1million(bencher: Bencher) {
        let num_hashes = 1_000_000;
        let auth_paths: PowMastPaths = random();
        bencher.bench_local(move || {
            (0..num_hashes).into_par_iter().for_each(|_| {
                let pow: BlockPow = random();
                let _hash = auth_paths.fast_mast_hash(pow);
            });
        });
    }
}
