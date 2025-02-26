use divan::Bencher;
use rand::random;

fn main() {
    divan::main();
}

mod fast_kernel_mast_hash_bench {
    use neptune_cash::mine_loop::fast_kernel_mast_hash;
    use neptune_cash::models::blockchain::block::block_header::BlockHeader;
    use neptune_cash::models::blockchain::block::block_kernel::BlockKernel;
    use neptune_cash::models::proof_abstractions::mast_hash::MastHash;
    use rayon::iter::IntoParallelRefIterator;
    use rayon::iter::ParallelIterator;
    use tasm_lib::prelude::Digest;
    use tasm_lib::twenty_first::math::other::random_elements;

    use super::*;

    #[divan::bench]
    fn par_bench_collect(bencher: Bencher) {
        let num_hashes = 1_000_000;
        let kernel_auth_path: [Digest; BlockKernel::MAST_HEIGHT] = random();
        let header_auth_path: [Digest; BlockHeader::MAST_HEIGHT] = random();
        let nonces: Vec<Digest> = random_elements(num_hashes);
        bencher.bench_local(|| {
            let _a: Vec<_> = nonces
                .par_iter()
                .map(|nonce| fast_kernel_mast_hash(kernel_auth_path, header_auth_path, *nonce))
                .collect();
        });
    }

    #[divan::bench]
    fn par_bench_no_collect(bencher: Bencher) {
        let num_hashes = 1_000_000;
        let kernel_auth_path: [Digest; BlockKernel::MAST_HEIGHT] = random();
        let header_auth_path: [Digest; BlockHeader::MAST_HEIGHT] = random();
        let threshold: Digest = Digest::default();
        let nonces: Vec<Digest> = random_elements(num_hashes);
        bencher.bench_local(move || {
            nonces.par_iter().for_each(|nonce| {
                let hash = fast_kernel_mast_hash(kernel_auth_path, header_auth_path, *nonce);
                if hash < threshold {
                    unreachable!();
                }
            });
        });
    }
}
