use crate::tests::shared::Randomness;

impl<const BA: usize, const D: usize> rand::distr::Distribution<Randomness<BA, D>>
    for rand::distr::StandardUniform
{
    fn sample<R: rand::Rng + ?Sized>(&self, rng: &mut R) -> Randomness<BA, D> {
        let mut bytes = [[Default::default(); 32]; BA];
        let mut digests = [Default::default(); D];
        for b in &mut bytes {
            rng.fill_bytes(b);
        }
        for d in &mut digests {
            *d = rng.random();
        }
        Randomness {
            bytes_arr: bytes,
            digests,
        }
    }
}

impl<const BA: usize, const D: usize> Default for Randomness<BA, D> {
    fn default() -> Self {
        Self {
            bytes_arr: [[Default::default(); 32]; BA],
            digests: [Default::default(); D],
        }
    }
}
