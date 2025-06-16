#[derive(Debug, Copy, Clone, Default, PartialEq, Eq)]
#[cfg_attr(
    any(test, feature = "arbitrary-impls"),
    derive(arbitrary::Arbitrary, strum::EnumIter)
)]
pub enum MergeVersion {
    #[default] // TODO: Change this after hard-fork
    Genesis,
    HardFork2,
}

impl MergeVersion {
    pub(crate) fn pack_removal_records(&self) -> bool {
        match self {
            MergeVersion::Genesis => false,
            MergeVersion::HardFork2 => true,
        }
    }
}

#[cfg(test)]
impl TryFrom<usize> for MergeVersion {
    fn try_from(value: usize) -> Result<Self, Self::Error> {
        use strum::IntoEnumIterator;

        for merge_version in MergeVersion::iter() {
            if merge_version as usize == value {
                return Ok(merge_version);
            }
        }
        Err(())
    }

    type Error = ();
}

#[cfg(test)]
impl rand::distr::Distribution<MergeVersion> for rand::distr::StandardUniform {
    fn sample<R: rand::Rng + ?Sized>(&self, rng: &mut R) -> MergeVersion {
        if rng.random_bool(0.5f64) {
            MergeVersion::Genesis
        } else {
            MergeVersion::HardFork2
        }
    }
}
