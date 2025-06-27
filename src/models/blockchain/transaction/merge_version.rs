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

macro_rules! for_each {
        ($var:ident in [$($const_val:ident),*] $body:block) => {
            $(
                {
                    const $var: usize = $const_val;
                    $body
                }
            )*
        };
    }
pub(crate) use for_each;

/// Repeats the given code while substituting all merge versions for the
/// const `VERSION`.
macro_rules! for_each_version {
        ($body: block) => {
            const GENESIS_VERSION: usize = MergeVersion::Genesis as usize;
            const HARD_FORK_2_VERSION: usize = MergeVersion::HardFork2 as usize;
            for_each!( VERSION in [GENESIS_VERSION, HARD_FORK_2_VERSION]  {
                $body
            });
        }
    }
pub(crate) use for_each_version;

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
