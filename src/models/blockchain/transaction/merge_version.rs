#[derive(Debug, Copy, Clone, Default, PartialEq, Eq)]
pub(crate) enum MergeVersion {
    #[default] // TODO: Change this after hard-fork
    Genesis,
    HardFork2,
}
