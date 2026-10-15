//! Keeping a protocol's state in step with the chain, from block
//! notifications.
//!
//! A plugin learns of new tips from notifications, which are hints: one may
//! arrive twice, after a later one, or not at all. A [`Driver`] turns them into
//! an exact sequence of changes to a [`ChainState`]: it rolls the state back to
//! the last block the old and the new branch share, and applies every block
//! after it, oldest first. It reads the blocks from a [`Chain`].

use std::collections::VecDeque;
use std::fmt;
use std::future::Future;

use neptune_primitives::block_selector::BlockSelector;
use neptune_rpc_api::api::rpc::RpcApi;
use neptune_rpc_api::api::rpc::RpcError;
use tasm_lib::prelude::Digest;

use crate::chain::BlockId;
use crate::chain::ObservedBlock;

/// Where a driver reads blocks.
pub trait Chain {
    /// The block with hash `hash`.
    fn block(&self, hash: Digest)
        -> impl Future<Output = Result<ObservedBlock, ChainError>> + Send;

    /// The hash of the tip.
    fn tip(&self) -> impl Future<Output = Result<Digest, ChainError>> + Send;
}

/// State a protocol keeps in step with the chain.
pub trait ChainState {
    /// Move the state to `block`, a child of the block it reflects, or of no
    /// block if it reflects none yet.
    fn apply(&mut self, block: &ObservedBlock);

    /// Undo every block applied after `ancestor`, which was applied earlier.
    fn roll_back_to(&mut self, ancestor: BlockId);
}

/// Why a [`Chain`] could not give a block.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ChainError {
    /// The chain knows no block with this hash.
    Unknown(Digest),

    /// The chain could not be read.
    Rpc(RpcError),
}

/// Why a [`Driver`] could not follow a notification. The state is then as it
/// was before the notification.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DriverError {
    Chain(ChainError),

    /// None of the last `depth` blocks of the new branch is among the last
    /// `depth` blocks the driver applied: the chain reorganized deeper than the
    /// driver can follow, or the driver missed that many blocks.
    TooDeep {
        depth: usize,
    },
}

impl From<ChainError> for DriverError {
    fn from(error: ChainError) -> Self {
        Self::Chain(error)
    }
}

impl fmt::Display for DriverError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Chain(ChainError::Unknown(hash)) => write!(f, "unknown block {}", hash.to_hex()),
            Self::Chain(ChainError::Rpc(error)) => write!(f, "cannot read the chain: {error}"),
            Self::TooDeep { depth } => write!(
                f,
                "the new tip does not descend from any of the last {depth} blocks applied"
            ),
        }
    }
}

impl std::error::Error for DriverError {}

/// A [`ChainState`], and the blocks applied to it.
#[derive(Debug)]
pub struct Driver<S> {
    state: S,

    /// The last blocks applied, oldest first, at most `depth` of them.
    applied: VecDeque<BlockId>,
    depth: usize,
}

impl<S: ChainState> Driver<S> {
    /// A driver for `state`, which reflects no block yet. It follows a
    /// reorganization if and only if the new branch leaves the old one within
    /// the last `depth` blocks applied.
    pub fn new(state: S, depth: usize) -> Self {
        assert!(
            depth > 0,
            "a driver remembers at least the block applied last"
        );
        Self {
            state,
            applied: VecDeque::new(),
            depth,
        }
    }

    pub fn state(&self) -> &S {
        &self.state
    }

    /// The block applied last.
    pub fn tip(&self) -> Option<BlockId> {
        self.applied.back().copied()
    }

    /// Follow a notification of the block with hash `hash`.
    ///
    /// If that block was applied already, nothing changes. Otherwise the
    /// driver reads it and its ancestors from `chain`, back to the first one
    /// it applied, rolls the state back to that one, and applies the rest,
    /// oldest first; so a reorganization and a gap of missed notifications
    /// are followed alike. The first block a driver follows is applied alone.
    /// Every block is read before the state changes, so an error leaves the
    /// state as it was.
    pub async fn on_block(&mut self, hash: Digest, chain: &impl Chain) -> Result<(), DriverError> {
        if self.applied.iter().any(|id| id.hash == hash) {
            return Ok(());
        }

        // The blocks to apply, newest first.
        let mut branch = vec![chain.block(hash).await?];
        let mut shared = None;
        while !self.applied.is_empty() {
            let parent = branch.last().expect("the branch holds a block").parent;
            if let Some(position) = self.applied.iter().position(|id| id.hash == parent) {
                shared = Some(position);
                break;
            }
            if branch.len() >= self.depth {
                return Err(DriverError::TooDeep { depth: self.depth });
            }
            branch.push(chain.block(parent).await?);
        }

        if let Some(position) = shared.filter(|position| position + 1 < self.applied.len()) {
            self.state.roll_back_to(self.applied[position]);
            self.applied.truncate(position + 1);
        }
        for block in branch.iter().rev() {
            self.state.apply(block);
            self.applied.push_back(block.id);
            if self.applied.len() > self.depth {
                self.applied.pop_front();
            }
        }

        Ok(())
    }

    /// Follow a notice that notifications were missed, by following the tip.
    pub async fn on_lagged(&mut self, chain: &impl Chain) -> Result<(), DriverError> {
        let tip = chain.tip().await?;
        self.on_block(tip, chain).await
    }
}

/// `neptune-core`, read over JSON-RPC. Reading a block by its hash needs the
/// `archival` namespace.
#[derive(Debug, Clone)]
pub struct RpcChain<C> {
    pub client: C,
}

impl<C: RpcApi> Chain for RpcChain<C> {
    async fn block(&self, hash: Digest) -> Result<ObservedBlock, ChainError> {
        let kernel = self
            .client
            .get_block_kernel(BlockSelector::Digest(hash))
            .await
            .map_err(ChainError::Rpc)?
            .kernel
            .ok_or(ChainError::Unknown(hash))?;
        let transaction = kernel.body.transaction_kernel;

        // The body's accumulator counts the transaction's outputs but not the
        // guesser's, which come after them.
        let first_leaf_index =
            kernel.body.mutator_set_accumulator.aocl.leaf_count - transaction.outputs.len() as u64;

        Ok(ObservedBlock {
            id: BlockId {
                height: kernel.header.height,
                hash,
            },
            parent: kernel.header.prev_block_digest,
            first_leaf_index,
            announcements: transaction
                .announcements
                .into_iter()
                .map(Into::into)
                .collect(),
            outputs: transaction.outputs.into_iter().map(Into::into).collect(),
            spent: transaction
                .inputs
                .into_iter()
                .map(|input| input.absolute_indices)
                .collect(),
        })
    }

    async fn tip(&self) -> Result<Digest, ChainError> {
        Ok(self
            .client
            .tip_digest()
            .await
            .map_err(ChainError::Rpc)?
            .digest)
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use neptune_primitives::block_height::BlockHeight;

    use super::*;

    /// A chain held in memory, as a tree of blocks named by strings.
    #[derive(Default)]
    struct MapChain {
        blocks: HashMap<Digest, ObservedBlock>,
        tip: Option<Digest>,
    }

    /// The hash of the block named `name`.
    fn hash(name: &str) -> Digest {
        use tasm_lib::prelude::Tip5;
        use tasm_lib::triton_vm::prelude::BFieldElement;

        let elements = name.bytes().map(|byte| BFieldElement::new(u64::from(byte)));
        Tip5::hash_varlen(&elements.collect::<Vec<_>>())
    }

    impl MapChain {
        /// Add the block `name` at `height` with parent `parent`, and make it
        /// the tip.
        fn add(&mut self, name: &str, height: u64, parent: &str) {
            let block = ObservedBlock {
                id: BlockId {
                    height: BlockHeight::new(height.into()),
                    hash: hash(name),
                },
                parent: hash(parent),
                first_leaf_index: 0,
                announcements: vec![],
                outputs: vec![],
                spent: vec![],
            };
            self.blocks.insert(hash(name), block);
            self.tip = Some(hash(name));
        }

        /// Add the blocks `names`, each the child of the one before, the first
        /// a child of `parent` at height `height`.
        fn extend(&mut self, parent: &str, height: u64, names: &[&str]) {
            let mut parent = parent;
            for (offset, name) in names.iter().enumerate() {
                self.add(name, height + offset as u64, parent);
                parent = name;
            }
        }
    }

    impl Chain for MapChain {
        async fn block(&self, hash: Digest) -> Result<ObservedBlock, ChainError> {
            self.blocks
                .get(&hash)
                .cloned()
                .ok_or(ChainError::Unknown(hash))
        }

        async fn tip(&self) -> Result<Digest, ChainError> {
            Ok(self.tip.expect("a tip"))
        }
    }

    /// What was done to the state, by block name.
    #[derive(Debug, Default, PartialEq, Eq)]
    struct Log(Vec<String>);

    fn name(hash: Digest) -> String {
        ["g", "a", "b", "c", "d", "e", "b2", "c2", "d2", "e2", "x"]
            .into_iter()
            .find(|name| self::hash(name) == hash)
            .unwrap()
            .to_owned()
    }

    impl ChainState for Log {
        fn apply(&mut self, block: &ObservedBlock) {
            self.0.push(format!("apply {}", name(block.id.hash)));
        }

        fn roll_back_to(&mut self, ancestor: BlockId) {
            self.0.push(format!("back to {}", name(ancestor.hash)));
        }
    }

    fn log(entries: &[&str]) -> Log {
        Log(entries.iter().map(|entry| (*entry).to_owned()).collect())
    }

    /// The chain `g a b c d e`, and a driver of depth `depth` that followed
    /// `a`.
    async fn followed_a(depth: usize) -> (MapChain, Driver<Log>) {
        let mut chain = MapChain::default();
        chain.extend("none", 0, &["g", "a", "b", "c", "d", "e"]);
        let mut driver = Driver::new(Log::default(), depth);
        driver.on_block(hash("a"), &chain).await.unwrap();
        (chain, driver)
    }

    #[tokio::test]
    async fn the_first_block_is_applied_alone() {
        let (_, driver) = followed_a(10).await;
        assert_eq!(&log(&["apply a"]), driver.state());
        assert_eq!(Some(hash("a")), driver.tip().map(|id| id.hash));
    }

    #[tokio::test]
    async fn each_child_is_applied_in_turn() {
        let (chain, mut driver) = followed_a(10).await;
        for block in ["b", "c"] {
            driver.on_block(hash(block), &chain).await.unwrap();
        }
        assert_eq!(&log(&["apply a", "apply b", "apply c"]), driver.state());
    }

    /// A gap of missed notifications is filled from the chain, and a
    /// notification that comes again, or after a later one, changes nothing.
    #[tokio::test]
    async fn gaps_are_filled_and_stale_notifications_ignored() {
        let (chain, mut driver) = followed_a(10).await;
        for block in ["d", "b", "d", "a", "c"] {
            driver.on_block(hash(block), &chain).await.unwrap();
        }
        assert_eq!(
            &log(&["apply a", "apply b", "apply c", "apply d"]),
            driver.state()
        );
    }

    #[tokio::test]
    async fn a_lag_notice_is_followed_to_the_tip() {
        let (chain, mut driver) = followed_a(10).await;
        driver.on_lagged(&chain).await.unwrap();
        assert_eq!(
            &log(&["apply a", "apply b", "apply c", "apply d", "apply e"]),
            driver.state()
        );
    }

    /// A reorganization rolls back to the last block both branches share and
    /// applies the new branch after it, whether it leaves one block or three
    /// behind.
    #[tokio::test]
    async fn a_reorganization_rolls_back_and_applies_the_new_branch() {
        let (mut chain, mut driver) = followed_a(10).await;
        driver.on_block(hash("b"), &chain).await.unwrap();
        chain.add("b2", 2, "a");
        driver.on_block(hash("b2"), &chain).await.unwrap();
        assert_eq!(
            &log(&["apply a", "apply b", "back to a", "apply b2"]),
            driver.state()
        );

        let (mut chain, mut driver) = followed_a(10).await;
        driver.on_block(hash("d"), &chain).await.unwrap();
        chain.extend("a", 2, &["b2", "c2", "d2", "e2"]);
        driver.on_block(hash("e2"), &chain).await.unwrap();
        assert_eq!(
            &log(&[
                "apply a",
                "apply b",
                "apply c",
                "apply d",
                "back to a",
                "apply b2",
                "apply c2",
                "apply d2",
                "apply e2",
            ]),
            driver.state()
        );
        assert_eq!(Some(hash("e2")), driver.tip().map(|id| id.hash));
    }

    /// The driver remembers `depth` blocks, and follows a reorganization if
    /// and only if the new branch leaves the old one among them. If not, it
    /// reports so and the state is as it was.
    #[tokio::test]
    async fn a_reorganization_deeper_than_the_driver_remembers_is_an_error() {
        // With depth 3, after a b c d the driver remembers b c d.
        let (mut chain, mut driver) = followed_a(3).await;
        driver.on_block(hash("d"), &chain).await.unwrap();
        chain.extend("b", 3, &["c2", "d2", "e2"]);
        driver.on_block(hash("e2"), &chain).await.unwrap();
        assert_eq!(Some(hash("e2")), driver.tip().map(|id| id.hash));

        let (mut chain, mut driver) = followed_a(3).await;
        driver.on_block(hash("d"), &chain).await.unwrap();
        chain.extend("a", 2, &["b2", "c2", "d2", "e2"]);
        let before = driver.state().0.clone();
        assert_eq!(
            Err(DriverError::TooDeep { depth: 3 }),
            driver.on_block(hash("e2"), &chain).await
        );
        assert_eq!(before, driver.state().0);
        assert_eq!(Some(hash("d")), driver.tip().map(|id| id.hash));
    }

    /// A block the chain does not know leaves the state as it was, even when
    /// it is an ancestor found while walking back.
    #[tokio::test]
    async fn an_unknown_block_is_an_error_that_changes_nothing() {
        let (mut chain, mut driver) = followed_a(10).await;
        assert_eq!(
            Err(DriverError::Chain(ChainError::Unknown(hash("x")))),
            driver.on_block(hash("x"), &chain).await
        );

        chain.add("c2", 3, "x");
        assert_eq!(
            Err(DriverError::Chain(ChainError::Unknown(hash("x")))),
            driver.on_block(hash("c2"), &chain).await
        );
        assert_eq!(&log(&["apply a"]), driver.state());
    }

    /// A chain whose blocks name each other as parents, as a lying node may
    /// serve, does not keep the driver walking forever.
    #[tokio::test]
    async fn a_cycle_of_parents_ends_in_an_error() {
        let (mut chain, mut driver) = followed_a(10).await;
        chain.add("b2", 2, "c2");
        chain.add("c2", 3, "b2");

        let followed = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            driver.on_block(hash("c2"), &chain),
        )
        .await
        .expect("the driver stops walking");
        assert_eq!(Err(DriverError::TooDeep { depth: 10 }), followed);
        assert_eq!(&log(&["apply a"]), driver.state());
    }

    /// A driver of depth 1 remembers only the block it applied last: it
    /// follows children and gaps of none, and refuses any other branch.
    #[tokio::test]
    async fn a_driver_of_depth_one_follows_children_only() {
        let (mut chain, mut driver) = followed_a(1).await;
        driver.on_block(hash("b"), &chain).await.unwrap();
        chain.add("b2", 2, "a");
        assert_eq!(
            Err(DriverError::TooDeep { depth: 1 }),
            driver.on_block(hash("b2"), &chain).await
        );
        assert_eq!(
            Err(DriverError::TooDeep { depth: 1 }),
            driver.on_block(hash("d"), &chain).await
        );
        driver.on_block(hash("c"), &chain).await.unwrap();
        assert_eq!(&log(&["apply a", "apply b", "apply c"]), driver.state());
    }
}
