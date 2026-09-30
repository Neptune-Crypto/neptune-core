pub mod observe;
pub mod order_book;
pub mod sofun;
pub mod sso_lock_script;
pub mod v1;

use std::collections::HashSet;
use std::fmt::Debug;

use neptune_consensus::transaction::announcement::Announcement;
use neptune_consensus::transaction::utxo_triple::UtxoTriple;
use neptune_consensus::type_scripts::native_currency_amount::NativeCurrencyAmount;
use neptune_mutator_set::removal_record::absolute_index_set::AbsoluteIndexSet;
use order_book::OrderId;
use tasm_lib::prelude::Digest;
use tasm_lib::prelude::Tip5;
use tasm_lib::triton_vm::prelude::BFieldCodec;
use tasm_lib::triton_vm::prelude::BFieldElement;

/// Element 0 of every standing swap order announcement.
///
/// An announcement flag is defined next to the protocol that writes it --
/// generation addresses, symmetric key addresses and lustration each define
/// their own -- so this is the allocation itself and not a stand-in for one.
pub const STANDING_SWAP_ORDER_FLAG: BFieldElement = BFieldElement::new(1000);

/// The domain separators for deriving an order's three randomnesses from its
/// seed.
///
/// Each randomness has a domain of its own. Were two of them to share one,
/// two of an order's randomnesses would have the same value, and two orders
/// whose rewards share an addition record can both be filled by one output.
const OFFERED_SENDER_RANDOMNESS_DOMAIN: u64 = 0;
const OFFERED_RECEIVER_PREIMAGE_DOMAIN: u64 = 1;
const REWARD_SENDER_RANDOMNESS_DOMAIN: u64 = 2;

/// The hash of a type script, which is how an asset is named.
pub type TypeScriptHash = Digest;

/// An asset, as the set of type scripts its coins carry.
pub type Asset = HashSet<TypeScriptHash>;

/// The two sides of a market: what its orders offer and what they demand.
///
/// Every order in one [`order_book::OrderBook`] shares the same pair, so the
/// pair is stored once, on the book, rather than repeated on each order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AssetPair {
    pub offered: Asset,
    pub demanded: Asset,
}

impl AssetPair {
    /// `pair_id`, element 1 of an announcement: the first element of the hash
    /// of the offered type scripts followed by the demanded ones.
    pub fn pair_id(&self) -> BFieldElement {
        fn type_script_hashes(asset: &Asset) -> Vec<BFieldElement> {
            let mut type_scripts = asset.iter().copied().collect::<Vec<_>>();
            // Sorting makes the order deterministic so that different consumers
            // compute the same pair ID.
            type_scripts.sort();
            type_scripts.iter().flat_map(|ts| ts.values()).collect()
        }

        let offered = type_script_hashes(&self.offered);
        let demanded = type_script_hashes(&self.demanded);
        Tip5::hash_varlen(&[offered, demanded].concat()).values()[0]
    }
}

/// Common logic and data structures for various types of standing swap orders.
pub trait Swappable: Sized {
    /// What an order carries beyond the terms every configuration shares.
    type Params: Debug + Clone;

    /// How the order is encoded in an announcement on the blockchain.
    ///
    /// Encoding cannot fail: every [`StandingSwapOrder<Self>`] was built by a
    /// constructor that establishes this configuration's invariants.
    type EncodingFormat: BFieldCodec
        + From<StandingSwapOrder<Self>>
        + TryInto<StandingSwapOrder<Self>>;

    /// The schema version of [`Self::EncodingFormat`], written as element 2 of
    /// the announcement envelope.
    fn version() -> u64;

    /// The UTXO holding an order's offered amount under the order's lock
    /// script.
    ///
    /// Its addition record is what the proposer's transaction outputs
    /// alongside the announcement, and so it is what a driver looks for among
    /// the outputs of the announcement's block.
    fn order_utxo(order: &StandingSwapOrder<Self>) -> UtxoTriple;

    /// Extract the order from an announcement, if the message is an order of
    /// this configuration on the pair named by `pair_id`.
    fn recognize(
        pair_id: BFieldElement,
        message: &[BFieldElement],
    ) -> Result<StandingSwapOrder<Self>, UnrecognizedOrder> {
        if message.first() != Some(&STANDING_SWAP_ORDER_FLAG) {
            return Err(UnrecognizedOrder::NotAnOrder);
        }
        let [_, id, version, body @ ..] = message else {
            return Err(UnrecognizedOrder::Malformed);
        };
        if *id != pair_id {
            return Err(UnrecognizedOrder::NotThisPair);
        }
        if *version != BFieldElement::new(Self::version()) {
            return Err(UnrecognizedOrder::UnknownVersion(*version));
        }

        let body = <Self::EncodingFormat as BFieldCodec>::decode(body)
            .map_err(|_| UnrecognizedOrder::Malformed)?;
        TryInto::<StandingSwapOrder<Self>>::try_into(*body)
            .map_err(|_| UnrecognizedOrder::Malformed)
    }
}

/// Why [`Swappable::recognize`] rejected an announcement.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UnrecognizedOrder {
    /// Element 0 is not [`STANDING_SWAP_ORDER_FLAG`].
    NotAnOrder,

    /// A standing swap order on another pair.
    NotThisPair,

    /// An order on this pair, under a schema version this configuration does
    /// not implement. Consumers should report it rather than skip it silently.
    UnknownVersion(BFieldElement),

    /// The flag and pair match, but the envelope is truncated or the body does
    /// not decode to a valid order.
    Malformed,
}

/// A standing order for swapping two assets.
///
/// Public on the blockchain. Can be cancelled or filled at any
/// time -- first come, first serve. Fills are atomic: no partial fills.
///
/// The fields are private to this module, so a value can only be built by a
/// constructor in this module or one of its children. Each configuration `C`
/// supplies its own constructor, and that constructor is where the relation
/// between the terms and `C::Params` is established.
#[derive(Debug, Clone, Copy)]
pub struct StandingSwapOrder<C: Swappable> {
    offered_amount: NativeCurrencyAmount,
    demanded_amount: NativeCurrencyAmount,
    seed: Digest,
    cancel_post_image: Digest,
    reward_lock_script_hash: Digest,
    reward_receiver_digest: Digest,
    params: C::Params,
}

impl<C: Swappable> StandingSwapOrder<C> {
    /// The message that announces this order.
    pub fn announce(self, pair: &AssetPair) -> Announcement {
        let envelope = vec![
            STANDING_SWAP_ORDER_FLAG,
            pair.pair_id(),
            BFieldElement::new(C::version()),
        ];
        let body = C::EncodingFormat::from(self).encode();

        Announcement::new([envelope, body].concat())
    }

    pub fn offered_amount(&self) -> NativeCurrencyAmount {
        self.offered_amount
    }

    pub fn demanded_amount(&self) -> NativeCurrencyAmount {
        self.demanded_amount
    }

    pub fn params(&self) -> C::Params {
        self.params.clone()
    }

    /// See [`Swappable::order_utxo`].
    pub fn order_utxo(&self) -> UtxoTriple {
        C::order_utxo(self)
    }

    /// The absolute index set of the removal record that spends the order
    /// UTXO, which became AOCL leaf `id`.
    ///
    /// Every ingredient is public, so anyone can tell when an order is closed,
    /// whether by a fill or by a cancel.
    pub fn absolute_index_set(&self, id: OrderId) -> AbsoluteIndexSet {
        AbsoluteIndexSet::compute(
            Tip5::hash(&self.order_utxo().utxo),
            self.offered_sender_randomness(),
            self.offered_receiver_preimage(),
            id.0,
        )
    }

    /// The offered UTXO's sender_randomness derived from the order's public
    /// `seed`.
    pub fn offered_sender_randomness(&self) -> Digest {
        self.derive_from_seed(OFFERED_SENDER_RANDOMNESS_DOMAIN)
    }

    /// The offered UTXO's receiver_preimage derived from the order's public
    /// `seed`.
    ///
    /// Public, like the seed, so that anyone can compute the removal record
    /// of the order UTXO: the lock script, not the preimage, guards it.
    pub fn offered_receiver_preimage(&self) -> Digest {
        self.derive_from_seed(OFFERED_RECEIVER_PREIMAGE_DOMAIN)
    }

    /// The reward's sender_randomness derived from the order's public `seed`.
    ///
    /// Every configuration derives it the same way. The seed is public in all
    /// of them, and it is the seed's freshness that keeps two orders' rewards
    /// from sharing an addition record, not what the demanded UTXO happens to
    /// be, so nothing here depends on which configuration `C` is.
    pub(crate) fn reward_sender_randomness(&self) -> Digest {
        self.derive_from_seed(REWARD_SENDER_RANDOMNESS_DOMAIN)
    }

    fn derive_from_seed(&self, domain: u64) -> Digest {
        Tip5::hash_varlen(
            &[
                self.seed.values().to_vec(),
                vec![BFieldElement::new(domain)],
            ]
            .concat(),
        )
    }
}

#[cfg(test)]
mod tests {
    use proptest::collection::vec;
    use proptest_arbitrary_interop::arb;
    use tasm_lib::triton_vm::prelude::bfe_array;
    use test_strategy::proptest;

    use super::*;

    fn pair(offered: &[Digest], demanded: &[Digest]) -> AssetPair {
        AssetPair {
            offered: offered.iter().copied().collect(),
            demanded: demanded.iter().copied().collect(),
        }
    }

    /// Two [`HashSet`]s holding the same type scripts do not iterate in the
    /// same order, because each draws its own hash seed. Every consumer of one
    /// market must nonetheless arrive at the same `pair_id`, so the id cannot
    /// depend on how the sets were built.
    #[proptest]
    fn pair_id_ignores_insertion_order(
        #[strategy(vec(arb::<Digest>(), 2..5))] offered: Vec<Digest>,
        #[strategy(vec(arb::<Digest>(), 2..5))] demanded: Vec<Digest>,
    ) {
        let reverse = |ts: &[Digest]| ts.iter().copied().rev().collect::<Vec<_>>();
        assert_eq!(
            pair(&offered, &demanded).pair_id(),
            pair(&reverse(&offered), &reverse(&demanded)).pair_id()
        );
    }

    /// A pair is directed: offering A for B is not offering B for A. So the
    /// two sides are hashed one after the other, and not canonicalized
    /// together.
    #[test]
    fn pair_id_is_directed() {
        let one = [Digest::default()];
        let other = [Digest::new(bfe_array![1, 0, 0, 0, 0])];
        assert_ne!(pair(&one, &other).pair_id(), pair(&other, &one).pair_id());
    }
}
