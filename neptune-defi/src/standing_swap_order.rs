pub mod order_book;
pub mod sofun;
pub mod sso_lock_script;
pub mod v1;

use std::collections::HashSet;
use std::fmt::Debug;

use neptune_consensus::type_scripts::native_currency_amount::NativeCurrencyAmount;
use tasm_lib::prelude::Digest;
use tasm_lib::prelude::Tip5;
use tasm_lib::triton_vm::prelude::BFieldCodec;
use tasm_lib::triton_vm::prelude::BFieldElement;

/// Element 0 of every standing swap order announcement.
//
// ponytail: defined here until the flag is allocated in `AnnouncementFlag`.
pub const STANDING_SWAP_ORDER_FLAG: BFieldElement = BFieldElement::new(1000);

/// The domain separator for deriving the reward's sender randomness from the
/// seed (§4.3).
///
/// Domains 0 and 1 belong to the offered side's `sender_randomness` and
/// `receiver_preimage`, which the wallet derives from the same seed. They are
/// reserved rather than used here. Reusing one of them would give two of an
/// order's randomnesses the same value, which is the collision §7.1 is about.
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
    pub fn offered_amount(&self) -> NativeCurrencyAmount {
        self.offered_amount
    }

    pub fn demanded_amount(&self) -> NativeCurrencyAmount {
        self.demanded_amount
    }

    pub fn params(&self) -> C::Params {
        self.params.clone()
    }

    /// The reward's sender_randomness derived from the order's public `seed`.
    ///
    /// Every configuration derives it the same way. The seed is public in all
    /// of them, and §7.1's freshness requirement is about the seed rather than
    /// about what the demanded UTXO happens to be, so nothing here depends on
    /// which configuration `C` is.
    pub(crate) fn reward_sender_randomness(&self) -> Digest {
        Tip5::hash_varlen(
            &[
                self.seed.values().to_vec(),
                vec![BFieldElement::new(REWARD_SENDER_RANDOMNESS_DOMAIN)],
            ]
            .concat(),
        )
    }
}
