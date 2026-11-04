//! Vaults, and the bearer tokens they back.
//!
//! A vault holds coins of some type script `Vaultee`. The vault type script
//! `Vault(Vaultee, Bearer)` gives every vault a marker coin, and its other
//! coins are tokens, each of which can be redeemed against any vault. Vaulted
//! NPT is [`Vault::vnpt`].

use neptune_consensus::proof_abstractions::tasm::program::TritonProgram;
use neptune_consensus::transaction::announcement::Announcement;
use neptune_consensus::transaction::lock_script::LockScript;
use neptune_consensus::transaction::transaction_kernel::TransactionKernel;
use neptune_consensus::transaction::utxo::Coin;
use neptune_consensus::transaction::utxo::Utxo;
use neptune_consensus::type_scripts::native_currency::NativeCurrency;
use neptune_consensus::type_scripts::native_currency_amount::NativeCurrencyAmount;
use neptune_mutator_set::commit;
use tasm_lib::prelude::Digest;
use tasm_lib::prelude::Tip5;
use tasm_lib::triton_vm::prelude::*;

/// Element 0 of every vault announcement.
pub const VAULT_FLAG: BFieldElement = BFieldElement::new(1001);

/// The state of a coin of a [`Vault`] type script.
#[derive(Debug, Clone, Copy, PartialEq, Eq, BFieldCodec)]
pub enum VaultState {
    /// The UTXO carrying this coin holds this many tokens.
    Token(NativeCurrencyAmount),

    /// The UTXO carrying this coin is a vault.
    Marker,
}

/// The vault type script `Vault(Vaultee, Bearer)`.
///
/// A coin of `Vaultee` carries an amount as its state, encoded as a
/// [`NativeCurrencyAmount`]. The policy is `Bearer`, whose code is part of
/// the program, so the program's hash names both `Vaultee` and the policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Vault {
    pub vaultee: Digest,
}

/// The reason [`Vault::validate`] rejects a transaction.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VaultError {
    /// The state of a coin of this vault type script does not decode.
    InvalidState,

    /// Output `i` carries a vault marker but is not a vault.
    NotAVault(usize),

    /// No announcement of the transaction is a vault announcement of output
    /// `i` whose randomnesses give the output's addition record.
    MissingAnnouncement(usize),

    /// Output `i` carries a negative token amount.
    NegativeToken(usize),

    /// A sum of token amounts or of holdings exceeds the largest amount.
    OutOfRange,

    /// More than one vault is among the inputs, or among the outputs.
    TooManyVaults,

    /// The tokens minted, less those burnt, differ from the holding added to
    /// the vaults, less that taken from them.
    Unbacked,
}

/// What [`Vault`] counts in a list of UTXOs.
#[derive(Debug, Default)]
struct Tally {
    tokens: i128,
    holding: i128,
    num_vaults: usize,
}

impl Vault {
    /// Vaulted NPT, `Vault(NativeCurrency, Bearer)`.
    pub fn vnpt() -> Self {
        Self {
            vaultee: NativeCurrency.hash(),
        }
    }

    // ponytail: a program that always crashes, so that no coin of this type
    // script is valid until the type script itself replaces it.
    pub fn program(&self) -> Program {
        let vaultee = self.vaultee.values().map(|e| e.value());
        triton_program!(
            push {vaultee[0]} push {vaultee[1]} push {vaultee[2]} push {vaultee[3]}
            push {vaultee[4]} pop 5
            push 0 assert
            halt
        )
    }

    pub fn hash(&self) -> Digest {
        self.program().hash()
    }

    /// A coin of `a` tokens.
    pub fn token(&self, amount: NativeCurrencyAmount) -> Coin {
        self.coin(VaultState::Token(amount))
    }

    /// The vault holding `holding`.
    pub fn vault_utxo(&self, holding: NativeCurrencyAmount) -> Utxo {
        let vaultee = Coin {
            type_script_hash: self.vaultee,
            state: holding.encode(),
        };
        Utxo::new(
            vault_lock_script().hash(),
            vec![vaultee, self.coin(VaultState::Marker)],
        )
    }

    fn coin(&self, state: VaultState) -> Coin {
        Coin {
            type_script_hash: self.hash(),
            state: state.encode(),
        }
    }

    /// Accept or reject a transaction, as the type script does.
    ///
    /// `inputs` and `outputs` are the transaction's input and output UTXOs, and
    /// `outputs[i]` is the UTXO of `kernel.outputs[i]`. The transaction is
    /// accepted if and only if
    ///
    ///  1. every output that carries a vault marker is a vault, and the kernel
    ///     carries a vault announcement of it whose randomnesses give its
    ///     addition record,
    ///  2. every token amount among the outputs is non-negative, and no sum of
    ///     token amounts or of holdings exceeds the largest amount,
    ///  3. at most one vault is among the inputs, and at most one among the
    ///     outputs, and
    ///  4. the tokens among the outputs less those among the inputs equal the
    ///     holdings of the vaults among the outputs less those among the
    ///     inputs.
    ///
    /// Rule 4 is the bearer policy's, and implies that no transaction mints
    /// more tokens than it adds to the vaults' holding.
    pub fn validate(
        &self,
        kernel: &TransactionKernel,
        inputs: &[Utxo],
        outputs: &[Utxo],
    ) -> Result<(), VaultError> {
        for (i, output) in outputs.iter().enumerate() {
            let states = self.states(output)?;
            if states.contains(&VaultState::Marker) {
                self.check_vault(kernel, i, output)?;
            }
            if states
                .iter()
                .any(|state| matches!(state, VaultState::Token(amount) if amount.is_negative()))
            {
                return Err(VaultError::NegativeToken(i));
            }
        }

        let inputs = self.tally(inputs)?;
        let outputs = self.tally(outputs)?;
        if inputs.num_vaults > 1 || outputs.num_vaults > 1 {
            return Err(VaultError::TooManyVaults);
        }
        if outputs.tokens - inputs.tokens != outputs.holding - inputs.holding {
            return Err(VaultError::Unbacked);
        }

        Ok(())
    }

    /// The states of the coins of this type script that `utxo` carries.
    fn states(&self, utxo: &Utxo) -> Result<Vec<VaultState>, VaultError> {
        utxo.coins()
            .iter()
            .filter(|coin| coin.type_script_hash == self.hash())
            .map(|coin| {
                VaultState::decode(&coin.state)
                    .map(|state| *state)
                    .map_err(|_| VaultError::InvalidState)
            })
            .collect()
    }

    /// Check that output `i`, which carries a vault marker, is an announced
    /// vault.
    fn check_vault(
        &self,
        kernel: &TransactionKernel,
        i: usize,
        output: &Utxo,
    ) -> Result<(), VaultError> {
        let [vaultee, marker] = output.coins() else {
            return Err(VaultError::NotAVault(i));
        };
        let is_vault = output.lock_script_hash() == vault_lock_script().hash()
            && vaultee.type_script_hash == self.vaultee
            && NativeCurrencyAmount::decode(&vaultee.state).is_ok()
            && *marker == self.coin(VaultState::Marker);
        if !is_vault {
            return Err(VaultError::NotAVault(i));
        }

        let announced = kernel.announcements.iter().any(|announcement| {
            VaultAnnouncement::decode(announcement).is_some_and(|announced| {
                announced.utxo == *output
                    && kernel.outputs.get(i) == Some(&announced.addition_record())
            })
        });
        if !announced {
            return Err(VaultError::MissingAnnouncement(i));
        }

        Ok(())
    }

    fn tally(&self, utxos: &[Utxo]) -> Result<Tally, VaultError> {
        let max = NativeCurrencyAmount::MAX_NAU;
        let add = |sum: i128, amount: i128| {
            sum.checked_add(amount)
                .filter(|sum| *sum <= max)
                .ok_or(VaultError::OutOfRange)
        };

        let mut tally = Tally::default();
        for utxo in utxos {
            for state in self.states(utxo)? {
                match state {
                    VaultState::Token(amount) => {
                        tally.tokens = add(tally.tokens, amount.to_nau())?;
                    }
                    VaultState::Marker => {
                        tally.num_vaults += 1;
                        let holding = utxo
                            .coins()
                            .iter()
                            .filter(|coin| coin.type_script_hash == self.vaultee)
                            .map(|coin| NativeCurrencyAmount::decode(&coin.state))
                            .map(|amount| amount.map_err(|_| VaultError::InvalidState))
                            .try_fold(0, |sum, amount| add(sum, amount?.to_nau()))?;
                        tally.holding = add(tally.holding, holding)?;
                    }
                }
            }
        }

        Ok(tally)
    }
}

/// The lock script of every vault, which halts on every input.
pub fn vault_lock_script() -> LockScript {
    LockScript::new(triton_program!(halt))
}

/// The announcement that makes a vault spendable by anyone: its UTXO and both
/// randomnesses, from which anyone can compute its removal record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VaultAnnouncement {
    pub sender_randomness: Digest,
    pub receiver_preimage: Digest,
    pub utxo: Utxo,
}

impl VaultAnnouncement {
    /// The addition record of the announced vault.
    pub fn addition_record(&self) -> neptune_mutator_set::addition_record::AdditionRecord {
        commit(
            Tip5::hash(&self.utxo),
            self.sender_randomness,
            self.receiver_preimage.hash(),
        )
    }

    /// The announcement: [`VAULT_FLAG`], the sender randomness, the receiver
    /// preimage and the encoding of the UTXO.
    pub fn announcement(&self) -> Announcement {
        Announcement {
            message: [
                vec![VAULT_FLAG],
                self.sender_randomness.encode(),
                self.receiver_preimage.encode(),
                self.utxo.encode(),
            ]
            .concat(),
        }
    }

    /// The vault announcement that `announcement` is, if it is one.
    ///
    /// Every announcement has at most one reading, since the UTXO's encoding
    /// must take up exactly the elements that follow the randomnesses.
    pub fn decode(announcement: &Announcement) -> Option<Self> {
        let (flag, rest) = announcement.message.split_first()?;
        if *flag != VAULT_FLAG || rest.len() < 2 * Digest::LEN {
            return None;
        }
        let (sender_randomness, rest) = rest.split_at(Digest::LEN);
        let (receiver_preimage, utxo) = rest.split_at(Digest::LEN);

        Some(Self {
            sender_randomness: *Digest::decode(sender_randomness).ok()?,
            receiver_preimage: *Digest::decode(receiver_preimage).ok()?,
            utxo: *Utxo::decode(utxo).ok()?,
        })
    }
}

#[cfg(test)]
mod tests {
    use neptune_consensus::transaction::transaction_kernel::TransactionKernelModifier;
    use proptest::prelude::*;
    use proptest_arbitrary_interop::arb;
    use test_strategy::proptest;

    use super::*;

    /// The largest amount, which is also the largest a vault may hold.
    const MAX: i128 = NativeCurrencyAmount::MAX_NAU;

    fn nau(amount: i128) -> NativeCurrencyAmount {
        NativeCurrencyAmount::from_nau(amount)
    }

    fn token_utxo(amount: i128) -> Utxo {
        let lock_script_hash = Digest::default();
        Utxo::new(lock_script_hash, vec![Vault::vnpt().token(nau(amount))])
    }

    fn npt_utxo(amount: i128) -> Utxo {
        Utxo::new_native_currency(Digest::default(), nau(amount))
    }

    /// A transaction from `inputs` to `outputs`, as `Vault::validate` sees it.
    ///
    /// Every output gets an addition record from `randomness`, and every
    /// output that carries a vault marker is announced.
    struct Tx {
        kernel: TransactionKernel,
        inputs: Vec<Utxo>,
        outputs: Vec<Utxo>,
    }

    impl Tx {
        fn new(kernel: TransactionKernel, inputs: Vec<Utxo>, outputs: Vec<Utxo>) -> Self {
            let announcements = Self::announcements(&outputs);
            let kernel = TransactionKernelModifier::default()
                .outputs(
                    announcements
                        .iter()
                        .map(VaultAnnouncement::addition_record)
                        .collect(),
                )
                .announcements(
                    announcements
                        .iter()
                        .filter(|announced| {
                            announced
                                .utxo
                                .coins()
                                .contains(&Vault::vnpt().coin(VaultState::Marker))
                        })
                        .map(VaultAnnouncement::announcement)
                        .collect(),
                )
                .modify(kernel);
            Self {
                kernel,
                inputs,
                outputs,
            }
        }

        fn announcements(outputs: &[Utxo]) -> Vec<VaultAnnouncement> {
            outputs
                .iter()
                .enumerate()
                .map(|(i, utxo)| VaultAnnouncement {
                    sender_randomness: Tip5::hash(&(i as u64)),
                    receiver_preimage: Tip5::hash(&(i as u64 + 1000)),
                    utxo: utxo.clone(),
                })
                .collect()
        }

        fn validate(&self) -> Result<(), VaultError> {
            Vault::vnpt().validate(&self.kernel, &self.inputs, &self.outputs)
        }
    }

    fn vault(holding: i128) -> Utxo {
        Vault::vnpt().vault_utxo(nau(holding))
    }

    #[proptest(cases = 20)]
    fn announcement_round_trips(
        #[strategy(arb())] sender_randomness: Digest,
        #[strategy(arb())] receiver_preimage: Digest,
        #[strategy(0..=MAX)] holding: i128,
    ) {
        let announced = VaultAnnouncement {
            sender_randomness,
            receiver_preimage,
            utxo: vault(holding),
        };
        prop_assert_eq!(
            Some(announced.clone()),
            VaultAnnouncement::decode(&announced.announcement())
        );
    }

    #[test]
    fn other_announcements_are_not_vault_announcements() {
        let announced = VaultAnnouncement {
            sender_randomness: Digest::default(),
            receiver_preimage: Digest::default(),
            utxo: vault(1),
        };
        let mut message = announced.announcement().message;
        message[0] = BFieldElement::new(1000);
        assert_eq!(
            None,
            VaultAnnouncement::decode(&Announcement {
                message: message.clone()
            })
        );

        message[0] = VAULT_FLAG;
        message.pop();
        assert_eq!(None, VaultAnnouncement::decode(&Announcement { message }));
    }

    #[proptest(cases = 20)]
    fn create_is_accepted(
        #[strategy(arb())] kernel: TransactionKernel,
        #[strategy(0..=MAX)] holding: i128,
    ) {
        let tx = Tx::new(
            kernel,
            vec![npt_utxo(holding)],
            vec![vault(holding), token_utxo(holding)],
        );
        prop_assert_eq!(Ok(()), tx.validate());
    }

    #[proptest(cases = 5)]
    fn creating_the_largest_vault_is_accepted(#[strategy(arb())] kernel: TransactionKernel) {
        let tx = Tx::new(
            kernel,
            vec![npt_utxo(MAX)],
            vec![vault(MAX), token_utxo(MAX)],
        );
        prop_assert_eq!(Ok(()), tx.validate());
    }

    #[proptest(cases = 20)]
    fn withdrawal_is_accepted(
        #[strategy(arb())] kernel: TransactionKernel,
        #[strategy(1..=MAX)] holding: i128,
        #[strategy(0..#holding)] withdrawn: i128,
    ) {
        let tx = Tx::new(
            kernel,
            vec![vault(holding), token_utxo(withdrawn)],
            vec![vault(holding - withdrawn), npt_utxo(withdrawn)],
        );
        prop_assert_eq!(Ok(()), tx.validate());
    }

    #[proptest(cases = 20)]
    fn emptying_is_accepted(
        #[strategy(arb())] kernel: TransactionKernel,
        #[strategy(0..=MAX)] holding: i128,
    ) {
        let tx = Tx::new(
            kernel,
            vec![vault(holding), token_utxo(holding)],
            vec![npt_utxo(holding)],
        );
        prop_assert_eq!(Ok(()), tx.validate());
    }

    #[proptest(cases = 20)]
    fn top_up_is_accepted(
        #[strategy(arb())] kernel: TransactionKernel,
        #[strategy(0..=MAX)] holding: i128,
        #[strategy(0..=MAX - #holding)] added: i128,
    ) {
        let tx = Tx::new(
            kernel,
            vec![vault(holding), npt_utxo(added)],
            vec![vault(holding + added), token_utxo(added)],
        );
        prop_assert_eq!(Ok(()), tx.validate());
    }

    #[proptest(cases = 20)]
    fn transfer_is_accepted(
        #[strategy(arb())] kernel: TransactionKernel,
        #[strategy(0..=MAX)] amount: i128,
        #[strategy(0..=#amount)] split: i128,
    ) {
        let tx = Tx::new(
            kernel,
            vec![token_utxo(amount)],
            vec![token_utxo(split), token_utxo(amount - split)],
        );
        prop_assert_eq!(Ok(()), tx.validate());
    }

    #[proptest(cases = 20)]
    fn minting_without_a_deposit_is_rejected(
        #[strategy(arb())] kernel: TransactionKernel,
        #[strategy(1..=MAX)] amount: i128,
    ) {
        let tx = Tx::new(kernel, vec![], vec![token_utxo(amount)]);
        prop_assert_eq!(Err(VaultError::Unbacked), tx.validate());
    }

    #[proptest(cases = 20)]
    fn withdrawal_without_a_burn_is_rejected(
        #[strategy(arb())] kernel: TransactionKernel,
        #[strategy(1..=MAX)] holding: i128,
        #[strategy(1..=#holding)] withdrawn: i128,
    ) {
        let tx = Tx::new(
            kernel,
            vec![vault(holding)],
            vec![vault(holding - withdrawn), npt_utxo(withdrawn)],
        );
        prop_assert_eq!(Err(VaultError::Unbacked), tx.validate());
    }

    #[proptest(cases = 20)]
    fn minting_in_a_withdrawal_is_rejected(
        #[strategy(arb())] kernel: TransactionKernel,
        #[strategy(1..=MAX)] holding: i128,
        #[strategy(1..=#holding)] withdrawn: i128,
    ) {
        let tx = Tx::new(
            kernel,
            vec![vault(holding)],
            vec![vault(holding - withdrawn), token_utxo(withdrawn)],
        );
        prop_assert_eq!(Err(VaultError::Unbacked), tx.validate());
    }

    #[proptest(cases = 20)]
    fn spending_two_vaults_is_rejected(
        #[strategy(arb())] kernel: TransactionKernel,
        #[strategy(0..=MAX / 2)] a: i128,
        #[strategy(0..=MAX / 2)] b: i128,
    ) {
        let tx = Tx::new(kernel, vec![vault(a), vault(b)], vec![vault(a + b)]);
        prop_assert_eq!(Err(VaultError::TooManyVaults), tx.validate());
    }

    #[proptest(cases = 20)]
    fn outputting_two_vaults_is_rejected(
        #[strategy(arb())] kernel: TransactionKernel,
        #[strategy(0..=MAX / 2)] a: i128,
        #[strategy(0..=MAX / 2)] b: i128,
    ) {
        let tx = Tx::new(kernel, vec![vault(a + b)], vec![vault(a), vault(b)]);
        prop_assert_eq!(Err(VaultError::TooManyVaults), tx.validate());
    }

    #[proptest(cases = 20)]
    fn a_vault_without_its_announcement_is_rejected(
        #[strategy(arb())] kernel: TransactionKernel,
        #[strategy(0..=MAX)] holding: i128,
    ) {
        let mut tx = Tx::new(
            kernel,
            vec![npt_utxo(holding)],
            vec![vault(holding), token_utxo(holding)],
        );
        tx.kernel = TransactionKernelModifier::default()
            .announcements(vec![])
            .modify(tx.kernel);
        prop_assert_eq!(Err(VaultError::MissingAnnouncement(0)), tx.validate());
    }

    #[proptest(cases = 20)]
    fn an_announcement_with_other_randomness_is_rejected(
        #[strategy(arb())] kernel: TransactionKernel,
        #[strategy(0..=MAX)] holding: i128,
        #[strategy(arb())] other_randomness: Digest,
    ) {
        let mut tx = Tx::new(
            kernel,
            vec![npt_utxo(holding)],
            vec![vault(holding), token_utxo(holding)],
        );
        let [announced] = &Tx::announcements(&tx.outputs)[..1] else {
            unreachable!()
        };
        prop_assume!(other_randomness != announced.sender_randomness);
        let wrong = VaultAnnouncement {
            sender_randomness: other_randomness,
            ..announced.clone()
        };
        tx.kernel = TransactionKernelModifier::default()
            .announcements(vec![wrong.announcement()])
            .modify(tx.kernel);
        prop_assert_eq!(Err(VaultError::MissingAnnouncement(0)), tx.validate());
    }

    #[proptest(cases = 20)]
    fn a_negative_token_is_rejected(
        #[strategy(arb())] kernel: TransactionKernel,
        #[strategy(1..=MAX)] amount: i128,
    ) {
        let tx = Tx::new(
            kernel,
            vec![token_utxo(0)],
            vec![token_utxo(-amount), token_utxo(amount)],
        );
        prop_assert_eq!(Err(VaultError::NegativeToken(0)), tx.validate());
    }

    #[proptest(cases = 5)]
    fn tokens_beyond_the_largest_amount_are_rejected(#[strategy(arb())] kernel: TransactionKernel) {
        let tx = Tx::new(kernel, vec![], vec![token_utxo(MAX), token_utxo(1)]);
        prop_assert_eq!(Err(VaultError::OutOfRange), tx.validate());
    }

    #[proptest(cases = 20)]
    fn a_vault_under_another_lock_script_is_rejected(
        #[strategy(arb())] kernel: TransactionKernel,
        #[strategy(0..=MAX)] holding: i128,
        #[strategy(arb())] lock_script_hash: Digest,
    ) {
        prop_assume!(lock_script_hash != vault_lock_script().hash());
        let locked = Utxo::new(lock_script_hash, vault(holding).coins().to_vec());
        let tx = Tx::new(
            kernel,
            vec![npt_utxo(holding)],
            vec![locked, token_utxo(holding)],
        );
        prop_assert_eq!(Err(VaultError::NotAVault(0)), tx.validate());
    }

    #[proptest(cases = 20)]
    fn a_vault_with_a_third_coin_is_rejected(
        #[strategy(arb())] kernel: TransactionKernel,
        #[strategy(0..=MAX)] holding: i128,
        #[strategy(arb())] third: Coin,
    ) {
        let coins = [vault(holding).coins().to_vec(), vec![third]].concat();
        let with_third = Utxo::new(vault_lock_script().hash(), coins);
        let tx = Tx::new(
            kernel,
            vec![npt_utxo(holding)],
            vec![with_third, token_utxo(holding)],
        );
        prop_assert_eq!(Err(VaultError::NotAVault(0)), tx.validate());
    }
}
