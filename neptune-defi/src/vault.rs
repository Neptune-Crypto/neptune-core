//! Vaults, and the bearer tokens they back.
//!
//! A vault holds coins of some type script `Vaultee`. The vault type script
//! `Vault(Vaultee, Bearer)` gives every vault a marker coin, and its other
//! coins are tokens, each of which can be redeemed against any vault. Vaulted
//! NPT is [`Vault::vnpt`].

mod tasm;

use std::sync::OnceLock;

use neptune_consensus::proof_abstractions::tasm::program::TritonProgram;
use neptune_consensus::transaction::announcement::Announcement;
use neptune_consensus::transaction::lock_script::LockScript;
use neptune_consensus::transaction::primitive_witness::SaltedUtxos;
use neptune_consensus::transaction::transaction_kernel::TransactionKernel;
use neptune_consensus::transaction::utxo::Coin;
use neptune_consensus::transaction::utxo::Utxo;
use neptune_consensus::type_scripts::native_currency::NativeCurrency;
use neptune_consensus::type_scripts::native_currency_amount::NativeCurrencyAmount;
use neptune_consensus::type_scripts::TypeScriptAndWitness;
use neptune_mutator_set::commit;
use tasm_lib::prelude::Digest;
use tasm_lib::prelude::Tip5;
use tasm_lib::triton_vm::prelude::*;

/// The length of the encoding of an amount, which is the state of a coin of
/// `Vaultee`.
const AMOUNT_LEN: usize = 4;

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
    vaultee: Digest,
    hash: Digest,
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

    /// A token amount, a holding, or a sum of either lies outside the range
    /// from zero to the largest amount.
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
    /// The vault type script of the coins of `vaultee`.
    pub fn new(vaultee: Digest) -> Self {
        Self {
            vaultee,
            hash: tasm::program(vaultee).hash(),
        }
    }

    /// Vaulted NPT, `Vault(NativeCurrency, Bearer)`.
    pub fn vnpt() -> Self {
        static VNPT: OnceLock<Vault> = OnceLock::new();
        *VNPT.get_or_init(|| Self::new(NativeCurrency.hash()))
    }

    pub fn vaultee(&self) -> Digest {
        self.vaultee
    }

    pub fn program(&self) -> Program {
        tasm::program(self.vaultee)
    }

    pub fn hash(&self) -> Digest {
        self.hash
    }

    /// The type script with its witness for a transaction, which halts if and
    /// only if [`Self::validate`] accepts it.
    ///
    /// The witness depends on nothing but its arguments, so it can be generated
    /// again whenever the kernel changes.
    pub fn type_script_and_witness(
        &self,
        kernel: &TransactionKernel,
        salted_inputs: &SaltedUtxos,
        salted_outputs: &SaltedUtxos,
    ) -> TypeScriptAndWitness {
        tasm::type_script_and_witness(self, kernel, salted_inputs, salted_outputs)
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
    ///  2. every token amount among the outputs is non-negative, and every
    ///     token amount, every holding of a vault, and every sum of either lies
    ///     between zero and the largest amount,
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
            && vaultee.state.len() == AMOUNT_LEN
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

    /// The tokens, the holdings of the vaults and the number of vault markers
    /// among `utxos`.
    ///
    /// A UTXO's holding is the sum of its coins of `Vaultee`, and counts if and
    /// only if the UTXO carries a vault marker.
    fn tally(&self, utxos: &[Utxo]) -> Result<Tally, VaultError> {
        let range = 0..=NativeCurrencyAmount::MAX_NAU;
        let in_range = |amount: i128| {
            Some(amount)
                .filter(|amount| range.contains(amount))
                .ok_or(VaultError::OutOfRange)
        };
        let add = |sum: i128, amount: NativeCurrencyAmount| {
            in_range(sum.checked_add(in_range(amount.to_nau())?).unwrap_or(-1))
        };

        let mut tally = Tally::default();
        for utxo in utxos {
            let mut num_markers = 0;
            for state in self.states(utxo)? {
                match state {
                    VaultState::Token(amount) => tally.tokens = add(tally.tokens, amount)?,
                    VaultState::Marker => num_markers += 1,
                }
            }
            if num_markers == 0 {
                continue;
            }

            tally.num_vaults += num_markers;
            let holding = utxo
                .coins()
                .iter()
                .filter(|coin| coin.type_script_hash == self.vaultee)
                .map(|coin| NativeCurrencyAmount::decode(&coin.state))
                .map(|amount| amount.map_err(|_| VaultError::InvalidState))
                .try_fold(0, |sum, amount| add(sum, *amount?))?;
            tally.holding = add(tally.holding, NativeCurrencyAmount::from_nau(holding))?;
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
    use neptune_primitives::mast_hash::MastHash;
    use proptest::collection::vec;
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

        /// The type script with its witness, and its standard input.
        fn type_script_and_witness(&self) -> (TypeScriptAndWitness, PublicInput) {
            let salted_inputs = SaltedUtxos::new(self.inputs.clone());
            let salted_outputs = SaltedUtxos::new(self.outputs.clone());
            let type_script_and_witness = Vault::vnpt().type_script_and_witness(
                &self.kernel,
                &salted_inputs,
                &salted_outputs,
            );
            let standard_input = [
                self.kernel.mast_hash(),
                Tip5::hash(&salted_inputs),
                Tip5::hash(&salted_outputs),
            ]
            .into_iter()
            .flat_map(|digest| digest.reversed().values())
            .collect::<Vec<_>>();

            (type_script_and_witness, PublicInput::new(standard_input))
        }

        /// What [`Vault::validate`] says of the transaction, after checking
        /// that the type script halts if and only if it accepts.
        fn validate(&self) -> Result<(), VaultError> {
            let verdict = Vault::vnpt().validate(&self.kernel, &self.inputs, &self.outputs);
            let (type_script_and_witness, standard_input) = self.type_script_and_witness();
            let run = VM::run(
                type_script_and_witness.program.clone(),
                standard_input,
                type_script_and_witness.nondeterminism(),
            );
            match (verdict, run) {
                (Ok(()), Ok(_)) => (),
                (Err(error), Err(crash)) => {
                    let id = match &crash.source {
                        InstructionError::AssertionFailed(assertion)
                        | InstructionError::VectorAssertionFailed(_, assertion) => assertion.id,
                        _ => None,
                    };
                    assert_eq!(
                        Some(error_id(error)),
                        id,
                        "reference: {error:?}; type script: {}",
                        crash.source
                    );
                }
                (verdict, run) => panic!(
                    "reference: {verdict:?}; type script: {:?}",
                    run.err().map(|crash| crash.source)
                ),
            }

            verdict
        }
    }

    /// The assertion on which the type script crashes for a transaction that
    /// the reference rejects with `error`.
    fn error_id(error: VaultError) -> i128 {
        match error {
            VaultError::InvalidState => tasm::INVALID_STATE_ERROR,
            VaultError::NotAVault(_) => tasm::NOT_A_VAULT_ERROR,
            VaultError::MissingAnnouncement(_) => tasm::MISSING_ANNOUNCEMENT_ERROR,
            // The type script reads a negative amount as one beyond the largest.
            VaultError::NegativeToken(_) | VaultError::OutOfRange => tasm::OUT_OF_RANGE_ERROR,
            VaultError::TooManyVaults => tasm::TOO_MANY_VAULTS_ERROR,
            VaultError::Unbacked => tasm::UNBACKED_ERROR,
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

    /// A witness of an accepted transaction with one word changed: a word of
    /// memory, a divined announcement index, or a digest of an authentication
    /// path.
    #[proptest(cases = 40)]
    fn a_tampered_witness_is_rejected(
        #[strategy(arb())] kernel: TransactionKernel,
        #[strategy(1..=MAX)] holding: i128,
        #[strategy(0..#holding)] withdrawn: i128,
        #[strategy(0..3usize)] part: usize,
        #[strategy(arb())] index: usize,
        #[strategy(arb())] value: BFieldElement,
    ) {
        let tx = Tx::new(
            kernel,
            vec![vault(holding), token_utxo(withdrawn)],
            vec![vault(holding - withdrawn), npt_utxo(withdrawn)],
        );
        prop_assert_eq!(Ok(()), tx.validate());

        let (witness, standard_input) = tx.type_script_and_witness();
        let mut nondeterminism = witness.nondeterminism();
        match part {
            0 => {
                let mut addresses = nondeterminism.ram.keys().copied().collect::<Vec<_>>();
                addresses.sort_by_key(|address| address.value());
                let address = addresses[index % addresses.len()];
                prop_assume!(nondeterminism.ram[&address] != value);
                nondeterminism.ram.insert(address, value);
            }
            1 => {
                let tokens = &mut nondeterminism.individual_tokens;
                let i = index % tokens.len();
                prop_assume!(tokens[i] != value);
                tokens[i] = value;
            }
            _ => {
                let digests = &mut nondeterminism.digests;
                let i = index % digests.len();
                let digest = Digest::new([value; Digest::LEN]);
                prop_assume!(digests[i] != digest);
                digests[i] = digest;
            }
        }

        prop_assert!(VM::run(witness.program, standard_input, nondeterminism).is_err());
    }

    #[proptest(cases = 20)]
    fn a_coin_of_neither_state_is_rejected(
        #[strategy(arb())] kernel: TransactionKernel,
        #[strategy(arb())] state: Vec<BFieldElement>,
    ) {
        prop_assume!(VaultState::decode(&state).is_err());
        let coin = Coin {
            type_script_hash: Vault::vnpt().hash(),
            state,
        };
        let tx = Tx::new(
            kernel,
            vec![],
            vec![Utxo::new(Digest::default(), vec![coin])],
        );
        prop_assert_eq!(Err(VaultError::InvalidState), tx.validate());
    }

    #[proptest(cases = 20)]
    fn a_token_whose_amount_does_not_decode_is_rejected(
        #[strategy(arb())] kernel: TransactionKernel,
        #[strategy(0..4usize)] limb: usize,
        #[strategy(1u64 << 32..BFieldElement::P)] value: u64,
    ) {
        let mut coin = Vault::vnpt().token(nau(1));
        coin.state[1 + limb] = bfe!(value);
        let tx = Tx::new(
            kernel,
            vec![],
            vec![Utxo::new(Digest::default(), vec![coin])],
        );
        prop_assert_eq!(Err(VaultError::InvalidState), tx.validate());
    }

    #[proptest(cases = 20)]
    fn a_vault_whose_holding_does_not_decode_is_rejected(
        #[strategy(arb())] kernel: TransactionKernel,
        #[strategy(0..4usize)] limb: usize,
        #[strategy(1u64 << 32..BFieldElement::P)] value: u64,
    ) {
        let mut coins = vault(1).coins().to_vec();
        coins[0].state[limb] = bfe!(value);
        let tx = Tx::new(
            kernel,
            vec![npt_utxo(1)],
            vec![Utxo::new(vault_lock_script().hash(), coins), token_utxo(1)],
        );
        prop_assert_eq!(Err(VaultError::InvalidState), tx.validate());
    }

    #[proptest(cases = 20)]
    fn a_vault_whose_holding_has_another_length_is_rejected(
        #[strategy(arb())] kernel: TransactionKernel,
        #[strategy(vec(arb::<BFieldElement>(), 0..8))] state: Vec<BFieldElement>,
    ) {
        prop_assume!(state.len() != AMOUNT_LEN);
        let mut coins = vault(1).coins().to_vec();
        coins[0].state = state;
        let tx = Tx::new(
            kernel,
            vec![npt_utxo(1)],
            vec![Utxo::new(vault_lock_script().hash(), coins), token_utxo(1)],
        );
        prop_assert_eq!(Err(VaultError::NotAVault(0)), tx.validate());
    }

    #[proptest(cases = 1)]
    fn cost_by_number_of_token_utxos(#[strategy(arb())] kernel: TransactionKernel) {
        println!("token UTXOs  cycles  padded height");
        for log2_num_tokens in 0..7 {
            let num_tokens = 1 << log2_num_tokens;
            let holding = 1000 * num_tokens;
            let tx = Tx::new(
                kernel.clone(),
                [
                    vec![vault(holding)],
                    vec![token_utxo(1000); num_tokens as usize],
                ]
                .concat(),
                vec![vault(0), npt_utxo(holding)],
            );
            prop_assert_eq!(Ok(()), tx.validate());

            let (witness, standard_input) = tx.type_script_and_witness();
            let (aet, _) = VM::trace_execution(
                witness.program.clone(),
                standard_input,
                witness.nondeterminism(),
            )
            .unwrap();
            println!(
                "{num_tokens:11}  {:6}  {:13}",
                aet.processor_trace.nrows(),
                aet.padded_height()
            );
        }
    }
}
