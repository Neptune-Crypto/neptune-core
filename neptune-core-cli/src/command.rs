use clap::Parser;

use crate::command::blockchain::BlockchainCommand;
use crate::command::mempool::MempoolCommand;
use crate::command::mining::MiningCommand;
use crate::command::network::NetworkCommand;
use crate::command::node::NodeCommand;
use crate::command::payment::PaymentCommand;
use crate::command::statistics::StatisticsCommand;
use crate::command::wallet::WalletCommand;

pub(crate) mod blockchain;
pub(crate) mod mempool;
pub(crate) mod mining;
pub(crate) mod network;
pub(crate) mod node;
pub(crate) mod payment;
pub(crate) mod statistics;
pub(crate) mod wallet;

/// The CLI Command
///
// The enum enumerates subclasses but due to the #[command(flatten)] directive,
// it is one big list from clap's perspective.
#[derive(Debug, Clone, Parser)]
#[command(version)]
pub(crate) enum Command {
    /// Dump shell completions.
    Completions,

    #[command(flatten)]
    Network(NetworkCommand),
    #[command(flatten)]
    Blockchain(BlockchainCommand),
    #[command(flatten)]
    Wallet(WalletCommand),
    #[command(flatten)]
    Mempool(MempoolCommand),
    #[command(flatten)]
    Statistics(StatisticsCommand),
    #[command(flatten)]
    Payment(PaymentCommand),
    #[command(flatten)]
    Mining(MiningCommand),
    #[command(flatten)]
    Node(NodeCommand),
}
