use super::blockchain::block::Block;

#[derive(Clone, Debug)]
pub enum MainToMiner {
    Empty,
    NewBlock(Box<Block>),
    // StopMining,
    // StartMining,
    // SetCoinbasePubkey,
}

#[derive(Clone, Debug)]
pub enum MinerToMain {
    NewBlock(Box<Block>),
}

#[derive(Clone, Debug)]
pub enum MainToPeerThread {
    Block(Box<Block>),
    BlockFromMiner(Box<Block>),
    Transaction(i32),
}

#[derive(Clone, Debug)]
pub enum PeerThreadToMain {
    NewBlock(Box<Block>),
    NewTransaction(i32),
}
