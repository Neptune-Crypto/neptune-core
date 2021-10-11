use super::blockchain::Block;

#[derive(Clone, Debug)]
pub enum ToMiner {
    Empty,
    NewBlock(Box<Block>),
}

#[derive(Clone, Debug)]
pub enum FromMinerToMain {
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
