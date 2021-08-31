use anyhow::Result;
use log::{debug, error, info, trace, warn};
use structopt::StructOpt;
mod args;
mod logger;

#[paw::main]
fn main(_args: args::Args) -> Result<()> {
    let args: args::Args = StructOpt::from_args();
    println!("{:?}", args);
    logger::Logger::init(args);
    trace!("hi from trace");
    debug!("hi from debug");
    info!("hi from info");
    warn!("hi from warn");
    error!("hi from error");
    neptune_core::my_library_function()
}
