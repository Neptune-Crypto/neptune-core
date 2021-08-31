use structopt::StructOpt;

/// See the [structopt
/// documentation](https://docs.rs/structopt/0.3.21/structopt) for more
/// information.
#[derive(Debug, StructOpt)]
#[structopt(name = "neptune-core", about = "A Sea of Freedom")]
pub struct Args {
    /// File name: only required when `out-type` is set to `file`
    #[structopt(short, long, default_value = "neptune-core.log")]
    pub log_file_name: String,

    /// Set mining argument to participate in competitive mining
    #[structopt(short, long)]
    pub mine: bool,

    // The number of occurrences of the `v/verbose` flag
    /// Verbose mode (-v, -vv, -vvv, etc.)
    #[structopt(short, long, parse(from_occurrences))]
    pub verbose: u8,
}
