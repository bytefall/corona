use clap::Parser;

#[derive(Parser)]
#[command(version, about)]
pub enum Args {
    /// Toss inbound mail
    Toss,
}
