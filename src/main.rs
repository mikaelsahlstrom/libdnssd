#[macro_use]
extern crate lazy_static;

use clap::Parser;
use log::{ info, warn, error, debug };

mod debug;
mod dnssd;

#[derive(Parser)]
#[command(author, version, about, long_about)]
struct Args
{
    #[arg(short, long)]
    list: bool
}

fn main() {
    env_logger::init();
    let args = Args::parse();

    if args.list
    {
        let service = match dnssd::ServiceDiscovery::new()
        {
            Ok(service) => service,
            Err(err) =>
            {
                error!("Failed to create service discovery: {}", err);
                return;
            }
        };
    }
}
