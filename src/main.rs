#[macro_use]
extern crate lazy_static;
use clap::Parser;
use ansi_term::Colour::Red;

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
    let args = Args::parse();

    if args.list
    {
        let service = match dnssd::ServiceDiscovery::new()
        {
            Ok(service) => service,
            Err(err) =>
            {
                println!("{} {}", Red.bold().paint("Error:"), err);
                return;
            }
        };
    }
}
