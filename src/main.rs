#[macro_use]
extern crate lazy_static;

use std::thread;
use clap::Parser;

mod debug;
mod mdns;

#[derive(Parser)]
#[command(author, version, about, long_about)]
struct Args
{
    #[arg(short, long, default_value = "v4")]
    ip_version: String
}

fn main()
{
    let args = Args::parse();

    if args.ip_version == "v4"
    {
        let mdns_handle = thread::spawn(move ||
        {
            mdns::listen(mdns::IpVersion::IPV4);
        });

        mdns_handle.join().unwrap();
    }
    else if args.ip_version == "v6"
    {
        let mdns_handle = thread::spawn(move ||
        {
            mdns::listen(mdns::IpVersion::IPV6);
        });

        mdns_handle.join().unwrap();
    }
    else
    {
        println!("Unknown IP version. Supported: v4, v6.");
    }
}
