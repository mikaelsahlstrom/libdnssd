#[macro_use]
extern crate lazy_static;

use std::thread;
use std::process;

use clap::Parser;
use ansi_term::Color::Red;

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

    let mut mdns_listener = if args.ip_version == "v4"
    {
        match mdns::MDnsListener::new(mdns::IpVersion::IPV4)
        {
            Ok(l) => l,
            Err(e) =>
            {
                println!("{} {}", Red.bold().paint("ERROR:"), e);
                process::exit(1);
            }
        }
    }
    else if args.ip_version == "v6"
    {
        match mdns::MDnsListener::new(mdns::IpVersion::IPV6)
        {
            Ok(l) => l,
            Err(e) =>
            {
                println!("{} {}", Red.bold().paint("ERROR:"), e);
                process::exit(1);
            }
        }
    }
    else
    {
        println!("Unknown IP version. Supported: v4, v6.");
        process::exit(1);
    };

    let mdns_handle = thread::spawn(move ||
    {
        loop
        {
            match mdns_listener.recv_packet()
            {
                Ok(()) => (),
                Err(e) =>
                {
                    println!("{} {}", Red.bold().paint("ERROR:"), e);
                    break;
                }
            }
        }
    });

    mdns_handle.join().unwrap();
}
