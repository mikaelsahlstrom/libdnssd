#[macro_use]
extern crate lazy_static;

use clap::Parser;
use log::{ info, warn, error };

mod dnssd;

#[derive(Parser)]
#[command(author, version, about, long_about)]
struct Args
{
    #[arg(short, long)]
    service: String
}

fn main() {
    env_logger::init();
    let args = Args::parse();

    if args.service.len() == 0
    {
        error!("No service specified.");
        return;
    }

    let mut service = match dnssd::ServiceDiscovery::new()
    {
        Ok(service) => service,
        Err(err) =>
        {
            error!("Failed to create service discovery: {}", err);
            return;
        }
    };

    service.find_service(args.service.as_str());

    loop
    {
        let service = match service.get_service(args.service.as_str())
        {
            Some(service) => service,
            None =>
            {
                warn!("Service not found.");
                // Sleep for 5 seconds.
                std::thread::sleep(std::time::Duration::from_secs(5));
                continue;
            }
        };

        info!("Found service: {} {} {}", service.service, service.ip_addr, service.port);
    }
}
