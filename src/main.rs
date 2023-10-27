#[macro_use]
extern crate lazy_static;

use clap::Parser;
use log::{ info, error, debug };

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
        let ip_port = match service.get_ipv6_and_port(args.service.as_str())
        {
            Some(ip_port) => ip_port,
            None =>
            {
                std::thread::sleep(std::time::Duration::from_millis(200));
                continue;
            }
        };

        info!("Found service: {}:{}", ip_port.0, ip_port.1);

        match service.get_txt_records(args.service.as_str())
        {
            Some(txt_records) =>
            {
                for txt_record in txt_records
                {
                    debug!("TXT Record: {}", txt_record);
                }
            },
            None =>
            {
                debug!("No TXT records found.");
                break;
            }
        }
        return;
    }
}
