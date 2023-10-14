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
        let service = match service.get_service(args.service.as_str())
        {
            Some(service) => service,
            None =>
            {
                debug!("Service not found.");
                // Sleep for 5 seconds.
                std::thread::sleep(std::time::Duration::from_secs(5));
                continue;
            }
        };

        info!("Found service:");
        for ptr_answer in service.ptr_answers.iter()
        {
            info!("\tPTR: {}", ptr_answer.label);
        }

        for srv_answer in service.srv_answers.iter()
        {
            info!("\tSRV: {}:{}", srv_answer.label, srv_answer.port);
        }

        for txt_answer in service.txt_answers.iter()
        {
            info!("\tTXT:");
            for record in txt_answer.records.iter()
            {
                info!("\t\t{}", record);
            }
        }

        for a_answer in service.a_answers.iter()
        {
            info!("\tA: {}", a_answer.address);
        }

        for aaaa_answer in service.aaaa_answers.iter()
        {
            info!("\tAAAA: {}", aaaa_answer.address);
        }
    }
}
