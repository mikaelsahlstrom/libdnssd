use log::{ info, error, debug };
use libdnssd::{ ServiceDiscovery, IpType };

fn main() {
    env_logger::init();

    //find_ipv4_service("DIRIGERA._hap._tcp.local");
    find_ipv6_service("_matterc._udp.local");
}

fn find_ipv4_service(service: &str)
{
    let mut service_discovery = match ServiceDiscovery::new(IpType::V4)
    {
        Ok(service) => service,
        Err(err) =>
        {
            error!("Failed to create service discovery: {}", err);
            return;
        }
    };

    // Multiple services can be found by calling find_service multiple times.
    service_discovery.find_service(service);

    loop
    {
        // Get IP address and port for one of the services added to be found.
        match service_discovery.get_ip_and_port(service)
        {
            Some(ip_port) =>
            {
                info!("Found service: {}:{}", ip_port.0, ip_port.1);
            },
            None =>
            {
                std::thread::sleep(std::time::Duration::from_millis(200));
                continue;
            }
        };

        // Additionally we can also get TXT records if included for the service.
        match service_discovery.get_txt_records(service)
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
                break;
            }
        }
        return;
    }
}

fn find_ipv6_service(service: &str)
{
    let mut service_discovery = match ServiceDiscovery::new(IpType::V6)
    {
        Ok(service) => service,
        Err(err) =>
        {
            error!("Failed to create service discovery: {}", err);
            return;
        }
    };

    // Multiple services can be found by calling find_service multiple times.
    service_discovery.find_service(service);

    loop
    {
        // Get IP address and port for one of the services added to be found.
        match service_discovery.get_ip_and_port(service)
        {
            Some(ip_port) =>
            {
                info!("Found service: {}:{}", ip_port.0, ip_port.1);
            }
            None =>
            {
                std::thread::sleep(std::time::Duration::from_millis(200));
                continue;
            }
        };

        // Additionally we can also get TXT records if included for the service.
        match service_discovery.get_txt_records(service)
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
                break;
            }
        }
        return;
    }
}
