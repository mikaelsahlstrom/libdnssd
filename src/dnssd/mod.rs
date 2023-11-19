use std::{sync::{ Arc, Mutex }, net::IpAddr };

mod dnssd_error;
mod dns;
mod socket;
mod discovery_handler;
mod sender;
mod receiver;

use dnssd_error::DnsSdError;
use discovery_handler::DiscoveryHandler;
use sender::Sender;
use receiver::Receiver;
use dns::DnsSdResponse;

#[derive(Clone)]
pub enum IpType
{
    V4,
    V6
}

pub struct ServiceDiscovery
{
    discovery_handler: Arc<Mutex<DiscoveryHandler>>,
    _receiver: Option<Receiver>,
    _sender: Sender,
    _ip_type: IpType
}

impl ServiceDiscovery
{
    pub fn new(ip_type: IpType) -> Result<ServiceDiscovery, DnsSdError>
    {
        let discovery_handler: DiscoveryHandler = DiscoveryHandler::new();
        let handler = Arc::new(Mutex::new(discovery_handler));
        // let receiver = Receiver::new(handler.clone())?;
        let sender = Sender::new(handler.clone(), &ip_type)?;

        Ok(ServiceDiscovery
        {
            discovery_handler: handler,
            _receiver: None,
            _sender: sender,
            _ip_type: ip_type
        })
    }

    pub fn find_service(&mut self, service: &str)
    {
        self.discovery_handler.lock().unwrap().add_service(String::from(service));
    }

    pub fn get_ip_address(&self, service: &str) -> Option<IpAddr>
    {
        let handler = self.discovery_handler.lock().unwrap();
        let maybe_services = handler.get_found_service(service);
        if maybe_services.is_none()
        {
            return None;
        }

        let services = maybe_services.unwrap();
        for service in services
        {
            match service
            {
                DnsSdResponse::AAnswer(a_answer) =>
                {
                    return Some(IpAddr::V4(a_answer.address));
                },
                DnsSdResponse::AaaaAnswer(aaaa_answer) =>
                {
                    return Some(IpAddr::V6(aaaa_answer.address));
                }
                _ => continue
            }
        }

        return None;
    }

    pub fn get_port(&self, service: &str) -> Option<u16>
    {
        let handler = self.discovery_handler.lock().unwrap();
        let maybe_services = handler.get_found_service(service);
        if maybe_services.is_none()
        {
            return None;
        }

        let services = maybe_services.unwrap();
        for service in services
        {
            match service
            {
                DnsSdResponse::SrvAnswer(srv_answer) =>
                {
                    return Some(srv_answer.port);
                },
                _ => continue
            }
        }

        return None;
    }

    pub fn get_ip_and_port(&self, service: &str) -> Option<(IpAddr, u16)>
    {
        let ip = self.get_ip_address(service);
        if ip.is_none()
        {
            return None;
        }

        let port = self.get_port(service);
        if port.is_none()
        {
            return None;
        }

        return Some((ip.unwrap(), port.unwrap()));
    }

    pub fn get_txt_records(&self, service: &str) -> Option<Vec<String>>
    {
        let handler = self.discovery_handler.lock().unwrap();
        let maybe_services = handler.get_found_service(service);
        if maybe_services.is_none()
        {
            return None;
        }

        let services = maybe_services.unwrap();
        for service in services
        {
            match service
            {
                DnsSdResponse::TxtAnswer(txt_answer) =>
                {
                    return Some(txt_answer.records.clone());
                },
                _ => continue
            }
        }

        return None;
    }
}
