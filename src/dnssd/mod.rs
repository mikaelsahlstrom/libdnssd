use std::{sync::{ Arc, Mutex }, net::{IpAddr, Ipv4Addr, Ipv6Addr}};

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
use log::debug;

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

    pub fn get_ip_and_port(&self, service: &str) -> Option<(IpAddr, u16)>
    {
        let handler = self.discovery_handler.lock().unwrap();
        let maybe_responses = handler.get_found_service(service);
        if maybe_responses.is_none()
        {
            return None;
        }

        let responses = maybe_responses.unwrap();
        let ip = self.find_ip(&responses);
        if ip.is_some()
        {
            return Some((ip.unwrap(), self.find_port(&responses)));
        }

        debug!("Didn't find an IP address directly, checking SRV and PTR records.");

        for response in responses
        {
            match response
            {
                DnsSdResponse::PtrAnswer(ptr_answer) =>
                {
                    let maybe_responses = handler.get_found_service(&ptr_answer.service);
                    if maybe_responses.is_none()
                    {
                        continue;
                    }

                    let responses = maybe_responses.unwrap();
                    let ip = self.find_ip(&responses);
                    if ip.is_some()
                    {
                        return Some((ip.unwrap(), self.find_port(&responses)));
                    }
                },
                DnsSdResponse::SrvAnswer(srv_answer) =>
                {
                    let maybe_responses = handler.get_found_service(&srv_answer.service);
                    if maybe_responses.is_none()
                    {
                        continue;
                    }

                    let responses = maybe_responses.unwrap();
                    let ip = self.find_ip(&responses);
                    if ip.is_some()
                    {
                        return Some((ip.unwrap(), srv_answer.port));
                    }
                },
                _ => continue
            }
        }

        return None;
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

    fn find_ip(&self, responses: &Vec<DnsSdResponse>) -> Option<IpAddr>
    {
        for response in responses
        {
            match response
            {
                DnsSdResponse::AAnswer(a_answer) =>
                {
                    return Some(IpAddr::V4(a_answer.address));
                },
                DnsSdResponse::AaaaAnswer(aaaa_answer) =>
                {
                    return Some(IpAddr::V6(aaaa_answer.address));
                },
                _ => continue
            }
        }

        return None;
    }

    fn find_port(&self, responses: &Vec<DnsSdResponse>) -> u16
    {
        for response in responses
        {
            match response
            {
                DnsSdResponse::SrvAnswer(srv_answer) =>
                {
                    return srv_answer.port;
                },
                _ => continue
            }
        }

        return 0;
    }
}
