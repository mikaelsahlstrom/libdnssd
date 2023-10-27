use std::{sync::{ Arc, Mutex }, net::Ipv6Addr};

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

pub struct ServiceDiscovery
{
    discovery_handler: Arc<Mutex<DiscoveryHandler>>,
    receiver: Option<Receiver>,
    sender: Sender
}

impl ServiceDiscovery
{
    pub fn new() -> Result<ServiceDiscovery, DnsSdError>
    {
        let discovery_handler: DiscoveryHandler = DiscoveryHandler::new();
        let handler = Arc::new(Mutex::new(discovery_handler));
        // let receiver = Receiver::new(handler.clone())?;
        let sender = Sender::new(handler.clone())?;

        Ok(ServiceDiscovery
        {
            discovery_handler: handler,
            receiver: None,
            sender: sender
        })
    }

    pub fn find_service(&mut self, service: &str)
    {
        self.discovery_handler.lock().unwrap().add_service(String::from(service));
    }

    pub fn get_ipv6_and_port(&self, service: &str) -> Option<(Ipv6Addr, u16)>
    {
        let mut response: (Ipv6Addr, u16) = (Ipv6Addr::UNSPECIFIED, 0);
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
                DnsSdResponse::AaaaAnswer(aaaa_answer) =>
                {
                    response.0 = aaaa_answer.address;
                    if response.1 != 0
                    {
                        return Some(response);
                    }
                },
                DnsSdResponse::SrvAnswer(srv_answer) =>
                {
                    response.1 = srv_answer.port;
                    if response.0 != Ipv6Addr::UNSPECIFIED
                    {
                        return Some(response);
                    }
                },
                _ => continue
            }
        }

        debug!("Didn't find an IPv6 address directly, checking SRV and PTR records.");

        // We didn't find an IPv6 address directly, check SRV and PTR records.
        for service in services
        {
            match service
            {
                DnsSdResponse::PtrAnswer(ptr_answer) =>
                {
                    debug!("Found PTR answer: {}", ptr_answer.service);
                    let maybe_services = handler.get_found_service(&ptr_answer.service);
                    if maybe_services.is_none()
                    {
                        continue;
                    }

                    let ptr_services = maybe_services.unwrap();
                    for ptr_service in ptr_services
                    {
                        match ptr_service
                        {
                            DnsSdResponse::AaaaAnswer(aaaa_answer) =>
                            {
                                response.0 = aaaa_answer.address;
                                if response.1 != 0
                                {
                                    return Some(response);
                                }
                            },
                            DnsSdResponse::SrvAnswer(srv_answer) =>
                            {
                                response.1 = srv_answer.port;
                                if response.0 != Ipv6Addr::UNSPECIFIED
                                {
                                    return Some(response);
                                }
                            },
                            _ => continue
                        }
                    }
                },
                DnsSdResponse::SrvAnswer(srv_answer) =>
                {
                    let maybe_services = handler.get_found_service(&srv_answer.service);
                    if maybe_services.is_none()
                    {
                        continue;
                    }

                    let srv_services = maybe_services.unwrap();
                    for srv_service in srv_services
                    {
                        match srv_service
                        {
                            DnsSdResponse::AaaaAnswer(aaaa_answer) =>
                            {
                                response.0 = aaaa_answer.address;
                                if response.1 != 0
                                {
                                    return Some(response);
                                }
                            },
                            DnsSdResponse::SrvAnswer(srv_answer) =>
                            {
                                response.1 = srv_answer.port;
                                if response.0 != Ipv6Addr::UNSPECIFIED
                                {
                                    return Some(response);
                                }
                            },
                            _ => continue
                        }
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
}
