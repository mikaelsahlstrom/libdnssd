use std::{sync::{ Arc, Mutex }, net::IpAddr };

mod dnssd_error;
mod dns;
mod socket;
mod discovery_handler;
mod sender;

use dnssd_error::DnsSdError;
use discovery_handler::DiscoveryHandler;
use sender::Sender;
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
    ip_type: IpType,
    _sender: Sender
}

impl ServiceDiscovery
{
    pub fn new(ip_type: IpType) -> Result<ServiceDiscovery, DnsSdError>
    {
        let discovery_handler: DiscoveryHandler = DiscoveryHandler::new();
        let handler = Arc::new(Mutex::new(discovery_handler));
        let sender = Sender::new(handler.clone(), &ip_type)?;

        Ok(ServiceDiscovery
        {
            discovery_handler: handler,
            ip_type: ip_type,
            _sender: sender
        })
    }

    pub fn find_service(&mut self, service: &str)
    {
        self.discovery_handler.lock().unwrap().add_service(String::from(service));
    }

    pub fn get_ip_address(&self, service: &str) -> Option<IpAddr>
    {
        let handler = self.discovery_handler.lock().unwrap();
        let maybe_services = handler.get_found_services(service);
        if maybe_services.is_none()
        {
            return None;
        }

        let timed_services = maybe_services.unwrap();
        if let Some(timed_service) = timed_services.last()
        {
            for service in &timed_service.responses
            {
                match service
                {
                    DnsSdResponse::AAnswer(a_answer) =>
                    {
                        match self.ip_type
                        {
                            IpType::V6 => continue,
                            _ => ()
                        }

                        return Some(IpAddr::V4(a_answer.address));
                    },
                    DnsSdResponse::AaaaAnswer(aaaa_answer) =>
                    {
                        match self.ip_type
                        {
                            IpType::V4 => continue,
                            _ => ()
                        }

                        return Some(IpAddr::V6(aaaa_answer.address));
                    }
                    _ =>
                    {
                        continue
                    }
                }
            }
        }

        return None;
    }

    pub fn get_port(&self, service: &str) -> Option<u16>
    {
        let handler = self.discovery_handler.lock().unwrap();
        let maybe_services = handler.get_found_services(service);
        if maybe_services.is_none()
        {
            return None;
        }

        let timed_services = maybe_services.unwrap();
        if let Some(timed_service) = timed_services.last()
        {
            for service in &timed_service.responses
            {
                match service
                {
                    DnsSdResponse::SrvAnswer(srv_answer) =>
                    {
                        return Some(srv_answer.port);
                    },
                    _ =>
                    {
                        continue
                    }
                }
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
        let maybe_services = handler.get_found_services(service);
        if maybe_services.is_none()
        {
            return None;
        }

        let timed_services = maybe_services.unwrap();
        if let Some(time_service) = timed_services.last()
        {
            for service in &time_service.responses
            {
                match service
                {
                    DnsSdResponse::TxtAnswer(txt_answer) =>
                    {
                        return Some(txt_answer.records.clone());
                    },
                    _ =>
                    {
                        continue
                    }
                }
            }
        }

        return None;
    }

    pub fn stop_find_service(&mut self, service: &str)
    {
        self.discovery_handler.lock().unwrap().remove_service(String::from(service));
    }
}
