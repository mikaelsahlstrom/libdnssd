use std::sync::{ Arc, Mutex };

mod dnssd_error;
mod dns;
mod socket;
mod discovery_handler;
mod sender;
mod receiver;

use dnssd_error::DnsSdError;
use discovery_handler::{ DiscoveryHandler, Service };
use sender::Sender;
use receiver::Receiver;

pub struct ServiceDiscovery
{
    discovery_handler: Arc<Mutex<DiscoveryHandler>>,
    receiver: Receiver,
    sender: Sender
}

impl ServiceDiscovery
{
    pub fn new() -> Result<ServiceDiscovery, DnsSdError>
    {
        let discovery_handler: DiscoveryHandler = DiscoveryHandler::new();
        let handler = Arc::new(Mutex::new(discovery_handler));
        let receiver = Receiver::new(handler.clone())?;
        let sender = Sender::new(handler.clone())?;

        Ok(ServiceDiscovery
        {
            discovery_handler: handler,
            receiver: receiver,
            sender: sender
        })
    }

    pub fn find_service(&mut self, service: &str)
    {
        self.discovery_handler.lock().unwrap().add_service(String::from(service));
    }

    pub fn get_service(&mut self, service: &str) -> Option<Service>
    {
        return self.discovery_handler.lock().unwrap().get_found_service(service);
    }
}
