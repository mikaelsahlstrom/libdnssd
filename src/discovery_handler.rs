use std::collections::HashMap;
use std::time::SystemTime;
use log::debug;

use crate::dns::DnsSdResponse;

pub struct TimeStampedResponse
{
    pub timestamp: SystemTime,
    pub responses: Vec<DnsSdResponse>,
}

impl TimeStampedResponse
{
    pub fn new(responses: Vec<DnsSdResponse>) -> TimeStampedResponse
    {
        TimeStampedResponse
        {
            timestamp: SystemTime::now(),
            responses,
        }
    }
}

pub struct DiscoveryHandler
{
    services: Vec<String>,
    found_services: HashMap<String, Vec<TimeStampedResponse>>
}

impl DiscoveryHandler
{
    pub fn new() -> DiscoveryHandler
    {
        DiscoveryHandler
        {
            services: Vec::new(),
            found_services: HashMap::new()
        }
    }

    pub fn add_service(&mut self, service: String)
    {
        debug!("Adding service: {}", service);
        self.services.push(service);
    }

    pub fn add_response(&mut self, service_label: String, services: Vec<DnsSdResponse>)
    {
        debug!("Adding found service: {}", service_label);
        let entry = self.found_services.entry(service_label).or_insert(Vec::new());
        entry.push(TimeStampedResponse::new(services));
    }

    pub fn remove_service(&mut self, service_label: String)
    {
        debug!("Removing service: {}", service_label);
        let position = self.services.iter().position(|x| *x == service_label);
        if let Some(position) = position
        {
            self.services.remove(position);
        }
    }

    pub fn get_found_services(&self, service: &str) -> Option<&Vec<TimeStampedResponse>>
    {
        return self.found_services.get(service);
    }

    pub fn get_services(&self) -> &Vec<String>
    {
        return &self.services;
    }
}
