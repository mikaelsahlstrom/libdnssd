use std::collections::HashMap;
use log::debug;

use crate::dns::DnsSdResponse;

pub struct DiscoveryHandler
{
    services: Vec<String>,
    found_services: HashMap<String, Vec<DnsSdResponse>>
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

    pub fn is_service_wanted(&self, service: &String) -> bool
    {
        return self.services.contains(service);
    }

    pub fn add_found_service(&mut self, service_label: String, service: DnsSdResponse)
    {
        debug!("Adding found service: {}", service_label);
        self.found_services.entry(service_label).or_insert(Vec::new()).push(service);
    }

    pub fn remove_service(&mut self, service_label: String)
    {
        debug!("Removing service: {}", service_label);
        self.services.remove(self.services.iter().position(|x| *x == service_label).unwrap());
    }

    pub fn get_found_service(&self, service: &str) -> Option<&Vec<DnsSdResponse>>
    {
        return self.found_services.get(service);
    }

    pub fn get_services(&self) -> &Vec<String>
    {
        return &self.services;
    }
}
