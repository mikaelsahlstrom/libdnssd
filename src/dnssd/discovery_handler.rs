use std::collections::HashMap;

use crate::dnssd::dns::DnsSdResponse;

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
        self.services.push(service);
    }

    pub fn is_service_wanted(&self, service: &String) -> bool
    {
        return self.services.contains(service);
    }

    pub fn add_found_service(&mut self, service_label: String, service: DnsSdResponse)
    {
        self.found_services.entry(service_label).or_insert(Vec::new()).push(service);
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
