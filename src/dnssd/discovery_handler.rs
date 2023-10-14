use std::collections::HashMap;

use crate::dnssd::dns::{ PtrAnswer, SrvAnswer, TxtAnswer, AAnswer, AaaaAnswer };

pub struct Service
{
    pub ptr_answers: Vec<PtrAnswer>,
    pub srv_answers: Vec<SrvAnswer>,
    pub txt_answers: Vec<TxtAnswer>,
    pub a_answers: Vec<AAnswer>,
    pub aaaa_answers: Vec<AaaaAnswer>
}

pub struct DiscoveryHandler
{
    services: Vec<String>,
    found_services: HashMap<String, Service>
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

    pub fn add_found_service(&mut self, service_label: String, service: Service)
    {
        self.services.remove(self.services.iter().position(|x| *x == service_label).unwrap());
        self.found_services.insert(service_label, service);
    }

    pub fn get_found_service(&mut self, service: &str) -> Option<Service>
    {
        return self.found_services.remove(service);
    }

    pub fn get_services(&self) -> &Vec<String>
    {
        return &self.services;
    }
}

#[cfg(test)]
mod tests
{
    use super::*;

    #[test]
    fn test_add_service()
    {
        let mut discovery_handler = DiscoveryHandler::new();
        discovery_handler.add_service("test".to_string());
        assert_eq!(discovery_handler.services.len(), 1);
    }

    #[test]
    fn test_is_service_wanted()
    {
        let mut discovery_handler = DiscoveryHandler::new();
        discovery_handler.add_service("test".to_string());
        assert_eq!(discovery_handler.is_service_wanted(&"test".to_string()), true);
        assert_eq!(discovery_handler.is_service_wanted(&"test2".to_string()), false);
    }

    #[test]
    fn test_add_found_service()
    {
        let mut discovery_handler = DiscoveryHandler::new();
        let service = String::from("test");
        discovery_handler.add_service("test".to_string());
        discovery_handler.add_found_service(service, Service
        {
            ptr_answers: Vec::new(),
            srv_answers: Vec::new(),
            txt_answers: Vec::new(),
            a_answers: Vec::new(),
            aaaa_answers: Vec::new()
        });
        assert_eq!(discovery_handler.services.len(), 0);
        assert_eq!(discovery_handler.found_services.len(), 1);
    }

    #[test]
    fn test_get_found_service()
    {
        let mut discovery_handler = DiscoveryHandler::new();
        let service = String::from("test");
        discovery_handler.add_service("test".to_string());
        discovery_handler.add_found_service(service.clone(), Service
        {
            ptr_answers: Vec::new(),
            srv_answers: Vec::new(),
            txt_answers: Vec::new(),
            a_answers: Vec::new(),
            aaaa_answers: Vec::new()
        });
        assert_eq!(discovery_handler.services.len(), 0);
        assert_eq!(discovery_handler.found_services.len(), 1);
        let found_service = discovery_handler.get_found_service(&service);
        assert_eq!(found_service.is_some(), true);
        assert_eq!(discovery_handler.found_services.len(), 0);
    }
}
