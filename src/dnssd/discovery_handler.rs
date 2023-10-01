use std::collections::HashMap;
use std::net::IpAddr;

pub struct Service
{
    pub service: String,
    pub ip_addr: IpAddr,
    pub port: u16
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

    pub fn add_found_service(&mut self, service: String, ip_addr: IpAddr, port: u16)
    {
        let pos = self.services.iter().position(|s| *s == service).unwrap();
        self.found_services.insert(self.services.remove(pos), Service
        {
            service,
            ip_addr,
            port
        });
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
    use std::net::Ipv4Addr;

    #[test]
    fn test_add_service()
    {
        let mut discovery_handler = DiscoveryHandler::new();
        discovery_handler.add_service("test".to_string());
        assert_eq!(discovery_handler.services.len(), 1);
    }

    #[test]
    fn test_add_found_service()
    {
        let mut discovery_handler = DiscoveryHandler::new();
        let service = String::from("test");
        discovery_handler.add_service("test".to_string());
        discovery_handler.add_found_service(service, IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 1234);
        assert_eq!(discovery_handler.services.len(), 0);
        assert_eq!(discovery_handler.found_services.len(), 1);
    }

    #[test]
    fn test_get_found_service()
    {
        let mut discovery_handler = DiscoveryHandler::new();
        let service = String::from("test");
        discovery_handler.add_service("test".to_string());
        discovery_handler.add_found_service(service, IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 1234);
        let service = discovery_handler.get_found_service("test");
        assert_eq!(service.is_some(), true);
        match service.as_ref().unwrap().ip_addr
        {
            IpAddr::V4(ip_addr) => assert_eq!(ip_addr, Ipv4Addr::new(127, 0, 0, 1)),
            _ => assert_eq!(true, false)
        }
        assert_eq!(service.unwrap().port, 1234);
    }
}
