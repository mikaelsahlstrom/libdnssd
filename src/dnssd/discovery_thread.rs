use std::thread;
use std::sync::{ mpsc, Mutex };
use std::time::{ Duration, Instant };

use crate::dnssd::dnssd_error::DnsSdError;
use crate::dnssd::dns::DnsSdResponse;
use crate::dnssd::socket;

use crate::dnssd::socket::{ join_multicast, MULTICAST_IPV6_SOCKET };
use crate::dnssd::{ ServiceDiscovery, Ipv4Answer, Ipv6Answer };

pub struct DiscoveryThread<'a>
{
    thread: Option<thread::JoinHandle<Result<(), DnsSdError>>>,
    sender: mpsc::Sender<ServiceDiscovery>,
    receiver: mpsc::Receiver<ServiceDiscovery>,
    services: Mutex<Vec<&'a str>>
}

impl DiscoveryThread<'_>
{
    pub fn new<'a>() -> DiscoveryThread<'a>
    {
        let (send, recv) = mpsc::channel();

        DiscoveryThread
        {
            thread: None,
            sender: send,
            receiver: recv,
            services: Mutex::new(Vec::new())
        }
    }

    pub fn start(&mut self, service_name: &str) -> Result<(), DnsSdError>
    {
        if self.thread.is_some()
        {
            return Err(DnsSdError::ThreadAlreadyStarted);
        }

        self.services.lock().unwrap().push(service_name);

        let t = thread::spawn(move ||
        {
            // Create a multicast IPv6 socket and listen.
            let socket = join_multicast(&MULTICAST_IPV6_SOCKET)?;
            let mut buffer: [u8; 4096] = [0u8; 4096];
            let mut timeouts = 0;
            let start = Instant::now();

            loop
            {
                let (count, addr) = match socket.recv_from(&mut buffer)
                {
                    Ok((count, addr)) => (count, addr),
                    Err(err) =>
                    {
                        return socket::conv_error::<()>(Err(err));
                    }
                };

                // Only parse buffer if we are looking for a service.
                if self.services.lock().unwrap().len() == 0
                {
                    continue;
                }

                // TODO: First parse frame then compare to services.

                for service in self.services.lock().unwrap().iter()
                {
                    match DnsSdResponse::from(service, &buffer)
                    {
                        Ok(DnsSdResponse::A { ipv4_addr }) =>
                        {
                            println!("Got IPv4 address: {}", ipv4_addr);
                            self.sender.send(ServiceDiscovery::IPV4 { answer: Ipv4Answer { ipv4_addr: ipv4_addr, port: 80 } }).unwrap();
                        },
                        Ok(DnsSdResponse::AAAA { ipv6_addr }) =>
                        {
                            println!("Got IPv6 address: {}", ipv6_addr);
                            self.sender.send(ServiceDiscovery::IPV6 { answer: Ipv6Answer { ipv6_addr: ipv6_addr, port: 80 } }).unwrap();
                        },
                        Err(err) =>
                        {
                            println!("Error: {:?}", err);
                        }
                    }
                }
            }
        });

        Ok(())
    }

    pub fn add_service(&mut self, service: &str)
    {
        self.services.lock().unwrap().push(service);
    }

    pub fn try_get_service(&self) -> Option<ServiceDiscovery>
    {
        if let Ok(_) = self.receiver.recv_timeout(Duration::from_secs(5))
        {
            return Some(ServiceDiscovery::new());
        }

        None
    }
}
