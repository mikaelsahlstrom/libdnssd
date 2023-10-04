use std::sync::{ Arc, Mutex };
use std::thread;
use log::debug;

use crate::dnssd::dnssd_error::DnsSdError;
use crate::dnssd::socket::{ create_sender_socket, MULTICAST_ADDR_IPV6, MULTICAST_PORT };
use crate::dnssd::dns::new_query;
use crate::dnssd::discovery_handler::DiscoveryHandler;

pub struct Sender
{
    thread: Option<thread::JoinHandle<Result<(), DnsSdError>>>
}

impl Sender
{
    pub fn new(handler: Arc<Mutex<DiscoveryHandler>>) -> Result<Sender, DnsSdError>
    {
        let thread = thread::spawn(move ||
        {
            let socket = match create_sender_socket()
            {
                Ok(socket) => socket,
                Err(err) =>
                {
                    debug!("Failed to create sender socket: {}", err);
                    return Err(err);
                }
            };

            debug!("Created sender socket.");

            loop
            {
                // For each service in handler, send a query.
                for service in handler.lock().unwrap().get_services()
                {
                    let query = new_query(service)?;
                    debug!("Created query for service: {}", service);

                    // Send a query for the service.
                    match socket.send_to(&query, (MULTICAST_ADDR_IPV6, MULTICAST_PORT))
                    {
                        Ok(_) => {},
                        Err(err) =>
                        {
                            debug!("Failed to send query: {}", err);
                            return Err(err.into());
                        }
                    }
                    debug!("Sent query for service: {}", service);
                }

                // Wait for 5 seconds.
                thread::sleep(std::time::Duration::from_secs(5));
            }
        });

        Ok(Sender
        {
            thread: Some(thread)
        })
    }
}
