use std::sync::{ Arc, Mutex };
use std::thread;
use log::debug;

use crate::dnssd_error::DnsSdError;
use crate::socket::{ create_sender_socket, MULTICAST_ADDR_IPV6, MULTICAST_ADDR_IPV4, MULTICAST_PORT };
use crate::dns::{ new_query, DnsSdResponse };
use crate::discovery_handler::DiscoveryHandler;
use crate::IpType;

pub struct Sender
{
    _send_thread: Option<thread::JoinHandle<Result<(), DnsSdError>>>,
    _listen_thread: Option<thread::JoinHandle<Result<(), DnsSdError>>>
}

impl Sender
{
    pub fn new(handler: Arc<Mutex<DiscoveryHandler>>, ip_type: &IpType) -> Result<Sender, DnsSdError>
    {
        let listen_handler = handler.clone();
        let listen_socket = match create_sender_socket(ip_type)
        {
            Ok(socket) => socket,
            Err(err) =>
            {
                debug!("Failed to create sender socket: {}", err);
                return Err(err);
            }
        };

        let send_socket = listen_socket.try_clone()?;
        let send_handler = listen_handler.clone();

        let listen_thread = thread::spawn(move ||
        {
            let mut buffer: [u8; 4096] = [0u8; 4096];

            loop
            {
                let (count, addr) = match listen_socket.recv_from(&mut buffer)
                {
                    Ok((count, addr)) => (count, addr),
                    Err(err) =>
                    {
                        debug!("Failed to receive data: {}", err);
                        continue;
                    }
                };

                debug!("Received {} bytes from {}", count, addr);

                // Only parse buffer if we are looking for services.
                if listen_handler.lock().unwrap().get_services().len() == 0
                {
                    continue;
                }

                let (service_label, responses) = match DnsSdResponse::from(&buffer, count)
                {
                    Ok(responses) => responses,
                    Err(err) =>
                    {
                        debug!("Failed to parse response: {}", err);
                        continue;
                    }
                };

                debug!("Parsed response:\n{:?}", responses);

                if handler.lock().unwrap().get_services().contains(&service_label)
                {
                    handler.lock().unwrap().add_response(service_label, responses);
                }
            }
        });

        let new_ip_type = ip_type.clone();
        let send_thread = thread::spawn(move ||
        {
            loop
            {
                // For each service in handler, send a query.
                for service in send_handler.lock().unwrap().get_services()
                {
                    debug!("Sending query for service: {}", service);
                    let query = new_query(service)?;

                    match new_ip_type
                    {
                        IpType::V4 =>
                        {
                            match send_socket.send_to(&query, (MULTICAST_ADDR_IPV4, MULTICAST_PORT))
                            {
                                Ok(_) => {},
                                Err(err) =>
                                {
                                    debug!("Failed to send query: {}", err);
                                    return Err(err.into());
                                }
                            }
                        },
                        IpType::V6 =>
                        {
                            match send_socket.send_to(&query, (MULTICAST_ADDR_IPV6, MULTICAST_PORT))
                            {
                                Ok(_) => {},
                                Err(err) =>
                                {
                                    debug!("Failed to send query: {}", err);
                                    return Err(err.into());
                                }
                            }
                        }
                    }
                }

                // Wait for 1 second.
                thread::sleep(std::time::Duration::from_secs(1));
            }
        });

        Ok(Sender
        {
            _send_thread: Some(send_thread),
            _listen_thread: Some(listen_thread)
        })
    }
}
