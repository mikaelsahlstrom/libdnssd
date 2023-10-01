use std::sync::{ Arc, Mutex };
use std::thread;

use crate::dnssd::dnssd_error::DnsSdError;
use crate::dnssd::dns::DnsSdResponse;
use crate::dnssd::socket;
use crate::dnssd::discovery_handler::DiscoveryHandler;

pub struct Receiver
{
    thread: Option<thread::JoinHandle<Result<(), DnsSdError>>>
}

impl Receiver
{
    pub fn new(handler: Arc<Mutex<DiscoveryHandler>>) -> Result<Receiver, DnsSdError>
    {
        let thread = thread::spawn(move ||
        {
            // Create a multicast IPv6 socket and listen.
            let socket = socket::join_multicast(&socket::MULTICAST_IPV6_SOCKET)?;
            let mut buffer: [u8; 4096] = [0u8; 4096];

            loop
            {
                let (count, addr) = match socket.recv_from(&mut buffer)
                {
                    Ok((count, addr)) => (count, addr),
                    Err(err) =>
                    {
                        return socket::convert_error::<()>(Err(err));
                    }
                };

                // Only parse buffer if we are looking for services.
                if handler.lock().unwrap().get_services().len() == 0
                {
                    continue;
                }

                let response = match DnsSdResponse::from(&buffer)
                {
                    Ok(response) => response,
                    Err(err) =>
                    {
                        return Err(err);
                    }
                };

                for answer in response.answers.into_iter()
                {
                    if handler.lock().unwrap().is_service_wanted(&answer.label)
                    {
                        handler.lock().unwrap().add_found_service(answer.label, answer.address, answer.port);
                    }
                }
            }
        });

        Ok(Receiver
        {
            thread: Some(thread)
        })
    }
}
