use std::sync::{ Arc, Mutex };
use std::thread;
use log::{ debug, error };

use crate::dnssd::dnssd_error::DnsSdError;
use crate::dnssd::dns::DnsSdResponse;
use crate::dnssd::socket;
use crate::dnssd::discovery_handler::DiscoveryHandler;

pub struct Receiver
{
    _thread: Option<thread::JoinHandle<Result<(), DnsSdError>>>
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
                        error!("Failed to receive data: {}", err);
                        continue;
                    }
                };

                debug!("Received {} bytes from {}", count, addr);

                // Only parse buffer if we are looking for services.
                if handler.lock().unwrap().get_services().len() == 0
                {
                    continue;
                }

                let responses = match DnsSdResponse::from(&buffer, count)
                {
                    Ok(responses) => responses,
                    Err(err) =>
                    {
                        debug!("Failed to parse response: {}", err);
                        continue;
                    }
                };

                // Start by finding all PTR and SRV answers that are wanted.
                let mut wanted_ptrs: Vec<String> = Vec::new();
                for response in responses.iter()
                {
                    match response
                    {
                        DnsSdResponse::PtrAnswer(ptr) =>
                        {
                            if handler.lock().unwrap().is_service_wanted(&ptr.label)
                            {
                                wanted_ptrs.push(ptr.service.clone());
                            }
                        },
                        DnsSdResponse::SrvAnswer(srv) =>
                        {
                            if handler.lock().unwrap().is_service_wanted(&srv.label)
                            {
                                wanted_ptrs.push(srv.service.clone());
                            }
                        },
                        _ => {
                            // Ignore other responses for now.
                        }
                    }
                }

                // Then find all other answers that are wanted or in wanted ptrs.
                for response in responses.into_iter()
                {
                    match response
                    {
                        DnsSdResponse::SrvAnswer(srv) =>
                        {
                            if handler.lock().unwrap().is_service_wanted(&srv.label) ||
                                wanted_ptrs.contains(&&srv.label)
                            {
                                handler.lock().unwrap().add_found_service(
                                    srv.label.clone(),
                                    DnsSdResponse::SrvAnswer(
                                        crate::dnssd::dns::SrvAnswer
                                        {
                                            label: srv.label,
                                            service: srv.service,
                                            port: srv.port
                                        }
                                    )
                                );
                            }
                        },
                        DnsSdResponse::TxtAnswer(txt) =>
                        {
                            if handler.lock().unwrap().is_service_wanted(&txt.label) ||
                                wanted_ptrs.contains(&&txt.label)
                            {
                                handler.lock().unwrap().add_found_service(
                                    txt.label.clone(),
                                    DnsSdResponse::TxtAnswer(
                                        crate::dnssd::dns::TxtAnswer
                                        {
                                            label: txt.label,
                                            records: txt.records
                                        }
                                    )
                                );
                            }
                        },
                        DnsSdResponse::AAnswer(a) =>
                        {
                            if handler.lock().unwrap().is_service_wanted(&a.label) ||
                                wanted_ptrs.contains(&&a.label)
                            {
                                handler.lock().unwrap().add_found_service(
                                    a.label.clone(),
                                    DnsSdResponse::AAnswer(
                                        crate::dnssd::dns::AAnswer
                                        {
                                            label: a.label,
                                            address: a.address
                                        }
                                    )
                                );
                            }
                        },
                        DnsSdResponse::AaaaAnswer(aaa) =>
                        {
                            if handler.lock().unwrap().is_service_wanted(&aaa.label) ||
                                wanted_ptrs.contains(&&aaa.label)
                            {
                                handler.lock().unwrap().add_found_service(
                                    aaa.label.clone(),
                                    DnsSdResponse::AaaaAnswer(
                                        crate::dnssd::dns::AaaaAnswer
                                        {
                                            label: aaa.label,
                                            address: aaa.address
                                        }
                                    )
                                );
                            }
                        },
                        DnsSdResponse::PtrAnswer(ptr) =>
                        {
                            if handler.lock().unwrap().is_service_wanted(&ptr.label)
                            {
                                handler.lock().unwrap().add_found_service(
                                    ptr.label.clone(),
                                    DnsSdResponse::PtrAnswer(
                                        crate::dnssd::dns::PtrAnswer
                                        {
                                            label: ptr.label,
                                            service: ptr.service
                                        }
                                    )
                                );
                            }
                        }
                    }
                }
            }
        });

        Ok(Receiver
        {
            _thread: Some(thread)
        })
    }
}
