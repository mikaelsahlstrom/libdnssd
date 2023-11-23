use std::collections::HashMap;
use std::sync::{ Arc, Mutex };
use std::thread;
use log::debug;

use crate::dnssd_error::DnsSdError;
use crate::socket::{ create_sender_socket, MULTICAST_ADDR_IPV6, MULTICAST_ADDR_IPV4, MULTICAST_PORT };
use crate::dns::{ new_query, DnsSdResponse, TxtAnswer, SrvAnswer, AAnswer, AaaaAnswer, PtrAnswer };
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

                let responses = match DnsSdResponse::from(&buffer, count)
                {
                    Ok(responses) => responses,
                    Err(err) =>
                    {
                        debug!("Failed to parse response: {}", err);
                        continue;
                    }
                };

                debug!("Parsed response:\n{:?}", responses);

                // Start by finding all PTR and SRV answers that are wanted.
                let mut reverse_lookup: HashMap<String, String> = HashMap::new();
                for response in responses.iter()
                {
                    match response
                    {
                        DnsSdResponse::PtrAnswer(ptr) =>
                        {
                            if handler.lock().unwrap().is_service_wanted(&ptr.label)
                            {
                                if ptr.service != ptr.label
                                {
                                    reverse_lookup.insert(ptr.service.clone(), ptr.label.clone());
                                }
                            }
                        },
                        DnsSdResponse::SrvAnswer(srv) =>
                        {
                            if handler.lock().unwrap().is_service_wanted(&srv.label)
                            {
                                if srv.service != srv.label
                                {
                                    reverse_lookup.insert(srv.service.clone(), srv.label.clone());
                                }
                            }
                        },
                        _ =>
                        {
                            // Ignore other responses for now.
                        }
                    }
                }

                let mut service_to_remove: Option<String> = None;

                // Then find all other answers that are wanted or in reverse_lookup.
                for response in responses.into_iter()
                {
                    match response
                    {
                        DnsSdResponse::TxtAnswer(txt) =>
                        {
                            if handler.lock().unwrap().is_service_wanted(&txt.label)
                            {
                                // Also schedule it for removal.
                                service_to_remove = Some(txt.label.clone());

                                handler.lock().unwrap().add_found_service(
                                    txt.label.clone(),
                                    DnsSdResponse::TxtAnswer(
                                        TxtAnswer
                                        {
                                            label: txt.label,
                                            records: txt.records
                                        }
                                    )
                                );
                            }
                            else if reverse_lookup.contains_key(&txt.label)
                            {
                                handler.lock().unwrap().add_found_service(
                                    reverse_lookup.get(&txt.label).unwrap().to_string(),
                                    DnsSdResponse::TxtAnswer(
                                        TxtAnswer
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
                            if handler.lock().unwrap().is_service_wanted(&a.label)
                            {
                                // Also schedule it for removal.
                                service_to_remove = Some(a.label.clone());

                                handler.lock().unwrap().add_found_service(
                                    a.label.clone(),
                                    DnsSdResponse::AAnswer(
                                        AAnswer
                                        {
                                            label: a.label,
                                            address: a.address
                                        }
                                    )
                                );
                            }
                            else if reverse_lookup.contains_key(&a.label)
                            {
                                handler.lock().unwrap().add_found_service(
                                    reverse_lookup.get(&a.label).unwrap().to_string(),
                                    DnsSdResponse::AAnswer(
                                        AAnswer
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
                            if handler.lock().unwrap().is_service_wanted(&aaa.label)
                            {
                                // Also schedule it for removal.
                                service_to_remove = Some(aaa.label.clone());

                                handler.lock().unwrap().add_found_service(
                                    aaa.label.clone(),
                                    DnsSdResponse::AaaaAnswer(
                                        AaaaAnswer
                                        {
                                            label: aaa.label,
                                            address: aaa.address
                                        }
                                    )
                                );
                            }
                            else if reverse_lookup.contains_key(&aaa.label)
                            {
                                handler.lock().unwrap().add_found_service(
                                    reverse_lookup.get(&aaa.label).unwrap().to_string(),
                                    DnsSdResponse::AaaaAnswer(
                                        AaaaAnswer
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
                                // Also schedule it for removal.
                                service_to_remove = Some(ptr.label.clone());

                                handler.lock().unwrap().add_found_service(
                                    ptr.label.clone(),
                                    DnsSdResponse::PtrAnswer(
                                        PtrAnswer
                                        {
                                            label: ptr.label,
                                            service: ptr.service
                                        }
                                    )
                                );
                            }
                            else if reverse_lookup.contains_key(&ptr.label)
                            {
                                handler.lock().unwrap().add_found_service(
                                    reverse_lookup.get(&ptr.label).unwrap().to_string(),
                                    DnsSdResponse::PtrAnswer(
                                        PtrAnswer
                                        {
                                            label: ptr.label,
                                            service: ptr.service
                                        }
                                    )
                                );
                            }
                        },
                        DnsSdResponse::SrvAnswer(srv) =>
                        {
                            if handler.lock().unwrap().is_service_wanted(&srv.label)
                            {
                                // Also schedule it for removal.
                                service_to_remove = Some(srv.label.clone());

                                handler.lock().unwrap().add_found_service(
                                    srv.label.clone(),
                                    DnsSdResponse::SrvAnswer(
                                        SrvAnswer
                                        {
                                            label: srv.label,
                                            service: srv.service,
                                            port: srv.port
                                        }
                                    )
                                );
                            }
                            else if reverse_lookup.contains_key(&srv.label)
                            {
                                handler.lock().unwrap().add_found_service(
                                    reverse_lookup.get(&srv.label).unwrap().to_string(),
                                    DnsSdResponse::SrvAnswer(
                                        SrvAnswer
                                        {
                                            label: srv.label,
                                            service: srv.service,
                                            port: srv.port
                                        }
                                    )
                                );
                            }
                        },
                    }
                }

                if service_to_remove.is_some()
                {
                    handler.lock().unwrap().remove_service(service_to_remove.unwrap());
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
