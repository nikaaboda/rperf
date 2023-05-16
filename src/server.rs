/*
 * Copyright (C) 2021 Evtech Solutions, Ltd., dba 3D-P
 * Copyright (C) 2021 Neil Tallim <neiltallim@3d-p.com>
 *
 * This file is part of rperf.
 *
 * rperf is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * rperf is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with rperf.  If not, see <https://www.gnu.org/licenses/>.
 */

use std::error::Error;
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, Shutdown, SocketAddr};
use std::sync::atomic::{AtomicBool, AtomicU16, Ordering};
use std::sync::mpsc::channel;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use clap::ArgMatches;

use mio::net::{TcpListener, TcpStream};
use mio::{Events, Poll, PollOpt, Ready, Token};

use crate::protocol::communication::{receive, send, KEEPALIVE_DURATION};

use crate::protocol::messaging::{prepare_connect, prepare_connect_ready};

use crate::stream::tls;
use crate::stream::udp;
use crate::stream::{ktls, tcp};
// use crate::stream::TestStream;
use crate::stream::{
    ktls::{
        receiver::{KtlsReceiver},
        sender::KtlsSender,
        KtlsTestDefinition,
    },
    tcp::receiver::TcpReceiver,
    tcp::sender::TcpSender,
    tls::receiver::TlsReceiver,
    tls::sender::TlsSender,
    udp::receiver::UdpReceiver,
    udp::sender::UdpSender,
};

type BoxResult<T> = Result<T, Box<dyn Error>>;

const POLL_TIMEOUT: Duration = Duration::from_millis(500);

/// when false, the system is shutting down
static ALIVE: AtomicBool = AtomicBool::new(true);

/// a count of connected clients
static CLIENTS: AtomicU16 = AtomicU16::new(0);

async fn handle_client(
    stream: &mut TcpStream,
    cpu_affinity_manager: Arc<Mutex<crate::utils::cpu_affinity::CpuAffinityManager>>,
    tcp_port_pool: Arc<Mutex<tcp::receiver::TcpPortPool>>,
    udp_port_pool: Arc<Mutex<udp::receiver::UdpPortPool>>,
    tls_port_pool: Arc<Mutex<tls::receiver::TlsPortPool>>,
    ktls_port_pool: Arc<tokio::sync::Mutex<ktls::receiver::KtlsPortPool>>,
) -> BoxResult<()> {
    let mut started = false;
    let peer_addr = stream.peer_addr()?;

    //scaffolding to track and relay the streams and stream-results associated with this client
    // let mut parallel_streams: Vec<Arc<Mutex<(dyn TestStream + Sync + Send)>>> = Vec::new();
    let mut parallel_streams_tcp_send: Vec<Arc<Mutex<TcpSender>>> = Vec::new();
    let mut parallel_streams_udp_send: Vec<Arc<Mutex<UdpSender>>> = Vec::new();
    let mut parallel_streams_tls_send: Vec<Arc<Mutex<TlsSender>>> = Vec::new();
    let mut parallel_streams_ktls_send: Vec<Arc<tokio::sync::Mutex<KtlsSender>>> = Vec::new();
    let mut parallel_streams_tcp_receive: Vec<Arc<Mutex<TcpReceiver>>> = Vec::new();
    let mut parallel_streams_udp_receive: Vec<Arc<Mutex<UdpReceiver>>> = Vec::new();
    let mut parallel_streams_tls_receive: Vec<Arc<Mutex<TlsReceiver>>> = Vec::new();
    let mut parallel_streams_ktls_receive: Vec<Arc<tokio::sync::Mutex<KtlsReceiver>>> = Vec::new();

    let mut parallel_streams_joinhandles = Vec::new();
    let mut parallel_streams_joinhandles_ktls = Vec::new();
    let (results_tx, results_rx): (
        std::sync::mpsc::Sender<Box<dyn crate::protocol::results::IntervalResult + Sync + Send>>,
        std::sync::mpsc::Receiver<Box<dyn crate::protocol::results::IntervalResult + Sync + Send>>,
    ) = channel();

    //a closure used to pass results from stream-handlers to the client-communication stream
    let mut forwarding_send_stream = stream.try_clone()?;
    let mut results_handler = || -> BoxResult<()> {
        loop {
            //drain all results every time this closer is invoked
            match results_rx.try_recv() {
                //if there's something to forward, write it to the client
                Ok(result) => {
                    send(&mut forwarding_send_stream, &result.to_json())?;
                }
                Err(_) => break, //whether it's empty or disconnected, there's nothing to do
            }
        }
        Ok(())
    };

    //server operations are entirely driven by client-signalling, making this a (simple) state-machine
    while is_alive() {
        let payload = receive(stream, is_alive, &mut results_handler)?;
        /*
        The client is expected to send a JSON object with the following fields:
        serde_json::json!({
            "kind": "configuration",

            "family": "udp",
            "role": "download",

            "test_id": test_id,
            "streams": 1,

            "length": calculate_length_udp(length),
        })

         */
        match payload.get("kind") {
            Some(kind) => {
                match kind.as_str().unwrap() {
                    "configuration" => {
                        //we either need to connect streams to the client or prepare to receive connections
                        if payload
                            .get("role")
                            .unwrap_or(&serde_json::json!("download"))
                            .as_str()
                            .unwrap()
                            == "download"
                        {
                            log::info!(
                                "[{}] running in forward-mode: server will be receiving data",
                                &peer_addr
                            );

                            let stream_count = payload
                                .get("streams")
                                .unwrap_or(&serde_json::json!(1))
                                .as_i64()
                                .unwrap();
                            //since we're receiving data, we're also responsible for letting the client know where to send it
                            let mut stream_ports = Vec::with_capacity(stream_count as usize);

                            let tcp_json = serde_json::json!("tcp");
                            let family =
                                payload.get("family").unwrap_or(&tcp_json).as_str().unwrap();

                            log::info!("family: {}", family);

                            if family == "udp" {
                                log::info!(
                                    "[{}] preparing for UDP test with {} streams...",
                                    &peer_addr,
                                    stream_count
                                );

                                let mut c_udp_port_pool = udp_port_pool.lock().unwrap();

                                let test_definition = udp::UdpTestDefinition::new(&payload)?;
                                for stream_idx in 0..stream_count {
                                    log::debug!(
                                        "[{}] preparing UDP-receiver for stream {}...",
                                        &peer_addr,
                                        stream_idx
                                    );
                                    let test = udp::receiver::UdpReceiver::new(
                                        test_definition.clone(),
                                        &(stream_idx as u8),
                                        &mut c_udp_port_pool,
                                        &peer_addr.ip(),
                                        &(payload["receive_buffer"].as_i64().unwrap() as usize),
                                    )?;
                                    stream_ports.push(test.get_port()?);
                                    parallel_streams_udp_receive.push(Arc::new(Mutex::new(test)));
                                }
                            } else if family == "tls" {
                                log::info!(
                                    "[{}] preparing for TLS test with {} streams...",
                                    &peer_addr,
                                    stream_count
                                );

                                let mut c_tls_port_pool = tls_port_pool.lock().unwrap();

                                let test_definition = tls::TlsTestDefinition::new(&payload)?;
                                for stream_idx in 0..stream_count {
                                    log::debug!(
                                        "[{}] preparing TLS-receiver for stream {}...",
                                        &peer_addr,
                                        stream_idx
                                    );
                                    let test = tls::receiver::TlsReceiver::new(
                                        test_definition.clone(),
                                        &(stream_idx as u8),
                                        &mut c_tls_port_pool,
                                        &peer_addr.ip(),
                                        // &(payload["receive_buffer"].as_i64().unwrap() as usize),
                                    )?;
                                    stream_ports.push(test.get_port()?);
                                    parallel_streams_tls_receive.push(Arc::new(Mutex::new(test)));
                                }
                            } else if family == "ktls" {
                                log::info!(
                                    "[{}] preparing for KTLS test with {} streams...",
                                    &peer_addr,
                                    stream_count
                                );

                                let mut c_ktls_port_pool = ktls_port_pool.lock().await;

                                let test_definition = ktls::KtlsTestDefinition::new(&payload)?;
                                for stream_idx in 0..stream_count {
                                    log::debug!(
                                        "[{}] preparing TLS-receiver for stream {}...",
                                        &peer_addr,
                                        stream_idx
                                    );
                                    let test = KtlsReceiver::new(
                                        test_definition.clone(),
                                        &(stream_idx as u8),
                                        &mut c_ktls_port_pool,
                                        &peer_addr.ip(),
                                        // &(payload["receive_buffer"].as_i64().unwrap() as usize),
                                    )
                                    .await
                                    .unwrap();
                                    log::info!("new ktls receiver created");
                                    stream_ports.push(test.get_port()?);
                                    parallel_streams_ktls_receive
                                        .push(Arc::new(tokio::sync::Mutex::new(test)));
                                }
                            } else {
                                // TCP
                                log::info!(
                                    "[{}] preparing for TCP test with {} streams...",
                                    &peer_addr,
                                    stream_count
                                );

                                let mut c_tcp_port_pool = tcp_port_pool.lock().unwrap();

                                let test_definition = tcp::TcpTestDefinition::new(&payload)?;
                                for stream_idx in 0..stream_count {
                                    log::debug!(
                                        "[{}] preparing TCP-receiver for stream {}...",
                                        &peer_addr,
                                        stream_idx
                                    );
                                    let test = tcp::receiver::TcpReceiver::new(
                                        test_definition.clone(),
                                        &(stream_idx as u8),
                                        &mut c_tcp_port_pool,
                                        &peer_addr.ip(),
                                        &(payload["receive_buffer"].as_i64().unwrap() as usize),
                                    )?;
                                    stream_ports.push(test.get_port()?);
                                    parallel_streams_tcp_receive.push(Arc::new(Mutex::new(test)));
                                }
                            }

                            //let the client know we're ready to receive the connection; stream-ports are in stream-index order
                            send(stream, &prepare_connect(&stream_ports))?;
                            log::info!("told client that im ready to receive");
                        } else {
                            //upload
                            log::info!(
                                "[{}] running in reverse-mode: server will be uploading data",
                                &peer_addr
                            );

                            let stream_ports =
                                payload.get("stream_ports").unwrap().as_array().unwrap();

                            let tcp_json = serde_json::json!("tcp");

                            let family =
                                payload.get("family").unwrap_or(&tcp_json).as_str().unwrap();

                            if family == "udp" {
                                log::info!(
                                    "[{}] preparing for UDP test with {} streams...",
                                    &peer_addr,
                                    stream_ports.len()
                                );

                                let test_definition = udp::UdpTestDefinition::new(&payload)?;
                                for (stream_idx, port) in stream_ports.iter().enumerate() {
                                    log::debug!(
                                        "[{}] preparing UDP-sender for stream {}...",
                                        &peer_addr,
                                        stream_idx
                                    );
                                    let test = udp::sender::UdpSender::new(
                                        test_definition.clone(),
                                        &(stream_idx as u8),
                                        &0,
                                        &peer_addr.ip(),
                                        &(port.as_i64().unwrap_or(0) as u16),
                                        &(payload
                                            .get("duration")
                                            .unwrap_or(&serde_json::json!(0.0))
                                            .as_f64()
                                            .unwrap()
                                            as f32),
                                        &(payload
                                            .get("send_interval")
                                            .unwrap_or(&serde_json::json!(1.0))
                                            .as_f64()
                                            .unwrap()
                                            as f32),
                                        &(payload["send_buffer"].as_i64().unwrap() as usize),
                                    )?;
                                    parallel_streams_udp_send.push(Arc::new(Mutex::new(test)));
                                }
                            } else if family == "tls" {
                                log::info!(
                                    "[{}] preparing for TLS test with {} streams...",
                                    &peer_addr,
                                    stream_ports.len()
                                );

                                let test_definition = tls::TlsTestDefinition::new(&payload)?;
                                for (stream_idx, port) in stream_ports.iter().enumerate() {
                                    log::debug!(
                                        "[{}] preparing TLS-sender for stream {}...",
                                        &peer_addr,
                                        stream_idx
                                    );
                                    let test = tls::sender::TlsSender::new(
                                        test_definition.clone(),
                                        &(stream_idx as u8),
                                        &peer_addr.ip(),
                                        &(port.as_i64().unwrap() as u16),
                                        &(payload["duration"].as_f64().unwrap() as f32),
                                        &(payload["send_interval"].as_f64().unwrap() as f32),
                                        &(payload["send_buffer"].as_i64().unwrap() as usize),
                                        &(payload["no_delay"].as_bool().unwrap()),
                                    )?;
                                    parallel_streams_tls_send.push(Arc::new(Mutex::new(test)));
                                }
                            } else if family == "ktls" {
                                log::info!(
                                    "[{}] preparing for KTLS test with {} streams...",
                                    &peer_addr,
                                    stream_ports.len()
                                );

                                let test_definition = KtlsTestDefinition::new(&payload)?;
                                for (stream_idx, port) in stream_ports.iter().enumerate() {
                                    log::debug!(
                                        "[{}] preparing TLS-sender for stream {}...",
                                        &peer_addr,
                                        stream_idx
                                    );
                                    let test = KtlsSender::new(
                                        test_definition.clone(),
                                        &(stream_idx as u8),
                                        &peer_addr.ip(),
                                        &(port.as_i64().unwrap() as u16),
                                        &(payload["duration"].as_f64().unwrap() as f32),
                                        &(payload["send_interval"].as_f64().unwrap() as f32),
                                        &(payload["send_buffer"].as_i64().unwrap() as usize),
                                        &(payload["no_delay"].as_bool().unwrap()),
                                    )?;
                                    parallel_streams_ktls_send
                                        .push(Arc::new(tokio::sync::Mutex::new(test)));
                                }
                            } else {
                                //TCP
                                log::info!(
                                    "[{}] preparing for TCP test with {} streams...",
                                    &peer_addr,
                                    stream_ports.len()
                                );

                                let test_definition = tcp::TcpTestDefinition::new(&payload)?;
                                for (stream_idx, port) in stream_ports.iter().enumerate() {
                                    log::debug!(
                                        "[{}] preparing TCP-sender for stream {}...",
                                        &peer_addr,
                                        stream_idx
                                    );
                                    let test = tcp::sender::TcpSender::new(
                                        test_definition.clone(),
                                        &(stream_idx as u8),
                                        &peer_addr.ip(),
                                        &(port.as_i64().unwrap() as u16),
                                        &(payload["duration"].as_f64().unwrap() as f32),
                                        &(payload["send_interval"].as_f64().unwrap() as f32),
                                        &(payload["send_buffer"].as_i64().unwrap() as usize),
                                        &(payload["no_delay"].as_bool().unwrap()),
                                    )?;
                                    parallel_streams_tcp_send.push(Arc::new(Mutex::new(test)));
                                }
                            }

                            //let the client know we're ready to begin
                            send(stream, &prepare_connect_ready())?;
                        }
                    }
                    "begin" => {
                        log::info!("initialized parallel streams. started: {}", started);

                        if !started {
                            //a simple guard to protect against reinitialisaion  
                            for (stream_idx, parallel_stream) in
                                parallel_streams_tcp_receive.iter_mut().enumerate()
                            {
                                log::info!(
                                    "[{}] beginning execution of stream {}...",
                                    &peer_addr,
                                    stream_idx
                                );
                                let c_ps = Arc::clone(&parallel_stream);
                                let c_results_tx = results_tx.clone();
                                let c_cam = cpu_affinity_manager.clone();
                                let handle = thread::spawn(move || {
                                    {
                                        //set CPU affinity, if enabled
                                        c_cam.lock().unwrap().set_affinity();
                                    }
                                    loop {
                                        let mut test = c_ps.lock().unwrap();
                                        log::debug!(
                                            "[{}] beginning test-interval for stream {}",
                                            &peer_addr,
                                            test.get_idx()
                                        );
                                        match test.run_interval() {
                                            Some(interval_result) => {
                                                match interval_result {
                                                    Ok(ir) => match c_results_tx.send(ir) {
                                                        Ok(_) => (),
                                                        Err(e) => {
                                                            log::error!("[{}] unable to process interval-result: {}", &peer_addr, e);
                                                            break;
                                                        }
                                                    },
                                                    Err(e) => {
                                                        log::error!(
                                                "[{}] unable to process stream: {}",
                                                peer_addr,
                                                e
                                            );
                                                        match c_results_tx.send(Box::new(crate::protocol::results::ServerFailedResult{stream_idx: test.get_idx()})) {
                                                Ok(_) => (),
                                                Err(e) => log::error!("[{}] unable to report interval-failed-result: {}", &peer_addr, e),
                                            }
                                                        break;
                                                    }
                                                }
                                            }
                                            None => {
                                                match c_results_tx.send(Box::new(crate::protocol::results::ServerDoneResult{stream_idx: test.get_idx()})) {
                                            Ok(_) => (),
                                            Err(e) => log::error!("[{}] unable to report interval-done-result: {}", &peer_addr, e),
                                        }
                                                break;
                                            }
                                        }
                                    }
                                });
                                parallel_streams_joinhandles.push(handle);
                            }
                        
                        
                            for (stream_idx, parallel_stream) in
                                parallel_streams_udp_receive.iter_mut().enumerate()
                            {
                                log::info!(
                                    "[{}] beginning execution of stream {}...",
                                    &peer_addr,
                                    stream_idx
                                );
                                let c_ps = Arc::clone(&parallel_stream);
                                let c_results_tx = results_tx.clone();
                                let c_cam = cpu_affinity_manager.clone();
                                let handle = thread::spawn(move || {
                                    {
                                        //set CPU affinity, if enabled
                                        c_cam.lock().unwrap().set_affinity();
                                    }
                                    loop {
                                        let mut test = c_ps.lock().unwrap();
                                        log::debug!(
                                            "[{}] beginning test-interval for stream {}",
                                            &peer_addr,
                                            test.get_idx()
                                        );
                                        match test.run_interval() {
                                            Some(interval_result) => {
                                                match interval_result {
                                                    Ok(ir) => match c_results_tx.send(ir) {
                                                        Ok(_) => (),
                                                        Err(e) => {
                                                            log::error!("[{}] unable to process interval-result: {}", &peer_addr, e);
                                                            break;
                                                        }
                                                    },
                                                    Err(e) => {
                                                        log::error!(
                                                "[{}] unable to process stream: {}",
                                                peer_addr,
                                                e
                                            );
                                                        match c_results_tx.send(Box::new(crate::protocol::results::ServerFailedResult{stream_idx: test.get_idx()})) {
                                                Ok(_) => (),
                                                Err(e) => log::error!("[{}] unable to report interval-failed-result: {}", &peer_addr, e),
                                            }
                                                        break;
                                                    }
                                                }
                                            }
                                            None => {
                                                match c_results_tx.send(Box::new(crate::protocol::results::ServerDoneResult{stream_idx: test.get_idx()})) {
                                            Ok(_) => (),
                                            Err(e) => log::error!("[{}] unable to report interval-done-result: {}", &peer_addr, e),
                                        }
                                                break;
                                            }
                                        }
                                    }
                                });
                                parallel_streams_joinhandles.push(handle);
                            }
                        
                        
                            for (stream_idx, parallel_stream) in
                                parallel_streams_tls_receive.iter_mut().enumerate()
                            {
                                log::info!(
                                    "[{}] beginning execution of stream {}...",
                                    &peer_addr,
                                    stream_idx
                                );
                                let c_ps = Arc::clone(&parallel_stream);
                                let c_results_tx = results_tx.clone();
                                let c_cam = cpu_affinity_manager.clone();
                                let handle = thread::spawn(move || {
                                    {
                                        //set CPU affinity, if enabled
                                        c_cam.lock().unwrap().set_affinity();
                                    }
                                    loop {
                                        let mut test = c_ps.lock().unwrap();
                                        log::debug!(
                                            "[{}] beginning test-interval for stream {}",
                                            &peer_addr,
                                            test.get_idx()
                                        );
                                        match test.run_interval() {
                                            Some(interval_result) => {
                                                match interval_result {
                                                    Ok(ir) => match c_results_tx.send(ir) {
                                                        Ok(_) => (),
                                                        Err(e) => {
                                                            log::error!("[{}] unable to process interval-result: {}", &peer_addr, e);
                                                            break;
                                                        }
                                                    },
                                                    Err(e) => {
                                                        log::error!(
                                                "[{}] unable to process stream: {}",
                                                peer_addr,
                                                e
                                            );
                                                        match c_results_tx.send(Box::new(crate::protocol::results::ServerFailedResult{stream_idx: test.get_idx()})) {
                                                Ok(_) => (),
                                                Err(e) => log::error!("[{}] unable to report interval-failed-result: {}", &peer_addr, e),
                                            }
                                                        break;
                                                    }
                                                }
                                            }
                                            None => {
                                                match c_results_tx.send(Box::new(crate::protocol::results::ServerDoneResult{stream_idx: test.get_idx()})) {
                                            Ok(_) => (),
                                            Err(e) => log::error!("[{}] unable to report interval-done-result: {}", &peer_addr, e),
                                        }
                                                break;
                                            }
                                        }
                                    }
                                });
                                parallel_streams_joinhandles.push(handle);
                            }
                        
                        
                            log::info!("inside ktls block");
                            for (stream_idx, parallel_stream) in
                                parallel_streams_ktls_receive.iter_mut().enumerate()
                            {
                                log::info!("hello: {}", stream_idx);
                                log::info!(
                                    "[{}] beginning execution of stream {}...",
                                    &peer_addr,
                                    stream_idx
                                );
                                let c_ps = Arc::clone(&parallel_stream);
                                let c_results_tx = results_tx.clone();
                                let c_cam = cpu_affinity_manager.clone();
                                let handle = tokio::spawn(async move {
                                    {
                                        //set CPU affinity, if enabled
                                        c_cam.lock().unwrap().set_affinity();
                                    }
                                    loop {
                                        let mut test = c_ps.lock().await;
                                        log::debug!(
                                            "[{}] beginning test-interval for stream {}",
                                            &peer_addr,
                                            test.get_idx()
                                        );
                                        match test.run_interval().await.unwrap() {
                                            interval_result => match interval_result {
                                                Ok(ir) => match c_results_tx.send(ir) {
                                                    Ok(_) => (),
                                                    Err(e) => {
                                                        log::error!("[{}] unable to process interval-result: {}", &peer_addr, e);
                                                        break;
                                                    }
                                                },
                                                Err(e) => {
                                                    log::error!(
                                                        "[{}] unable to process stream: {}",
                                                        peer_addr,
                                                        e
                                                    );
                                                    match c_results_tx.send(Box::new(crate::protocol::results::ServerFailedResult{stream_idx: test.get_idx()})) {
                                                Ok(_) => (),
                                                Err(e) => log::error!("[{}] unable to report interval-failed-result: {}", &peer_addr, e),
                                            }
                                                    break;
                                                }
                                            },
                                            // None => {
                                            //     match c_results_tx.send(Box::new(crate::protocol::results::ServerDoneResult{stream_idx: test.get_idx()})) {
                                            //         Ok(_) => (),
                                            //         Err(e) => log::error!("[{}] unable to report interval-done-result: {}", &peer_addr, e),
                                            //     }
                                            //     break;
                                            // }
                                        }
                                    }
                                });
                                parallel_streams_joinhandles_ktls.push(handle);
                            }
                        
                            for (stream_idx, parallel_stream) in
                                parallel_streams_tcp_send.iter_mut().enumerate()
                            {
                                log::info!(
                                    "[{}] beginning execution of stream {}...",
                                    &peer_addr,
                                    stream_idx
                                );
                                let c_ps = Arc::clone(&parallel_stream);
                                let c_results_tx = results_tx.clone();
                                let c_cam = cpu_affinity_manager.clone();
                                let handle = thread::spawn(move || {
                                    {
                                        //set CPU affinity, if enabled
                                        c_cam.lock().unwrap().set_affinity();
                                    }
                                    loop {
                                        let mut test = c_ps.lock().unwrap();
                                        log::debug!(
                                            "[{}] beginning test-interval for stream {}",
                                            &peer_addr,
                                            test.get_idx()
                                        );
                                        match test.run_interval() {
                                            Some(interval_result) => {
                                                match interval_result {
                                                    Ok(ir) => match c_results_tx.send(ir) {
                                                        Ok(_) => (),
                                                        Err(e) => {
                                                            log::error!("[{}] unable to process interval-result: {}", &peer_addr, e);
                                                            break;
                                                        }
                                                    },
                                                    Err(e) => {
                                                        log::error!(
                                                "[{}] unable to process stream: {}",
                                                peer_addr,
                                                e
                                            );
                                                        match c_results_tx.send(Box::new(crate::protocol::results::ServerFailedResult{stream_idx: test.get_idx()})) {
                                                Ok(_) => (),
                                                Err(e) => log::error!("[{}] unable to report interval-failed-result: {}", &peer_addr, e),
                                            }
                                                        break;
                                                    }
                                                }
                                            }
                                            None => {
                                                match c_results_tx.send(Box::new(crate::protocol::results::ServerDoneResult{stream_idx: test.get_idx()})) {
                                            Ok(_) => (),
                                            Err(e) => log::error!("[{}] unable to report interval-done-result: {}", &peer_addr, e),
                                        }
                                                break;
                                            }
                                        }
                                    }
                                });
                                parallel_streams_joinhandles.push(handle);
                            }
                        
                            for (stream_idx, parallel_stream) in
                                parallel_streams_udp_send.iter_mut().enumerate()
                            {
                                log::info!(
                                    "[{}] beginning execution of stream {}...",
                                    &peer_addr,
                                    stream_idx
                                );
                                let c_ps = Arc::clone(&parallel_stream);
                                let c_results_tx = results_tx.clone();
                                let c_cam = cpu_affinity_manager.clone();
                                let handle = thread::spawn(move || {
                                    {
                                        //set CPU affinity, if enabled
                                        c_cam.lock().unwrap().set_affinity();
                                    }
                                    loop {
                                        let mut test = c_ps.lock().unwrap();
                                        log::debug!(
                                            "[{}] beginning test-interval for stream {}",
                                            &peer_addr,
                                            test.get_idx()
                                        );
                                        match test.run_interval() {
                                            Some(interval_result) => {
                                                match interval_result {
                                                    Ok(ir) => match c_results_tx.send(ir) {
                                                        Ok(_) => (),
                                                        Err(e) => {
                                                            log::error!("[{}] unable to process interval-result: {}", &peer_addr, e);
                                                            break;
                                                        }
                                                    },
                                                    Err(e) => {
                                                        log::error!(
                                                "[{}] unable to process stream: {}",
                                                peer_addr,
                                                e
                                            );
                                                        match c_results_tx.send(Box::new(crate::protocol::results::ServerFailedResult{stream_idx: test.get_idx()})) {
                                                Ok(_) => (),
                                                Err(e) => log::error!("[{}] unable to report interval-failed-result: {}", &peer_addr, e),
                                            }
                                                        break;
                                                    }
                                                }
                                            }
                                            None => {
                                                match c_results_tx.send(Box::new(crate::protocol::results::ServerDoneResult{stream_idx: test.get_idx()})) {
                                            Ok(_) => (),
                                            Err(e) => log::error!("[{}] unable to report interval-done-result: {}", &peer_addr, e),
                                        }
                                                break;
                                            }
                                        }
                                    }
                                });
                                parallel_streams_joinhandles.push(handle);
                            }
                        
                            for (stream_idx, parallel_stream) in
                                parallel_streams_tls_send.iter_mut().enumerate()
                            {
                                log::info!(
                                    "[{}] beginning execution of stream {}...",
                                    &peer_addr,
                                    stream_idx
                                );
                                let c_ps = Arc::clone(&parallel_stream);
                                let c_results_tx = results_tx.clone();
                                let c_cam = cpu_affinity_manager.clone();
                                let handle = thread::spawn(move || {
                                    {
                                        //set CPU affinity, if enabled
                                        c_cam.lock().unwrap().set_affinity();
                                    }
                                    loop {
                                        let mut test = c_ps.lock().unwrap();
                                        log::debug!(
                                            "[{}] beginning test-interval for stream {}",
                                            &peer_addr,
                                            test.get_idx()
                                        );
                                        match test.run_interval() {
                                            Some(interval_result) => {
                                                match interval_result {
                                                    Ok(ir) => match c_results_tx.send(ir) {
                                                        Ok(_) => (),
                                                        Err(e) => {
                                                            log::error!("[{}] unable to process interval-result: {}", &peer_addr, e);
                                                            break;
                                                        }
                                                    },
                                                    Err(e) => {
                                                        log::error!(
                                                "[{}] unable to process stream: {}",
                                                peer_addr,
                                                e
                                            );
                                                        match c_results_tx.send(Box::new(crate::protocol::results::ServerFailedResult{stream_idx: test.get_idx()})) {
                                                Ok(_) => (),
                                                Err(e) => log::error!("[{}] unable to report interval-failed-result: {}", &peer_addr, e),
                                            }
                                                        break;
                                                    }
                                                }
                                            }
                                            None => {
                                                match c_results_tx.send(Box::new(crate::protocol::results::ServerDoneResult{stream_idx: test.get_idx()})) {
                                            Ok(_) => (),
                                            Err(e) => log::error!("[{}] unable to report interval-done-result: {}", &peer_addr, e),
                                        }
                                                break;
                                            }
                                        }
                                    }
                                });
                                parallel_streams_joinhandles.push(handle);
                            }
                        
                            for (stream_idx, parallel_stream) in
                                parallel_streams_ktls_send.iter_mut().enumerate()
                            {
                                log::info!(
                                    "[{}] beginning execution of stream {}...",
                                    &peer_addr,
                                    stream_idx
                                );
                                let c_ps = Arc::clone(&parallel_stream);
                                let c_results_tx = results_tx.clone();
                                let c_cam = cpu_affinity_manager.clone();
                                let handle = tokio::spawn(async move {
                                    {
                                        //set CPU affinity, if enabled
                                        c_cam.lock().unwrap().set_affinity();
                                    }
                                    loop {
                                        let mut test = c_ps.lock().await;
                                        log::debug!(
                                            "[{}] beginning test-interval for stream {}",
                                            &peer_addr,
                                            test.get_idx()
                                        );
                                        match test.run_interval().await.unwrap() {
                                            interval_result => match interval_result {
                                                Ok(ir) => match c_results_tx.send(ir) {
                                                    Ok(_) => (),
                                                    Err(e) => {
                                                        log::error!("[{}] unable to process interval-result: {}", &peer_addr, e);
                                                        break;
                                                    }
                                                },
                                                Err(e) => {
                                                    log::error!(
                                                        "[{}] unable to process stream: {}",
                                                        peer_addr,
                                                        e
                                                    );
                                                    match c_results_tx.send(Box::new(crate::protocol::results::ServerFailedResult{stream_idx: test.get_idx()})) {
                                                Ok(_) => (),
                                                Err(e) => log::error!("[{}] unable to report interval-failed-result: {}", &peer_addr, e),
                                            }
                                                    break;
                                                }
                                            },
                                            // None => {
                                            //     match c_results_tx.send(Box::new(crate::protocol::results::ServerDoneResult{stream_idx: test.get_idx()})) {
                                            //         Ok(_) => (),
                                            //         Err(e) => log::error!("[{}] unable to report interval-done-result: {}", &peer_addr, e),
                                            //     }
                                            //     break;
                                            // }
                                        }
                                    }
                                });
                                parallel_streams_joinhandles_ktls.push(handle);
                            }
                        
                            
                            started = true;
                        } else {
                            //this can only happen in case of malicious action
                            log::error!("[{}] duplicate begin-signal", &peer_addr);
                            break;
                        }
                    }
                    "end" => {
                        //the client has indicated that testing is done; stop cleanly
                        log::info!("[{}] end of testing signaled", &peer_addr);
                        break;
                    }
                    _ => {
                        log::error!("[{}] invalid data", &peer_addr);
                        break;
                    }
                }
            }
            None => {
                log::error!("[{}] invalid data", &peer_addr);
                break;
            }
        }
    }

    log::debug!("[{}] stopping any still-in-progress streams", &peer_addr);

    for ps in parallel_streams_tcp_receive.iter_mut() {
        let mut stream = match (*ps).lock() {
            Ok(guard) => guard,
            Err(poisoned) => {
                log::error!(
                    "[{}] a stream-handler was poisoned; this indicates some sort of logic error",
                    &peer_addr
                );
                poisoned.into_inner()
            }
        };
        stream.stop();
    }

    for ps in parallel_streams_udp_receive.iter_mut() {
        let mut stream = match (*ps).lock() {
            Ok(guard) => guard,
            Err(poisoned) => {
                log::error!(
                    "[{}] a stream-handler was poisoned; this indicates some sort of logic error",
                    &peer_addr
                );
                poisoned.into_inner()
            }
        };
        stream.stop();
    }

    for ps in parallel_streams_tls_receive.iter_mut() {
        let mut stream = match (*ps).lock() {
            Ok(guard) => guard,
            Err(poisoned) => {
                log::error!(
                    "[{}] a stream-handler was poisoned; this indicates some sort of logic error",
                    &peer_addr
                );
                poisoned.into_inner()
            }
        };
        stream.stop();
    }

    for ps in parallel_streams_ktls_receive.iter_mut() {
        let mut stream = (*ps).lock().await;
        stream.stop();
    }

    for ps in parallel_streams_tcp_send.iter_mut() {
        let mut stream = match (*ps).lock() {
            Ok(guard) => guard,
            Err(poisoned) => {
                log::error!(
                    "[{}] a stream-handler was poisoned; this indicates some sort of logic error",
                    &peer_addr
                );
                poisoned.into_inner()
            }
        };
        stream.stop();
    }

    for ps in parallel_streams_udp_send.iter_mut() {
        let mut stream = match (*ps).lock() {
            Ok(guard) => guard,
            Err(poisoned) => {
                log::error!(
                    "[{}] a stream-handler was poisoned; this indicates some sort of logic error",
                    &peer_addr
                );
                poisoned.into_inner()
            }
        };
        stream.stop();
    }

    for ps in parallel_streams_tls_send.iter_mut() {
        let mut stream = match (*ps).lock() {
            Ok(guard) => guard,
            Err(poisoned) => {
                log::error!(
                    "[{}] a stream-handler was poisoned; this indicates some sort of logic error",
                    &peer_addr
                );
                poisoned.into_inner()
            }
        };
        stream.stop();
    }

    for ps in parallel_streams_ktls_send.iter_mut() {
        let mut stream = (*ps).lock().await;
        stream.stop();
    }

    log::debug!("[{}] waiting for all streams to end", &peer_addr);
    for jh in parallel_streams_joinhandles {
        match jh.join() {
            Ok(_) => (),
            Err(e) => log::error!("[{}] error in parallel stream: {:?}", &peer_addr, e),
        }
    }

    for jh in parallel_streams_joinhandles_ktls {
        match jh.await {
            Ok(_) => (),
            Err(e) => log::error!("[{}] error in parallel stream: {:?}", &peer_addr, e),
        }
    }

    Ok(())
}

/// a panic-tolerant means of indicating that a client has been disconnected
struct ClientThreadMonitor {
    client_address: String,
}
impl Drop for ClientThreadMonitor {
    fn drop(&mut self) {
        CLIENTS.fetch_sub(1, Ordering::Relaxed);
        if thread::panicking() {
            log::warn!("{} disconnecting due to panic", self.client_address);
        } else {
            log::info!("{} disconnected", self.client_address);
        }
    }
}

pub async fn serve(args: ArgMatches<'_>) -> BoxResult<()> {
    //config-parsing and pre-connection setup
    let tcp_port_pool = Arc::new(Mutex::new(tcp::receiver::TcpPortPool::new(
        args.value_of("tcp_port_pool").unwrap().to_string(),
        args.value_of("tcp6_port_pool").unwrap().to_string(),
    )));
    let udp_port_pool = Arc::new(Mutex::new(udp::receiver::UdpPortPool::new(
        args.value_of("udp_port_pool").unwrap().to_string(),
        args.value_of("udp6_port_pool").unwrap().to_string(),
    )));
    let tls_port_pool = Arc::new(Mutex::new(tls::receiver::TlsPortPool::new(
        args.value_of("tls_port_pool").unwrap().to_string(),
        args.value_of("tls6_port_pool").unwrap().to_string(),
    )));
    let ktls_port_pool = Arc::new(tokio::sync::Mutex::new(ktls::receiver::KtlsPortPool::new(
        args.value_of("tls_port_pool").unwrap().to_string(),
        args.value_of("tls6_port_pool").unwrap().to_string(),
    )));

    let cpu_affinity_manager = Arc::new(Mutex::new(
        crate::utils::cpu_affinity::CpuAffinityManager::new(args.value_of("affinity").unwrap())?,
    ));

    let client_limit: u16 = args.value_of("client_limit").unwrap().parse()?;
    if client_limit > 0 {
        log::debug!("limiting service to {} concurrent clients", client_limit);
    }

    //start listening for connections
    let port: u16 = args.value_of("port").unwrap().parse()?;
    let mut listener: TcpListener;
    if args.is_present("version6") {
        listener = TcpListener::bind(&SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), port))
            .expect(format!("failed to bind TCP socket, port {}", port).as_str());
    } else {
        listener = TcpListener::bind(&SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), port))
            .expect(format!("failed to bind TCP socket, port {}", port).as_str());
    }
    log::info!("server listening on {}", listener.local_addr()?);

    let mio_token = Token(0);
    let poll = Poll::new()?;
    poll.register(&mut listener, mio_token, Ready::readable(), PollOpt::edge())?;
    let mut events = Events::with_capacity(32);

    while is_alive() {
        poll.poll(&mut events, Some(POLL_TIMEOUT))?;
        for event in events.iter() {
            match event.token() {
                _ => loop {
                    match listener.accept() {
                        Ok((mut stream, address)) => {
                            log::info!("connection from {}", address);

                            stream
                                .set_nodelay(true)
                                .expect("cannot disable Nagle's algorithm");
                            stream
                                .set_keepalive(Some(KEEPALIVE_DURATION))
                                .expect("unable to set TCP keepalive");

                            let client_count = CLIENTS.fetch_add(1, Ordering::Relaxed) + 1;
                            if client_limit > 0 && client_count > client_limit {
                                log::warn!(
                                    "client-limit ({}) reached; disconnecting {}...",
                                    client_limit,
                                    address.to_string()
                                );
                                stream.shutdown(Shutdown::Both).unwrap_or_default();
                                CLIENTS.fetch_sub(1, Ordering::Relaxed);
                            } else {
                                let c_cam = cpu_affinity_manager.clone();
                                let c_tcp_port_pool = tcp_port_pool.clone();
                                let c_udp_port_pool = udp_port_pool.clone();
                                let c_tls_port_pool = tls_port_pool.clone();
                                let c_ktls_port_pool = ktls_port_pool.clone();
                                // let thread_builder =
                                //     thread::Builder::new().name(address.to_string().into());
                                // tokio::spawn(async move {
                                //ensure the client is accounted-for even if the handler panics
                                let _client_thread_monitor = ClientThreadMonitor {
                                    client_address: address.to_string(),
                                };

                                match handle_client(
                                    &mut stream,
                                    c_cam,
                                    c_tcp_port_pool,
                                    c_udp_port_pool,
                                    c_tls_port_pool,
                                    c_ktls_port_pool,
                                )
                                .await
                                {
                                    Ok(_) => (),
                                    Err(e) => log::error!("error in client-handler: {}", e),
                                }

                                //in the event of panic, this will happen when the stream is dropped
                                stream.shutdown(Shutdown::Both).unwrap_or_default();
                                // });
                            }
                        }
                        Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
                            //nothing to do
                            break;
                        }
                        Err(e) => {
                            return Err(Box::new(e));
                        }
                    }
                },
            }
        }
    }

    //wait until all clients have been disconnected
    loop {
        let clients_count = CLIENTS.load(Ordering::Relaxed);
        if clients_count > 0 {
            log::info!("waiting for {} clients to finish...", clients_count);
            thread::sleep(POLL_TIMEOUT);
        } else {
            break;
        }
    }
    Ok(())
}

pub fn kill() -> bool {
    ALIVE.swap(false, Ordering::Relaxed)
}
fn is_alive() -> bool {
    ALIVE.load(Ordering::Relaxed)
}
