extern crate nix;

use nix::sys::socket::{setsockopt, sockopt::SndBuf};

use crate::protocol::results::{
    get_unix_timestamp, IntervalResult, TlsReceiveResult, TlsSendResult,
};
use std::os::fd::{AsRawFd, RawFd};
use tokio::io::{AsyncRead, AsyncWrite};

use super::{parse_port_spec, INTERVAL};

use std::error::Error;
type BoxResult<T> = Result<T, Box<dyn Error>>;

pub const TEST_HEADER_SIZE: usize = 16;

#[derive(Clone)]
pub struct KtlsTestDefinition {
    //a UUID used to identify packets associated with this test
    pub test_id: [u8; 16],
    //bandwidth target, in bytes/sec
    pub bandwidth: u64,
    //the length of the buffer to exchange
    pub length: usize,
}
impl KtlsTestDefinition {
    pub fn new(details: &serde_json::Value) -> super::BoxResult<KtlsTestDefinition> {
        let mut test_id_bytes = [0_u8; 16];
        for (i, v) in details
            .get("test_id")
            .unwrap_or(&serde_json::json!([]))
            .as_array()
            .unwrap()
            .iter()
            .enumerate()
        {
            if i >= 16 {
                //avoid out-of-bounds if given malicious data
                break;
            }
            test_id_bytes[i] = v.as_i64().unwrap_or(0) as u8;
        }

        let length = details
            .get("length")
            .unwrap_or(&serde_json::json!(TEST_HEADER_SIZE))
            .as_i64()
            .unwrap() as usize;
        if length < TEST_HEADER_SIZE {
            return Err(Box::new(simple_error::simple_error!(std::format!(
                "{} is too short of a length to satisfy testing requirements",
                length
            ))));
        }

        Ok(KtlsTestDefinition {
            test_id: test_id_bytes,
            bandwidth: details
                .get("bandwidth")
                .unwrap_or(&serde_json::json!(0.0))
                .as_f64()
                .unwrap() as u64,
            length: length,
        })
    }
}

pub mod receiver {
    use std::fs::File;
    use std::io::Read;
    use std::mem::swap;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
    use std::sync::{Arc, Mutex};
    use std::time::{Duration, Instant};
    use std::vec;

    use ktls::CorkStream;
    use rustls::cipher_suite::TLS13_AES_128_GCM_SHA256;
    use rustls::version::TLS13;
    use rustls::{Certificate, KeyLogFile, PrivateKey, ServerConfig};
    use tokio;
    use tokio::io::AsyncReadExt;

    use super::SpyStream;

    const POLL_TIMEOUT: Duration = Duration::from_millis(250);
    const RECEIVE_TIMEOUT: Duration = Duration::from_secs(3);

    pub struct KtlsPortPool {
        pub ports_ip4: Vec<u16>,
        pub ports_ip6: Vec<u16>,
        pos_ip4: usize,
        pos_ip6: usize,
        lock_ip4: Mutex<u8>,
        lock_ip6: Mutex<u8>,
    }
    impl KtlsPortPool {
        pub fn new(port_spec: String, port_spec6: String) -> KtlsPortPool {
            let ports = super::parse_port_spec(port_spec);
            if !ports.is_empty() {
                log::debug!("configured IPv4 TCP port pool: {:?}", ports);
            } else {
                log::debug!("using OS assignment for IPv4 TCP ports");
            }

            let ports6 = super::parse_port_spec(port_spec6);
            if !ports.is_empty() {
                log::debug!("configured IPv6 TCP port pool: {:?}", ports6);
            } else {
                log::debug!("using OS assignment for IPv6 TCP ports");
            }

            KtlsPortPool {
                ports_ip4: ports,
                pos_ip4: 0,
                lock_ip4: Mutex::new(0),

                ports_ip6: ports6,
                pos_ip6: 0,
                lock_ip6: Mutex::new(0),
            }
        }

        pub async fn bind(
            &mut self,
            peer_ip: &IpAddr,
        ) -> super::BoxResult<tokio::net::TcpListener> {
            match peer_ip {
                IpAddr::V6(_) => {
                    if self.ports_ip6.is_empty() {
                        return Ok(tokio::net::TcpListener::bind(&SocketAddr::new(
                            IpAddr::V6(Ipv6Addr::UNSPECIFIED),
                            0,
                        ))
                        .await
                        .unwrap());
                    } else {
                        let _guard = self.lock_ip6.lock().unwrap();

                        for port_idx in (self.pos_ip6 + 1)..self.ports_ip6.len() {
                            //iterate to the end of the pool; this will skip the first element in the pool initially, but that's fine
                            let listener_result = tokio::net::TcpListener::bind(&SocketAddr::new(
                                IpAddr::V6(Ipv6Addr::UNSPECIFIED),
                                self.ports_ip6[port_idx],
                            ))
                            .await;

                            if listener_result.is_ok() {
                                self.pos_ip6 = port_idx;
                                return Ok(listener_result.unwrap());
                            } else {
                                log::warn!(
                                    "unable to bind IPv6 TCP port {}",
                                    self.ports_ip6[port_idx]
                                );
                            }
                        }
                        for port_idx in 0..=self.pos_ip6 {
                            //circle back to where the search started
                            let listener_result = tokio::net::TcpListener::bind(&SocketAddr::new(
                                IpAddr::V6(Ipv6Addr::UNSPECIFIED),
                                self.ports_ip6[port_idx],
                            ))
                            .await;

                            if listener_result.is_ok() {
                                self.pos_ip6 = port_idx;
                                return Ok(listener_result.unwrap());
                            } else {
                                log::warn!(
                                    "unable to bind IPv6 TCP port {}",
                                    self.ports_ip6[port_idx]
                                );
                            }
                        }
                    }
                    return Err(Box::new(simple_error::simple_error!(
                        "unable to allocate IPv6 TCP port"
                    )));
                }
                IpAddr::V4(_) => {
                    if self.ports_ip4.is_empty() {
                        return Ok(tokio::net::TcpListener::bind(&SocketAddr::new(
                            IpAddr::V4(Ipv4Addr::UNSPECIFIED),
                            0,
                        ))
                        .await
                        .expect(format!("failed to bind OS-assigned IPv4 TCP socket").as_str()));
                    } else {
                        let _guard = self.lock_ip4.lock().unwrap();

                        for port_idx in (self.pos_ip4 + 1)..self.ports_ip4.len() {
                            //iterate to the end of the pool; this will skip the first element in the pool initially, but that's fine
                            let listener_result = tokio::net::TcpListener::bind(&SocketAddr::new(
                                IpAddr::V4(Ipv4Addr::UNSPECIFIED),
                                self.ports_ip4[port_idx],
                            ))
                            .await;
                            if listener_result.is_ok() {
                                self.pos_ip4 = port_idx;
                                return Ok(listener_result.unwrap());
                            } else {
                                log::warn!(
                                    "unable to bind IPv4 TCP port {}",
                                    self.ports_ip4[port_idx]
                                );
                            }
                        }
                        for port_idx in 0..=self.pos_ip4 {
                            //circle back to where the search started
                            let listener_result = tokio::net::TcpListener::bind(&SocketAddr::new(
                                IpAddr::V4(Ipv4Addr::UNSPECIFIED),
                                self.ports_ip4[port_idx],
                            ))
                            .await;
                            if listener_result.is_ok() {
                                self.pos_ip4 = port_idx;
                                return Ok(listener_result.unwrap());
                            } else {
                                log::warn!(
                                    "unable to bind IPv4 TCP port {}",
                                    self.ports_ip4[port_idx]
                                );
                            }
                        }
                    }
                    return Err(Box::new(simple_error::simple_error!(
                        "unable to allocate IPv4 TCP port"
                    )));
                }
            };
        }
    }

    pub struct KtlsReceiver {
        active: bool,
        test_definition: super::KtlsTestDefinition,
        stream_idx: u8,

        listener: Option<tokio::net::TcpListener>,
        stream: Option<tokio::net::TcpStream>,

        tls_acceptor: tokio_rustls::TlsAcceptor,
    }
    impl KtlsReceiver {
        pub async fn new(
            test_definition: super::KtlsTestDefinition,
            stream_idx: &u8,
            port_pool: &mut KtlsPortPool,
            peer_ip: &IpAddr,
        ) -> super::BoxResult<KtlsReceiver> {
            log::debug!("binding TCP listener for stream {}...", stream_idx);
            let listener: tokio::net::TcpListener = port_pool
                .bind(peer_ip)
                .await
                .expect(format!("failed to bind TCP socket").as_str());

            log::debug!(
                "bound TCP listener for stream {}: {}",
                stream_idx,
                listener.local_addr()?
            );

            let mut server_cert_der = Vec::new();
            let mut server_key_der = Vec::new();
            File::open("server_cert.der")
                .expect("Unable to open cert file")
                .read_to_end(&mut server_cert_der)
                .expect("Unable to read cert data");
            File::open("server_key.der")
                .expect("Unable to open key file")
                .read_to_end(&mut server_key_der)
                .expect("Unable to read key data");

            let server_cert = Certificate(server_cert_der);
            let server_key = PrivateKey(server_key_der);

            let mut tls_config = ServerConfig::builder()
                .with_cipher_suites(&[TLS13_AES_128_GCM_SHA256])
                .with_safe_default_kx_groups()
                .with_protocol_versions(&[&TLS13])
                .expect("incosistent cipher-suite and protocol-version")
                .with_no_client_auth()
                .with_single_cert(vec![server_cert], server_key)
                .expect("bad certificate/private key");

            tls_config.enable_secret_extraction = true; // for ktls
            tls_config.key_log = Arc::new(KeyLogFile::new());

            let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(tls_config));

            Ok(KtlsReceiver {
                active: true,
                test_definition: test_definition,
                stream_idx: stream_idx.to_owned(),

                listener: Some(listener),
                stream: None,

                tls_acceptor: acceptor,
            })
        }

        async fn process_connection(&mut self) -> super::BoxResult<tokio::net::TcpStream> {
            log::info!(
                "preparing to receive TCP stream {} connection...",
                self.stream_idx
            );

            let listener = self.listener.as_mut().unwrap();

            let start = Instant::now();

            while self.active {
                if start.elapsed() >= RECEIVE_TIMEOUT {
                    return Err(Box::new(simple_error::simple_error!(
                        "TCP listening for stream {} timed out",
                        self.stream_idx
                    )));
                }

                let result = tokio::time::timeout(POLL_TIMEOUT, listener.accept()).await;

                match result {
                    Ok(Ok((stream, address))) => {
                        log::info!(
                            "received TCP stream {} connection from {}",
                            self.stream_idx,
                            address
                        );
                        return Ok(stream);
                    }
                    Ok(Err(e)) => {
                        return Err(Box::new(e));
                    }
                    Err(_) => {
                        // Timeout occurred
                        log::info!("timeout occured");
                    }
                }
            }

            Err(Box::new(simple_error::simple_error!(
                "did not receive a connection"
            )))
        }

        pub async fn run_interval(
            &mut self,
        ) -> Option<super::BoxResult<Box<dyn super::IntervalResult + Sync + Send>>> {
            let mut bytes_received: u64 = 0;

            if self.stream.is_none() {
                //if still in the setup phase, receive the sender
                match self.process_connection().await {
                    Ok(stream) => {
                        self.stream = Some(stream);
                        //NOTE: the connection process consumes the test-header; account for those bytes
                        bytes_received += super::TEST_HEADER_SIZE as u64;
                    }
                    Err(e) => {
                        return Some(Err(e));
                    }
                }
                self.listener = None; //drop it, closing the socket
            }

            let mut stream_clone = Default::default();
            swap(&mut stream_clone, &mut self.stream);

            let stream = SpyStream(stream_clone.unwrap());
            let stream = CorkStream::new(stream);
            let stream = self.tls_acceptor.accept(stream).await.unwrap();
            let mut stream = ktls::config_ktls_server(stream).await.unwrap();

            let mut buf = vec![0_u8; self.test_definition.length];

            let start = Instant::now();

            while self.active {
                if start.elapsed() >= RECEIVE_TIMEOUT {
                    return Some(Err(Box::new(simple_error::simple_error!(
                        "TCP reception for stream {}",
                        self.stream_idx,
                    ))));
                }
                log::info!("ktls reading");
                match stream.read_exact(&mut buf).await.unwrap() {
                    packet_size => {
                        if packet_size == 0 {
                            //test's over
                            self.active = false; //HACK: can't call self.stop() because it's a double-borrow due to the unwrapped stream
                            break;
                        }

                        bytes_received += packet_size as u64;

                        let elapsed_time = start.elapsed();
                        if elapsed_time >= super::INTERVAL {
                            return Some(Ok(Box::new(super::TlsReceiveResult {
                                timestamp: super::get_unix_timestamp(),

                                stream_idx: self.stream_idx,

                                duration: elapsed_time.as_secs_f32(),

                                bytes_received: bytes_received,
                            })));
                        }
                    }
                }
            }
            if bytes_received > 0 {
                Some(Ok(Box::new(super::TlsReceiveResult {
                    timestamp: super::get_unix_timestamp(),

                    stream_idx: self.stream_idx,

                    duration: start.elapsed().as_secs_f32(),

                    bytes_received: bytes_received,
                })))
            } else {
                None
            }
        }

        pub fn get_port(&self) -> super::BoxResult<u16> {
            match &self.listener {
                Some(listener) => Ok(listener.local_addr()?.port()),
                None => match &self.stream {
                    Some(stream) => Ok(stream.local_addr()?.port()),
                    None => Err(Box::new(simple_error::simple_error!(
                        "no port currently bound"
                    ))),
                },
            }
        }

        pub fn get_idx(&self) -> u8 {
            self.stream_idx.to_owned()
        }

        pub fn stop(&mut self) {
            self.active = false;
        }
    }
}

pub mod sender {
    use std::fs::File;
    use std::io::Read;
    use std::mem::swap;
    use std::net::{IpAddr, SocketAddr};
    use std::os::unix::io::AsRawFd;
    use std::sync::Arc;
    use std::time::{Duration, Instant};

    use ktls::CorkStream;
    use tokio::io::AsyncWriteExt;
    use tokio_rustls::rustls::cipher_suite::TLS13_AES_128_GCM_SHA256;
    use tokio_rustls::rustls::version::TLS13;
    use tokio_rustls::rustls::{Certificate, ClientConfig, RootCertStore};

    use std::thread::sleep;

    use super::SpyStream;

    const CONNECT_TIMEOUT: Duration = Duration::from_secs(2);
    const WRITE_TIMEOUT: Duration = Duration::from_millis(50);
    const BUFFER_FULL_TIMEOUT: Duration = Duration::from_millis(1);

    pub struct KtlsSender {
        active: bool,
        test_definition: super::KtlsTestDefinition,
        stream_idx: u8,

        socket_addr: SocketAddr,
        stream: Option<tokio::net::TcpStream>,

        //the interval, in seconds, at which to send data
        send_interval: f32,

        remaining_duration: f32,
        staged_buffer: Vec<u8>,

        send_buffer: usize,
        no_delay: bool,

        tls_connector: tokio_rustls::TlsConnector,
    }

    impl KtlsSender {
        pub fn new(
            test_definition: super::KtlsTestDefinition,
            stream_idx: &u8,
            receiver_ip: &IpAddr,
            receiver_port: &u16,
            send_duration: &f32,
            send_interval: &f32,
            send_buffer: &usize,
            no_delay: &bool,
        ) -> super::BoxResult<KtlsSender> {
            let mut staged_buffer = vec![0_u8; test_definition.length];
            for i in super::TEST_HEADER_SIZE..(staged_buffer.len()) {
                //fill the packet with a fixed sequence
                staged_buffer[i] = (i % 256) as u8;
            }
            //embed the test ID
            staged_buffer[0..16].copy_from_slice(&test_definition.test_id);

            let mut server_cert_der = Vec::new();
            File::open("server_cert.der")
                .expect("Unable to open file")
                .read_to_end(&mut server_cert_der)
                .expect("Unable to read data");

            let server_cert = Certificate(server_cert_der);

            let mut root_certs = RootCertStore::empty();
            root_certs.add(&server_cert).unwrap();

            let config = ClientConfig::builder()
                .with_cipher_suites(&[TLS13_AES_128_GCM_SHA256])
                .with_safe_default_kx_groups()
                .with_protocol_versions(&[&TLS13])
                .expect("inconsistent cipher-suite/versions selected")
                .with_root_certificates(root_certs)
                .with_no_client_auth();

            

            let tls_connector = tokio_rustls::TlsConnector::from(Arc::new(config));

            Ok(KtlsSender {
                active: true,
                test_definition: test_definition,
                stream_idx: stream_idx.to_owned(),

                socket_addr: SocketAddr::new(*receiver_ip, *receiver_port),
                stream: None,

                send_interval: send_interval.to_owned(),

                remaining_duration: send_duration.to_owned(),
                staged_buffer: staged_buffer,

                send_buffer: send_buffer.to_owned(),
                no_delay: no_delay.to_owned(),

                tls_connector: tls_connector,
            })
        }

        fn process_connection(&mut self) -> super::BoxResult<tokio::net::TcpStream> {
            log::info!("preparing to connect TCP stream {}...", self.stream_idx);

            let raw_stream =
                match std::net::TcpStream::connect_timeout(&self.socket_addr, CONNECT_TIMEOUT) {
                    Ok(s) => s,
                    Err(e) => {
                        return Err(Box::new(simple_error::simple_error!(
                            "unable to connect stream {}: {}",
                            self.stream_idx,
                            e
                        )))
                    }
                };
            raw_stream.set_write_timeout(Some(WRITE_TIMEOUT))?;
            let stream = match tokio::net::TcpStream::from_std(raw_stream) {
                Ok(s) => s,
                Err(e) => {
                    return Err(Box::new(simple_error::simple_error!(
                        "unable to prepare TCP stream {}: {}",
                        self.stream_idx,
                        e
                    )))
                }
            };
            log::info!(
                "connected TCP stream {} to {}",
                self.stream_idx,
                stream.peer_addr()?
            );

            if self.no_delay {
                log::info!("setting no-delay...");
                stream.set_nodelay(true)?;
            }
            if !cfg!(windows) {
                //NOTE: features unsupported on Windows
                if self.send_buffer != 0 {
                    log::info!("setting send-buffer to {}...", self.send_buffer);
                    super::setsockopt(stream.as_raw_fd(), super::SndBuf, &self.send_buffer)?;
                }
            }

            Ok(stream)
        }

        pub async fn run_interval(
            &mut self,
        ) -> Option<super::BoxResult<Box<dyn super::IntervalResult + Sync + Send>>> {
            if self.stream.is_none() {
                //if still in the setup phase, connect to the receiver
                match self.process_connection() {
                    Ok(stream) => {
                        self.stream = Some(stream);
                    }
                    Err(e) => {
                        return Some(Err(e));
                    }
                }
            }

            log::info!("started ktls conversion");
            let ip_addr = &"localhost".to_string()[..];
            let server_name = ip_addr
                .try_into()
                .expect("IP address is not valid server name");
            // let stream = self.stream.as_mut().unwrap();
            let mut stream_clone = Default::default();
            swap(&mut stream_clone, &mut self.stream);
            let stream = SpyStream(stream_clone.expect("could not finish spy stream"));
            let stream = CorkStream::new(stream);
            let stream = self
                .tls_connector
                .connect(server_name, stream)
                .await
                .expect("finish tls connection");
            let mut stream = ktls::config_ktls_client(stream).await.expect("finish ktls config");
            log::info!("finished ktls conversion");

            let interval_duration = Duration::from_secs_f32(self.send_interval);
            let mut interval_iteration = 0;
            let bytes_to_send =
                ((self.test_definition.bandwidth as f32) * super::INTERVAL.as_secs_f32()) as i64;
            let mut bytes_to_send_remaining = bytes_to_send;
            let bytes_to_send_per_interval_slice =
                ((bytes_to_send as f32) * self.send_interval) as i64;
            let mut bytes_to_send_per_interval_slice_remaining = bytes_to_send_per_interval_slice;

            let mut sends_blocked: u64 = 0;
            let mut bytes_sent: u64 = 0;

            let cycle_start = Instant::now();

            while self.active && self.remaining_duration > 0.0 && bytes_to_send_remaining > 0 {
                let packet_start = Instant::now();
                log::info!("ktls writing");
                match stream.write_all(&mut self.staged_buffer).await.unwrap() {
                    //it doesn't matter if the whole thing couldn't be written, since it's just garbage data
                    empty => {
                        let packet_size = self.staged_buffer.len();
                        let bytes_written = packet_size as i64;
                        bytes_sent += packet_size as u64;
                        bytes_to_send_remaining -= bytes_written;
                        bytes_to_send_per_interval_slice_remaining -= bytes_written;

                        let elapsed_time = cycle_start.elapsed();
                        if elapsed_time >= super::INTERVAL {
                            self.remaining_duration -= packet_start.elapsed().as_secs_f32();

                            return Some(Ok(Box::new(super::TlsSendResult {
                                timestamp: super::get_unix_timestamp(),

                                stream_idx: self.stream_idx,

                                duration: elapsed_time.as_secs_f32(),

                                bytes_sent: bytes_sent,
                                sends_blocked: sends_blocked,
                            })));
                        }
                    } // Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                      //     //send-buffer is full
                      //     //nothing to do, but avoid burning CPU cycles
                      //     sleep(BUFFER_FULL_TIMEOUT);
                      //     sends_blocked += 1;
                      // }
                      // Err(e) => {
                      //     return Some(Err(Box::new(e)));
                      // }
                }

                if bytes_to_send_remaining <= 0 {
                    //interval's target is exhausted, so sleep until the end
                    let elapsed_time = cycle_start.elapsed();
                    if super::INTERVAL > elapsed_time {
                        sleep(super::INTERVAL - elapsed_time);
                    }
                } else if bytes_to_send_per_interval_slice_remaining <= 0 {
                    // interval subsection exhausted
                    interval_iteration += 1;
                    bytes_to_send_per_interval_slice_remaining = bytes_to_send_per_interval_slice;
                    let elapsed_time = cycle_start.elapsed();
                    let interval_endtime = interval_iteration * interval_duration;
                    if interval_endtime > elapsed_time {
                        sleep(interval_endtime - elapsed_time);
                    }
                }
                self.remaining_duration -= packet_start.elapsed().as_secs_f32();
            }
            if bytes_sent > 0 {
                Some(Ok(Box::new(super::TlsSendResult {
                    timestamp: super::get_unix_timestamp(),

                    stream_idx: self.stream_idx,

                    duration: cycle_start.elapsed().as_secs_f32(),

                    bytes_sent: bytes_sent,
                    sends_blocked: sends_blocked,
                })))
            } else {
                //indicate that the test is over by dropping the stream
                self.stream = None;
                None
            }
        }

        pub fn get_idx(&self) -> u8 {
            self.stream_idx.to_owned()
        }

        pub fn stop(&mut self) {
            self.active = false;
        }
    }
}

struct SpyStream<IO>(IO);

impl<IO> AsyncRead for SpyStream<IO>
where
    IO: AsyncRead,
{
    fn poll_read(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        let old_filled = buf.filled().len();
        let res = unsafe {
            let io = self.map_unchecked_mut(|s| &mut s.0);
            io.poll_read(cx, buf)
        };

        match &res {
            std::task::Poll::Ready(res) => match res {
                Ok(_) => {
                    let num_read = buf.filled().len() - old_filled;
                    log::debug!("SpyStream read {num_read} bytes",);
                }
                Err(e) => {
                    log::debug!("SpyStream read errored: {e}");
                }
            },
            std::task::Poll::Pending => {
                log::debug!("SpyStream read would've blocked")
            }
        }
        res
    }
}

impl<IO> AsyncWrite for SpyStream<IO>
where
    IO: AsyncWrite,
{
    fn poll_write(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<Result<usize, std::io::Error>> {
        let res = unsafe {
            let io = self.map_unchecked_mut(|s| &mut s.0);
            io.poll_write(cx, buf)
        };

        match &res {
            std::task::Poll::Ready(res) => match res {
                Ok(n) => {
                    log::debug!("SpyStream wrote {n} bytes");
                }
                Err(e) => {
                    log::debug!("SpyStream writing errored: {e}");
                }
            },
            std::task::Poll::Pending => {
                log::debug!("SpyStream writing would've blocked")
            }
        }
        res
    }

    fn poll_flush(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), std::io::Error>> {
        unsafe {
            let io = self.map_unchecked_mut(|s| &mut s.0);
            io.poll_flush(cx)
        }
    }

    fn poll_shutdown(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), std::io::Error>> {
        unsafe {
            let io = self.map_unchecked_mut(|s| &mut s.0);
            io.poll_shutdown(cx)
        }
    }
}

impl<IO> AsRawFd for SpyStream<IO>
where
    IO: AsRawFd,
{
    fn as_raw_fd(&self) -> RawFd {
        self.0.as_raw_fd()
    }
}
