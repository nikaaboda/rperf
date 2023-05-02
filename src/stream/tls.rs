extern crate nix;

// use nix::sys::socket::{setsockopt, sockopt::RcvBuf, sockopt::SndBuf};
use nix::sys::socket::{setsockopt, sockopt::RcvBuf};
use std::{
    os::fd::{AsRawFd, RawFd},
    sync::Arc,
};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::protocol::results::{
    get_unix_timestamp,
    IntervalResult,
    TcpReceiveResult,
    // get_unix_timestamp, IntervalResult, TcpReceiveResult, TcpSendResult,
};

use super::{parse_port_spec, TestStream, INTERVAL};

use std::error::Error;
type BoxResult<T> = Result<T, Box<dyn Error>>;

pub const TEST_HEADER_SIZE: usize = 16;

#[derive(Clone)]
pub struct TlsTestDefinition {
    //a UUID used to identify packets associated with this test
    pub test_id: [u8; 16],
    //bandwidth target, in bytes/sec
    pub bandwidth: u64,
    //the length of the buffer to exchange
    pub length: usize,
}

impl TlsTestDefinition {
    pub fn new(details: &serde_json::Value) -> super::BoxResult<TlsTestDefinition> {
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

        Ok(TlsTestDefinition {
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
    use std::io::Read;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
    use std::os::unix::io::AsRawFd;
    use std::sync::Mutex;
    use std::time::{Duration, Instant};

    use mio::net::{TcpListener, TcpStream};
    use mio::{Events, Poll, PollOpt, Ready, Token};
    // added for tls
    use ktls::CorkStream;
    use rcgen::generate_simple_self_signed;
    use rustls::{cipher_suite::TLS13_AES_128_GCM_SHA256, version::TLS13, ServerConfig};
    use std::sync::Arc;
    use tokio_rustls::TlsAcceptor;

    use crate::stream::tls::SpyStream;

    const POLL_TIMEOUT: Duration = Duration::from_millis(250);
    const RECEIVE_TIMEOUT: Duration = Duration::from_secs(3);

    pub struct TlsPortPool {
        pub ports_ip4: Vec<u16>,
        pub ports_ip6: Vec<u16>,
        pos_ip4: usize,
        pos_ip6: usize,
        lock_ip4: Mutex<u8>,
        lock_ip6: Mutex<u8>,
    }
    impl TlsPortPool {
        pub fn new(port_spec: String, port_spec6: String) -> TlsPortPool {
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

            TlsPortPool {
                ports_ip4: ports,
                pos_ip4: 0,
                lock_ip4: Mutex::new(0),

                ports_ip6: ports6,
                pos_ip6: 0,
                lock_ip6: Mutex::new(0),
            }
        }

        pub fn bind(&mut self, peer_ip: &IpAddr) -> super::BoxResult<TcpListener> {
            match peer_ip {
                IpAddr::V6(_) => {
                    if self.ports_ip6.is_empty() {
                        return Ok(TcpListener::bind(&SocketAddr::new(
                            IpAddr::V6(Ipv6Addr::UNSPECIFIED),
                            0,
                        ))
                        .expect(format!("failed to bind OS-assigned IPv6 TCP socket").as_str()));
                    } else {
                        let _guard = self.lock_ip6.lock().unwrap();

                        for port_idx in (self.pos_ip6 + 1)..self.ports_ip6.len() {
                            //iterate to the end of the pool; this will skip the first element in the pool initially, but that's fine
                            let listener_result = TcpListener::bind(&SocketAddr::new(
                                IpAddr::V6(Ipv6Addr::UNSPECIFIED),
                                self.ports_ip6[port_idx],
                            ));
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
                            let listener_result = TcpListener::bind(&SocketAddr::new(
                                IpAddr::V6(Ipv6Addr::UNSPECIFIED),
                                self.ports_ip6[port_idx],
                            ));
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
                        return Ok(TcpListener::bind(&SocketAddr::new(
                            IpAddr::V4(Ipv4Addr::UNSPECIFIED),
                            0,
                        ))
                        .expect(format!("failed to bind OS-assigned IPv4 TCP socket").as_str()));
                    } else {
                        let _guard = self.lock_ip4.lock().unwrap();

                        for port_idx in (self.pos_ip4 + 1)..self.ports_ip4.len() {
                            //iterate to the end of the pool; this will skip the first element in the pool initially, but that's fine
                            let listener_result = TcpListener::bind(&SocketAddr::new(
                                IpAddr::V4(Ipv4Addr::UNSPECIFIED),
                                self.ports_ip4[port_idx],
                            ));
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
                            let listener_result = TcpListener::bind(&SocketAddr::new(
                                IpAddr::V4(Ipv4Addr::UNSPECIFIED),
                                self.ports_ip4[port_idx],
                            ));
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

    pub struct TlsReceiver {
        active: bool,
        test_definition: super::TlsTestDefinition,
        stream_idx: u8,

        listener: Option<TcpListener>,
        acceptor: Option<TlsAcceptor>,
        stream: Option<TcpStream>,
        mio_poll_token: Token,
        mio_poll: Poll,

        receive_buffer: usize,
    }
    impl TlsReceiver {
        pub fn new(
            test_definition: super::TlsTestDefinition,
            stream_idx: &u8,
            port_pool: &mut TlsPortPool,
            peer_ip: &IpAddr,
            receive_buffer: &usize,
        ) -> super::BoxResult<TlsReceiver> {
            // ktls acceptor
            let subject_alt_names = vec!["localhost".to_string()];

            let cert = generate_simple_self_signed(subject_alt_names).unwrap();
            // println!("{}", cert.serialize_pem().unwrap());
            // println!("{}", cert.serialize_private_key_pem());

            let mut server_config = ServerConfig::builder()
                .with_cipher_suites(&[TLS13_AES_128_GCM_SHA256])
                .with_safe_default_kx_groups()
                .with_protocol_versions(&[&TLS13])
                .unwrap()
                .with_no_client_auth()
                .with_single_cert(
                    vec![rustls::Certificate(cert.serialize_der().unwrap())],
                    rustls::PrivateKey(cert.serialize_private_key_der()),
                )
                .unwrap();

            server_config.enable_secret_extraction = true;
            server_config.key_log = Arc::new(rustls::KeyLogFile::new());

            let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(server_config));

            log::debug!("binding TCP listener for stream {}...", stream_idx);
            let listener: TcpListener = port_pool
                .bind(peer_ip)
                .expect(format!("failed to bind TCP socket").as_str());
            log::debug!(
                "bound TCP listener for stream {}: {}",
                stream_idx,
                listener.local_addr()?
            );

            let mio_poll_token = Token(0);
            let mio_poll = Poll::new()?;

            Ok(TlsReceiver {
                active: true,
                test_definition: test_definition,
                stream_idx: stream_idx.to_owned(),

                listener: Some(listener),
                acceptor: Some(acceptor),
                stream: None,
                mio_poll_token: mio_poll_token,
                mio_poll: mio_poll,

                receive_buffer: receive_buffer.to_owned(),
            })
        }

        fn process_connection(&mut self) -> super::BoxResult<TcpStream> {
            log::debug!(
                "preparing to receive TCP stream {} connection...",
                self.stream_idx
            );

            let listener = self.listener.as_mut().unwrap();
            let acceptor = self.acceptor.as_mut().unwrap();

            let mio_token = Token(0);
            let poll = Poll::new()?;
            poll.register(listener, mio_token, Ready::readable(), PollOpt::edge())?;
            let mut events = Events::with_capacity(1);

            let start = Instant::now();

            while self.active {
                if start.elapsed() >= RECEIVE_TIMEOUT {
                    return Err(Box::new(simple_error::simple_error!(
                        "TCP listening for stream {} timed out",
                        self.stream_idx
                    )));
                }

                poll.poll(&mut events, Some(POLL_TIMEOUT))?;
                for event in events.iter() {
                    match event.token() {
                        _ => loop {
                            match listener.accept() {
                                Ok((stream, address)) => {
                                    log::debug!(
                                        "received TCP stream {} connection from {}",
                                        self.stream_idx,
                                        address
                                    );
                                    // why does spy stream not work here?
                                    let stream = SpyStream(stream);
                                    let stream = CorkStream::new(stream);

                                    let stream = acceptor.accept(stream).await.unwrap();
                                    log::debug!("Completed TLS handshake");

                                    let mut stream =
                                        ktls::config_ktls_server(stream).await.unwrap();
                                    log::debug!("Configured kTLS");

                                    let mut verification_stream = stream.try_clone()?;
                                    let mio_token2 = Token(0);
                                    let poll2 = Poll::new()?;
                                    poll2.register(
                                        &verification_stream,
                                        mio_token2,
                                        Ready::readable(),
                                        PollOpt::edge(),
                                    )?;

                                    let mut buffer = [0_u8; 16];
                                    let mut events2 = Events::with_capacity(1);
                                    poll2.poll(&mut events2, Some(RECEIVE_TIMEOUT))?;
                                    for event2 in events2.iter() {
                                        match event2.token() {
                                            _ => match verification_stream.read(&mut buffer) {
                                                Ok(_) => {
                                                    if buffer == self.test_definition.test_id {
                                                        log::debug!("validated TCP stream {} connection from {}", self.stream_idx, address);
                                                        if !cfg!(windows) {
                                                            //NOTE: features unsupported on Windows
                                                            if self.receive_buffer != 0 {
                                                                log::debug!("setting receive-buffer to {}...", self.receive_buffer);
                                                                super::setsockopt(
                                                                    stream.as_raw_fd(),
                                                                    super::RcvBuf,
                                                                    &self.receive_buffer,
                                                                )?;
                                                            }
                                                        }

                                                        self.mio_poll.register(
                                                            &stream,
                                                            self.mio_poll_token,
                                                            Ready::readable(),
                                                            PollOpt::edge(),
                                                        )?;
                                                        return Ok(stream);
                                                    }
                                                }
                                                Err(ref e)
                                                    if e.kind()
                                                        == std::io::ErrorKind::WouldBlock =>
                                                {
                                                    //client didn't provide anything
                                                    break;
                                                }
                                                Err(e) => {
                                                    return Err(Box::new(e));
                                                }
                                            },
                                        }
                                    }
                                    log::warn!(
                                        "could not validate TCP stream {} connection from {}",
                                        self.stream_idx,
                                        address
                                    );
                                }
                                Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
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
            Err(Box::new(simple_error::simple_error!(
                "did not receive a connection"
            )))
        }
    }
    impl super::TestStream for TlsReceiver {
        fn run_interval(
            &mut self,
        ) -> Option<super::BoxResult<Box<dyn super::IntervalResult + Sync + Send>>> {
            let mut bytes_received: u64 = 0;

            if self.stream.is_none() {
                //if still in the setup phase, receive the sender
                match self.process_connection() {
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
            let stream = self.stream.as_mut().unwrap();

            let mut events = Events::with_capacity(1); //only watching one socket
            let mut buf = vec![0_u8; self.test_definition.length];

            let peer_addr = match stream.peer_addr() {
                Ok(pa) => pa,
                Err(e) => return Some(Err(Box::new(e))),
            };
            let start = Instant::now();

            while self.active {
                if start.elapsed() >= RECEIVE_TIMEOUT {
                    return Some(Err(Box::new(simple_error::simple_error!(
                        "TCP reception for stream {} from {} timed out",
                        self.stream_idx,
                        peer_addr
                    ))));
                }

                log::trace!(
                    "awaiting TCP stream {} from {}...",
                    self.stream_idx,
                    peer_addr
                );
                let poll_result = self.mio_poll.poll(&mut events, Some(POLL_TIMEOUT));
                if poll_result.is_err() {
                    return Some(Err(Box::new(poll_result.unwrap_err())));
                }
                for event in events.iter() {
                    if event.token() == self.mio_poll_token {
                        loop {
                            match stream.read(&mut buf) {
                                Ok(packet_size) => {
                                    log::trace!(
                                        "received {} bytes in TCP stream {} from {}",
                                        packet_size,
                                        self.stream_idx,
                                        peer_addr
                                    );
                                    if packet_size == 0 {
                                        //test's over
                                        self.active = false; //HACK: can't call self.stop() because it's a double-borrow due to the unwrapped stream
                                        break;
                                    }

                                    bytes_received += packet_size as u64;

                                    let elapsed_time = start.elapsed();
                                    if elapsed_time >= super::INTERVAL {
                                        return Some(Ok(Box::new(super::TcpReceiveResult {
                                            timestamp: super::get_unix_timestamp(),

                                            stream_idx: self.stream_idx,

                                            duration: elapsed_time.as_secs_f32(),

                                            bytes_received: bytes_received,
                                        })));
                                    }
                                }
                                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                                    //receive timeout
                                    break;
                                }
                                Err(e) => {
                                    return Some(Err(Box::new(e)));
                                }
                            }
                        }
                    } else {
                        log::warn!("got event for unbound token: {:?}", event);
                    }
                }
            }
            if bytes_received > 0 {
                Some(Ok(Box::new(super::TcpReceiveResult {
                    timestamp: super::get_unix_timestamp(),

                    stream_idx: self.stream_idx,

                    duration: start.elapsed().as_secs_f32(),

                    bytes_received: bytes_received,
                })))
            } else {
                None
            }
        }

        fn get_port(&self) -> super::BoxResult<u16> {
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

        fn get_idx(&self) -> u8 {
            self.stream_idx.to_owned()
        }

        fn stop(&mut self) {
            self.active = false;
        }
    }
}

pub struct SpyStream<IO>(IO);

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
