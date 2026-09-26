use crate::error::TransportError;
use compio::BufResult;
use compio::buf::{IoBuf, IoBufMut, IoVectoredBuf};
use compio::io::{AsyncRead, AsyncWrite};
use compio::net::{TcpStream, UnixStream};
use error_stack::{Report, ResultExt};
use std::net::SocketAddr;
use std::path::Path;

use crate::net::vsock::{VStream, VsockTarget};

#[cfg(windows)]
use crate::net::npipe::NamedPipeStream;

#[derive(Clone)]
pub enum Conn {
    Tcp(TcpStream),
    Uds(UnixStream),
    #[cfg(windows)]
    Npipe(NamedPipeStream),
    Vsock(VStream),
}

#[derive(Debug, Clone, Copy)]
pub enum PeerIdentity {
    Pid { pid: u32 },
    Unknown,
}

impl Conn {
    pub async fn connect_tcp(addr: SocketAddr) -> Result<Self, Report<TransportError>> {
        TcpStream::connect(addr)
            .await
            .map(Self::Tcp)
            .change_context(TransportError::Connect)
            .attach(format!("tcp {addr}"))
    }

    pub async fn connect_uds(path: &Path) -> Result<Self, Report<TransportError>> {
        UnixStream::connect(path)
            .await
            .map(Self::Uds)
            .change_context(TransportError::Connect)
            .attach(format!("uds {}", path.display()))
    }

    #[cfg(windows)]
    pub async fn connect_npipe(name: &str) -> Result<Self, Report<TransportError>> {
        crate::net::npipe::connect(name)
            .await
            .map(Self::Npipe)
            .change_context(TransportError::Connect)
            .attach(format!("npipe {name}"))
    }

    pub async fn connect_vsock(
        target: VsockTarget,
        port: u32,
    ) -> Result<Self, Report<TransportError>> {
        VStream::connect(target, port)
            .await
            .map(Self::Vsock)
            .change_context(TransportError::Connect)
            .attach(format!("vsock port {port}"))
    }

    pub async fn connect_vsock_loopback(port: u32) -> Result<Self, Report<TransportError>> {
        VStream::connect_loopback(port)
            .await
            .map(Self::Vsock)
            .change_context(TransportError::Connect)
            .attach(format!("vsock loopback port {port}"))
    }

    pub fn kind(&self) -> &'static str {
        match self {
            Self::Tcp(_) => "tcp",
            Self::Uds(_) => "uds",
            #[cfg(windows)]
            Self::Npipe(_) => "npipe",
            Self::Vsock(_) => "vsock",
        }
    }

    pub fn peer_identity(&self) -> PeerIdentity {
        match self {
            #[cfg(windows)]
            Self::Npipe(NamedPipeStream::Server(server)) => npipe_client_pid(server),
            #[cfg(target_os = "linux")]
            Self::Uds(stream) => linux_uds_peer_pid(stream),
            _ => PeerIdentity::Unknown,
        }
    }
}

#[cfg(windows)]
fn npipe_client_pid(server: &compio::fs::named_pipe::NamedPipeServer) -> PeerIdentity {
    use compio::driver::AsRawFd;
    use windows::Win32::{GetNamedPipeClientProcessId, HANDLE};

    let mut pid = 0u32;
    // SAFETY: the handle is borrowed from the live pipe server; `pid` is a valid out-pointer.
    if unsafe { GetNamedPipeClientProcessId(HANDLE(server.as_raw_fd() as _), &mut pid) }.as_bool() {
        PeerIdentity::Pid { pid }
    } else {
        PeerIdentity::Unknown
    }
}

#[cfg(target_os = "linux")]
fn linux_uds_peer_pid(stream: &UnixStream) -> PeerIdentity {
    use std::os::fd::AsFd;

    match rustix::net::sockopt::socket_peercred(stream.as_fd()) {
        Ok(cred) => PeerIdentity::Pid {
            pid: cred.pid.as_raw_pid() as u32,
        },
        Err(_) => PeerIdentity::Unknown,
    }
}

impl AsyncRead for Conn {
    async fn read<B: IoBufMut>(&mut self, buf: B) -> BufResult<usize, B> {
        match self {
            Self::Tcp(s) => s.read(buf).await,
            Self::Uds(s) => s.read(buf).await,
            #[cfg(windows)]
            Self::Npipe(s) => s.read(buf).await,
            Self::Vsock(s) => s.read(buf).await,
        }
    }
}

impl AsyncWrite for Conn {
    async fn write<T: IoBuf>(&mut self, buf: T) -> BufResult<usize, T> {
        match self {
            Self::Tcp(s) => s.write(buf).await,
            Self::Uds(s) => s.write(buf).await,
            #[cfg(windows)]
            Self::Npipe(s) => s.write(buf).await,
            Self::Vsock(s) => s.write(buf).await,
        }
    }

    async fn write_vectored<T: IoVectoredBuf>(&mut self, buf: T) -> BufResult<usize, T> {
        match self {
            Self::Tcp(s) => s.write_vectored(buf).await,
            Self::Uds(s) => s.write_vectored(buf).await,
            #[cfg(windows)]
            Self::Npipe(s) => s.write_vectored(buf).await,
            Self::Vsock(s) => s.write_vectored(buf).await,
        }
    }

    async fn flush(&mut self) -> std::io::Result<()> {
        match self {
            Self::Tcp(s) => s.flush().await,
            Self::Uds(s) => s.flush().await,
            #[cfg(windows)]
            Self::Npipe(s) => s.flush().await,
            Self::Vsock(s) => s.flush().await,
        }
    }

    async fn shutdown(&mut self) -> std::io::Result<()> {
        match self {
            Self::Tcp(s) => s.shutdown().await,
            Self::Uds(s) => s.shutdown().await,
            #[cfg(windows)]
            Self::Npipe(s) => s.shutdown().await,
            Self::Vsock(s) => s.shutdown().await,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::net::Listener;

    #[cfg(windows)]
    #[compio::test]
    async fn npipe_server_peer_identity_is_os_reported_client_pid() {
        let name = format!("ogurpchik-peerid-test-{}", std::process::id());

        let listener = Listener::bind_npipe(&name).await.expect("bind failed");
        let accept = listener.accept();
        let connect = Conn::connect_npipe(&name);
        let (server, client) = futures::try_join!(accept, connect).expect("join failed");

        match server.peer_identity() {
            PeerIdentity::Pid { pid } => assert_eq!(pid, std::process::id()),
            PeerIdentity::Unknown => panic!("npipe server must see the client PID"),
        }
        assert!(matches!(client.peer_identity(), PeerIdentity::Unknown));
    }

    #[cfg(target_os = "linux")]
    #[compio::test]
    async fn uds_peer_identity_is_os_reported_peer_pid() {
        let path = std::env::temp_dir().join(format!("ogurpchik-peerid-test-{}.sock", std::process::id()));

        let listener = Listener::bind_uds(&path).await.expect("bind failed");
        let accept = listener.accept();
        let connect = Conn::connect_uds(&path);
        let (server, _client) = futures::try_join!(accept, connect).expect("join failed");

        match server.peer_identity() {
            PeerIdentity::Pid { pid } => assert_eq!(pid, std::process::id()),
            PeerIdentity::Unknown => panic!("uds on Linux must see the peer PID"),
        }
    }

    #[compio::test]
    async fn tcp_peer_identity_is_unknown() {
        let listener = Listener::bind_tcp("127.0.0.1:0".parse().unwrap())
            .await
            .expect("bind failed");
        let Listener::Tcp(inner) = &listener else {
            unreachable!()
        };
        let addr = inner.local_addr().expect("local_addr failed");

        let accept = listener.accept();
        let connect = Conn::connect_tcp(addr);
        let (server, client) = futures::try_join!(accept, connect).expect("join failed");

        assert!(matches!(server.peer_identity(), PeerIdentity::Unknown));
        assert!(matches!(client.peer_identity(), PeerIdentity::Unknown));
    }

    #[cfg(windows)]
    #[compio::test]
    async fn uds_peer_identity_is_unknown_on_windows() {
        let path = std::env::temp_dir().join(format!("ogurpchik-peerid-test-{}.sock", std::process::id()));

        let listener = Listener::bind_uds(&path).await.expect("bind failed");
        let accept = listener.accept();
        let connect = Conn::connect_uds(&path);
        let (server, _client) = futures::try_join!(accept, connect).expect("join failed");

        assert!(matches!(server.peer_identity(), PeerIdentity::Unknown));
    }
}
