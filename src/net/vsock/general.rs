use crate::net::Splitable;
use crate::net::vsock::VsockTarget;
use compio::BufResult;
use compio::buf::{IoBuf, IoBufMut, IoVectoredBuf};
use compio::io::{AsyncRead, AsyncWrite};
use socket2::SockAddr;
use std::io;

#[derive(Clone)]
pub enum VStream {
    #[cfg(windows)]
    Hv(crate::net::vsock::windows::HvStream),

    #[cfg(unix)]
    Vsock(crate::net::vsock::linux::VsockStream),
}

impl Splitable for VStream {
    fn split(self) -> (Self, Self) {
        let clone = match &self {
            #[cfg(windows)]
            Self::Hv(s) => Self::Hv(s.clone()),
            #[cfg(unix)]
            Self::Vsock(s) => Self::Vsock(s.clone()),
        };
        (clone, self)
    }
}

impl VStream {
    pub async fn connect_loopback(port: u32) -> io::Result<Self> {
        #[cfg(unix)]
        {
            Self::connect(VsockTarget::Cid(libc::VMADDR_CID_LOCAL), port).await
        }
        #[cfg(windows)]
        {
            Self::connect(VsockTarget::Cid(1), port).await
        }
    }
    pub async fn connect(target: VsockTarget, port: u32) -> io::Result<Self> {
        #[cfg(unix)]
        {
            let cid = match target {
                VsockTarget::Cid(c) => c,
                VsockTarget::Guid(_) => {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "UUID not supported on Unix",
                    ));
                }
            };
            crate::net::vsock::linux::VsockStream::connect(cid, port)
                .await
                .map(Self::Vsock)
        }

        #[cfg(windows)]
        {
            use crate::net::vsock::utils::uuid_to_guid;
            use crate::net::vsock::windows::ToServiceId;
            let (vm_guid, service_id) = match target {
                VsockTarget::Cid(cid) => {
                    let g = match cid {
                        u32::MAX => crate::net::vsock::windows::HV_GUID_CHILDREN,
                        0 | 1 => crate::net::vsock::windows::HV_GUID_LOOPBACK,
                        2 => crate::net::vsock::windows::HV_GUID_PARENT,
                        _ => crate::net::vsock::windows::HV_GUID_CHILDREN,
                    };
                    (g, port.to_guid())
                }
                VsockTarget::Guid(u) => (uuid_to_guid(u), port.to_guid()),
            };

            crate::net::vsock::windows::HvStream::connect(vm_guid, service_id)
                .await
                .map(Self::Hv)
        }
    }
}

impl AsyncRead for VStream {
    async fn read<B: IoBufMut>(&mut self, buf: B) -> BufResult<usize, B> {
        match self {
            #[cfg(windows)]
            Self::Hv(s) => s.read(buf).await,

            #[cfg(unix)]
            Self::Vsock(s) => s.read(buf).await,
        }
    }
}

impl AsyncWrite for VStream {
    async fn write<T: IoBuf>(&mut self, buf: T) -> BufResult<usize, T> {
        match self {
            #[cfg(windows)]
            Self::Hv(s) => s.write(buf).await,

            #[cfg(unix)]
            Self::Vsock(s) => s.write(buf).await,
        }
    }

    async fn write_vectored<T: IoVectoredBuf>(&mut self, buf: T) -> BufResult<usize, T> {
        match self {
            #[cfg(windows)]
            Self::Hv(s) => s.write_vectored(buf).await,

            #[cfg(unix)]
            Self::Vsock(s) => s.write_vectored(buf).await,
        }
    }

    async fn flush(&mut self) -> io::Result<()> {
        match self {
            #[cfg(windows)]
            Self::Hv(s) => s.flush().await,

            #[cfg(unix)]
            Self::Vsock(s) => s.flush().await,
        }
    }

    async fn shutdown(&mut self) -> io::Result<()> {
        match self {
            #[cfg(windows)]
            Self::Hv(s) => s.shutdown().await,

            #[cfg(unix)]
            Self::Vsock(s) => s.shutdown().await,
        }
    }
}

pub enum VListener {
    #[cfg(windows)]
    Hv(crate::net::vsock::windows::HvListener),
    #[cfg(unix)]
    Vsock(crate::net::vsock::linux::VsockListener),
}

impl VListener {
    pub fn bind(target: VsockTarget, port: u32) -> io::Result<Self> {
        #[cfg(windows)]
        {
            Ok(Self::Hv(crate::net::vsock::windows::HvListener::bind(
                target, port,
            )?))
        }
        #[cfg(unix)]
        {
            let _ = target;
            Ok(Self::Vsock(
                crate::net::vsock::linux::VsockListener::bind(port)?,
            ))
        }
    }

    pub fn bind_loopback(port: u32) -> io::Result<Self> {
        #[cfg(windows)]
        {
            Ok(Self::Hv(crate::net::vsock::windows::HvListener::bind(
                VsockTarget::Cid(0),
                port,
            )?))
        }
        #[cfg(unix)]
        {
            Ok(Self::Vsock(
                crate::net::vsock::linux::VsockListener::bind_loopback(port)?,
            ))
        }
    }

    pub async fn accept(&self) -> io::Result<(VStream, SockAddr)> {
        match self {
            #[cfg(windows)]
            Self::Hv(l) => {
                let (stream, addr) = l.accept().await?;
                Ok((VStream::Hv(stream), addr))
            }
            #[cfg(unix)]
            Self::Vsock(l) => {
                let (stream, addr) = l.accept().await?;
                Ok((VStream::Vsock(stream), addr))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use compio::io::{AsyncReadExt, AsyncWriteExt};

    const TEST_PORT: u32 = 12345;

    #[compio::test]
    async fn test_stream_full_cycle() {
        let listener = VListener::bind_loopback(TEST_PORT).expect("Failed to bind listener");

        let client_task = async {
            let mut client = VStream::connect_loopback(TEST_PORT)
                .await
                .expect("Client failed to connect");

            let msg = b"hello from client";
            let BufResult(res, _) = client.write_all(msg).await;
            res.expect("Client write failed");

            let buf = vec![0u8; 17];
            let BufResult(res, buf) = client.read_exact(buf).await;
            res.expect("Client read failed");
            assert_eq!(&buf, b"hello from server");
        };

        let server_task = async {
            let (mut server_stream, _) = listener.accept().await.expect("Accept failed");

            let buf = vec![0u8; 17];
            let BufResult(res, buf) = server_stream.read_exact(buf).await;
            res.expect("Server read failed");
            assert_eq!(&buf, b"hello from client");

            let BufResult(res, _) = server_stream.write_all(b"hello from server").await;
            res.expect("Server write failed");
        };

        futures::join!(client_task, server_task);
    }

    #[compio::test]
    async fn test_stream_split() {
        let listener = VListener::bind_loopback(TEST_PORT + 1).expect("Bind failed");

        let client_fut = async {
            let stream = VStream::connect_loopback(TEST_PORT + 1).await.unwrap();
            let (mut reader, mut writer) = stream.split();

            writer.write_all(b"ping").await.0.unwrap();
            let buf = vec![0u8; 4];
            let BufResult(res, buf) = reader.read_exact(buf).await;
            res.expect("Split failed");
            assert_eq!(&buf, b"pong");
        };

        let server_fut = async {
            let (mut server, _) = listener.accept().await.unwrap();
            let buf = vec![0u8; 4];
            let BufResult(_res, buf) = server.read_exact(buf).await;
            assert_eq!(&buf, b"ping");
            server.write_all(b"pong").await.0.unwrap();
        };

        futures::join!(client_fut, server_fut);
    }
}
