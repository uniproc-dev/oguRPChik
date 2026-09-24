use compio::BufResult;
use compio::buf::{IntoInner, IoBuf, IoBufMut, IoVectoredBuf};
use compio::driver::SharedFd;
use compio::driver::op::{Accept, Connect, Recv, Send, SendVectored, BufResultExt};
use compio::io::{AsyncRead, AsyncWrite};
use compio::runtime::{Attacher, submit};
use socket2::{Domain, SockAddr, Socket, Type};
use std::io;
use std::os::fd::{AsFd, BorrowedFd};
use std::os::unix::io::{AsRawFd, FromRawFd, OwnedFd};
use tracing::{debug, error, instrument, trace};

#[derive(Clone)]
pub struct VsockStream {
    inner: Attacher<OwnedFd>,
}

impl VsockStream {
    #[instrument(level = "trace", skip_all, fields(cid = cid, port = port))]
    pub async fn connect(cid: u32, port: u32) -> io::Result<Self> {
        trace!("VsockStream: creating socket object");
        let socket = Socket::new(Domain::VSOCK, Type::STREAM, None).map_err(|e| {
            error!(error = %e, "Failed to create Socket object");
            e
        })?;

        let addr = SockAddr::vsock(cid, port);
        let fd = SharedFd::new(OwnedFd::from(socket));

        trace!("VsockStream: preparing connect operation");
        let op = Connect::new(fd.clone(), addr);

        trace!("VsockStream: submitting to proactor...");
        let BufResult(res, _) = submit(op).await;

        if let Err(ref e) = res {
            error!(error = %e, cid, port, "VsockStream: proactor submit returned error");
        } else {
            debug!(cid, port, "VsockStream: proactor connect successful");
        }

        res?;

        trace!("VsockStream: attaching file descriptor");
        let inner = Attacher::new(fd.try_unwrap().expect("have not strong reference"))?;

        Ok(Self { inner })
    }

    pub fn from_raw(fd: i32) -> io::Result<Self> {
        let owned = unsafe { OwnedFd::from_raw_fd(fd) };
        Ok(Self {
            inner: Attacher::new(owned)?,
        })
    }
}

struct VsockHandle(Attacher<OwnedFd>);

impl AsFd for VsockHandle {
    fn as_fd(&self) -> BorrowedFd<'_> {
        self.0.as_fd()
    }
}

impl AsyncRead for VsockStream {
    async fn read<B: IoBufMut>(&mut self, buf: B) -> BufResult<usize, B> {
        let op = Recv::new(VsockHandle(self.inner.clone()), buf, 0);
        let res = submit(op).await.into_inner();
        unsafe { res.map_advanced() }
    }
}

impl AsyncWrite for VsockStream {
    async fn write<T: IoBuf>(&mut self, buf: T) -> BufResult<usize, T> {
        let op = Send::new(VsockHandle(self.inner.clone()), buf, 0);
        submit(op).await.map_buffer(|op| op.into_inner())
    }

    async fn write_vectored<T: IoVectoredBuf>(&mut self, buf: T) -> BufResult<usize, T> {
        let op = SendVectored::new(VsockHandle(self.inner.clone()), buf, 0);
        submit(op).await.map_buffer(|op| op.into_inner())
    }
    async fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
    async fn shutdown(&mut self) -> io::Result<()> {
        unsafe {
            libc::shutdown(self.inner.as_raw_fd(), libc::SHUT_WR);
        }
        Ok(())
    }
}

pub struct VsockListener {
    inner: Attacher<OwnedFd>,
}

impl VsockListener {
    pub fn bind(port: u32) -> io::Result<Self> {
        Self::bind_internal(libc::VMADDR_CID_ANY, port)
    }

    pub fn bind_loopback(port: u32) -> io::Result<Self> {
        Self::bind_internal(libc::VMADDR_CID_LOCAL, port)
    }

    pub fn bind_internal(cid: u32, port: u32) -> io::Result<Self> {
        let socket = Socket::new(Domain::VSOCK, Type::STREAM, None)?;
        let addr = SockAddr::vsock(cid, port);
        socket.bind(&addr)?;
        socket.listen(128)?;
        Ok(Self {
            inner: Attacher::new(OwnedFd::from(socket))?,
        })
    }

    pub async fn accept(&self) -> io::Result<(VsockStream, SockAddr)> {
        loop {
            let op = Accept::new(VsockHandle(self.inner.clone()));

            let BufResult(res, op) = submit(op).await;

            match res {
                Ok(fd) => {
                    let raw_fd = fd as std::os::unix::io::RawFd;
                    let addr = op.into_addr();

                    let owned_fd = unsafe { OwnedFd::from_raw_fd(raw_fd) };

                    return Ok((
                        VsockStream {
                            inner: Attacher::new(owned_fd)?,
                        },
                        addr,
                    ));
                }
                Err(e) if e.kind() == io::ErrorKind::Interrupted => {
                    continue;
                }
                Err(e) => {
                    return Err(e);
                }
            }
        }
    }
}
