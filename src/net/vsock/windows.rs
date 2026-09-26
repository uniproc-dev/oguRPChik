use crate::net::vsock::VsockTarget;
use crate::net::vsock::utils::uuid_to_guid;
use compio::BufResult;
use compio::buf::{IntoInner, IoBuf, IoBufMut, IoVectoredBuf};
use compio::driver::op::{Accept, Connect, Recv, Send, SendVectored, BufResultExt};
use compio::driver::{AsFd, BorrowedFd};
use compio::io::{AsyncRead, AsyncWrite};
use compio::runtime::{Attacher, submit};
use socket2::{Domain, Protocol, SockAddr, SockAddrStorage, Socket, Type};
use std::io;
use std::os::windows::io::{AsRawSocket, FromRawSocket, OwnedSocket};
use windows::Win32::{
    ADDRESS_FAMILY, AF_HYPERV, SD_SEND, SO_UPDATE_ACCEPT_CONTEXT, SOCKADDR, SOCKET, SOCKET_ERROR,
    SOL_SOCKET, SOMAXCONN, bind, listen, setsockopt, shutdown,
};
use windows::core::GUID;

#[repr(C)]
#[allow(non_snake_case)]
pub(crate) struct SOCKADDR_HV {
    Family: ADDRESS_FAMILY,
    Reserved: u16,
    VmId: GUID,
    ServiceId: GUID,
}

pub(crate) const HV_PROTOCOL_RAW: i32 = 1;
pub(crate) const HV_GUID_ZERO: GUID = GUID::zeroed();
pub(crate) const HV_GUID_CHILDREN: GUID = GUID::from_u128(0x90db8b89_0d35_4f79_8ce9_49ea0ac8b7cd);
pub(crate) const HV_GUID_LOOPBACK: GUID = GUID::from_u128(0xe0e16197_dd56_4a10_9195_5ee7a155a838);
pub(crate) const HV_GUID_PARENT: GUID = GUID::from_u128(0xa42e7cda_d03f_480c_9cc2_a4de20abb878);
pub(crate) const HV_GUID_VSOCK_TEMPLATE: GUID =
    GUID::from_u128(0x00000000_facb_11e6_bd58_64006a7986d3);

#[derive(Clone)]
pub struct HvStream {
    inner: Attacher<OwnedSocket>,
}

impl HvStream {
    pub fn from_owned(owned: OwnedSocket) -> io::Result<Self> {
        Ok(Self {
            inner: Attacher::new(owned)?,
        })
    }

    pub fn from_raw(raw: u64) -> io::Result<Self> {
        let owned = unsafe { OwnedSocket::from_raw_socket(raw as _) };
        Self::from_owned(owned)
    }

    pub async fn connect(vm_guid: GUID, service_id: GUID) -> io::Result<Self> {
        let socket = create_hv_socket()?;

        let local_addr = create_hv_sockaddr(HV_GUID_ZERO, GUID::zeroed());
        unsafe {
            if bind(
                SOCKET(socket.as_raw_socket() as usize),
                &local_addr as *const _ as *const SOCKADDR,
                size_of::<SOCKADDR_HV>() as i32,
            ) == SOCKET_ERROR
            {
                return Err(io::Error::last_os_error());
            }
        }

        let attached = Attacher::new(OwnedSocket::from(socket))?;
        let remote_addr = create_hv_sockaddr(vm_guid, service_id);

        let mut storage = SockAddrStorage::zeroed();
        unsafe {
            std::ptr::copy_nonoverlapping(
                &remote_addr as *const _ as *const u8,
                &mut storage as *mut _ as *mut u8,
                size_of::<SOCKADDR_HV>(),
            );
        }

        let dest_addr = unsafe { SockAddr::new(storage, size_of::<SOCKADDR_HV>() as i32) };

        let op = Connect::new(HvHandle(attached.clone()), dest_addr);
        let BufResult(res, _) = submit(op).await;
        res?;

        Ok(Self { inner: attached })
    }
}

struct HvHandle(Attacher<OwnedSocket>);
impl AsFd for HvHandle {
    fn as_fd(&self) -> BorrowedFd<'_> {
        self.0.as_fd()
    }
}

impl AsyncRead for HvStream {
    async fn read<B: IoBufMut>(&mut self, buf: B) -> BufResult<usize, B> {
        let op = Recv::new(HvHandle(self.inner.clone()), buf, 0);
        let res = submit(op).await.into_inner();
        unsafe { res.map_advanced() }
    }
}

impl AsyncWrite for HvStream {
    async fn write<T: IoBuf>(&mut self, buf: T) -> BufResult<usize, T> {
        let op = Send::new(HvHandle(self.inner.clone()), buf, 0);
        submit(op).await.map_buffer(|op| op.into_inner())
    }

    async fn write_vectored<T: IoVectoredBuf>(&mut self, buf: T) -> BufResult<usize, T> {
        let op = SendVectored::new(HvHandle(self.inner.clone()), buf, 0);
        submit(op).await.map_buffer(|op| op.into_inner())
    }

    async fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }

    async fn shutdown(&mut self) -> io::Result<()> {
        let raw_socket = SOCKET(self.inner.as_raw_socket() as usize);
        unsafe {
            if shutdown(raw_socket, SD_SEND) == SOCKET_ERROR {
                return Err(io::Error::last_os_error());
            }
        }
        Ok(())
    }
}

pub struct HvListener {
    inner: Attacher<OwnedSocket>,
}

impl HvListener {
    pub async fn accept(&self) -> io::Result<(HvStream, SockAddr)> {
        let accept_socket = create_hv_socket()?;
        let op = Accept::new(HvHandle(self.inner.clone()), accept_socket);
        let BufResult(res, op) = submit(op).await;
        res?;

        let (accepted_owned, addr) = op.into_addr()?;

        unsafe {
            let listener_handle = (self.inner.as_raw_socket() as usize).to_ne_bytes();
            if setsockopt(
                SOCKET(accepted_owned.as_raw_socket() as usize),
                SOL_SOCKET,
                SO_UPDATE_ACCEPT_CONTEXT,
                Some(listener_handle.as_ptr().cast()),
                listener_handle.len() as i32,
            ) == SOCKET_ERROR
            {
                return Err(io::Error::last_os_error());
            }
        }

        Ok((HvStream::from_owned(accepted_owned.into())?, addr))
    }

    pub fn bind(target: VsockTarget, port: u32) -> io::Result<Self> {
        let socket = create_hv_socket()?;
        let raw_fd = SOCKET(socket.as_raw_socket() as usize);

        let vm_guid = match target {
            VsockTarget::Cid(_) => HV_GUID_CHILDREN,
            VsockTarget::Guid(u) => uuid_to_guid(u),
        };

        let hv_addr = create_hv_sockaddr(vm_guid, port.to_guid());

        unsafe {
            if bind(
                raw_fd,
                &hv_addr as *const _ as *const SOCKADDR,
                size_of::<SOCKADDR_HV>() as i32,
            ) == SOCKET_ERROR
            {
                return Err(io::Error::last_os_error());
            }
            if listen(raw_fd, SOMAXCONN) == SOCKET_ERROR {
                return Err(io::Error::last_os_error());
            }
        }

        Ok(Self {
            inner: Attacher::new(OwnedSocket::from(socket))?,
        })
    }
}

fn create_hv_socket() -> io::Result<Socket> {
    Socket::new(
        Domain::from(AF_HYPERV),
        Type::STREAM,
        Some(Protocol::from(HV_PROTOCOL_RAW)),
    )
}

fn create_hv_sockaddr(vm_guid: GUID, service_id: GUID) -> SOCKADDR_HV {
    SOCKADDR_HV {
        Family: ADDRESS_FAMILY(AF_HYPERV as u16),
        Reserved: 0,
        VmId: vm_guid,
        ServiceId: service_id,
    }
}

pub trait ToServiceId {
    fn to_guid(&self) -> GUID;
}

impl ToServiceId for u32 {
    fn to_guid(&self) -> GUID {
        let mut guid = HV_GUID_VSOCK_TEMPLATE;

        guid.data1 = *self;
        guid
    }
}
