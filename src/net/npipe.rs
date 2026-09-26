
use crate::net::Splitable;
use compio::buf::{BufResult, IoBuf, IoBufMut};
use compio::fs::named_pipe::{ClientOptions, NamedPipeClient, NamedPipeServer, ServerOptions};
use compio::io::{AsyncRead, AsyncWrite};
use futures::lock::Mutex;
use std::fmt::{Display, Formatter};
use std::io;
use std::sync::Arc;

#[derive(Debug, Clone)]
pub enum NamedPipeStream {
    Server(NamedPipeServer),
    Client(NamedPipeClient),
}

impl AsyncRead for NamedPipeStream {
    async fn read<B: IoBufMut>(&mut self, buf: B) -> BufResult<usize, B> {
        match self {
            Self::Server(stream) => stream.read(buf).await,
            Self::Client(stream) => stream.read(buf).await,
        }
    }
}

impl AsyncWrite for NamedPipeStream {
    async fn write<B: IoBuf>(&mut self, buf: B) -> BufResult<usize, B> {
        match self {
            Self::Server(stream) => stream.write(buf).await,
            Self::Client(stream) => stream.write(buf).await,
        }
    }

    async fn flush(&mut self) -> io::Result<()> {
        match self {
            Self::Server(stream) => stream.flush().await,
            Self::Client(stream) => stream.flush().await,
        }
    }

    async fn shutdown(&mut self) -> io::Result<()> {
        match self {
            Self::Server(stream) => stream.shutdown().await,
            Self::Client(stream) => stream.shutdown().await,
        }
    }
}

impl Splitable for NamedPipeStream {
    fn split(self) -> (Self, Self) {
        (self.clone(), self)
    }
}

#[derive(Debug, Clone)]
pub struct NamedPipePath(String);

impl NamedPipePath {
    pub fn new(path: impl Into<String>) -> Self {
        let path = path.into();
        if path.starts_with(r"\\.\pipe\") {
            Self(path)
        } else {
            Self(format!(r"\\.\pipe\{}", path.trim_start_matches('\\')))
        }
    }
}

impl Display for NamedPipePath {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

pub struct NamedPipeAcceptor {
    path: NamedPipePath,
    current: Arc<Mutex<NamedPipeServer>>,
}

/// Security descriptor applied to every pipe instance we create.
///
/// A privileged server (an agent that controls processes or services must run
/// elevated) otherwise produces a pipe that its own unprivileged client cannot
/// open at all. Two separate things block it, and both are handled here:
///
/// - `D:` - SYSTEM, Administrators and the account running the server get full
///   control; authenticated users get only read/write, which is what
///   `CreateFile` on the client side needs. They deliberately do *not* get
///   `GA`: full control carries `FILE_CREATE_PIPE_INSTANCE`, which would let
///   any local user stand up another instance of the same pipe and intercept
///   connections meant for the real server.
///
///   The server's own account has to be named explicitly (`{sid}` below). Being
///   the object's owner is not enough - implicit owner rights are only
///   `READ_CONTROL | WRITE_DAC`, not instance creation - so an unelevated
///   server would otherwise match nothing but the `AU` ACE and fail to open its
///   second pipe instance.
/// - `S:(ML;;NW;;;ME)` - the mandatory label. This is the part that actually
///   bites: a kernel object inherits its creator's integrity level, and the
///   default `no-write-up` policy denies a medium-integrity client the write
///   access a pipe connection requires. Lowering the label to medium is what
///   lets a normal desktop app connect to an elevated agent.
///
/// Widening the DACL moves the security boundary onto the handshake, which is
/// why a server exposing anything privileged should not be run with
/// `HandshakeMode::version_only`.
#[cfg(windows)]
/// File rights (`FA`/`FRFW`), not generic ones (`GA`/`GRGW`): a pipe is a
/// file-like object, and generic bits placed in an ACL this way are stored
/// verbatim rather than mapped to concrete rights, so an access check for
/// `FILE_CREATE_PIPE_INSTANCE` never matches them.
const PIPE_SDDL_TEMPLATE: &str = "D:(A;;FA;;;SY)(A;;FA;;;BA)(A;;FA;;;{sid})(A;;FRFW;;;AU)S:(ML;;NW;;;ME)";

/// SID of the account this process runs as, in SDDL string form.
#[cfg(windows)]
fn current_user_sid() -> io::Result<String> {
    use windows::Win32::{
        ConvertSidToStringSidW, GetCurrentProcess, GetTokenInformation, HANDLE, LocalFree,
        OpenProcessToken, TOKEN_QUERY, TOKEN_USER, TokenUser,
    };

    let mut token = HANDLE::default();
    // SAFETY: `GetCurrentProcess` returns a pseudo-handle that needs no close;
    // `token` is a valid out-pointer.
    unsafe {
        OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY as u32, &mut token)
            .ok()
            .map_err(|e| io::Error::other(format!("failed to open the process token: {e}")))?;
    }
    let _token_guard = HandleGuard(token);

    // First call is the size probe; it is expected to fail with
    // ERROR_INSUFFICIENT_BUFFER, so only `len` is of interest.
    let mut len = 0u32;
    // SAFETY: passing a null buffer with zero length is the documented way to
    // ask for the required size.
    unsafe {
        let _ = GetTokenInformation(token, TokenUser, None, 0, &mut len);
    }
    if len == 0 {
        return Err(io::Error::other("token user information reported zero size"));
    }

    let mut buffer = vec![0u8; len as usize];
    // SAFETY: `buffer` is `len` bytes long, which is what the probe asked for.
    unsafe {
        GetTokenInformation(
            token,
            TokenUser,
            Some(buffer.as_mut_ptr().cast()),
            len,
            &mut len,
        )
        .ok()
        .map_err(|e| io::Error::other(format!("failed to read the token user: {e}")))?;
    }

    // SAFETY: on success the buffer holds a TOKEN_USER whose SID points inside
    // that same allocation, which is alive for the rest of this function.
    let sid = unsafe { (*buffer.as_ptr().cast::<TOKEN_USER>()).User.Sid };

    let mut raw = windows::core::PWSTR::null();
    // SAFETY: `sid` is valid as above; on success the callee allocates the
    // string with LocalAlloc, freed below.
    unsafe {
        ConvertSidToStringSidW(sid, &mut raw)
            .ok()
            .map_err(|e| io::Error::other(format!("failed to stringify the user SID: {e}")))?;
    }
    // SAFETY: `raw` is a NUL-terminated wide string owned by us until LocalFree.
    let text = unsafe { raw.to_string() }
        .map_err(|e| io::Error::other(format!("user SID is not valid UTF-16: {e}")))?;
    // SAFETY: `raw` came from ConvertSidToStringSidW and is unused afterwards.
    unsafe {
        let _ = LocalFree(HANDLE(raw.0.cast()));
    }
    Ok(text)
}

#[cfg(windows)]
struct HandleGuard(windows::Win32::HANDLE);

#[cfg(windows)]
impl Drop for HandleGuard {
    fn drop(&mut self) {
        // SAFETY: the handle came from OpenProcessToken and is not used after
        // this point.
        unsafe {
            let _ = windows::Win32::CloseHandle(self.0);
        }
    }
}

/// Applies [`PIPE_SDDL`] to an already-created pipe instance.
///
/// Done after creation rather than through `SECURITY_ATTRIBUTES` because that
/// is the route `compio` supports: it hands out `write_dac`/`write_owner` on
/// the open mode and expects `SetSecurityInfo` on the resulting handle.
#[cfg(windows)]
fn apply_pipe_security(server: &NamedPipeServer) -> io::Result<()> {
    use compio::driver::AsRawFd;
    use windows::Win32::{
        ACL, ConvertStringSecurityDescriptorToSecurityDescriptorW, DACL_SECURITY_INFORMATION,
        GetSecurityDescriptorDacl, GetSecurityDescriptorSacl, HANDLE, LABEL_SECURITY_INFORMATION,
        LocalFree, PSECURITY_DESCRIPTOR, SDDL_REVISION_1, SE_KERNEL_OBJECT, SECURITY_INFORMATION,
        SetSecurityInfo,
    };
    use windows::core::HSTRING;

    let sddl = HSTRING::from(PIPE_SDDL_TEMPLATE.replace("{sid}", &current_user_sid()?));
    let mut descriptor = PSECURITY_DESCRIPTOR::default();

    // SAFETY: `sddl` is a valid NUL-terminated wide string that outlives the
    // call; `descriptor` is a valid out-pointer. On success the callee
    // allocates with LocalAlloc, freed below.
    unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            &sddl,
            SDDL_REVISION_1 as u32,
            &mut descriptor,
            None,
        )
        .ok()
        .map_err(|e| io::Error::other(format!("failed to parse the pipe SDDL: {e}")))?;
    }

    let result = (|| -> io::Result<()> {
        let mut dacl: *mut ACL = std::ptr::null_mut();
        let mut dacl_present = false.into();
        let mut defaulted = false.into();
        // SAFETY: `descriptor` came from a successful conversion above; all
        // out-pointers are valid for the duration of the call.
        unsafe {
            GetSecurityDescriptorDacl(descriptor, &mut dacl_present, &mut dacl, &mut defaulted)
                .ok()
                .map_err(|e| io::Error::other(format!("failed to read the pipe DACL: {e}")))?;
        }

        let mut sacl: *mut ACL = std::ptr::null_mut();
        let mut sacl_present = false.into();
        // SAFETY: as above. The SACL here carries only the mandatory label.
        unsafe {
            GetSecurityDescriptorSacl(descriptor, &mut sacl_present, &mut sacl, &mut defaulted)
                .ok()
                .map_err(|e| io::Error::other(format!("failed to read the pipe label: {e}")))?;
        }

        let handle = HANDLE(server.as_raw_fd() as _);

        // Applied as two calls rather than one so a failure says which of the
        // two it was - they need different rights (WRITE_DAC vs WRITE_OWNER)
        // and fail for entirely different reasons.
        // SAFETY: the handle is borrowed from the live pipe server, and the ACL
        // pointer borrows from `descriptor`, which is still alive here.
        let status = unsafe {
            SetSecurityInfo(
                handle,
                SE_KERNEL_OBJECT,
                SECURITY_INFORMATION(DACL_SECURITY_INFORMATION as u32),
                None,
                None,
                Some(dacl.cast_const()),
                None,
            )
        };
        if status != 0 {
            return Err(io::Error::other(format!(
                "failed to set the pipe DACL: {}",
                io::Error::from_raw_os_error(status as i32)
            )));
        }

        // SAFETY: as above; `sacl` carries only the mandatory label.
        let status = unsafe {
            SetSecurityInfo(
                handle,
                SE_KERNEL_OBJECT,
                SECURITY_INFORMATION(LABEL_SECURITY_INFORMATION as u32),
                None,
                None,
                None,
                Some(sacl.cast_const()),
            )
        };
        if status != 0 {
            return Err(io::Error::other(format!(
                "failed to set the pipe integrity label: {}",
                io::Error::from_raw_os_error(status as i32)
            )));
        }
        Ok(())
    })();

    // SAFETY: `descriptor` was allocated by the conversion call above and is
    // not referenced past this point.
    unsafe {
        let _ = LocalFree(HANDLE(descriptor.0));
    }

    result
}

impl NamedPipeAcceptor {
    fn create_server(path: &NamedPipePath, first_instance: bool) -> io::Result<NamedPipeServer> {
        let mut options = ServerOptions::new();
        options.first_pipe_instance(first_instance);

        if !first_instance {
            // Only the first instance carries the security work. The descriptor
            // belongs to the pipe, not to an instance, so setting it once is
            // enough - and asking for WRITE_DAC/WRITE_OWNER here would actively
            // break things: those rights are also access-checked against the
            // existing pipe when opening a further instance, and that check
            // fails, so every `accept` after the first would die with
            // ERROR_ACCESS_DENIED.
            return options.create(&path.0);
        }

        // Needed by `apply_pipe_security`: WRITE_DAC to replace the DACL,
        // WRITE_OWNER to lower the mandatory label.
        options.write_dac(true);
        options.write_owner(true);
        let server = options.create(&path.0)?;
        apply_pipe_security(&server)?;
        Ok(server)
    }

    pub async fn bind(path: impl Into<String>) -> io::Result<Self> {
        let path = NamedPipePath::new(path);
        let server = Self::create_server(&path, true)?;
        Ok(Self {
            path,
            current: Arc::new(Mutex::new(server)),
        })
    }

    pub fn local_addr(&self) -> impl Display {
        self.path.clone()
    }

    pub async fn accept(&self) -> io::Result<NamedPipeStream> {
        let connected = {
            let mut guard = self.current.lock().await;
            let connected = guard.clone();
            let next = Self::create_server(&self.path, false)?;
            *guard = next;
            connected
        };

        connected.connect().await?;
        Ok(NamedPipeStream::Server(connected))
    }
}

pub async fn connect(path: impl Into<String>) -> io::Result<NamedPipeStream> {
    let path = NamedPipePath::new(path);
    ClientOptions::new()
        .open(&path.0)
        .await
        .map(NamedPipeStream::Client)
}

#[cfg(test)]
mod tests {
    use super::*;
    use compio::io::{AsyncReadExt, AsyncWriteExt};

    fn pipe_name(name: &str) -> String {
        format!("ogurpchik-net-test-{}-{}", std::process::id(), name)
    }

    #[compio::test]
    async fn test_named_pipe_roundtrip() {
        let acceptor = NamedPipeAcceptor::bind(pipe_name("roundtrip"))
            .await
            .expect("bind failed");
        let endpoint = acceptor.local_addr().to_string();

        let accept_task = compio::runtime::spawn(async move {
            let mut stream = acceptor.accept().await.expect("accept failed");
            let BufResult(res, buf) = stream.read_exact(vec![0u8; 4]).await;
            res.expect("server read failed");
            assert_eq!(buf, b"ping");
            let BufResult(res, _) = stream.write_all(b"pong").await;
            res.expect("server write failed");
        });

        let mut client = connect(endpoint).await.expect("connect failed");
        let BufResult(res, _) = client.write_all(b"ping").await;
        res.expect("client write failed");
        let BufResult(res, buf) = client.read_exact(vec![0u8; 4]).await;
        res.expect("client read failed");
        assert_eq!(buf, b"pong");

        accept_task.await.unwrap();
    }

    #[compio::test]
    async fn test_named_pipe_reuses_listener() {
        let acceptor = NamedPipeAcceptor::bind(pipe_name("reuse"))
            .await
            .expect("bind failed");
        let endpoint = acceptor.local_addr().to_string();

        for expected in [b"one1", b"two2"] {
            let accept_future = acceptor.accept();
            let connect_future = connect(endpoint.clone());
            let (mut server_stream, mut client_stream) =
                futures::try_join!(accept_future, connect_future).expect("join failed");

            let BufResult(res, _) = client_stream.write_all(expected.as_slice()).await;
            res.expect("client write failed");
            let BufResult(res, buf) = server_stream.read_exact(vec![0u8; expected.len()]).await;
            res.expect("server read failed");
            assert_eq!(buf.as_slice(), expected.as_slice());
        }
    }
}
