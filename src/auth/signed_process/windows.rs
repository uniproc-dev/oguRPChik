use crate::auth::signed_process::verify_signed_file;
use crate::error::{HandshakeError, Result};
use error_stack::{Report, ResultExt};
use std::ffi::OsString;
use std::os::windows::ffi::OsStringExt;
use std::path::PathBuf;
use windows::Win32::{
    CloseHandle, FILETIME, GetProcessTimes, HANDLE, OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION,
    QueryFullProcessImageNameW,
};
use windows::core::PWSTR;

const PROCESS_NAME_WIN32: u32 = 0;

pub(crate) fn process_creation_time(pid: u32) -> Result<u64, HandshakeError> {
    ProcessHandle::open(pid)?.creation_time()
}

pub(crate) fn verify_process_image(pid: u32, public_key: &[u8]) -> Result<(), HandshakeError> {
    let handle = ProcessHandle::open(pid)?;
    let image_path = handle.image_path()?;
    verify_signed_file(&image_path, public_key)
}

struct ProcessHandle(HANDLE);

impl ProcessHandle {
    fn open(pid: u32) -> Result<Self, HandshakeError> {
        let handle = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION as u32, false, pid) };
        if handle.0.is_null() {
            return Err(Report::new(std::io::Error::last_os_error())
                .change_context(HandshakeError::SignedProcessVerificationFailed)
                .attach(format!("failed to open process {pid}")));
        }
        Ok(Self(handle))
    }

    fn image_path(&self) -> Result<PathBuf, HandshakeError> {
        let mut buf = vec![0u16; 32_768];
        let mut len = buf.len() as u32;
        unsafe {
            QueryFullProcessImageNameW(
                self.0,
                PROCESS_NAME_WIN32,
                PWSTR(buf.as_mut_ptr()),
                &mut len,
            )
        }
        .ok()
        .change_context(HandshakeError::SignedProcessVerificationFailed)
        .attach("failed to query process image path")?;
        Ok(PathBuf::from(OsString::from_wide(&buf[..len as usize])))
    }

    fn creation_time(&self) -> Result<u64, HandshakeError> {
        let zero = FILETIME {
            dwLowDateTime: 0,
            dwHighDateTime: 0,
        };
        let (mut creation, mut exit, mut kernel, mut user) = (zero, zero, zero, zero);
        unsafe { GetProcessTimes(self.0, &mut creation, &mut exit, &mut kernel, &mut user) }
            .ok()
            .change_context(HandshakeError::SignedProcessVerificationFailed)
            .attach("failed to query process times")?;
        Ok(((creation.dwHighDateTime as u64) << 32) | creation.dwLowDateTime as u64)
    }
}

impl Drop for ProcessHandle {
    fn drop(&mut self) {
        let _ = unsafe { CloseHandle(self.0) };
    }
}
