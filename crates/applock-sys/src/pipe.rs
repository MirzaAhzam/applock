//! Local-only Windows named pipe server and client with explicit ACLs and PID verification.

use std::ptr;

use windows_sys::Win32::Foundation::{
    CloseHandle, GetLastError, LocalFree, ERROR_PIPE_CONNECTED, GENERIC_READ, GENERIC_WRITE,
    HANDLE, HLOCAL, INVALID_HANDLE_VALUE,
};
use windows_sys::Win32::Security::Authorization::ConvertStringSecurityDescriptorToSecurityDescriptorW;
use windows_sys::Win32::Security::{PSECURITY_DESCRIPTOR, SECURITY_ATTRIBUTES};
use windows_sys::Win32::Storage::FileSystem::{
    CreateFileW, FlushFileBuffers, ReadFile, WriteFile, FILE_ATTRIBUTE_NORMAL, OPEN_EXISTING,
    PIPE_ACCESS_DUPLEX,
};
use windows_sys::Win32::System::Pipes::{
    ConnectNamedPipe, CreateNamedPipeW, DisconnectNamedPipe, GetNamedPipeClientProcessId,
    WaitNamedPipeW, PIPE_READMODE_MESSAGE, PIPE_REJECT_REMOTE_CLIENTS, PIPE_TYPE_MESSAGE,
    PIPE_WAIT,
};

use crate::{process::query_image_path, to_wide_null, WinError};

/// Default local named pipe path for `AppLock` IPC.
pub const PIPE_NAME: &str = r"\\.\pipe\AppLockIpcV1";

const MAX_FRAME_BYTES: usize = 16 * 1024;
const SDDL_PIPE_ACL: &str = "D:(A;;GA;;;SY)(A;;GA;;;BA)(A;;GRGW;;;AU)";

/// Verified identity of a connected named-pipe client.
#[derive(Debug, Clone)]
pub struct ClientIdentity {
    /// Client process ID reported by the kernel.
    pub pid: u32,
    /// Full executable path of the client process.
    pub image_path: String,
}

/// Named-pipe server instance with an explicit local-only ACL.
pub struct PipeServer {
    handle: HANDLE,
}

impl PipeServer {
    /// Creates a new named-pipe server instance at `pipe_name`.
    ///
    /// # Errors
    /// Returns `WinError` if ACL creation or `CreateNamedPipeW` fails.
    pub fn create(pipe_name: &str) -> Result<Self, WinError> {
        let pipe_wide = to_wide_null(pipe_name);
        let sddl_wide = to_wide_null(SDDL_PIPE_ACL);
        let mut sd: PSECURITY_DESCRIPTOR = ptr::null_mut();

        // SAFETY: `ConvertStringSecurityDescriptorToSecurityDescriptorW` allocates `sd`,
        // which is freed via `LocalFree` right after `CreateNamedPipeW`.
        unsafe {
            let ok_sd = ConvertStringSecurityDescriptorToSecurityDescriptorW(
                sddl_wide.as_ptr(),
                1,
                &raw mut sd,
                ptr::null_mut(),
            );
            if ok_sd == 0 {
                return Err(WinError {
                    code: GetLastError(),
                    context: "ConvertStringSecurityDescriptorToSecurityDescriptorW",
                });
            }

            let mut sa = SECURITY_ATTRIBUTES {
                nLength: u32::try_from(std::mem::size_of::<SECURITY_ATTRIBUTES>()).unwrap_or(0),
                lpSecurityDescriptor: sd,
                bInheritHandle: 0,
            };

            let buf_size = u32::try_from(MAX_FRAME_BYTES).unwrap_or(16 * 1024);
            let handle = CreateNamedPipeW(
                pipe_wide.as_ptr(),
                PIPE_ACCESS_DUPLEX,
                PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS,
                16,
                buf_size,
                buf_size,
                5000,
                &raw mut sa,
            );
            let err = GetLastError();
            LocalFree(sd as HLOCAL);

            if handle == INVALID_HANDLE_VALUE || handle.is_null() {
                return Err(WinError {
                    code: err,
                    context: "CreateNamedPipeW",
                });
            }
            Ok(Self { handle })
        }
    }

    /// Blocks until a client connects and returns its kernel-verified PID and image path.
    ///
    /// # Errors
    /// Returns `WinError` if connecting or querying client identity fails.
    pub fn accept(&self) -> Result<ClientIdentity, WinError> {
        // SAFETY: `self.handle` is a valid named-pipe handle.
        unsafe {
            let ok = ConnectNamedPipe(self.handle, ptr::null_mut());
            if ok == 0 {
                let err = GetLastError();
                if err != ERROR_PIPE_CONNECTED {
                    return Err(WinError {
                        code: err,
                        context: "ConnectNamedPipe",
                    });
                }
            }
            let mut pid: u32 = 0;
            if GetNamedPipeClientProcessId(self.handle, &raw mut pid) == 0 {
                let err = GetLastError();
                let _ = DisconnectNamedPipe(self.handle);
                return Err(WinError {
                    code: err,
                    context: "GetNamedPipeClientProcessId",
                });
            }
            let image_path = query_image_path(pid).unwrap_or_default();
            Ok(ClientIdentity { pid, image_path })
        }
    }

    /// Reads one bounded message frame from the connected client.
    ///
    /// # Errors
    /// Returns `WinError` if `ReadFile` fails.
    pub fn read_frame(&self) -> Result<Vec<u8>, WinError> {
        read_pipe_frame(self.handle)
    }

    /// Writes one bounded message frame to the connected client and flushes.
    ///
    /// # Errors
    /// Returns `WinError` if `WriteFile` fails.
    pub fn write_frame(&self, data: &[u8]) -> Result<(), WinError> {
        write_pipe_frame(self.handle, data)
    }

    /// Disconnects the current client so the pipe can accept the next connection.
    pub fn disconnect(&self) {
        // SAFETY: `self.handle` is a valid named-pipe handle.
        unsafe {
            let _ = FlushFileBuffers(self.handle);
            let _ = DisconnectNamedPipe(self.handle);
        }
    }
}

impl Drop for PipeServer {
    fn drop(&mut self) {
        // SAFETY: `self.handle` is owned by `PipeServer` and closed once on drop.
        unsafe {
            let _ = CloseHandle(self.handle);
        }
    }
}

/// Client connection to the `AppLock` named pipe.
pub struct PipeClient {
    handle: HANDLE,
}

impl PipeClient {
    /// Connects to `pipe_name`, waiting up to `timeout_ms` if busy.
    ///
    /// # Errors
    /// Returns `WinError` if the pipe cannot be opened.
    pub fn connect(pipe_name: &str, timeout_ms: u32) -> Result<Self, WinError> {
        let pipe_wide = to_wide_null(pipe_name);
        // SAFETY: `CreateFileW` opens an existing local named pipe handle.
        unsafe {
            let _ = WaitNamedPipeW(pipe_wide.as_ptr(), timeout_ms);
            let handle = CreateFileW(
                pipe_wide.as_ptr(),
                GENERIC_READ | GENERIC_WRITE,
                0,
                ptr::null(),
                OPEN_EXISTING,
                FILE_ATTRIBUTE_NORMAL,
                ptr::null_mut(),
            );
            if handle == INVALID_HANDLE_VALUE || handle.is_null() {
                return Err(WinError {
                    code: GetLastError(),
                    context: "CreateFileW(pipe)",
                });
            }
            Ok(Self { handle })
        }
    }

    /// Writes one bounded message frame to the server.
    ///
    /// # Errors
    /// Returns `WinError` if `WriteFile` fails.
    pub fn write_frame(&self, data: &[u8]) -> Result<(), WinError> {
        write_pipe_frame(self.handle, data)
    }

    /// Reads one bounded message frame from the server.
    ///
    /// # Errors
    /// Returns `WinError` if `ReadFile` fails.
    pub fn read_frame(&self) -> Result<Vec<u8>, WinError> {
        read_pipe_frame(self.handle)
    }
}

impl Drop for PipeClient {
    fn drop(&mut self) {
        // SAFETY: `self.handle` is owned by `PipeClient` and closed once on drop.
        unsafe {
            let _ = CloseHandle(self.handle);
        }
    }
}

fn read_pipe_frame(handle: HANDLE) -> Result<Vec<u8>, WinError> {
    let mut buf = vec![0_u8; MAX_FRAME_BYTES];
    let mut bytes_read: u32 = 0;
    let buf_len = u32::try_from(buf.len()).unwrap_or(16 * 1024);
    // SAFETY: `buf` is valid for `buf_len` bytes during `ReadFile`.
    unsafe {
        let ok = ReadFile(
            handle,
            buf.as_mut_ptr(),
            buf_len,
            &raw mut bytes_read,
            ptr::null_mut(),
        );
        if ok == 0 {
            return Err(WinError {
                code: GetLastError(),
                context: "ReadFile(pipe)",
            });
        }
    }
    buf.truncate(usize::try_from(bytes_read).unwrap_or(0));
    Ok(buf)
}

fn write_pipe_frame(handle: HANDLE, data: &[u8]) -> Result<(), WinError> {
    let len = u32::try_from(data.len()).map_err(|_| WinError {
        code: 87,
        context: "write_pipe_frame(length)",
    })?;
    let mut written: u32 = 0;
    // SAFETY: `data` is valid for `len` bytes during `WriteFile`.
    unsafe {
        let ok = WriteFile(
            handle,
            data.as_ptr(),
            len,
            &raw mut written,
            ptr::null_mut(),
        );
        if ok == 0 {
            return Err(WinError {
                code: GetLastError(),
                context: "WriteFile(pipe)",
            });
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pipe_server_and_client_round_trip() -> Result<(), WinError> {
        let name = format!(r"\\.\pipe\AppLockTestPipe_{}", std::process::id());
        let server = PipeServer::create(&name)?;
        let name_clone = name;
        let client_thread = std::thread::spawn(move || -> Result<Vec<u8>, WinError> {
            let client = PipeClient::connect(&name_clone, 2000)?;
            client.write_frame(b"ping")?;
            client.read_frame()
        });

        let id = server.accept()?;
        assert_eq!(id.pid, std::process::id());
        let req = server.read_frame()?;
        assert_eq!(req, b"ping");
        server.write_frame(b"pong")?;
        server.disconnect();

        let resp = match client_thread.join() {
            Ok(client_out) => client_out?,
            Err(_) => {
                return Err(WinError {
                    code: 1,
                    context: "join",
                })
            }
        };
        assert_eq!(resp, b"pong");
        Ok(())
    }
}
