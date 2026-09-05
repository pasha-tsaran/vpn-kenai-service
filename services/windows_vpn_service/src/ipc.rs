// Local-only, bounded named-pipe transport for the privileged service.

use std::{
    ffi::c_void,
    io,
    mem::size_of,
    os::windows::io::AsRawHandle,
    ptr,
};

use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::windows::named_pipe::{NamedPipeServer, PipeMode, ServerOptions},
    sync::watch,
};
use vpn_contracts::{
    decode_request, declared_frame_size, encode_response, ConnectionPhase, ResponseEnvelope,
    CONTRACT_VERSION,
};
use vpn_service_core::{AuthorizationContext, CommandError, ServiceCommandProcessor};
use windows_sys::Win32::{
    Foundation::LocalFree,
    Security::{
        Authorization::{
            ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1,
        },
        PSECURITY_DESCRIPTOR, SECURITY_ATTRIBUTES,
    },
    System::{
        Pipes::GetNamedPipeClientProcessId,
        RemoteDesktop::{ProcessIdToSessionId, WTSGetActiveConsoleSessionId},
    },
};

const PIPE_NAME: &str = r"\\.\pipe\KenaiVpnControl-v1";
const HEADER_SIZE: usize = 12;
const INVALID_REQUEST_ID: &str = "invalid-request";

pub async fn serve(mut shutdown: watch::Receiver<bool>) -> io::Result<()> {
    let security = PipeSecurity::new()?;
    let mut processor = ServiceCommandProcessor::default();

    loop {
        if *shutdown.borrow() {
            return Ok(());
        }
        let server = security.create_server()?;
        tokio::select! {
            result = server.connect() => result?,
            result = shutdown.changed() => {
                let _ = result;
                return Ok(());
            }
        }

        let authorization = caller_authorization(&server)?;
        if !authorization.is_allowed() {
            continue;
        }
        tokio::select! {
            result = handle_one(server, authorization, &mut processor) => result?,
            result = shutdown.changed() => {
                let _ = result;
                return Ok(());
            }
        }
    }
}

async fn handle_one(
    mut server: NamedPipeServer,
    authorization: AuthorizationContext,
    processor: &mut ServiceCommandProcessor,
) -> io::Result<()> {
    let mut header = [0_u8; HEADER_SIZE];
    if server.read_exact(&mut header).await.is_err() {
        return Ok(());
    }
    let Ok(total_size) = declared_frame_size(&header) else {
        return write_safe_error(&mut server, INVALID_REQUEST_ID, "INVALID_REQUEST").await;
    };
    let mut frame = Vec::with_capacity(total_size);
    frame.extend_from_slice(&header);
    frame.resize(total_size, 0);
    if server.read_exact(&mut frame[HEADER_SIZE..]).await.is_err() {
        return Ok(());
    }

    let response = process_frame(&frame, authorization, processor);
    write_response(&mut server, response).await
}

fn process_frame(
    frame: &[u8],
    authorization: AuthorizationContext,
    processor: &mut ServiceCommandProcessor,
) -> ResponseEnvelope {
    let Ok(request) = decode_request(frame) else {
        return safe_error(INVALID_REQUEST_ID, "INVALID_REQUEST");
    };
    let request_id = request.request_id.clone();
    match processor.process(authorization, request) {
        Ok(outcome) => ResponseEnvelope {
            contract_version: CONTRACT_VERSION,
            request_id: outcome.request_id,
            phase: outcome.state.phase,
            profile_id: outcome.state.profile_id,
            kill_switch_active: outcome.state.kill_switch_active,
            code: outcome.code.into(),
        },
        Err(error) => safe_command_error(request_id, &error),
    }
}

fn safe_command_error(request_id: String, error: &CommandError) -> ResponseEnvelope {
    let code = match error {
        CommandError::Busy => "BUSY",
        CommandError::DuplicateRequest => "DUPLICATE_REQUEST",
        CommandError::EmptyOperationId
        | CommandError::EmptyProfileId
        | CommandError::InvalidFailurePhase => "INVALID_REQUEST",
        CommandError::UnauthorizedCaller => "UNAUTHORIZED",
    };
    ResponseEnvelope {
        contract_version: CONTRACT_VERSION,
        request_id,
        phase: ConnectionPhase::Error,
        profile_id: None,
        kill_switch_active: false,
        code: code.into(),
    }
}

async fn write_safe_error(
    server: &mut NamedPipeServer,
    request_id: &str,
    code: &str,
) -> io::Result<()> {
    write_response(server, safe_error(request_id, code)).await
}

fn safe_error(request_id: &str, code: &str) -> ResponseEnvelope {
    ResponseEnvelope {
        contract_version: CONTRACT_VERSION,
        request_id: request_id.into(),
        phase: ConnectionPhase::Error,
        profile_id: None,
        kill_switch_active: false,
        code: code.into(),
    }
}

async fn write_response(
    server: &mut NamedPipeServer,
    response: ResponseEnvelope,
) -> io::Result<()> {
    let bytes = encode_response(&response)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "safe response encoding failed"))?;
    server.write_all(&bytes).await?;
    server.flush().await
}

fn caller_authorization(server: &NamedPipeServer) -> io::Result<AuthorizationContext> {
    let handle = server.as_raw_handle();
    let mut process_id = 0_u32;
    let mut client_session_id = 0_u32;
    // SAFETY: Tokio owns a live connected pipe handle for the duration of both
    // calls, and both out-pointers refer to initialized local `u32` storage.
    let identified = unsafe {
        GetNamedPipeClientProcessId(handle, ptr::addr_of_mut!(process_id)) != 0
            && ProcessIdToSessionId(process_id, ptr::addr_of_mut!(client_session_id)) != 0
    };
    if !identified {
        return Err(io::Error::last_os_error());
    }
    let allowed_session_id = unsafe { WTSGetActiveConsoleSessionId() };
    Ok(AuthorizationContext {
        is_local: true,
        is_authenticated: true,
        client_session_id,
        allowed_session_id,
    })
}

struct PipeSecurity {
    descriptor: PSECURITY_DESCRIPTOR,
    attributes: SECURITY_ATTRIBUTES,
}

impl PipeSecurity {
    fn new() -> io::Result<Self> {
        // Protected DACL: deny anonymous/network tokens, allow SYSTEM and
        // Administrators full access, and authenticated users read/write.
        // The caller-session check narrows authenticated users after connect.
        let sddl = to_wide(
            "D:P(D;;GA;;;AN)(D;;GA;;;NU)(A;;GA;;;SY)(A;;GA;;;BA)(A;;GRGW;;;AU)",
        );
        let mut descriptor = ptr::null_mut();
        // SAFETY: `sddl` is NUL-terminated and lives through the call;
        // `descriptor` is a valid out-pointer released with `LocalFree`.
        let converted = unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                sddl.as_ptr(),
                SDDL_REVISION_1,
                ptr::addr_of_mut!(descriptor),
                ptr::null_mut(),
            )
        };
        if converted == 0 {
            return Err(io::Error::last_os_error());
        }
        let length = u32::try_from(size_of::<SECURITY_ATTRIBUTES>())
            .map_err(|_| io::Error::other("invalid security attributes size"))?;
        Ok(Self {
            descriptor,
            attributes: SECURITY_ATTRIBUTES {
                nLength: length,
                lpSecurityDescriptor: descriptor.cast::<c_void>(),
                bInheritHandle: 0,
            },
        })
    }

    fn create_server(&self) -> io::Result<NamedPipeServer> {
        let mut options = ServerOptions::new();
        options
            .first_pipe_instance(true)
            .pipe_mode(PipeMode::Byte)
            .reject_remote_clients(true)
            .max_instances(1)
            .in_buffer_size(u32::try_from(vpn_contracts::MAX_FRAME_SIZE).unwrap_or(16_384))
            .out_buffer_size(u32::try_from(vpn_contracts::MAX_FRAME_SIZE).unwrap_or(16_384));
        // SAFETY: `self.attributes` and its descriptor remain alive for the
        // synchronous pipe creation call. Tokio does not retain this pointer.
        unsafe {
            options.create_with_security_attributes_raw(
                PIPE_NAME,
                ptr::from_ref(&self.attributes).cast_mut().cast::<c_void>(),
            )
        }
    }
}

impl Drop for PipeSecurity {
    fn drop(&mut self) {
        if !self.descriptor.is_null() {
            // SAFETY: the descriptor was allocated by the SDDL conversion API
            // and is freed exactly once here.
            unsafe {
                LocalFree(self.descriptor.cast::<c_void>());
            }
        }
    }
}

fn to_wide(value: &str) -> Vec<u16> {
    value.encode_utf16().chain(std::iter::once(0)).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use vpn_contracts::{encode_request, ControlCommand, RequestEnvelope};

    #[test]
    fn command_errors_are_reduced_to_allow_listed_codes() {
        for (error, expected) in [
            (CommandError::Busy, "BUSY"),
            (CommandError::DuplicateRequest, "DUPLICATE_REQUEST"),
            (CommandError::EmptyProfileId, "INVALID_REQUEST"),
            (CommandError::UnauthorizedCaller, "UNAUTHORIZED"),
        ] {
            assert_eq!(
                safe_command_error("request-1".into(), &error).code,
                expected
            );
        }
    }

    #[test]
    fn malformed_and_unauthorized_frames_never_expose_internal_details() {
        let mut processor = ServiceCommandProcessor::default();
        let authorized = AuthorizationContext {
            is_local: true,
            is_authenticated: true,
            client_session_id: 3,
            allowed_session_id: 3,
        };
        let malformed = process_frame(b"not a frame", authorized, &mut processor);
        assert_eq!(malformed.request_id, INVALID_REQUEST_ID);
        assert_eq!(malformed.code, "INVALID_REQUEST");

        let request = RequestEnvelope {
            contract_version: CONTRACT_VERSION,
            request_id: "status-1".into(),
            command: ControlCommand::Status,
        };
        let frame = encode_request(&request).expect("valid frame");
        let unauthorized = process_frame(
            &frame,
            AuthorizationContext {
                is_local: true,
                is_authenticated: true,
                client_session_id: 2,
                allowed_session_id: 3,
            },
            &mut processor,
        );
        assert_eq!(unauthorized.request_id, "status-1");
        assert_eq!(unauthorized.code, "UNAUTHORIZED");
        assert_eq!(unauthorized.profile_id, None);
    }
}
