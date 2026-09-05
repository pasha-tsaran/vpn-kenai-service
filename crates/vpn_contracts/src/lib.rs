//! Dependency-free stage-1 equivalents of the versioned protobuf contract.

pub const CONTRACT_VERSION: u32 = 1;
pub const MAX_FRAME_SIZE: usize = 16 * 1024;
const MAGIC: &[u8; 4] = b"KVPN";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Protocol {
    WireGuard,
    AmneziaWg,
    VlessReality,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum ConnectionPhase {
    #[default]
    Disconnected,
    Validating,
    Connecting,
    Connected,
    Reconnecting,
    Disconnecting,
    BlockedBySubscription,
    NoNetwork,
    ServerUnavailable,
    Error,
}

impl ConnectionPhase {
    #[must_use]
    pub const fn is_failure(self) -> bool {
        matches!(
            self,
            Self::BlockedBySubscription | Self::NoNetwork | Self::ServerUnavailable | Self::Error
        )
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ConnectRequest {
    pub operation_id: String,
    pub profile_id: String,
    pub protocol: Protocol,
    pub kill_switch: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ControlCommand {
    Status,
    Connect(ConnectRequest),
    Disconnect { operation_id: String },
    Diagnostics,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RequestEnvelope {
    pub contract_version: u32,
    pub request_id: String,
    pub command: ControlCommand,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ResponseEnvelope {
    pub contract_version: u32,
    pub request_id: String,
    pub phase: ConnectionPhase,
    pub profile_id: Option<String>,
    pub kill_switch_active: bool,
    pub code: String,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FrameError {
    TooLarge,
    TooShort,
    InvalidMagic,
    UnsupportedVersion,
    UnknownOperation,
    InvalidLength,
    InvalidUtf8,
    InvalidIdentifier,
    InvalidProtocol,
    InvalidBoolean,
    TrailingData,
}

/// Returns the complete frame size declared by a 12-byte header.
///
/// # Errors
///
/// Returns [`FrameError`] if the header is incomplete, malformed, uses an
/// unsupported contract version, or declares an oversized frame.
pub fn declared_frame_size(header: &[u8]) -> Result<usize, FrameError> {
    if header.len() != 12 {
        return Err(FrameError::TooShort);
    }
    if &header[..4] != MAGIC {
        return Err(FrameError::InvalidMagic);
    }
    let version = u32::from(u16::from_le_bytes([header[4], header[5]]));
    if version != CONTRACT_VERSION {
        return Err(FrameError::UnsupportedVersion);
    }
    if header[7] != 0 {
        return Err(FrameError::UnknownOperation);
    }
    let body_len = usize::try_from(u32::from_le_bytes([
        header[8], header[9], header[10], header[11],
    ]))
    .map_err(|_| FrameError::InvalidLength)?;
    let total = body_len.checked_add(12).ok_or(FrameError::TooLarge)?;
    if total > MAX_FRAME_SIZE {
        return Err(FrameError::TooLarge);
    }
    Ok(total)
}

/// Encodes one validated client request into the bounded binary wire format.
///
/// # Errors
///
/// Returns [`FrameError`] when the contract version or an identifier is invalid,
/// or when the encoded frame would exceed [`MAX_FRAME_SIZE`].
pub fn encode_request(request: &RequestEnvelope) -> Result<Vec<u8>, FrameError> {
    validate_identifier(&request.request_id)?;
    if request.contract_version != CONTRACT_VERSION {
        return Err(FrameError::UnsupportedVersion);
    }

    let mut body = Vec::new();
    put_string(&mut body, &request.request_id)?;
    let opcode = match &request.command {
        ControlCommand::Status => 1,
        ControlCommand::Connect(connect) => {
            validate_identifier(&connect.operation_id)?;
            validate_identifier(&connect.profile_id)?;
            put_string(&mut body, &connect.operation_id)?;
            put_string(&mut body, &connect.profile_id)?;
            body.push(protocol_byte(connect.protocol));
            body.push(u8::from(connect.kill_switch));
            2
        }
        ControlCommand::Disconnect { operation_id } => {
            validate_identifier(operation_id)?;
            put_string(&mut body, operation_id)?;
            3
        }
        ControlCommand::Diagnostics => 4,
    };
    if body.len() + 12 > MAX_FRAME_SIZE {
        return Err(FrameError::TooLarge);
    }

    let mut frame = Vec::with_capacity(body.len() + 12);
    frame.extend_from_slice(MAGIC);
    let wire_version =
        u16::try_from(CONTRACT_VERSION).map_err(|_| FrameError::UnsupportedVersion)?;
    frame.extend_from_slice(&wire_version.to_le_bytes());
    frame.push(opcode);
    frame.push(0);
    let body_len = u32::try_from(body.len()).map_err(|_| FrameError::TooLarge)?;
    frame.extend_from_slice(&body_len.to_le_bytes());
    frame.extend_from_slice(&body);
    Ok(frame)
}

/// Decodes and validates one complete request frame.
///
/// # Errors
///
/// Returns [`FrameError`] for malformed, oversized, unsupported, or trailing
/// input. The decoder never accepts arbitrary paths or commands as identifiers.
pub fn decode_request(frame: &[u8]) -> Result<RequestEnvelope, FrameError> {
    if frame.len() > MAX_FRAME_SIZE {
        return Err(FrameError::TooLarge);
    }
    if frame.len() < 12 {
        return Err(FrameError::TooShort);
    }
    if &frame[..4] != MAGIC {
        return Err(FrameError::InvalidMagic);
    }
    let version = u32::from(u16::from_le_bytes([frame[4], frame[5]]));
    if version != CONTRACT_VERSION {
        return Err(FrameError::UnsupportedVersion);
    }
    let opcode = frame[6];
    if frame[7] != 0 {
        return Err(FrameError::UnknownOperation);
    }
    let body_len = u32::from_le_bytes([frame[8], frame[9], frame[10], frame[11]]) as usize;
    if body_len != frame.len() - 12 {
        return Err(FrameError::InvalidLength);
    }

    let mut cursor = Cursor::new(&frame[12..]);
    let request_id = cursor.string()?;
    validate_identifier(&request_id)?;
    let command = match opcode {
        1 => ControlCommand::Status,
        2 => {
            let operation_id = cursor.string()?;
            let profile_id = cursor.string()?;
            validate_identifier(&operation_id)?;
            validate_identifier(&profile_id)?;
            let protocol = match cursor.byte()? {
                1 => Protocol::WireGuard,
                2 => Protocol::AmneziaWg,
                3 => Protocol::VlessReality,
                _ => return Err(FrameError::InvalidProtocol),
            };
            let kill_switch = match cursor.byte()? {
                0 => false,
                1 => true,
                _ => return Err(FrameError::InvalidBoolean),
            };
            ControlCommand::Connect(ConnectRequest {
                operation_id,
                profile_id,
                protocol,
                kill_switch,
            })
        }
        3 => {
            let operation_id = cursor.string()?;
            validate_identifier(&operation_id)?;
            ControlCommand::Disconnect { operation_id }
        }
        4 => ControlCommand::Diagnostics,
        _ => return Err(FrameError::UnknownOperation),
    };
    if !cursor.finished() {
        return Err(FrameError::TrailingData);
    }
    Ok(RequestEnvelope {
        contract_version: version,
        request_id,
        command,
    })
}

/// Encodes one service response without diagnostic text or platform errors.
///
/// # Errors
///
/// Returns [`FrameError`] when a field is not an allow-listed identifier, the
/// version is unsupported, or the response exceeds [`MAX_FRAME_SIZE`].
pub fn encode_response(response: &ResponseEnvelope) -> Result<Vec<u8>, FrameError> {
    if response.contract_version != CONTRACT_VERSION {
        return Err(FrameError::UnsupportedVersion);
    }
    validate_identifier(&response.request_id)?;
    validate_identifier(&response.code)?;

    let mut body = Vec::new();
    put_string(&mut body, &response.request_id)?;
    body.push(phase_byte(response.phase));
    match &response.profile_id {
        Some(profile_id) => {
            body.push(1);
            put_string(&mut body, profile_id)?;
        }
        None => body.push(0),
    }
    body.push(u8::from(response.kill_switch_active));
    put_string(&mut body, &response.code)?;
    encode_frame(0x81, &body)
}

/// Decodes one complete, bounded service response.
///
/// # Errors
///
/// Returns [`FrameError`] for malformed, oversized, unsupported, or trailing
/// input.
pub fn decode_response(frame: &[u8]) -> Result<ResponseEnvelope, FrameError> {
    let (opcode, version, body) = decode_frame(frame)?;
    if opcode != 0x81 {
        return Err(FrameError::UnknownOperation);
    }
    let mut cursor = Cursor::new(body);
    let request_id = cursor.string()?;
    validate_identifier(&request_id)?;
    let phase = decode_phase(cursor.byte()?)?;
    let profile_id = match cursor.byte()? {
        0 => None,
        1 => {
            let value = cursor.string()?;
            validate_identifier(&value)?;
            Some(value)
        }
        _ => return Err(FrameError::InvalidBoolean),
    };
    let kill_switch_active = match cursor.byte()? {
        0 => false,
        1 => true,
        _ => return Err(FrameError::InvalidBoolean),
    };
    let code = cursor.string()?;
    validate_identifier(&code)?;
    if !cursor.finished() {
        return Err(FrameError::TrailingData);
    }
    Ok(ResponseEnvelope {
        contract_version: version,
        request_id,
        phase,
        profile_id,
        kill_switch_active,
        code,
    })
}

fn encode_frame(opcode: u8, body: &[u8]) -> Result<Vec<u8>, FrameError> {
    if body.len() + 12 > MAX_FRAME_SIZE {
        return Err(FrameError::TooLarge);
    }
    let wire_version =
        u16::try_from(CONTRACT_VERSION).map_err(|_| FrameError::UnsupportedVersion)?;
    let body_len = u32::try_from(body.len()).map_err(|_| FrameError::TooLarge)?;
    let mut frame = Vec::with_capacity(body.len() + 12);
    frame.extend_from_slice(MAGIC);
    frame.extend_from_slice(&wire_version.to_le_bytes());
    frame.push(opcode);
    frame.push(0);
    frame.extend_from_slice(&body_len.to_le_bytes());
    frame.extend_from_slice(body);
    Ok(frame)
}

fn decode_frame(frame: &[u8]) -> Result<(u8, u32, &[u8]), FrameError> {
    if frame.len() > MAX_FRAME_SIZE {
        return Err(FrameError::TooLarge);
    }
    if frame.len() < 12 {
        return Err(FrameError::TooShort);
    }
    if &frame[..4] != MAGIC {
        return Err(FrameError::InvalidMagic);
    }
    let version = u32::from(u16::from_le_bytes([frame[4], frame[5]]));
    if version != CONTRACT_VERSION {
        return Err(FrameError::UnsupportedVersion);
    }
    if frame[7] != 0 {
        return Err(FrameError::UnknownOperation);
    }
    let body_len = usize::try_from(u32::from_le_bytes([
        frame[8], frame[9], frame[10], frame[11],
    ]))
    .map_err(|_| FrameError::InvalidLength)?;
    if body_len != frame.len() - 12 {
        return Err(FrameError::InvalidLength);
    }
    Ok((frame[6], version, &frame[12..]))
}

const fn phase_byte(phase: ConnectionPhase) -> u8 {
    match phase {
        ConnectionPhase::Disconnected => 0,
        ConnectionPhase::Validating => 1,
        ConnectionPhase::Connecting => 2,
        ConnectionPhase::Connected => 3,
        ConnectionPhase::Reconnecting => 4,
        ConnectionPhase::Disconnecting => 5,
        ConnectionPhase::BlockedBySubscription => 6,
        ConnectionPhase::NoNetwork => 7,
        ConnectionPhase::ServerUnavailable => 8,
        ConnectionPhase::Error => 9,
    }
}

const fn decode_phase(value: u8) -> Result<ConnectionPhase, FrameError> {
    match value {
        0 => Ok(ConnectionPhase::Disconnected),
        1 => Ok(ConnectionPhase::Validating),
        2 => Ok(ConnectionPhase::Connecting),
        3 => Ok(ConnectionPhase::Connected),
        4 => Ok(ConnectionPhase::Reconnecting),
        5 => Ok(ConnectionPhase::Disconnecting),
        6 => Ok(ConnectionPhase::BlockedBySubscription),
        7 => Ok(ConnectionPhase::NoNetwork),
        8 => Ok(ConnectionPhase::ServerUnavailable),
        9 => Ok(ConnectionPhase::Error),
        _ => Err(FrameError::UnknownOperation),
    }
}

fn protocol_byte(protocol: Protocol) -> u8 {
    match protocol {
        Protocol::WireGuard => 1,
        Protocol::AmneziaWg => 2,
        Protocol::VlessReality => 3,
    }
}

fn validate_identifier(value: &str) -> Result<(), FrameError> {
    if value.is_empty()
        || value.len() > 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
    {
        return Err(FrameError::InvalidIdentifier);
    }
    Ok(())
}

fn put_string(target: &mut Vec<u8>, value: &str) -> Result<(), FrameError> {
    validate_identifier(value)?;
    let length = u8::try_from(value.len()).map_err(|_| FrameError::InvalidIdentifier)?;
    target.push(length);
    target.extend_from_slice(value.as_bytes());
    Ok(())
}

struct Cursor<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> Cursor<'a> {
    const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    fn byte(&mut self) -> Result<u8, FrameError> {
        let value = *self
            .bytes
            .get(self.offset)
            .ok_or(FrameError::InvalidLength)?;
        self.offset += 1;
        Ok(value)
    }

    fn string(&mut self) -> Result<String, FrameError> {
        let length = usize::from(self.byte()?);
        let end = self
            .offset
            .checked_add(length)
            .ok_or(FrameError::InvalidLength)?;
        let bytes = self
            .bytes
            .get(self.offset..end)
            .ok_or(FrameError::InvalidLength)?;
        self.offset = end;
        String::from_utf8(bytes.to_vec()).map_err(|_| FrameError::InvalidUtf8)
    }

    const fn finished(&self) -> bool {
        self.offset == self.bytes.len()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StateEvent {
    pub contract_version: u32,
    pub phase: ConnectionPhase,
    pub profile_id: Option<String>,
    pub kill_switch_active: bool,
    pub error_code: Option<String>,
}

impl Default for StateEvent {
    fn default() -> Self {
        Self {
            contract_version: CONTRACT_VERSION,
            phase: ConnectionPhase::Disconnected,
            profile_id: None,
            kill_switch_active: false,
            error_code: None,
        }
    }
}

#[cfg(test)]
mod frame_tests {
    use super::*;

    fn connect() -> RequestEnvelope {
        RequestEnvelope {
            contract_version: CONTRACT_VERSION,
            request_id: "request-1".into(),
            command: ControlCommand::Connect(ConnectRequest {
                operation_id: "connect-1".into(),
                profile_id: "profile-1".into(),
                protocol: Protocol::WireGuard,
                kill_switch: true,
            }),
        }
    }

    #[test]
    fn round_trips_every_allow_listed_operation() {
        for request in [
            RequestEnvelope {
                contract_version: CONTRACT_VERSION,
                request_id: "status-1".into(),
                command: ControlCommand::Status,
            },
            connect(),
            RequestEnvelope {
                contract_version: CONTRACT_VERSION,
                request_id: "disconnect-1".into(),
                command: ControlCommand::Disconnect {
                    operation_id: "operation-2".into(),
                },
            },
            RequestEnvelope {
                contract_version: CONTRACT_VERSION,
                request_id: "diagnostics-1".into(),
                command: ControlCommand::Diagnostics,
            },
        ] {
            let encoded = encode_request(&request).expect("valid request");
            assert_eq!(decode_request(&encoded), Ok(request));
        }
    }

    #[test]
    fn rejects_malformed_oversized_and_unknown_frames() {
        assert_eq!(decode_request(&[0; 11]), Err(FrameError::TooShort));
        assert_eq!(
            decode_request(&vec![0; MAX_FRAME_SIZE + 1]),
            Err(FrameError::TooLarge)
        );
        let mut frame = encode_request(&connect()).expect("valid request");
        frame[0] = b'X';
        assert_eq!(decode_request(&frame), Err(FrameError::InvalidMagic));
        let mut frame = encode_request(&connect()).expect("valid request");
        frame[6] = 99;
        assert_eq!(decode_request(&frame), Err(FrameError::UnknownOperation));

        let mut header = encode_request(&connect()).expect("valid request")[..12].to_vec();
        header[8..12].copy_from_slice(&u32::MAX.to_le_bytes());
        assert_eq!(declared_frame_size(&header), Err(FrameError::TooLarge));
    }

    #[test]
    fn identifiers_cannot_smuggle_paths_or_commands() {
        for value in [
            "../profile",
            "C:\\profile",
            "profile;whoami",
            "profile name",
        ] {
            let mut request = connect();
            if let ControlCommand::Connect(connect) = &mut request.command {
                connect.profile_id = value.into();
            }
            assert_eq!(encode_request(&request), Err(FrameError::InvalidIdentifier));
        }
    }

    #[test]
    fn response_round_trip_contains_only_typed_safe_fields() {
        let response = ResponseEnvelope {
            contract_version: CONTRACT_VERSION,
            request_id: "request-1".into(),
            phase: ConnectionPhase::Error,
            profile_id: Some("profile-1".into()),
            kill_switch_active: false,
            code: "ENGINE_NOT_INSTALLED".into(),
        };
        let encoded = encode_response(&response).expect("valid response");
        assert_eq!(decode_response(&encoded), Ok(response));
    }

    #[test]
    fn response_rejects_diagnostic_text_and_paths() {
        for code in ["access denied", "C:\\secret", "token=value"] {
            let response = ResponseEnvelope {
                contract_version: CONTRACT_VERSION,
                request_id: "request-1".into(),
                phase: ConnectionPhase::Error,
                profile_id: None,
                kill_switch_active: false,
                code: code.into(),
            };
            assert_eq!(
                encode_response(&response),
                Err(FrameError::InvalidIdentifier)
            );
        }
    }
}
