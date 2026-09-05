//! Pure service policy and state transitions. No operating-system calls.

#![allow(clippy::missing_errors_doc)]

use std::collections::{HashSet, VecDeque};

use vpn_contracts::{
    ConnectRequest, ConnectionPhase, ControlCommand, RequestEnvelope, StateEvent, WireGuardProfile,
    CONTRACT_VERSION,
};

#[derive(Debug, Eq, PartialEq)]
pub enum CommandError {
    Busy,
    DuplicateRequest,
    EmptyOperationId,
    EmptyProfileId,
    InvalidFailurePhase,
    UnauthorizedCaller,
    InvalidProfile,
    ProfileNotFound,
    ProfileStoreUnavailable,
}

pub trait ProfileVault {
    fn store_wireguard(&mut self, profile: &WireGuardProfile) -> Result<String, CommandError>;
    fn load_wireguard(&self, profile_id: &str) -> Result<WireGuardProfile, CommandError>;
    fn delete(&mut self, profile_id: &str) -> Result<(), CommandError>;
}

#[derive(Debug, Default)]
pub struct UnavailableProfileVault;

impl ProfileVault for UnavailableProfileVault {
    fn store_wireguard(&mut self, _profile: &WireGuardProfile) -> Result<String, CommandError> {
        Err(CommandError::ProfileStoreUnavailable)
    }

    fn load_wireguard(&self, _profile_id: &str) -> Result<WireGuardProfile, CommandError> {
        Err(CommandError::ProfileStoreUnavailable)
    }

    fn delete(&mut self, _profile_id: &str) -> Result<(), CommandError> {
        Err(CommandError::ProfileStoreUnavailable)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AuthorizationContext {
    pub is_local: bool,
    pub is_authenticated: bool,
    pub client_session_id: u32,
    pub allowed_session_id: u32,
}

impl AuthorizationContext {
    #[must_use]
    pub const fn is_allowed(self) -> bool {
        self.is_local
            && self.is_authenticated
            && self.client_session_id != 0
            && self.client_session_id == self.allowed_session_id
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CommandOutcome {
    pub request_id: String,
    pub state: StateEvent,
    pub code: &'static str,
}

#[derive(Debug)]
pub struct ServiceCommandProcessor<V = UnavailableProfileVault> {
    machine: ConnectionStateMachine,
    recent_ids: VecDeque<String>,
    recent_id_set: HashSet<String>,
    vault: V,
}

impl Default for ServiceCommandProcessor<UnavailableProfileVault> {
    fn default() -> Self {
        Self::new(UnavailableProfileVault)
    }
}

impl<V: ProfileVault> ServiceCommandProcessor<V> {
    const MAX_RECENT_REQUESTS: usize = 256;

    #[must_use]
    pub fn new(vault: V) -> Self {
        Self {
            machine: ConnectionStateMachine::default(),
            recent_ids: VecDeque::new(),
            recent_id_set: HashSet::new(),
            vault,
        }
    }

    pub fn process(
        &mut self,
        context: AuthorizationContext,
        request: RequestEnvelope,
    ) -> Result<CommandOutcome, CommandError> {
        if !context.is_allowed() {
            return Err(CommandError::UnauthorizedCaller);
        }
        if self.recent_id_set.contains(&request.request_id) {
            return Err(CommandError::DuplicateRequest);
        }
        self.remember(request.request_id.clone());

        let (code, returned_profile_id) = match request.command {
            ControlCommand::Status => ("OK", None),
            ControlCommand::Diagnostics => ("DIAGNOSTICS_REDACTED", None),
            ControlCommand::Connect(connect) => {
                if self.machine.state().phase.is_failure() {
                    self.machine.reset_failure()?;
                }
                self.machine.begin_connect(&connect)?;
                self.machine.mark_validated()?;
                self.machine
                    .fail(ConnectionPhase::Error, "ENGINE_NOT_INSTALLED")?;
                ("ENGINE_NOT_INSTALLED", None)
            }
            ControlCommand::Disconnect { operation_id } => {
                if self.machine.state().phase.is_failure() {
                    self.machine.reset_failure()?;
                } else {
                    self.machine.begin_disconnect(&operation_id)?;
                    self.machine.mark_disconnected()?;
                }
                ("DISCONNECTED", None)
            }
            ControlCommand::ImportWireGuardProfile(import) => {
                if import.operation_id.trim().is_empty() {
                    return Err(CommandError::EmptyOperationId);
                }
                import
                    .profile
                    .validate()
                    .map_err(|_| CommandError::InvalidProfile)?;
                let profile_id = self.vault.store_wireguard(&import.profile)?;
                if !valid_profile_id(&profile_id) {
                    return Err(CommandError::ProfileStoreUnavailable);
                }
                ("PROFILE_STORED", Some(profile_id))
            }
            ControlCommand::DeleteProfile {
                operation_id,
                profile_id,
            } => {
                if operation_id.trim().is_empty() {
                    return Err(CommandError::EmptyOperationId);
                }
                if profile_id.trim().is_empty() {
                    return Err(CommandError::EmptyProfileId);
                }
                self.vault.delete(&profile_id)?;
                ("PROFILE_DELETED", None)
            }
        };
        let mut state = self.machine.state().clone();
        if returned_profile_id.is_some() {
            state.profile_id = returned_profile_id;
        }
        Ok(CommandOutcome {
            request_id: request.request_id,
            state,
            code,
        })
    }

    fn remember(&mut self, request_id: String) {
        if self.recent_ids.len() == Self::MAX_RECENT_REQUESTS {
            if let Some(expired) = self.recent_ids.pop_front() {
                self.recent_id_set.remove(&expired);
            }
        }
        self.recent_id_set.insert(request_id.clone());
        self.recent_ids.push_back(request_id);
    }
}

fn valid_profile_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
}

#[derive(Debug, Default)]
pub struct ConnectionStateMachine {
    state: StateEvent,
}

impl ConnectionStateMachine {
    #[must_use]
    pub fn state(&self) -> &StateEvent {
        &self.state
    }

    pub fn begin_connect(&mut self, request: &ConnectRequest) -> Result<(), CommandError> {
        if request.operation_id.trim().is_empty() {
            return Err(CommandError::EmptyOperationId);
        }
        if request.profile_id.trim().is_empty() {
            return Err(CommandError::EmptyProfileId);
        }
        if self.state.phase != ConnectionPhase::Disconnected {
            return Err(CommandError::Busy);
        }
        self.state = StateEvent {
            contract_version: CONTRACT_VERSION,
            phase: ConnectionPhase::Validating,
            profile_id: Some(request.profile_id.clone()),
            kill_switch_active: false,
            error_code: None,
        };
        Ok(())
    }

    pub fn mark_validated(&mut self) -> Result<(), CommandError> {
        if self.state.phase != ConnectionPhase::Validating {
            return Err(CommandError::Busy);
        }
        self.state.phase = ConnectionPhase::Connecting;
        Ok(())
    }

    pub fn mark_connected(&mut self, kill_switch_active: bool) -> Result<(), CommandError> {
        if !matches!(
            self.state.phase,
            ConnectionPhase::Connecting | ConnectionPhase::Reconnecting
        ) {
            return Err(CommandError::Busy);
        }
        self.state.phase = ConnectionPhase::Connected;
        self.state.kill_switch_active = kill_switch_active;
        self.state.error_code = None;
        Ok(())
    }

    pub fn begin_reconnect(&mut self) -> Result<(), CommandError> {
        if self.state.phase != ConnectionPhase::Connected {
            return Err(CommandError::Busy);
        }
        self.state.phase = ConnectionPhase::Reconnecting;
        Ok(())
    }

    pub fn begin_disconnect(&mut self, operation_id: &str) -> Result<(), CommandError> {
        if operation_id.trim().is_empty() {
            return Err(CommandError::EmptyOperationId);
        }
        if !matches!(
            self.state.phase,
            ConnectionPhase::Connected | ConnectionPhase::Reconnecting
        ) {
            return Err(CommandError::Busy);
        }
        self.state.phase = ConnectionPhase::Disconnecting;
        Ok(())
    }

    pub fn mark_disconnected(&mut self) -> Result<(), CommandError> {
        if self.state.phase != ConnectionPhase::Disconnecting {
            return Err(CommandError::Busy);
        }
        self.state = StateEvent::default();
        Ok(())
    }

    pub fn fail(
        &mut self,
        phase: ConnectionPhase,
        error_code: impl Into<String>,
    ) -> Result<(), CommandError> {
        if !phase.is_failure() {
            return Err(CommandError::InvalidFailurePhase);
        }
        self.state.phase = phase;
        self.state.kill_switch_active = false;
        self.state.error_code = Some(error_code.into());
        Ok(())
    }

    pub fn reset_failure(&mut self) -> Result<(), CommandError> {
        if !self.state.phase.is_failure() {
            return Err(CommandError::Busy);
        }
        self.state = StateEvent::default();
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::IpAddr;
    use vpn_contracts::{ImportWireGuardProfileRequest, Protocol, SecretKey, WireGuardProfile};

    #[derive(Debug, Default)]
    struct MemoryVault {
        stored: bool,
    }

    impl ProfileVault for MemoryVault {
        fn store_wireguard(&mut self, _profile: &WireGuardProfile) -> Result<String, CommandError> {
            self.stored = true;
            Ok("wg-0011223344556677".into())
        }

        fn load_wireguard(&self, _profile_id: &str) -> Result<WireGuardProfile, CommandError> {
            if self.stored {
                Ok(profile())
            } else {
                Err(CommandError::ProfileNotFound)
            }
        }

        fn delete(&mut self, profile_id: &str) -> Result<(), CommandError> {
            if self.stored && profile_id == "wg-0011223344556677" {
                self.stored = false;
                Ok(())
            } else {
                Err(CommandError::ProfileNotFound)
            }
        }
    }

    fn request() -> ConnectRequest {
        ConnectRequest {
            operation_id: "connect-1".into(),
            profile_id: "profile-1".into(),
            protocol: Protocol::WireGuard,
            kill_switch: true,
        }
    }

    fn authorized() -> AuthorizationContext {
        AuthorizationContext {
            is_local: true,
            is_authenticated: true,
            client_session_id: 4,
            allowed_session_id: 4,
        }
    }

    fn profile() -> WireGuardProfile {
        WireGuardProfile {
            private_key: SecretKey([1; 32]),
            addresses: vec!["10.0.0.2/32".into()],
            dns_servers: vec![IpAddr::from([1, 1, 1, 1])],
            peer_public_key: SecretKey([2; 32]),
            preshared_key: None,
            endpoint_host: "vpn.example.test".into(),
            endpoint_port: 51820,
            allowed_ips: vec!["0.0.0.0/0".into()],
            persistent_keepalive: Some(25),
        }
    }

    #[test]
    fn follows_connect_reconnect_and_disconnect_lifecycle() {
        let mut machine = ConnectionStateMachine::default();

        assert_eq!(machine.begin_connect(&request()), Ok(()));
        assert_eq!(machine.state().phase, ConnectionPhase::Validating);
        assert_eq!(machine.mark_validated(), Ok(()));
        assert_eq!(machine.mark_connected(true), Ok(()));
        assert!(machine.state().kill_switch_active);
        assert_eq!(machine.begin_reconnect(), Ok(()));
        assert_eq!(machine.mark_connected(true), Ok(()));
        assert_eq!(machine.begin_disconnect("disconnect-1"), Ok(()));
        assert_eq!(machine.mark_disconnected(), Ok(()));
        assert_eq!(machine.state(), &StateEvent::default());
    }

    #[test]
    fn rejects_invalid_and_overlapping_commands() {
        let mut machine = ConnectionStateMachine::default();
        let mut invalid = request();
        invalid.operation_id.clear();
        assert_eq!(
            machine.begin_connect(&invalid),
            Err(CommandError::EmptyOperationId)
        );
        assert_eq!(machine.begin_connect(&request()), Ok(()));
        assert_eq!(machine.begin_connect(&request()), Err(CommandError::Busy));
        assert_eq!(
            machine.begin_disconnect("disconnect-1"),
            Err(CommandError::Busy)
        );
    }

    #[test]
    fn supports_all_failure_states_and_explicit_recovery() {
        for phase in [
            ConnectionPhase::BlockedBySubscription,
            ConnectionPhase::NoNetwork,
            ConnectionPhase::ServerUnavailable,
            ConnectionPhase::Error,
        ] {
            let mut machine = ConnectionStateMachine::default();
            assert_eq!(machine.fail(phase, "TEST_FAILURE"), Ok(()));
            assert_eq!(machine.state().phase, phase);
            assert_eq!(machine.reset_failure(), Ok(()));
            assert_eq!(machine.state().phase, ConnectionPhase::Disconnected);
        }
    }

    #[test]
    fn command_processor_rejects_unauthorized_and_duplicate_requests() {
        let request = RequestEnvelope {
            contract_version: CONTRACT_VERSION,
            request_id: "status-1".into(),
            command: ControlCommand::Status,
        };
        let mut processor = ServiceCommandProcessor::default();
        let denied = AuthorizationContext {
            client_session_id: 5,
            ..authorized()
        };

        assert_eq!(
            processor.process(denied, request.clone()),
            Err(CommandError::UnauthorizedCaller)
        );
        assert_eq!(
            processor
                .process(authorized(), request.clone())
                .expect("authorized status")
                .code,
            "OK"
        );
        assert_eq!(
            processor.process(authorized(), request),
            Err(CommandError::DuplicateRequest)
        );
    }

    #[test]
    fn connect_never_reports_success_without_an_engine() {
        let request = RequestEnvelope {
            contract_version: CONTRACT_VERSION,
            request_id: "connect-request-1".into(),
            command: ControlCommand::Connect(request()),
        };
        let mut processor = ServiceCommandProcessor::default();

        let outcome = processor
            .process(authorized(), request)
            .expect("valid request is handled safely");

        assert_eq!(outcome.code, "ENGINE_NOT_INSTALLED");
        assert_eq!(outcome.state.phase, ConnectionPhase::Error);
        assert!(!outcome.state.kill_switch_active);
    }

    #[test]
    fn provisions_an_opaque_handle_and_deletes_it_explicitly() {
        let mut processor = ServiceCommandProcessor::new(MemoryVault::default());
        let stored = processor
            .process(
                authorized(),
                RequestEnvelope {
                    contract_version: CONTRACT_VERSION,
                    request_id: "import-request-1".into(),
                    command: ControlCommand::ImportWireGuardProfile(
                        ImportWireGuardProfileRequest {
                            operation_id: "provision-1".into(),
                            profile: profile(),
                        },
                    ),
                },
            )
            .expect("profile stored");
        assert_eq!(stored.code, "PROFILE_STORED");
        assert_eq!(
            stored.state.profile_id.as_deref(),
            Some("wg-0011223344556677")
        );

        let deleted = processor
            .process(
                authorized(),
                RequestEnvelope {
                    contract_version: CONTRACT_VERSION,
                    request_id: "delete-request-1".into(),
                    command: ControlCommand::DeleteProfile {
                        operation_id: "cleanup-1".into(),
                        profile_id: "wg-0011223344556677".into(),
                    },
                },
            )
            .expect("profile deleted");
        assert_eq!(deleted.code, "PROFILE_DELETED");
        assert_eq!(deleted.state.profile_id, None);
    }
}
