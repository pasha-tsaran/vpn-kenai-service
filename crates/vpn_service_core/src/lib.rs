//! Pure service policy and state transitions. No operating-system calls.

#![allow(clippy::missing_errors_doc)]

use std::collections::{HashSet, VecDeque};

use vpn_contracts::{
    ConnectRequest, ConnectionPhase, ControlCommand, RequestEnvelope, StateEvent, CONTRACT_VERSION,
};

#[derive(Debug, Eq, PartialEq)]
pub enum CommandError {
    Busy,
    DuplicateRequest,
    EmptyOperationId,
    EmptyProfileId,
    InvalidFailurePhase,
    UnauthorizedCaller,
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

#[derive(Debug, Default)]
pub struct ServiceCommandProcessor {
    machine: ConnectionStateMachine,
    recent_ids: VecDeque<String>,
    recent_id_set: HashSet<String>,
}

impl ServiceCommandProcessor {
    const MAX_RECENT_REQUESTS: usize = 256;

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

        let code = match request.command {
            ControlCommand::Status => "OK",
            ControlCommand::Diagnostics => "DIAGNOSTICS_REDACTED",
            ControlCommand::Connect(connect) => {
                if self.machine.state().phase.is_failure() {
                    self.machine.reset_failure()?;
                }
                self.machine.begin_connect(&connect)?;
                self.machine.mark_validated()?;
                self.machine
                    .fail(ConnectionPhase::Error, "ENGINE_NOT_INSTALLED")?;
                "ENGINE_NOT_INSTALLED"
            }
            ControlCommand::Disconnect { operation_id } => {
                if self.machine.state().phase.is_failure() {
                    self.machine.reset_failure()?;
                } else {
                    self.machine.begin_disconnect(&operation_id)?;
                    self.machine.mark_disconnected()?;
                }
                "DISCONNECTED"
            }
        };
        Ok(CommandOutcome {
            request_id: request.request_id,
            state: self.machine.state().clone(),
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
    use vpn_contracts::Protocol;

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
}
