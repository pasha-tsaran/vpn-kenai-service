//! Minimal Windows SCM lifecycle for Kenai VPN.
//!
//! Stage 8 intentionally starts no VPN engine. Its local named pipe has an
//! explicit DACL, rejects remote clients, and verifies the caller session.

#[cfg(windows)]
mod windows_service_host {
    use std::{error::Error, ffi::OsString, time::Duration};

    use tokio::{runtime::Builder, sync::watch};
    use windows_service::{
        define_windows_service,
        service::{
            ServiceControl, ServiceControlAccept, ServiceExitCode, ServiceState, ServiceStatus,
            ServiceType,
        },
        service_control_handler::{self, ServiceControlHandlerResult},
        service_dispatcher,
    };

    #[allow(unsafe_code)]
    mod ipc {
        include!("ipc.rs");
    }

    #[allow(unsafe_code)]
    mod profile_vault {
        include!("profile_vault.rs");
    }

    #[allow(unsafe_code)]
    mod wireguard_engine {
        include!("wireguard_engine.rs");
    }
    #[allow(unsafe_code)]
    mod amneziawg_engine {
        include!("amneziawg_engine.rs");
    }
    mod windows_backend {
        include!("windows_backend.rs");
    }
    #[allow(unsafe_code)]
    mod xray_engine {
        include!("xray_engine.rs");
    }

    const SERVICE_NAME: &str = "KenaiVpnService";

    define_windows_service!(ffi_service_main, service_main);

    pub fn run() -> windows_service::Result<()> {
        service_dispatcher::start(SERVICE_NAME, ffi_service_main)
    }

    pub fn run_entry() -> Result<(), Box<dyn Error>> {
        let arguments: Vec<OsString> = std::env::args_os().collect();
        if arguments.len() == 3 && arguments[1] == "/wireguard-service" {
            return wireguard_engine::run_tunnel_service(std::path::Path::new(&arguments[2]))
                .map_err(Into::into);
        }
        run().map_err(Into::into)
    }

    fn service_main(_arguments: Vec<OsString>) {
        if run_service().is_err() {
            eprintln!("Kenai VPN service stopped: SERVICE_RUNTIME_FAILED");
        }
    }

    fn run_service() -> Result<(), Box<dyn Error + Send + Sync>> {
        let (shutdown_sender, shutdown_receiver) = watch::channel(false);
        let event_handler = move |control_event| match control_event {
            ServiceControl::Stop => {
                let _ = shutdown_sender.send(true);
                ServiceControlHandlerResult::NoError
            }
            ServiceControl::Interrogate => ServiceControlHandlerResult::NoError,
            _ => ServiceControlHandlerResult::NotImplemented,
        };
        let status_handle = service_control_handler::register(SERVICE_NAME, event_handler)?;

        status_handle.set_service_status(status(ServiceState::Running))?;
        let runtime = Builder::new_current_thread().enable_io().build()?;
        runtime.block_on(ipc::serve(shutdown_receiver))?;
        status_handle.set_service_status(status(ServiceState::Stopped))?;
        Ok(())
    }

    fn status(current_state: ServiceState) -> ServiceStatus {
        ServiceStatus {
            service_type: ServiceType::OWN_PROCESS,
            current_state,
            controls_accepted: if current_state == ServiceState::Running {
                ServiceControlAccept::STOP
            } else {
                ServiceControlAccept::empty()
            },
            exit_code: ServiceExitCode::Win32(0),
            checkpoint: 0,
            wait_hint: Duration::ZERO,
            process_id: None,
        }
    }
}

#[cfg(windows)]
fn main() -> Result<(), Box<dyn std::error::Error>> {
    windows_service_host::run_entry()
}

#[cfg(not(windows))]
fn main() {
    eprintln!("KenaiVpnService can run only under the Windows Service Control Manager");
}
