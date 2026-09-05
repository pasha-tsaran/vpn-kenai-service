use std::{
    ffi::OsString,
    fmt::Write as _,
    fs,
    io::{self, Write},
    path::PathBuf,
    process::Command,
    thread,
    time::{Duration, Instant},
};

use base64::{engine::general_purpose::STANDARD, Engine as _};
use sha2::{Digest, Sha256};
use vpn_contracts::{AmneziaWgProfile, TunnelStatistics, WireGuardProfile};
use vpn_service_core::{BackendFailure, VpnBackend};
use windows_service::{
    service::{
        ServiceAccess, ServiceDependency, ServiceErrorControl, ServiceInfo, ServiceSidType,
        ServiceStartType, ServiceState, ServiceType,
    },
    service_manager::{ServiceManager, ServiceManagerAccess},
};
use zeroize::Zeroizing;

use super::profile_vault::apply_service_acl;

const TUNNEL_NAME: &str = "KenaiAwg";
const SERVICE_NAME: &str = "AmneziaWGTunnel$KenaiAwg";
const ENGINE_SHA256: &str = "5b00905ed02619fe149ceafc898e79993d4455a0cdfa92072b3bb9aee7b2d537";
const TOOLS_SHA256: &str = "26ac0be14a8353eacf2f933736f6f7912f89ec7c59c4190cc990492934c74537";
const WINTUN_SHA256: &str = "e5da8447dc2c320edc0fc52fa01885c103de8c118481f683643cacc3220dafce";
const TIMEOUT: Duration = Duration::from_secs(30);

#[derive(Debug)]
pub struct AmneziaWgWindowsBackend {
    executable: PathBuf,
    runtime_root: PathBuf,
    config_path: PathBuf,
}

impl AmneziaWgWindowsBackend {
    pub fn system_default() -> io::Result<Self> {
        let executable = std::env::current_exe()?;
        let program_data = std::env::var_os("ProgramData")
            .filter(|value| !value.is_empty())
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "ProgramData unavailable"))?;
        let runtime_root = PathBuf::from(program_data).join("KenaiVPN").join("runtime");
        fs::create_dir_all(&runtime_root)?;
        apply_service_acl(&runtime_root)?;
        let backend = Self {
            executable,
            config_path: runtime_root.join(format!("{TUNNEL_NAME}.conf")),
            runtime_root,
        };
        backend
            .cleanup_stale()
            .map_err(|_| io::Error::other("AmneziaWG cleanup failed"))?;
        Ok(backend)
    }

    fn payload_root(&self) -> Result<PathBuf, BackendFailure> {
        self.executable
            .parent()
            .map(|root| root.join("amneziawg").join("amd64"))
            .ok_or(BackendFailure::EngineUnavailable)
    }

    fn verify_payloads(&self) -> Result<(), BackendFailure> {
        let root = self.payload_root()?;
        verify_hash(&root.join("amneziawg.exe"), ENGINE_SHA256)?;
        verify_hash(&root.join("awg.exe"), TOOLS_SHA256)?;
        verify_hash(&root.join("wintun.dll"), WINTUN_SHA256)
    }

    fn write_config(&self, profile: &AmneziaWgProfile) -> Result<(), BackendFailure> {
        let temporary = self.runtime_root.join(format!("{TUNNEL_NAME}.conf.new"));
        remove_if_present(&temporary)?;
        let mut file = fs::OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(&temporary)
            .map_err(|_| BackendFailure::Internal)?;
        let rendered = render_config(profile);
        if file
            .write_all(rendered.as_bytes())
            .and_then(|()| file.sync_all())
            .is_err()
        {
            let _ = fs::remove_file(temporary);
            return Err(BackendFailure::Internal);
        }
        drop(file);
        fs::rename(&temporary, &self.config_path).map_err(|_| BackendFailure::Internal)
    }

    fn start_service(&self) -> Result<(), BackendFailure> {
        let root = self.payload_root()?;
        let manager = ServiceManager::local_computer(
            None::<&str>,
            ServiceManagerAccess::CONNECT | ServiceManagerAccess::CREATE_SERVICE,
        )
        .map_err(|_| BackendFailure::EngineUnavailable)?;
        let info = ServiceInfo {
            name: OsString::from(SERVICE_NAME),
            display_name: OsString::from("Kenai VPN AmneziaWG 2.0 tunnel"),
            service_type: ServiceType::OWN_PROCESS,
            start_type: ServiceStartType::OnDemand,
            error_control: ServiceErrorControl::Normal,
            executable_path: root.join("amneziawg.exe"),
            launch_arguments: vec![
                OsString::from("/tunnelservice"),
                self.config_path.as_os_str().to_os_string(),
            ],
            dependencies: vec![
                ServiceDependency::Service(OsString::from("Nsi")),
                ServiceDependency::Service(OsString::from("TcpIp")),
            ],
            account_name: None,
            account_password: None,
        };
        let service = manager
            .create_service(&info, ServiceAccess::ALL_ACCESS)
            .map_err(|_| BackendFailure::Internal)?;
        service
            .set_config_service_sid_info(ServiceSidType::Unrestricted)
            .map_err(|_| BackendFailure::Internal)?;
        service
            .start::<&str>(&[])
            .map_err(|_| BackendFailure::Internal)?;
        wait_for_state(&service, ServiceState::Running, TIMEOUT)
            .map_err(|_| BackendFailure::ServerUnavailable)?;
        remove_if_present(&self.config_path)
    }

    fn cleanup_stale(&self) -> Result<(), BackendFailure> {
        let manager = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT)
            .map_err(|_| BackendFailure::EngineUnavailable)?;
        if let Ok(service) = manager.open_service(SERVICE_NAME, ServiceAccess::ALL_ACCESS) {
            if service
                .query_status()
                .map_err(|_| BackendFailure::Internal)?
                .current_state
                != ServiceState::Stopped
            {
                service.stop().map_err(|_| BackendFailure::Internal)?;
                wait_for_state(&service, ServiceState::Stopped, TIMEOUT)
                    .map_err(|_| BackendFailure::Internal)?;
            }
            service.delete().map_err(|_| BackendFailure::Internal)?;
        }
        remove_if_present(&self.config_path)?;
        remove_if_present(&self.runtime_root.join(format!("{TUNNEL_NAME}.conf.new")))
    }

    fn read_statistics(&self) -> Result<TunnelStatistics, BackendFailure> {
        self.verify_payloads()?;
        let output = Command::new(self.payload_root()?.join("awg.exe"))
            .args(["show", TUNNEL_NAME, "dump"])
            .output()
            .map_err(|_| BackendFailure::EngineUnavailable)?;
        if !output.status.success() || output.stdout.len() > 16 * 1024 {
            return Err(BackendFailure::Internal);
        }
        parse_statistics(&String::from_utf8(output.stdout).map_err(|_| BackendFailure::Internal)?)
    }
}

impl VpnBackend for AmneziaWgWindowsBackend {
    fn connect(
        &mut self,
        _id: &str,
        _profile: &WireGuardProfile,
        _kill_switch: bool,
    ) -> Result<(), BackendFailure> {
        Err(BackendFailure::UnsupportedFeature)
    }
    fn connect_amneziawg(
        &mut self,
        _id: &str,
        profile: &AmneziaWgProfile,
        kill_switch: bool,
    ) -> Result<(), BackendFailure> {
        if kill_switch {
            return Err(BackendFailure::UnsupportedFeature);
        }
        profile
            .validate()
            .map_err(|_| BackendFailure::InvalidProfile)?;
        self.cleanup_stale()?;
        self.verify_payloads()?;
        self.write_config(profile)?;
        if let Err(error) = self.start_service() {
            let _ = self.cleanup_stale();
            return Err(error);
        }
        Ok(())
    }
    fn disconnect(&mut self) -> Result<(), BackendFailure> {
        self.cleanup_stale()
    }
    fn is_connected(&self) -> Result<bool, BackendFailure> {
        let manager = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT)
            .map_err(|_| BackendFailure::EngineUnavailable)?;
        let Ok(service) = manager.open_service(SERVICE_NAME, ServiceAccess::QUERY_STATUS) else {
            return Ok(false);
        };
        Ok(service
            .query_status()
            .map_err(|_| BackendFailure::Internal)?
            .current_state
            == ServiceState::Running)
    }
    fn statistics(&self) -> Result<TunnelStatistics, BackendFailure> {
        self.read_statistics()
    }
}

fn render_config(profile: &AmneziaWgProfile) -> Zeroizing<String> {
    let base = &profile.wireguard;
    let endpoint = if base.endpoint_host.contains(':') {
        format!("[{}]", base.endpoint_host)
    } else {
        base.endpoint_host.clone()
    };
    let private_key = Zeroizing::new(STANDARD.encode(base.private_key.0));
    let mut config = Zeroizing::new(String::new());
    let _ = write!(
        config,
        "[Interface]\r\nPrivateKey = {}\r\nAddress = {}\r\n",
        private_key.as_str(),
        base.addresses.join(", ")
    );
    if !base.dns_servers.is_empty() {
        let _ = writeln!(
            config,
            "DNS = {}\r",
            base.dns_servers
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>()
                .join(", ")
        );
    }
    let _ = write!(config, "Jc = {}\r\nJmin = {}\r\nJmax = {}\r\nS1 = {}\r\nS2 = {}\r\nS3 = {}\r\nS4 = {}\r\nH1 = {}\r\nH2 = {}\r\nH3 = {}\r\nH4 = {}\r\n", profile.junk_packet_count, profile.junk_packet_min_size, profile.junk_packet_max_size, profile.init_packet_junk_size, profile.response_packet_junk_size, profile.init_packet_magic_header, profile.response_packet_magic_header, profile.transport_packet_magic_header, profile.init_packet_magic_header_value, profile.response_packet_magic_header_value, profile.transport_packet_magic_header_value);
    for (index, value) in profile.special_junk.iter().enumerate() {
        let _ = writeln!(config, "I{} = {}\r", index + 1, value);
    }
    let _ = write!(
        config,
        "\r\n[Peer]\r\nPublicKey = {}\r\n",
        STANDARD.encode(base.peer_public_key.0)
    );
    if let Some(key) = &base.preshared_key {
        let key = Zeroizing::new(STANDARD.encode(key.0));
        let _ = writeln!(config, "PresharedKey = {}\r", key.as_str());
    }
    let _ = write!(
        config,
        "Endpoint = {endpoint}:{}\r\nAllowedIPs = {}\r\n",
        base.endpoint_port,
        base.allowed_ips.join(", ")
    );
    if let Some(value) = base.persistent_keepalive {
        let _ = writeln!(config, "PersistentKeepalive = {value}\r");
    }
    config
}

fn parse_statistics(value: &str) -> Result<TunnelStatistics, BackendFailure> {
    let peer = value.lines().nth(1).ok_or(BackendFailure::Internal)?;
    let fields: Vec<&str> = peer.split('\t').collect();
    if fields.len() < 8 {
        return Err(BackendFailure::Internal);
    }
    let handshake = fields[4]
        .parse::<i64>()
        .map_err(|_| BackendFailure::Internal)?;
    Ok(TunnelStatistics {
        last_handshake_unix_ms: (handshake > 0).then_some(handshake.saturating_mul(1000)),
        bytes_received: fields[5].parse().map_err(|_| BackendFailure::Internal)?,
        bytes_sent: fields[6].parse().map_err(|_| BackendFailure::Internal)?,
    })
}

fn verify_hash(path: &PathBuf, expected: &str) -> Result<(), BackendFailure> {
    let bytes = fs::read(path).map_err(|_| BackendFailure::EngineUnavailable)?;
    let actual = format!("{:x}", Sha256::digest(bytes));
    if actual == expected {
        Ok(())
    } else {
        Err(BackendFailure::EngineUnavailable)
    }
}
fn remove_if_present(path: &PathBuf) -> Result<(), BackendFailure> {
    match fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(_) => Err(BackendFailure::Internal),
    }
}
fn wait_for_state(
    service: &windows_service::service::Service,
    expected: ServiceState,
    timeout: Duration,
) -> windows_service::Result<()> {
    let started = Instant::now();
    loop {
        if service.query_status()?.current_state == expected {
            return Ok(());
        }
        if started.elapsed() >= timeout {
            return Err(windows_service::Error::Winapi(io::Error::new(
                io::ErrorKind::TimedOut,
                "service transition timed out",
            )));
        }
        thread::sleep(Duration::from_millis(100));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn parses_only_awg_dump_counters() {
        let value = "private\tpublic\t51820\toff\npeer\t(none)\t1.2.3.4:1\t0.0.0.0/0\t1700000000\t120\t240\t25\n";
        let stats = parse_statistics(value).expect("valid dump");
        assert_eq!(stats.bytes_received, 120);
        assert_eq!(stats.bytes_sent, 240);
        assert_eq!(stats.last_handshake_unix_ms, Some(1_700_000_000_000));
    }
    #[test]
    fn committed_payload_hashes_match() {
        let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("..")
            .join("..")
            .join("third_party")
            .join("amneziawg")
            .join("windows")
            .join("amd64");
        verify_hash(&root.join("amneziawg.exe"), ENGINE_SHA256).expect("engine");
        verify_hash(&root.join("awg.exe"), TOOLS_SHA256).expect("tools");
        verify_hash(&root.join("wintun.dll"), WINTUN_SHA256).expect("wintun");
    }
}
