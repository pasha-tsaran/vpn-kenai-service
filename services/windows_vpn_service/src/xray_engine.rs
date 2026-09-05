use std::{
    ffi::c_void,
    fmt::Write as _,
    fs,
    io::{self, Write},
    mem::size_of,
    os::windows::{io::AsRawHandle, process::CommandExt},
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    ptr, thread,
    time::Duration,
};

use sha2::{Digest, Sha256};
use vpn_contracts::{TunnelStatistics, VlessRealityProfile, WireGuardProfile};
use vpn_service_core::{BackendFailure, VpnBackend};
use windows_sys::Win32::{
    Foundation::{CloseHandle, HANDLE, STILL_ACTIVE},
    System::{
        JobObjects::{
            AssignProcessToJobObject, CreateJobObjectW, JobObjectExtendedLimitInformation,
            SetInformationJobObject, TerminateJobObject, JOBOBJECT_EXTENDED_LIMIT_INFORMATION,
            JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
        },
        Threading::GetExitCodeProcess,
    },
};
use zeroize::Zeroizing;

use super::profile_vault::apply_service_acl;

const XRAY_SHA256: &str = "15c2d007954ac53ba69b80ec91242786b3c0b71d52649165b4ca1d5cc96ef8f1";
const WINTUN_SHA256: &str = "e5da8447dc2c320edc0fc52fa01885c103de8c118481f683643cacc3220dafce";
const CREATE_NO_WINDOW: u32 = 0x0800_0000;
const START_GRACE: Duration = Duration::from_millis(750);

#[derive(Debug)]
struct KillOnCloseJob(HANDLE);

impl KillOnCloseJob {
    fn create() -> Result<Self, BackendFailure> {
        // SAFETY: no security attributes or global name are supplied.
        let handle = unsafe { CreateJobObjectW(ptr::null(), ptr::null()) };
        if handle.is_null() {
            return Err(BackendFailure::Internal);
        }
        let mut information = JOBOBJECT_EXTENDED_LIMIT_INFORMATION::default();
        information.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
        let length = u32::try_from(size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>())
            .map_err(|_| BackendFailure::Internal)?;
        // SAFETY: `information` is initialized and valid for `length` bytes.
        let configured = unsafe {
            SetInformationJobObject(
                handle,
                JobObjectExtendedLimitInformation,
                ptr::from_ref(&information).cast::<c_void>(),
                length,
            )
        };
        if configured == 0 {
            // SAFETY: `handle` is owned and closed exactly once on this path.
            unsafe { CloseHandle(handle) };
            return Err(BackendFailure::Internal);
        }
        Ok(Self(handle))
    }

    fn assign(&self, child: &Child) -> Result<(), BackendFailure> {
        let process = child.as_raw_handle().cast::<c_void>();
        // SAFETY: both handles are live for the duration of this call.
        if unsafe { AssignProcessToJobObject(self.0, process) } == 0 {
            return Err(BackendFailure::Internal);
        }
        Ok(())
    }

    fn terminate(&self) -> Result<(), BackendFailure> {
        // SAFETY: the job handle remains owned by `self`.
        if unsafe { TerminateJobObject(self.0, 1) } == 0 {
            Err(BackendFailure::Internal)
        } else {
            Ok(())
        }
    }
}

impl Drop for KillOnCloseJob {
    fn drop(&mut self) {
        // Closing the last job handle is the crash-recovery boundary: every
        // assigned Xray process is terminated by the kernel.
        unsafe { CloseHandle(self.0) };
    }
}

#[derive(Debug)]
struct XrayProcess {
    child: Child,
    job: KillOnCloseJob,
}

impl XrayProcess {
    fn is_running(&self) -> Result<bool, BackendFailure> {
        let mut code = 0_u32;
        let handle = self.child.as_raw_handle().cast::<c_void>();
        // SAFETY: the child owns a live process handle and `code` is writable.
        if unsafe { GetExitCodeProcess(handle, ptr::addr_of_mut!(code)) } == 0 {
            return Err(BackendFailure::Internal);
        }
        Ok(code == STILL_ACTIVE as u32)
    }

    fn stop(mut self) -> Result<(), BackendFailure> {
        if self.job.terminate().is_err() {
            self.child
                .kill()
                .map_err(|_| BackendFailure::Internal)?;
        }
        self.child.wait().map_err(|_| BackendFailure::Internal)?;
        Ok(())
    }
}

#[derive(Debug)]
pub struct XrayWindowsBackend {
    executable: PathBuf,
    runtime_root: PathBuf,
    config_path: PathBuf,
    process: Option<XrayProcess>,
}

impl XrayWindowsBackend {
    pub fn system_default() -> io::Result<Self> {
        let executable = std::env::current_exe()?;
        let program_data = std::env::var_os("ProgramData")
            .filter(|value| !value.is_empty())
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "ProgramData unavailable"))?;
        let runtime_root = PathBuf::from(program_data).join("KenaiVPN").join("runtime");
        fs::create_dir_all(&runtime_root)?;
        apply_service_acl(&runtime_root)?;
        let config_path = runtime_root.join("KenaiXray.json");
        remove_if_present(&config_path).map_err(|_| io::Error::other("Xray cleanup failed"))?;
        Ok(Self {
            executable,
            runtime_root,
            config_path,
            process: None,
        })
    }

    fn payload_root(&self) -> Result<PathBuf, BackendFailure> {
        self.executable
            .parent()
            .map(|root| root.join("xray").join("amd64"))
            .ok_or(BackendFailure::EngineUnavailable)
    }

    fn verify_payloads(&self) -> Result<(), BackendFailure> {
        let root = self.payload_root()?;
        verify_hash(&root.join("xray.exe"), XRAY_SHA256)?;
        verify_hash(&root.join("wintun.dll"), WINTUN_SHA256)
    }

    fn write_config(&self, profile: &VlessRealityProfile) -> Result<(), BackendFailure> {
        let temporary = self.runtime_root.join("KenaiXray.json.new");
        remove_if_present(&temporary)?;
        let rendered = render_config(profile);
        let mut file = fs::OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(&temporary)
            .map_err(|_| BackendFailure::Internal)?;
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

    fn command(&self) -> Result<Command, BackendFailure> {
        let mut command = Command::new(self.payload_root()?.join("xray.exe"));
        command
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .creation_flags(CREATE_NO_WINDOW);
        Ok(command)
    }

    fn validate_config(&self) -> Result<(), BackendFailure> {
        let status = self
            .command()?
            .args(["run", "-test", "-config"])
            .arg(&self.config_path)
            .status()
            .map_err(|_| BackendFailure::EngineUnavailable)?;
        if status.success() {
            Ok(())
        } else {
            Err(BackendFailure::InvalidProfile)
        }
    }

    fn start(&mut self) -> Result<(), BackendFailure> {
        let job = KillOnCloseJob::create()?;
        let mut child = self
            .command()?
            .args(["run", "-config"])
            .arg(&self.config_path)
            .spawn()
            .map_err(|_| BackendFailure::EngineUnavailable)?;
        if let Err(error) = job.assign(&child) {
            let _ = child.kill();
            let _ = child.wait();
            return Err(error);
        }
        thread::sleep(START_GRACE);
        if child
            .try_wait()
            .map_err(|_| BackendFailure::Internal)?
            .is_some()
        {
            return Err(BackendFailure::ServerUnavailable);
        }
        self.process = Some(XrayProcess { child, job });
        remove_if_present(&self.config_path)
    }

    fn cleanup(&mut self) -> Result<(), BackendFailure> {
        let process_result = self.process.take().map_or(Ok(()), XrayProcess::stop);
        let config_result = remove_if_present(&self.config_path);
        let temporary_result = remove_if_present(&self.runtime_root.join("KenaiXray.json.new"));
        process_result.and(config_result).and(temporary_result)
    }
}

impl VpnBackend for XrayWindowsBackend {
    fn connect(
        &mut self,
        _id: &str,
        _profile: &WireGuardProfile,
        _kill_switch: bool,
    ) -> Result<(), BackendFailure> {
        Err(BackendFailure::UnsupportedFeature)
    }
    fn connect_vless(
        &mut self,
        _id: &str,
        profile: &VlessRealityProfile,
        kill_switch: bool,
    ) -> Result<(), BackendFailure> {
        if kill_switch {
            return Err(BackendFailure::UnsupportedFeature);
        }
        profile
            .validate()
            .map_err(|_| BackendFailure::InvalidProfile)?;
        self.cleanup()?;
        self.verify_payloads()?;
        self.write_config(profile)?;
        if let Err(error) = self.validate_config().and_then(|()| self.start()) {
            let _ = self.cleanup();
            return Err(error);
        }
        Ok(())
    }
    fn disconnect(&mut self) -> Result<(), BackendFailure> {
        self.cleanup()
    }
    fn is_connected(&self) -> Result<bool, BackendFailure> {
        self.process
            .as_ref()
            .map_or(Ok(false), XrayProcess::is_running)
    }
    fn statistics(&self) -> Result<TunnelStatistics, BackendFailure> {
        if !self.is_connected()? {
            return Err(BackendFailure::EngineUnavailable);
        }
        Ok(TunnelStatistics {
            bytes_received: 0,
            bytes_sent: 0,
            last_handshake_unix_ms: None,
        })
    }
}

impl Drop for XrayWindowsBackend {
    fn drop(&mut self) {
        let _ = self.cleanup();
    }
}

fn render_config(profile: &VlessRealityProfile) -> Zeroizing<String> {
    let mut config = Zeroizing::new(String::new());
    let _ = write!(config,
        "{{\"log\":{{\"loglevel\":\"none\"}},\"inbounds\":[{{\"tag\":\"kenai-tun\",\"protocol\":\"tun\",\"settings\":{{\"name\":\"KenaiXray\",\"desc\":\"Kenai VPN Xray\",\"mtu\":1500,\"gateway\":[\"10.254.0.1/30\",\"fd00:6b65:6e61:69::1/126\"],\"dns\":[\"1.1.1.1\",\"2606:4700:4700::1111\"],\"autoSystemRoutingTable\":[\"0.0.0.0/0\",\"::/0\"],\"autoOutboundsInterface\":\"auto\"}}}}],\"outbounds\":[{{\"tag\":\"proxy\",\"protocol\":\"vless\",\"settings\":{{\"address\":\"{}\",\"port\":{},\"id\":\"{}\",\"encryption\":\"none\",\"flow\":\"xtls-rprx-vision\"}},\"streamSettings\":{{\"network\":\"raw\",\"security\":\"reality\",\"realitySettings\":{{\"serverName\":\"{}\",\"fingerprint\":\"{}\",\"password\":\"{}\",\"shortId\":\"{}\",\"spiderX\":\"/\"}}}}}}]}}",
        profile.endpoint_host, profile.endpoint_port, profile.client_id, profile.server_name,
        profile.fingerprint, profile.reality_password, profile.short_id);
    config
}

fn verify_hash(path: &Path, expected: &str) -> Result<(), BackendFailure> {
    let bytes = fs::read(path).map_err(|_| BackendFailure::EngineUnavailable)?;
    let actual = format!("{:x}", Sha256::digest(bytes));
    if actual == expected {
        Ok(())
    } else {
        Err(BackendFailure::EngineUnavailable)
    }
}
fn remove_if_present(path: &Path) -> Result<(), BackendFailure> {
    match fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(_) => Err(BackendFailure::Internal),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn profile() -> VlessRealityProfile {
        let groups = [8_usize, 4, 4, 4, 12];
        let client_id = groups
            .iter()
            .map(|length| "a".repeat(*length))
            .collect::<Vec<_>>()
            .join("-");
        VlessRealityProfile {
            client_id,
            endpoint_host: "vpn.example.test".into(),
            endpoint_port: 443,
            server_name: "cover.example.test".into(),
            fingerprint: "chrome".into(),
            reality_password: "A".repeat(43),
            short_id: "aabbccdd".into(),
            spider_x: "/".into(),
        }
    }
    #[test]
    fn rendered_config_is_a_full_tun_and_never_enables_logs() {
        let config = render_config(&profile());
        assert!(config.contains("\"protocol\":\"tun\""));
        assert!(config.contains("\"autoSystemRoutingTable\":[\"0.0.0.0/0\",\"::/0\"]"));
        assert!(config.contains("\"security\":\"reality\""));
        assert!(config.contains("\"loglevel\":\"none\""));
    }
    #[test]
    fn committed_payload_hashes_match() {
        let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("..")
            .join("..")
            .join("third_party")
            .join("xray")
            .join("windows")
            .join("amd64");
        verify_hash(&root.join("xray.exe"), XRAY_SHA256).expect("xray");
        verify_hash(&root.join("wintun.dll"), WINTUN_SHA256).expect("wintun");
    }

    #[test]
    #[ignore = "Xray TUN validation opens Wintun and requires an elevated Windows token"]
    fn pinned_xray_accepts_rendered_configuration() {
        let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("..")
            .join("..")
            .join("third_party")
            .join("xray")
            .join("windows")
            .join("amd64");
        let config_path = std::env::temp_dir().join(format!(
            "kenai-xray-config-test-{}.json",
            std::process::id()
        ));
        fs::write(&config_path, render_config(&profile()).as_bytes()).expect("write config");
        let result = Command::new(root.join("xray.exe"))
            .args(["run", "-test", "-config"])
            .arg(&config_path)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .creation_flags(CREATE_NO_WINDOW)
            .status();
        let _ = fs::remove_file(config_path);
        assert!(result.expect("run pinned Xray").success());
    }
}
