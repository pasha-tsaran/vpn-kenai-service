use vpn_contracts::{AmneziaWgProfile, TunnelStatistics, WireGuardProfile};
use vpn_service_core::{BackendFailure, VpnBackend};

use super::{amneziawg_engine::AmneziaWgWindowsBackend, wireguard_engine::WireGuardWindowsBackend};

#[derive(Clone, Copy, Debug)]
enum ActiveEngine {
    WireGuard,
    AmneziaWg,
}

#[derive(Debug)]
pub struct WindowsVpnBackend {
    wireguard: WireGuardWindowsBackend,
    amneziawg: AmneziaWgWindowsBackend,
    active: Option<ActiveEngine>,
}

impl WindowsVpnBackend {
    pub fn system_default() -> std::io::Result<Self> {
        Ok(Self {
            wireguard: WireGuardWindowsBackend::system_default()?,
            amneziawg: AmneziaWgWindowsBackend::system_default()?,
            active: None,
        })
    }
}

impl VpnBackend for WindowsVpnBackend {
    fn connect(
        &mut self,
        id: &str,
        profile: &WireGuardProfile,
        kill_switch: bool,
    ) -> Result<(), BackendFailure> {
        self.amneziawg.disconnect()?;
        self.wireguard.connect(id, profile, kill_switch)?;
        self.active = Some(ActiveEngine::WireGuard);
        Ok(())
    }
    fn connect_amneziawg(
        &mut self,
        id: &str,
        profile: &AmneziaWgProfile,
        kill_switch: bool,
    ) -> Result<(), BackendFailure> {
        self.wireguard.disconnect()?;
        self.amneziawg.connect_amneziawg(id, profile, kill_switch)?;
        self.active = Some(ActiveEngine::AmneziaWg);
        Ok(())
    }
    fn disconnect(&mut self) -> Result<(), BackendFailure> {
        self.wireguard.disconnect()?;
        self.amneziawg.disconnect()?;
        self.active = None;
        Ok(())
    }
    fn is_connected(&self) -> Result<bool, BackendFailure> {
        match self.active {
            Some(ActiveEngine::WireGuard) => self.wireguard.is_connected(),
            Some(ActiveEngine::AmneziaWg) => self.amneziawg.is_connected(),
            None => Ok(false),
        }
    }
    fn statistics(&self) -> Result<TunnelStatistics, BackendFailure> {
        match self.active {
            Some(ActiveEngine::WireGuard) => self.wireguard.statistics(),
            Some(ActiveEngine::AmneziaWg) => self.amneziawg.statistics(),
            None => Err(BackendFailure::EngineUnavailable),
        }
    }
}
