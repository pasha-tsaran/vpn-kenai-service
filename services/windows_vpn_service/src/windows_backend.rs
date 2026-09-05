use vpn_contracts::{AmneziaWgProfile, TunnelStatistics, VlessRealityProfile, WireGuardProfile};
use vpn_service_core::{BackendFailure, VpnBackend};

use super::{
    amneziawg_engine::AmneziaWgWindowsBackend, wireguard_engine::WireGuardWindowsBackend,
    xray_engine::XrayWindowsBackend,
};

#[derive(Clone, Copy, Debug)]
enum ActiveEngine {
    WireGuard,
    AmneziaWg,
    Xray,
}

#[derive(Debug)]
pub struct WindowsVpnBackend {
    wireguard: WireGuardWindowsBackend,
    amneziawg: AmneziaWgWindowsBackend,
    xray: XrayWindowsBackend,
    active: Option<ActiveEngine>,
}

impl WindowsVpnBackend {
    pub fn system_default() -> std::io::Result<Self> {
        Ok(Self {
            wireguard: WireGuardWindowsBackend::system_default()?,
            amneziawg: AmneziaWgWindowsBackend::system_default()?,
            xray: XrayWindowsBackend::system_default()?,
            active: None,
        })
    }

    fn disconnect_all(&mut self) -> Result<(), BackendFailure> {
        let wireguard = self.wireguard.disconnect();
        let amneziawg = self.amneziawg.disconnect();
        let xray = self.xray.disconnect();
        self.active = None;
        wireguard.and(amneziawg).and(xray)
    }
}

impl VpnBackend for WindowsVpnBackend {
    fn connect(
        &mut self,
        id: &str,
        profile: &WireGuardProfile,
        kill_switch: bool,
    ) -> Result<(), BackendFailure> {
        self.disconnect_all()?;
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
        self.disconnect_all()?;
        self.amneziawg.connect_amneziawg(id, profile, kill_switch)?;
        self.active = Some(ActiveEngine::AmneziaWg);
        Ok(())
    }
    fn connect_vless(
        &mut self,
        id: &str,
        profile: &VlessRealityProfile,
        kill_switch: bool,
    ) -> Result<(), BackendFailure> {
        self.disconnect_all()?;
        self.xray.connect_vless(id, profile, kill_switch)?;
        self.active = Some(ActiveEngine::Xray);
        Ok(())
    }
    fn disconnect(&mut self) -> Result<(), BackendFailure> {
        self.disconnect_all()
    }
    fn is_connected(&self) -> Result<bool, BackendFailure> {
        match self.active {
            Some(ActiveEngine::WireGuard) => self.wireguard.is_connected(),
            Some(ActiveEngine::AmneziaWg) => self.amneziawg.is_connected(),
            Some(ActiveEngine::Xray) => self.xray.is_connected(),
            None => Ok(false),
        }
    }
    fn statistics(&self) -> Result<TunnelStatistics, BackendFailure> {
        match self.active {
            Some(ActiveEngine::WireGuard) => self.wireguard.statistics(),
            Some(ActiveEngine::AmneziaWg) => self.amneziawg.statistics(),
            Some(ActiveEngine::Xray) => self.xray.statistics(),
            None => Err(BackendFailure::EngineUnavailable),
        }
    }
}
