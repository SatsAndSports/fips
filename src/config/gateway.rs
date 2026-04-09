//! Gateway configuration types.
//!
//! Configuration for the outbound LAN gateway (`gateway.*`).

use serde::{Deserialize, Serialize};

/// Default gateway DNS listen address.
const DEFAULT_DNS_LISTEN: &str = "[::]:53";

/// Default upstream DNS resolver (FIPS daemon).
const DEFAULT_DNS_UPSTREAM: &str = "127.0.0.1:5354";

/// Default DNS TTL in seconds.
const DEFAULT_DNS_TTL: u32 = 60;

/// Default pool grace period in seconds.
const DEFAULT_GRACE_PERIOD: u64 = 60;

/// Default conntrack TCP established timeout (5 days).
const DEFAULT_CT_TCP_ESTABLISHED: u64 = 432_000;

/// Default conntrack UDP timeout (unreplied).
const DEFAULT_CT_UDP_TIMEOUT: u64 = 30;

/// Default conntrack UDP assured timeout (bidirectional).
const DEFAULT_CT_UDP_ASSURED: u64 = 180;

/// Default conntrack ICMP timeout.
const DEFAULT_CT_ICMP_TIMEOUT: u64 = 30;

/// Gateway configuration (`gateway.*`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GatewayConfig {
    /// Enable the gateway (`gateway.enabled`, default: false).
    #[serde(default)]
    pub enabled: bool,

    /// Virtual IP pool CIDR (e.g., `fd01::/112`).
    pub pool: String,

    /// LAN-facing interface for proxy ARP/NDP.
    pub lan_interface: String,

    /// Gateway DNS configuration.
    #[serde(default)]
    pub dns: GatewayDnsConfig,

    /// Pool grace period in seconds after last session before reclamation.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pool_grace_period: Option<u64>,

    /// Conntrack timeout overrides.
    #[serde(default)]
    pub conntrack: ConntrackConfig,
}

impl GatewayConfig {
    /// Get pool grace period (default: 60 seconds).
    pub fn grace_period(&self) -> u64 {
        self.pool_grace_period.unwrap_or(DEFAULT_GRACE_PERIOD)
    }
}

/// Gateway DNS resolver configuration (`gateway.dns.*`).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct GatewayDnsConfig {
    /// Listen address and port (default: `0.0.0.0:53`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub listen: Option<String>,

    /// Upstream FIPS daemon DNS resolver (default: `127.0.0.1:5354`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub upstream: Option<String>,

    /// DNS record TTL in seconds (default: 60).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ttl: Option<u32>,
}

impl GatewayDnsConfig {
    /// Get the listen address (default: `0.0.0.0:53`).
    pub fn listen(&self) -> &str {
        self.listen.as_deref().unwrap_or(DEFAULT_DNS_LISTEN)
    }

    /// Get the upstream resolver address (default: `127.0.0.1:5354`).
    pub fn upstream(&self) -> &str {
        self.upstream.as_deref().unwrap_or(DEFAULT_DNS_UPSTREAM)
    }

    /// Get the TTL in seconds (default: 60).
    pub fn ttl(&self) -> u32 {
        self.ttl.unwrap_or(DEFAULT_DNS_TTL)
    }
}

/// Conntrack timeout overrides (`gateway.conntrack.*`).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ConntrackConfig {
    /// TCP established timeout in seconds.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tcp_established: Option<u64>,

    /// UDP unreplied timeout in seconds.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub udp_timeout: Option<u64>,

    /// UDP assured (bidirectional) timeout in seconds.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub udp_assured: Option<u64>,

    /// ICMP timeout in seconds.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub icmp_timeout: Option<u64>,
}

impl ConntrackConfig {
    /// TCP established timeout (default: 432000s / 5 days).
    pub fn tcp_established(&self) -> u64 {
        self.tcp_established.unwrap_or(DEFAULT_CT_TCP_ESTABLISHED)
    }

    /// UDP unreplied timeout (default: 30s).
    pub fn udp_timeout(&self) -> u64 {
        self.udp_timeout.unwrap_or(DEFAULT_CT_UDP_TIMEOUT)
    }

    /// UDP assured timeout (default: 180s).
    pub fn udp_assured(&self) -> u64 {
        self.udp_assured.unwrap_or(DEFAULT_CT_UDP_ASSURED)
    }

    /// ICMP timeout (default: 30s).
    pub fn icmp_timeout(&self) -> u64 {
        self.icmp_timeout.unwrap_or(DEFAULT_CT_ICMP_TIMEOUT)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_gateway_config_defaults() {
        let yaml = r#"
pool: "fd01::/112"
lan_interface: "eth0"
"#;
        let config: GatewayConfig = serde_yaml::from_str(yaml).unwrap();
        assert!(!config.enabled);
        assert_eq!(config.pool, "fd01::/112");
        assert_eq!(config.lan_interface, "eth0");
        assert_eq!(config.dns.listen(), "[::]:53");
        assert_eq!(config.dns.upstream(), "127.0.0.1:5354");
        assert_eq!(config.dns.ttl(), 60);
        assert_eq!(config.grace_period(), 60);
        assert_eq!(config.conntrack.tcp_established(), 432_000);
        assert_eq!(config.conntrack.udp_timeout(), 30);
    }

    #[test]
    fn test_gateway_config_custom() {
        let yaml = r#"
enabled: true
pool: "fd01::/112"
lan_interface: "enp3s0"
dns:
  listen: "192.168.1.1:53"
  upstream: "127.0.0.1:5354"
  ttl: 120
pool_grace_period: 30
conntrack:
  tcp_established: 3600
  udp_timeout: 60
"#;
        let config: GatewayConfig = serde_yaml::from_str(yaml).unwrap();
        assert!(config.enabled);
        assert_eq!(config.dns.listen(), "192.168.1.1:53");
        assert_eq!(config.dns.ttl(), 120);
        assert_eq!(config.grace_period(), 30);
        assert_eq!(config.conntrack.tcp_established(), 3600);
        assert_eq!(config.conntrack.udp_timeout(), 60);
        // Unset fields use defaults
        assert_eq!(config.conntrack.udp_assured(), 180);
        assert_eq!(config.conntrack.icmp_timeout(), 30);
    }

    #[test]
    fn test_root_config_with_gateway() {
        let yaml = r#"
gateway:
  enabled: true
  pool: "fd01::/112"
  lan_interface: "eth0"
"#;
        let config: crate::Config = serde_yaml::from_str(yaml).unwrap();
        assert!(config.gateway.is_some());
        let gw = config.gateway.unwrap();
        assert!(gw.enabled);
        assert_eq!(gw.pool, "fd01::/112");
    }

    #[test]
    fn test_root_config_without_gateway() {
        let yaml = "node: {}";
        let config: crate::Config = serde_yaml::from_str(yaml).unwrap();
        assert!(config.gateway.is_none());
    }
}
