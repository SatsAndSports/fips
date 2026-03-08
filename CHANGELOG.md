# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Ethernet transport with beacon discovery and auto-connect
- TCP transport with configurable bind address and static peer support
- Docker sidecar deployment for containerized services
- Comprehensive node and transport statistics via control socket
- fipstop TUI monitoring tool with smoothed metrics and quality indices
- ECN congestion signaling and transport congestion detection
- Persistent identity with key file management (`fipsctl keygen`)
- Periodic Noise rekey with fresh DH for forward secrecy (FMP + FSP)
- Host-to-npub static mapping: resolve `hostname.fips` via host map
  populated from peer config aliases and `/etc/fips/hosts` file
- DNS responder auto-reloads hosts file on modification (no restart needed)
- Systemd service packaging with tarball installer
- Build version metadata: git commit hash, dirty flag, and target triple
  embedded in all binaries via `--version`
- CHANGELOG.md following Keep a Changelog format

### Fixed

- Spanning tree coordinate loop: reject parents whose ancestry contains us
- PMTUD per-destination path MTU check and ICMPv6 MTU field width
- Ethernet AEAD decryption failures caused by minimum-frame padding
- Link-dead detection skipping peers that never send data
- FMP version check added to TCP stream reader

### Changed

- GitHub repository moved from `jmcorgan/fips` to `fips-network/fips`

## [0.1.0-alpha] - 2026-02-24

### Added

- Core mesh routing protocol with greedy coordinate-based forwarding
- Noise IK handshake at FMP (link layer) and Noise XK at FSP (session layer)
- UDP transport with configurable bind address and static peers
- TUN-based virtual network interface (fips0) with ICMPv6 Packet Too Big
- DNS resolver for .fips domain names (port 5354)
- Spanning tree construction with cost-based parent selection and
  flap dampening
- Bloom filter-based identity discovery protocol with reverse-path routing
- MMP (Mesh Management Protocol) for link and session layer measurement
- Hybrid coordinate warmup (CoordsWarmup message and proactive fallback)
- Handshake retry with exponential backoff (link and session layer)
- Link-layer heartbeat and liveness timeout for dead peer detection
- Epoch-based peer restart detection
- Per-link MTU support and reactive MtuExceeded error signal
- Session idle timeout and identity cache expiry
- Unix domain control socket for runtime observability (fipsctl)
- Docker test harness with static and stochastic topologies
- CI with GitHub Actions (x86_64 and aarch64, unit and integration tests)
- Design documentation suite covering all protocol layers
