# Changelog

## [1.0.0] - 2026-02-01

### Initial Release

#### Security
- Fixed vulnerability **RUSTSEC-2025-0026** by removing unused `eventlog` dependency.

#### Dependencies
- Updated `human-panic` to 2.0.6.
- Stabilized project dependencies.

#### Features
- ✅ Real-time process monitoring (CPU, memory, status)
- ✅ Process details view with live updates
- ✅ Kill processes (admin privileges required)
- ✅ Multi-core CPU usage graphs
- ✅ Memory and swap monitoring
- ✅ Disk space information
- ✅ Network interfaces display
- ✅ System uptime tracking

#### Wi-Fi Monitoring
- ✅ Complete Wi-Fi connection details (SSID, BSSID, channel, frequency)
- ✅ 802.1x authentication detection (PEAP, EAP-TLS, MSCHAPv2)
- ✅ Signal strength and connection rates
- ✅ Security details (auth & cipher)

#### System Events
- ✅ Windows Event Log integration
- ✅ System errors and warnings monitoring
- ✅ Detailed event viewer

#### Smart Features
- ✅ Bilingual support (EN/FR) with auto-detection
- ✅ UTF-8 detection with ASCII fallback for legacy terminals
- ✅ Admin/User privilege detection with visual badge
- ✅ Configurable refresh rate (1s/2s/5s)
- ✅ Mouse support (scroll, click navigation)
- ✅ Process-by-PID tracking (stable across refreshes)

### Technical
- Rust edition 2024
- Optimized for size (LTO, codegen-units=1)
- Fully portable (no runtime dependencies)
- Windows 7+ compatible
