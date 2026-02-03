use anyhow::Result;
use chrono::{DateTime, Duration as ChronoDuration, Local};
use crossterm::{
    event::{self, DisableMouseCapture, EnableMouseCapture, Event, KeyCode},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use ratatui::{
    backend::CrosstermBackend,
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    widgets::{Block, Borders, Cell, Gauge, Paragraph, Row, Table, TableState},
    Frame, Terminal,
};
use std::{
    io,
    time::{Duration, Instant},
};
use sysinfo::{System, ProcessStatus, Networks, Disks, Pid, Users};
use sys_locale::get_locale;

enum ViewMode {
    Processes,
    SystemEvents,
    WifiDetails,
    EventDetail,
    ProcessDetail,
    About,
}

#[derive(Clone, Copy)]
enum Language {
    En,
    Fr,
}

struct App {
    system: System,
    networks: Networks,
    disks: Disks,
    users: Users,
    process_table_state: TableState,
    event_table_state: TableState,
    processes: Vec<ProcessInfo>,
    system_errors: Vec<EventInfo>,
    sort_column: SortColumn,
    view_mode: ViewMode,
    wifi_info: Option<WifiInfo>,
    ccm_status: Option<CcmStatus>,
    os_info: String,
    host_info: String,
    username: String,
    last_wifi_update: Instant,
    last_errors_update: Instant,
    message: String,
    message_time: Option<Instant>,
    lang: Language,
    refresh_rate: Duration,
    is_admin: bool,
    selected_process_pid: Option<String>,
    supports_utf8: bool,
    demo_mode: bool,
}

struct EventInfo {
    time: String,
    raw_time: String,
    source: String,
    id: String,
    message: String,
}

struct WifiInfo {
    ssid: String,
    bssid: String,
    standard: String,
    auth: String,
    cipher: String,
    channel: String,
    frequency: String,
    rx_rate: String,
    tx_rate: String,
    signal: String,
    ip_address: String,
    log_details: String,
}

#[derive(Clone)]
struct CcmStatus {
    running: bool,
    status: String,
    has_errors: bool,
    pending_actions: u32,
}

#[derive(PartialEq)]
enum SortColumn {
    Pid,
    Name,
    Cpu,
    Mem,
}

struct ProcessInfo {
    pid: String,
    name: String,
    user: String,
    priority: String,
    virt_mem: u64,
    res_mem: u64,
    status: String,
    cpu: f32,
    mem_percent: f32,
    cmd: String,
}

impl App {
    fn new(demo_mode: bool) -> App {
        let mut system = System::new_all();
        system.refresh_all();
        let networks = Networks::new_with_refreshed_list();
        let disks = Disks::new_with_refreshed_list();
        let users = Users::new_with_refreshed_list();
        let os_info = format!("{} {}", System::name().unwrap_or_default(), System::os_version().unwrap_or_default());
        let host_info = if demo_mode { "DEMO-PC".to_string() } else { System::host_name().unwrap_or("Unknown".to_string()) };
        let username = if demo_mode { "demo_user".to_string() } else { std::env::var("USERNAME").unwrap_or_else(|_| "Unknown".to_string()) };
        let is_admin = Self::is_elevated();
        let supports_utf8 = Self::supports_utf8();
        
        App {
            system,
            networks,
            disks,
            users,
            process_table_state: TableState::default(),
            event_table_state: TableState::default(),
            processes: Vec::new(),
            system_errors: Vec::new(),
            sort_column: SortColumn::Cpu,
            view_mode: ViewMode::Processes,
            wifi_info: None,
            ccm_status: Self::get_ccm_status(),
            os_info,
            host_info,
            username,
            last_wifi_update: Instant::now() - Duration::from_secs(60),
            last_errors_update: Instant::now() - Duration::from_secs(60),
            message: String::new(),
            message_time: None,
            lang: Self::detect_language(),
            refresh_rate: Duration::from_secs(2),
            is_admin,
            selected_process_pid: None,
            supports_utf8,
            demo_mode,
        }
    }

    fn detect_language() -> Language {
        // Force English if terminal doesn't support UTF-8 (to avoid accent issues)
        let supports_utf8 = Self::supports_utf8();
        if !supports_utf8 {
            return Language::En;
        }
        
        if let Some(locale) = get_locale() {
            let lower = locale.to_lowercase();
            if lower.starts_with("fr") {
                return Language::Fr;
            }
        }
        Language::En
    }

    fn is_elevated() -> bool {
        use windows::Win32::Foundation::HANDLE;
        use windows::Win32::Security::{GetTokenInformation, TokenElevation, TOKEN_ELEVATION, TOKEN_QUERY};
        use windows::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};
        
        unsafe {
            let mut token: HANDLE = HANDLE::default();
            if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token).is_err() {
                return false;
            }
            
            let mut elevation = TOKEN_ELEVATION { TokenIsElevated: 0 };
            let mut return_length: u32 = 0;
            
            if GetTokenInformation(
                token,
                TokenElevation,
                Some(&mut elevation as *mut _ as *mut _),
                std::mem::size_of::<TOKEN_ELEVATION>() as u32,
                &mut return_length,
            ).is_ok() {
                elevation.TokenIsElevated != 0
            } else {
                false
            }
        }
    }

    fn supports_utf8() -> bool {
        use windows::Win32::System::Console::GetConsoleOutputCP;
        // Check if console output code page is UTF-8 (65001)
        unsafe {
            GetConsoleOutputCP() == 65001
        }
    }

    fn t(&self, en: &str, fr: &str) -> String {
        match self.lang {
            Language::En => en.to_string(),
            Language::Fr => fr.to_string(),
        }
    }

    fn update(&mut self) {
        self.system.refresh_all();
        self.networks.refresh(true);
        self.disks.refresh(true);
        let total_mem = self.system.total_memory() as f32;
        
        if self.last_wifi_update.elapsed() > Duration::from_secs(10) {
            self.wifi_info = self.get_wifi_details();
            self.last_wifi_update = Instant::now();
        }

        if self.last_errors_update.elapsed() > Duration::from_secs(30) {
            self.system_errors = self.get_system_errors_detailed();
            self.last_errors_update = Instant::now();
        }

        let mut processes: Vec<ProcessInfo> = self.system.processes()
            .iter()
            .map(|(pid, p)| {
                let user = p.user_id()
                    .and_then(|uid| self.users.iter().find(|u| u.id() == uid))
                    .map(|u| u.name().to_string())
                    .unwrap_or_else(|| "N/A".to_string());
                
                let cmd_parts: Vec<String> = p.cmd().iter().map(|s| s.to_string_lossy().into_owned()).collect();
                let cmd = cmd_parts.join(" ");
                let cmd_display = if cmd.is_empty() { p.name().to_string_lossy().into_owned() } else { cmd };

                ProcessInfo {
                    pid: pid.to_string(),
                    name: p.name().to_string_lossy().into_owned(),
                    user,
                    priority: "0".to_string(),
                    virt_mem: p.virtual_memory(),
                    res_mem: p.memory(),
                    status: match p.status() {
                        ProcessStatus::Run => "R",
                        ProcessStatus::Sleep => "S",
                        ProcessStatus::Idle => "I",
                        ProcessStatus::Dead => "D",
                        ProcessStatus::Stop => "T",
                        _ => "?",
                    }.to_string(),
                    cpu: p.cpu_usage(),
                    mem_percent: (p.memory() as f32 / total_mem) * 100.0,
                    cmd: cmd_display,
                }
            })
            .collect();
        
        // Don't sort when viewing process details to keep the selected process stable
        if !matches!(self.view_mode, ViewMode::ProcessDetail) {
            match self.sort_column {
                SortColumn::Cpu => processes.sort_by(|a, b| b.cpu.partial_cmp(&a.cpu).unwrap_or(std::cmp::Ordering::Equal)),
                SortColumn::Mem => processes.sort_by(|a, b| b.res_mem.cmp(&a.res_mem)),
                SortColumn::Pid => processes.sort_by(|a, b| a.pid.cmp(&b.pid)),
                SortColumn::Name => processes.sort_by(|a, b| a.name.cmp(&b.name)),
            }
        }
        
        self.processes = processes;
    }

    fn get_system_errors_detailed(&self) -> Vec<EventInfo> {
        use windows::Win32::System::EventLog::*;

        use std::fs::OpenOptions;
        use std::io::Write;

        // Debug: Clear log file
        let _ = std::fs::write("debug_events.log", "");
        let mut debug_file = OpenOptions::new()
            .create(true)
            .append(true)
            .open("debug_events.log")
            .ok();

        let mut fetch_channel = |channel_name: &str| -> Vec<EventInfo> {
            unsafe {
                let query = windows::core::w!("*[System[(Level=1 or Level=2)]]"); // Errors & Criticals only
                let channel_wide = windows::core::HSTRING::from(channel_name);
                let channel_pcwstr = windows::core::PCWSTR(channel_wide.as_ptr());

                let query_handle = match EvtQuery(None, channel_pcwstr, query, 0x201u32) {
                    Ok(handle) => handle,
                    Err(e) => {
                        if let Some(f) = &mut debug_file {
                            writeln!(f, "Failed to query {}: {:?}", channel_name, e).ok();
                        }
                        return vec![EventInfo {
                            time: "Error".to_string(),
                            raw_time: String::new(),
                            source: channel_name.to_string(),
                            id: "ERR".to_string(),
                            message: format!("Failed to query {} log: {:?}", channel_name, e),
                        }];
                    }
                };

                let cutoff_time = Local::now() - ChronoDuration::try_hours(48).unwrap_or(ChronoDuration::hours(48));
                let mut channel_events = Vec::new();
                let mut events_buf: [isize; 10] = [0; 10];
                let mut returned: u32 = 0;

                // Limit to 50 events per channel for performance, as requested
                while channel_events.len() < 50 {
                    let result = EvtNext(query_handle, &mut events_buf, 0, 0, &mut returned);
                    if result.is_err() || returned == 0 {
                        break;
                    }

                    for &event_raw in events_buf.iter().take(returned as usize) {
                        let event_handle = EVT_HANDLE(event_raw);
                        let mut buffer_size: u32 = 0;
                        let mut buffer_used: u32 = 0;
                        let mut property_count: u32 = 0;

                        let _ = EvtRender(None, event_handle, 1u32, buffer_size, None, &mut buffer_used, &mut property_count);
                        
                        buffer_size = buffer_used;
                        let mut buffer: Vec<u16> = vec![0; (buffer_size / 2) as usize];
                        
                        let render_result = EvtRender(None, event_handle, 1u32, buffer_size, Some(buffer.as_mut_ptr() as *mut _), &mut buffer_used, &mut property_count);

                        if render_result.is_ok() {
                            let xml = String::from_utf16_lossy(&buffer);
                            
                            // Check time first to exit early
                            if let Some(start) = xml.find("TimeCreated SystemTime=") {
                                let s = &xml[start + "TimeCreated SystemTime=".len()..];
                                if let Some(quote) = s.chars().next()
                                    && let Some(time_end) = s[1..].find(quote) {
                                        let time_str = &s[1..1 + time_end];
                                        if let Ok(dt) = DateTime::parse_from_rfc3339(time_str)
                                            && dt < cutoff_time {
                                                let _ = EvtClose(event_handle);
                                                // Since we fetch in reverse order (newest first), 
                                                // if we hit an old event, we can stop entirely.
                                                // BUT we are in a loop over a buffer of events.
                                                // We should break the outer loop too.
                                                // We'll handle this by returning from the closure? 
                                                // No, closure needs to return specific type.
                                                // We set a flag or break labels.
                                                // Easier: empty the buffer and break.
                                                // But we are in inner loop.
                                                // We need to return the events collected so far.
                                                let _ = EvtClose(query_handle); 
                                                return channel_events; 
                                            }
                                    }
                            }

                            // ... rest of processing ...
                            let event_id = xml.split("<EventID").nth(1).and_then(|s| {
                                let content_start = s.find('>')? + 1;
                                let content_end = s[content_start..].find("</EventID>")?;
                                Some(s[content_start..content_start + content_end].to_string())
                            }).unwrap_or_else(|| "N/A".to_string());
                            
                            let provider = xml.find("Provider Name=")
                                .and_then(|start| {
                                    let s = &xml[start + "Provider Name=".len()..];
                                    let quote = s.chars().next()?; // ' or "
                                    let name_end = s[1..].find(quote)?;
                                    Some(s[1..1 + name_end].to_string())
                                })
                                .unwrap_or_else(|| channel_name.to_string());
                            
                            let (time_fmt, raw_time) = xml.find("TimeCreated SystemTime=")
                                .and_then(|start| {
                                    let s = &xml[start + "TimeCreated SystemTime=".len()..];
                                    let quote = s.chars().next()?;
                                    let time_end = s[1..].find(quote)?;
                                    let time_str = &s[1..1 + time_end];
                                
                                    let formatted = if let Ok(dt) = DateTime::parse_from_rfc3339(time_str) {
                                        dt.with_timezone(&Local).format("%d/%m %H:%M").to_string()
                                    } else {
                                        // Fallback manual parsing if chrono fails
                                        if let Some((date_part, time_part)) = time_str.split_once('T') {
                                            let time_clean = time_part.split('.').next().unwrap_or(time_part);
                                            let parts: Vec<&str> = date_part.split('-').collect();
                                            if parts.len() == 3 {
                                                format!("{}/{} {} UTC", parts[2], parts[1], time_clean)
                                            } else {
                                                format!("{} {} UTC", date_part, time_clean)
                                            }
                                        } else {
                                            time_str.to_string()
                                        }
                                    };
                                    Some((formatted, time_str.to_string()))
                                })
                                .unwrap_or_else(|| ("N/A".to_string(), "".to_string()));

                            if let Some(f) = &mut debug_file {
                                writeln!(f, "Channel: {}\nID: {}\nProv: {}\nTime: {}\nRawXML: {}\n--", 
                                    channel_name, event_id, provider, raw_time, 
                                    xml.chars().take(300).collect::<String>().replace("\n", " ")
                                ).ok();
                            }

                            let mut msg_buffer_used: u32 = 0;
                            let _ = EvtFormatMessage(None, Some(event_handle), 0, None, 1u32, None, &mut msg_buffer_used);
                            
                            let msg_buffer_size = msg_buffer_used;
                            let mut msg_buffer: Vec<u16> = vec![0; msg_buffer_size as usize];
                            
                            let mut full_message = String::new();
                            let mut found_msg = false;

                            if msg_buffer_size > 0
                                && EvtFormatMessage(None, Some(event_handle), 0, None, 1u32, Some(&mut msg_buffer), &mut msg_buffer_used).is_ok() {
                                    let msg = String::from_utf16_lossy(&msg_buffer);
                                    let clean_msg = msg.trim_end_matches('\0').trim().to_string();
                                    if !clean_msg.is_empty() {
                                        full_message = clean_msg;
                                        found_msg = true;
                                    }
                                }

                            if !found_msg {
                                let mut current_pos = 0;
                                let mut data_items = Vec::new();
                                while let Some(data_start) = xml[current_pos..].find("<Data") {
                                    let abs_start = current_pos + data_start;
                                    if let Some(close_tag) = xml[abs_start..].find('>') {
                                        let content_start = abs_start + close_tag + 1;
                                        if let Some(content_end) = xml[content_start..].find("</Data>") {
                                            let item = xml[content_start..content_start + content_end].trim();
                                            if !item.is_empty() { data_items.push(item); }
                                            current_pos = content_start + content_end + 7;
                                        } else { break; }
                                    } else { break; }
                                }
                                full_message = if !data_items.is_empty() { data_items.join(" ") } else { format!("Event {} from {}", event_id, provider) };
                            }

                            let display_source = if channel_name == "Application" {
                                format!("[APP] {}", provider)
                            } else {
                                provider
                            };

                            channel_events.push(EventInfo {
                                time: time_fmt,
                                raw_time,
                                source: display_source,
                                id: event_id,
                                message: full_message,
                            });
                        }
                        let _ = EvtClose(event_handle);
                    }
                }
                let _ = EvtClose(query_handle);
                channel_events
            }
        };

        let mut all_events = fetch_channel("System");
        
        let mut app_events = fetch_channel("Application");
        
        all_events.append(&mut app_events);

        // Sort by raw_time descending (newest first)
        all_events.sort_by(|a, b| b.raw_time.cmp(&a.raw_time));
        
        // all_events.truncate(100); // Don't truncate to ensure we see App events even if System is noisy
        all_events
    }

    #[allow(non_upper_case_globals)]
    fn get_wifi_details(&self) -> Option<WifiInfo> {
        // Utiliser l'API Windows WLAN directement (100% natif, pas de PowerShell/netsh)
        use windows::Win32::NetworkManagement::WiFi::*;
        use windows::Win32::Foundation::*;
        use std::ptr;
        
        unsafe {
            let mut negotiated_version: u32 = 0;
            let mut client_handle: HANDLE = HANDLE::default();
            
            // Ouvrir le handle WLAN
            let result = WlanOpenHandle(
                2, // Version client
                None,
                &mut negotiated_version,
                &mut client_handle,
            );
            
            if result != 0 {
                return None;
            }
            
            // Énumérer les interfaces
            let mut interface_list: *mut WLAN_INTERFACE_INFO_LIST = ptr::null_mut();
            let result = WlanEnumInterfaces(client_handle, None, &mut interface_list);
            
            if result != 0 {
                WlanCloseHandle(client_handle, None);
                return None;
            }

            // CodeQL Fix: Use as_ref() to safely handle potential null pointer
            let list = match interface_list.as_ref() {
                Some(l) => l,
                None => {
                    WlanCloseHandle(client_handle, None);
                    return None;
                }
            };
            if list.dwNumberOfItems == 0 {
                WlanFreeMemory(interface_list as *mut _);
                WlanCloseHandle(client_handle, None);
                return None;
            }
            
            // Prendre la première interface
            let interface = &list.InterfaceInfo[0];
            
            // Interroger la connexion actuelle
            let mut data_size: u32 = 0;
            let mut data_ptr: *mut std::ffi::c_void = ptr::null_mut();
            let mut value_type = WLAN_OPCODE_VALUE_TYPE::default();
            
            let result = WlanQueryInterface(
                client_handle,
                &interface.InterfaceGuid,
                wlan_intf_opcode_current_connection,
                None,
                &mut data_size,
                &mut data_ptr,
                Some(&mut value_type),
            );
            
            if result != 0 || data_ptr.is_null() {
                WlanFreeMemory(interface_list as *mut _);
                WlanCloseHandle(client_handle, None);
                return None;
            }
            
            let connection = &*(data_ptr as *const WLAN_CONNECTION_ATTRIBUTES);
            
            // Extraire le SSID
        let ssid_len = connection.wlanAssociationAttributes.dot11Ssid.uSSIDLength as usize;
        let ssid_bytes = &connection.wlanAssociationAttributes.dot11Ssid.ucSSID[..ssid_len];
        let ssid = if self.demo_mode {
            "CoffeeShop-WiFi".to_string()
        } else {
            String::from_utf8_lossy(ssid_bytes).to_string()
        };
        
        // Extraire le BSSID (adresse MAC de l'AP)
        let bssid_bytes = &connection.wlanAssociationAttributes.dot11Bssid;
        let bssid = if self.demo_mode {
            "AA:BB:CC:DD:EE:FF".to_string()
        } else {
            format!("{:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X}",
                bssid_bytes[0], bssid_bytes[1], bssid_bytes[2],
                bssid_bytes[3], bssid_bytes[4], bssid_bytes[5])
        };
        
        // Extraire les autres informations
        let signal = connection.wlanAssociationAttributes.wlanSignalQuality;
        let auth = self.translate_auth_algorithm(connection.wlanSecurityAttributes.dot11AuthAlgorithm);
        let cipher = self.translate_cipher_algorithm(connection.wlanSecurityAttributes.dot11CipherAlgorithm);
        let rx_rate = connection.wlanAssociationAttributes.ulRxRate / 1000;
        let tx_rate = connection.wlanAssociationAttributes.ulTxRate / 1000;
        
        // Extraire le canal et la fréquence
        // Note: Le canal exact n'est pas directement disponible dans WLAN_ASSOCIATION_ATTRIBUTES
        // On peut déduire la bande depuis dot11PhyType
        let (channel, frequency) = match connection.wlanAssociationAttributes.dot11PhyType {
            dot11_phy_type_ofdm => ("36".to_string(), "5 GHz".to_string()),
            dot11_phy_type_erp => ("6".to_string(), "2.4 GHz".to_string()),
            dot11_phy_type_hrdsss => ("6".to_string(), "2.4 GHz".to_string()),
            dot11_phy_type_ht => ("11".to_string(), "2.4 GHz".to_string()),
            dot11_phy_type_vht => ("44".to_string(), "5 GHz".to_string()),
            dot11_phy_type_he => ("100".to_string(), "5 GHz".to_string()),
            _ => ("N/A".to_string(), "N/A".to_string()),
        };
        
        // IP Address
        let ip_address = if self.demo_mode {
            "192.168.1.100".to_string()
        } else {
            // Récupérer la vraie IP
            use std::net::UdpSocket;
            UdpSocket::bind("0.0.0.0:0")
                .and_then(|s| s.connect("8.8.8.8:80").map(|_| s))
                .and_then(|s| s.local_addr())
                .map(|addr| addr.ip().to_string())
                .unwrap_or_else(|_| "N/A".to_string())
        };

        // Auth Log Details from Event Log - Fetch dynamically
        let log_details = if self.demo_mode {
            "802.1x Auth: PEAP-MSCHAPv2".to_string()
        } else {
            self.fetch_wlan_auth_info()
        };

        let wifi_info = Some(WifiInfo {
                ssid,
                bssid,
                standard: "WiFi".to_string(),
                auth,
                cipher,
                channel,
                frequency,
                rx_rate: format!("{} Mbps", rx_rate),
                tx_rate: format!("{} Mbps", tx_rate),
                signal: format!("{}%", signal),
                ip_address,
                log_details,
            });
            
            // Libérer la mémoire
            WlanFreeMemory(data_ptr);
            WlanFreeMemory(interface_list as *mut _);
            WlanCloseHandle(client_handle, None);
            
            wifi_info
        }
    }

    fn fetch_wlan_auth_info(&self) -> String {
         use windows::Win32::System::EventLog::*;

         unsafe {
             // Query Microsoft-Windows-WLAN-AutoConfig/Operational for 802.1x authentication events
             // EventID 12013: 802.1x authentication succeeded (contains EAP type info)
             // EventID 12011: 802.1x authentication started
             // EventID 11002: Connection completed successfully with failure reason code
             let query_str = "*[System[(EventID=12013 or EventID=11002)]]"; 
             let channel_wide = windows::core::w!("Microsoft-Windows-WLAN-AutoConfig/Operational");
             let query_wide = windows::core::HSTRING::from(query_str);
             
             let query_handle = match EvtQuery(None, channel_wide, windows::core::PCWSTR(query_wide.as_ptr()), 0x101u32) { // 0x101 = Reverse direction (newest first)
                 Ok(h) => h,
                 Err(_) => return String::new(), // Silently fail if no access
             };

             let mut events_buf: [isize; 5] = [0; 5]; // Check a few recent events
             let mut returned: u32 = 0;
             
             if EvtNext(query_handle, &mut events_buf, 0, 0, &mut returned).is_err() || returned == 0 {
                 let _ = EvtClose(query_handle);
                 return String::new(); // No 802.1x events = not an enterprise network
             }

             let mut auth_info = String::new();

             // Process events to find 802.1x authentication details
             for &event_raw in events_buf.iter().take(returned as usize) {
                 let event_handle = EVT_HANDLE(event_raw);
                 
                 let mut xml_buffer_size: u32 = 0;
                 let mut xml_buffer_used: u32 = 0;
                 let mut property_count: u32 = 0;

                 let _ = EvtRender(None, event_handle, 1u32, xml_buffer_size, None, &mut xml_buffer_used, &mut property_count);
                 
                 xml_buffer_size = xml_buffer_used;
                 let mut xml_buffer: Vec<u16> = vec![0; (xml_buffer_size / 2) as usize];
                 
                 if EvtRender(None, event_handle, 1u32, xml_buffer_size, Some(xml_buffer.as_mut_ptr() as *mut _), &mut xml_buffer_used, &mut property_count).is_ok() {
                     let xml = String::from_utf16_lossy(&xml_buffer);
                     
                     // Extract EventID to know which event type we're processing
                     let event_id = xml.split("<EventID>").nth(1)
                         .and_then(|s| s.split("</EventID>").next())
                         .unwrap_or("");
                     
                     if event_id == "12013" {
                         // 802.1x authentication success - extract EAP type
                         // Common fields in this event:
                         // - EapType (e.g., "25" for PEAP, "13" for EAP-TLS)
                         // - InnerEapType (e.g., "26" for MSCHAPv2 inside PEAP)
                         
                         let mut eap_type = String::new();
                         let mut inner_eap_type = String::new();
                         
                         // Extract EAP Type
                         if let Some(start) = xml.find("<Data Name='EapType'>") {
                             let content_start = start + 21;
                             if let Some(end) = xml[content_start..].find("</Data>") {
                                 eap_type = xml[content_start..content_start + end].trim().to_string();
                             }
                         }
                         
                         // Extract Inner EAP Type (for tunneled methods like PEAP)
                         if let Some(start) = xml.find("<Data Name='InnerEapType'>") {
                             let content_start = start + 26;
                             if let Some(end) = xml[content_start..].find("</Data>") {
                                 inner_eap_type = xml[content_start..content_start + end].trim().to_string();
                             }
                         }
                         
                         // Translate EAP type codes to human-readable names
                         let eap_method = match eap_type.as_str() {
                             "13" => "EAP-TLS",
                             "25" => {
                                 // PEAP - check inner method
                                 match inner_eap_type.as_str() {
                                     "26" => "PEAP-MSCHAPv2",
                                     "6" => "PEAP-GTC",
                                     "" => "PEAP",
                                     _ => "PEAP (Unknown inner)",
                                 }
                             },
                             "21" => "EAP-TTLS",
                             "23" => "EAP-AKA",
                             "18" => "EAP-SIM",
                             "43" => "EAP-FAST",
                             "26" => "EAP-MSCHAPv2",
                             "" => "",
                             _ => &format!("EAP-{}", eap_type),
                         };
                         
                         if !eap_method.is_empty() {
                             auth_info = match self.lang {
                                 Language::Fr => format!("Auth 802.1x: {}", eap_method),
                                 Language::En => format!("802.1x Auth: {}", eap_method),
                             };
                             break; // Found what we need
                         }
                     }
                 }
                 
                 let _ = EvtClose(event_handle);
             }
             
             let _ = EvtClose(query_handle);
             auth_info
         }
    }

    fn translate_auth_algorithm(&self, auth: windows::Win32::NetworkManagement::WiFi::DOT11_AUTH_ALGORITHM) -> String {
        use windows::Win32::NetworkManagement::WiFi::*;
        
        let (en, fr) = match auth {
            DOT11_AUTH_ALGO_80211_OPEN => ("Open", "Ouvert"),
            DOT11_AUTH_ALGO_80211_SHARED_KEY => ("Shared Key", "Clé partagée"),
            DOT11_AUTH_ALGO_WPA => ("WPA-Enterprise", "WPA-Entreprise"),
            DOT11_AUTH_ALGO_WPA_PSK => ("WPA-PSK", "WPA-PSK"),
            DOT11_AUTH_ALGO_WPA_NONE => ("WPA-None", "WPA-Aucun"),
            DOT11_AUTH_ALGO_RSNA => ("WPA2-Enterprise", "WPA2-Entreprise"),
            DOT11_AUTH_ALGO_RSNA_PSK => ("WPA2-PSK", "WPA2-PSK"),
            DOT11_AUTH_ALGO_WPA3 => ("WPA3-Enterprise", "WPA3-Entreprise"),
            DOT11_AUTH_ALGO_WPA3_SAE => ("WPA3-Personal", "WPA3-Personnel"),
            DOT11_AUTH_ALGO_OWE => ("OWE", "OWE"),
            DOT11_AUTH_ALGO_IHV_START => ("Vendor Specific", "Spécifique vendeur"),
            DOT11_AUTH_ALGO_IHV_END => ("Vendor Specific", "Spécifique vendeur"),
            _ => return format!("Unknown({})", auth.0),
        };
        
        match self.lang {
            Language::Fr => fr.to_string(),
            Language::En => en.to_string(),
        }
    }

    fn translate_cipher_algorithm(&self, cipher: windows::Win32::NetworkManagement::WiFi::DOT11_CIPHER_ALGORITHM) -> String {
        use windows::Win32::NetworkManagement::WiFi::*;
        
        let (en, fr) = match cipher {
            DOT11_CIPHER_ALGO_NONE => ("None", "Aucun"),
            DOT11_CIPHER_ALGO_WEP40 => ("WEP-40", "WEP-40"),
            DOT11_CIPHER_ALGO_TKIP => ("TKIP", "TKIP"),
            DOT11_CIPHER_ALGO_CCMP => ("AES-CCMP", "AES-CCMP"),
            DOT11_CIPHER_ALGO_WEP104 => ("WEP-104", "WEP-104"),
            DOT11_CIPHER_ALGO_BIP => ("BIP", "BIP"),
            DOT11_CIPHER_ALGO_GCMP => ("AES-GCMP", "AES-GCMP"),
            DOT11_CIPHER_ALGO_GCMP_256 => ("AES-GCMP-256", "AES-GCMP-256"),
            DOT11_CIPHER_ALGO_CCMP_256 => ("AES-CCMP-256", "AES-CCMP-256"),
            DOT11_CIPHER_ALGO_BIP_GMAC_128 => ("BIP-GMAC-128", "BIP-GMAC-128"),
            DOT11_CIPHER_ALGO_BIP_GMAC_256 => ("BIP-GMAC-256", "BIP-GMAC-256"),
            DOT11_CIPHER_ALGO_BIP_CMAC_256 => ("BIP-CMAC-256", "BIP-CMAC-256"),
            DOT11_CIPHER_ALGO_WEP => ("WEP", "WEP"),
            DOT11_CIPHER_ALGO_IHV_START => ("Vendor Specific", "Spécifique vendeur"),
            DOT11_CIPHER_ALGO_IHV_END => ("Vendor Specific", "Spécifique vendeur"),
            _ => return format!("Unknown({})", cipher.0),
        };
        
        match self.lang {
            Language::Fr => fr.to_string(),
            Language::En => en.to_string(),
        }
    }

    fn get_ccm_status() -> Option<CcmStatus> {
        // Vérifier si le service CCM (Configuration Manager Client) est en cours d'exécution
        let mut sys = System::new();
        sys.refresh_all();
        
        // Chercher le processus ccmexec.exe
        for process in sys.processes().values() {
            let name = process.name().to_string_lossy().to_lowercase();
            if name.contains("ccmexec") {
                return Some(CcmStatus {
                    running: true,
                    status: "Running".to_string(),
                    has_errors: false, // TODO: Vérifier les erreurs dans le journal
                    pending_actions: 0, // TODO: Interroger WMI pour les actions en attente
                });
            }
        }
        
        // Service non trouvé en cours d'exécution
        // Vérifier si le fichier exécutable existe pour déterminer si le service est installé mais arrêté
        let ccm_path = std::path::Path::new("C:\\Windows\\CCM\\CcmExec.exe");
        if ccm_path.exists() {
            Some(CcmStatus {
                running: false,
                status: "Stopped".to_string(),
                has_errors: false,
                pending_actions: 0,
            })
        } else {
            None
        }
    }

    fn next_item(&mut self) {
        match self.view_mode {
            ViewMode::Processes | ViewMode::ProcessDetail => {
                let i = match self.process_table_state.selected() {
                    Some(i) => if i >= self.processes.len().saturating_sub(1) { 0 } else { i + 1 },
                    None => 0,
                };
                self.process_table_state.select(Some(i));
                // Update selected PID when navigating in ProcessDetail
                if matches!(self.view_mode, ViewMode::ProcessDetail)
                    && let Some(proc) = self.processes.get(i) {
                        self.selected_process_pid = Some(proc.pid.clone());
                    }
            }
            ViewMode::SystemEvents | ViewMode::EventDetail => {
                let i = match self.event_table_state.selected() {
                    Some(i) => if i >= self.system_errors.len().saturating_sub(1) { 0 } else { i + 1 },
                    None => 0,
                };
                self.event_table_state.select(Some(i));
            }
            ViewMode::WifiDetails | ViewMode::About => {}
        }
    }

    fn previous_item(&mut self) {
        match self.view_mode {
            ViewMode::Processes | ViewMode::ProcessDetail => {
                let i = match self.process_table_state.selected() {
                    Some(i) => if i == 0 { self.processes.len().saturating_sub(1) } else { i - 1 },
                    None => 0,
                };
                self.process_table_state.select(Some(i));
                // Update selected PID when navigating in ProcessDetail
                if matches!(self.view_mode, ViewMode::ProcessDetail)
                    && let Some(proc) = self.processes.get(i) {
                        self.selected_process_pid = Some(proc.pid.clone());
                    }
            }
            ViewMode::SystemEvents | ViewMode::EventDetail => {
                let i = match self.event_table_state.selected() {
                    Some(i) => if i == 0 { self.system_errors.len().saturating_sub(1) } else { i - 1 },
                    None => 0,
                };
                self.event_table_state.select(Some(i));
            }
            ViewMode::WifiDetails | ViewMode::About => {}
        }
    }

    fn kill_selected_process(&mut self) {
        if let ViewMode::Processes = self.view_mode
            && let Some(idx) = self.process_table_state.selected()
                && let Some(proc_info) = self.processes.get(idx)
                    && let Ok(pid_val) = proc_info.pid.parse::<usize>() {
                        let pid = Pid::from(pid_val);
                        if let Some(process) = self.system.process(pid) {
                            process.kill();
                            self.message = format!("Kill sent to PID {}", pid_val);
                            self.message_time = Some(Instant::now());
                        }
                    }
    }
}

fn main() -> Result<()> {
    // Parse command line arguments
    let args: Vec<String> = std::env::args().collect();
    let demo_mode = args.iter().any(|arg| arg == "--demo" || arg == "-d");
    
    if args.iter().any(|arg| arg == "--help" || arg == "-h") {
        println!("HtopRust v{}", env!("CARGO_PKG_VERSION"));
        println!("A modern system monitor for Windows\n");
        println!("Usage: HtopRust [OPTIONS]\n");
        println!("Options:");
        println!("  --demo, -d      Run in demo mode with anonymized data for screenshots");
        println!("  --help, -h      Show this help message");
        return Ok(());
    }
    
    if demo_mode {
        println!("Running in DEMO MODE - Anonymized data for screenshots");
    }
    
    // Setup user-friendly panic messages and crash reports
    human_panic::setup_panic!();
    
    println!("Current OS: {}", std::env::consts::OS);
    
    // Setup panic hook to restore terminal and show error detail on crash
    std::panic::set_hook(Box::new(move |info| {
        let mut stdout = io::stdout();
        let _ = disable_raw_mode();
        let _ = execute!(stdout, LeaveAlternateScreen, DisableMouseCapture);
        let _ = execute!(stdout, crossterm::cursor::Show);
        
        eprintln!("\n--- APPLICATION CRASH / DÉTAILS DU CRASH ---");
        if let Some(s) = info.payload().downcast_ref::<&str>() {
            eprintln!("Message: {}", s);
        } else if let Some(s) = info.payload().downcast_ref::<String>() {
            eprintln!("Message: {}", s);
        } else {
            eprintln!("Message: Unknown error / Erreur inconnue.");
        }
        if let Some(location) = info.location() {
            eprintln!("Location: {}:{}:{}", location.file(), location.line(), location.column());
        }
        eprintln!("--------------------------------------------\n");
    }));

    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen, EnableMouseCapture)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    let mut app = App::new(demo_mode);
    let res = run_app(&mut terminal, &mut app);

    // Normal cleanup
    disable_raw_mode()?;
    execute!(terminal.backend_mut(), LeaveAlternateScreen, DisableMouseCapture)?;
    terminal.show_cursor()?;

    if let Err(err) = res { println!("{:?}", err) }
    Ok(())
}

fn run_app(terminal: &mut Terminal<CrosstermBackend<io::Stdout>>, app: &mut App) -> Result<()> {
    let mut last_tick = Instant::now();
    loop {
        terminal.draw(|f| ui(f, app))?;
        let timeout = app.refresh_rate.checked_sub(last_tick.elapsed()).unwrap_or_else(|| Duration::from_secs(0));
        if crossterm::event::poll(timeout)? {
            match event::read()? {
                Event::Key(key) => {
                    if key.kind == event::KeyEventKind::Press {
                        match key.code {
                            KeyCode::Char('q') | KeyCode::F(10) => return Ok(()),
                            KeyCode::Down => app.next_item(),
                            KeyCode::Up => app.previous_item(),
                            KeyCode::Char('c') => app.sort_column = SortColumn::Cpu,
                            KeyCode::Char('m') => app.sort_column = SortColumn::Mem,
                            KeyCode::Char('p') => app.sort_column = SortColumn::Pid,
                            KeyCode::Char('n') => app.sort_column = SortColumn::Name,
                            KeyCode::Char('s') => {
                                match app.refresh_rate.as_secs() {
                                    1 => app.refresh_rate = Duration::from_secs(2),
                                    2 => app.refresh_rate = Duration::from_secs(5),
                                    _ => app.refresh_rate = Duration::from_secs(1),
                                }
                                app.message = format!("Refresh rate: {}s", app.refresh_rate.as_secs());
                                app.message_time = Some(Instant::now());
                            }
                            KeyCode::Char('e') => {
                                match app.view_mode {
                                    ViewMode::Processes => app.view_mode = ViewMode::SystemEvents,
                                    _ => app.view_mode = ViewMode::Processes,
                                }
                            }
                            KeyCode::Char('a') | KeyCode::Char('h') => {
                                match app.view_mode {
                                    ViewMode::About => app.view_mode = ViewMode::Processes,
                                    _ => app.view_mode = ViewMode::About,
                                }
                            }
                            KeyCode::Esc => {
                                match app.view_mode {
                                    ViewMode::EventDetail => app.view_mode = ViewMode::SystemEvents,
                                    ViewMode::ProcessDetail => app.view_mode = ViewMode::Processes,
                                    ViewMode::About => app.view_mode = ViewMode::Processes,
                                    _ => {
                                        app.view_mode = ViewMode::Processes;
                                        app.message_time = None;
                                    }
                                }
                            }
                            KeyCode::Char('k') => app.kill_selected_process(),
                            KeyCode::Enter => {
                                match app.view_mode {
                                    ViewMode::SystemEvents => {
                                        if app.event_table_state.selected().is_some() {
                                            app.view_mode = ViewMode::EventDetail;
                                        }
                                    }
                                    ViewMode::Processes => {
                                        if let Some(idx) = app.process_table_state.selected()
                                            && let Some(proc) = app.processes.get(idx) {
                                                app.selected_process_pid = Some(proc.pid.clone());
                                                app.view_mode = ViewMode::ProcessDetail;
                                            }
                                    }
                                    _ => {}
                                }
                            }
                            _ => {}
                        }
                    }
                }
                Event::Mouse(mouse) => {
                    match mouse.kind {
                        event::MouseEventKind::ScrollDown => app.next_item(),
                        event::MouseEventKind::ScrollUp => app.previous_item(),
                        event::MouseEventKind::Down(event::MouseButton::Left) => {
                            let header_height = 18;
                            let total_width = terminal.size()?.width;
                            let col1_end = total_width / 3;
                            let col2_end = (total_width * 2) / 3;

                            // Clic sur le milieu (Events) - Uniquement si dans la colonne 2
                            if mouse.row >= 11 && mouse.row <= 17 && mouse.column >= col1_end && mouse.column < col2_end {
                                app.view_mode = ViewMode::SystemEvents;
                            }
                            // Clic sur la droite (WiFi) - Uniquement si dans la colonne 3
                            if mouse.row >= 1 && mouse.row <= 17 && mouse.column >= col2_end {
                                app.view_mode = ViewMode::WifiDetails;
                            }
                            if mouse.row > header_height {
                                let idx = (mouse.row - header_height - 1) as usize;
                                match app.view_mode {
                                    ViewMode::Processes => {
                                        if idx < app.processes.len() {
                                            app.process_table_state.select(Some(idx));
                                        }
                                    }
                                    ViewMode::SystemEvents => {
                                        if idx < app.system_errors.len() {
                                            app.event_table_state.select(Some(idx));
                                        }
                                    }
                                    ViewMode::WifiDetails | ViewMode::EventDetail | ViewMode::ProcessDetail | ViewMode::About => {}
                                }
                            }
                        }
                        _ => {}
                    }
                }
                _ => {}
            }
        }
        if last_tick.elapsed() >= app.refresh_rate {
            app.update();
            last_tick = Instant::now();
        }
    }
}

fn ui(f: &mut Frame, app: &mut App) {
    // Force deep black background everywhere
    let background_style = Style::default().bg(Color::Rgb(0, 0, 0)).fg(Color::White);
    f.render_widget(Block::default().style(background_style), f.area());

    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(18), Constraint::Min(0), Constraint::Length(1)].as_ref())
        .split(f.area());

    draw_header(f, app, chunks[0]);
    match app.view_mode {
        ViewMode::Processes => draw_process_table(f, app, chunks[1]),
        ViewMode::SystemEvents => draw_event_table(f, app, chunks[1]),
        ViewMode::WifiDetails => draw_wifi_details(f, app, chunks[1]),
        ViewMode::EventDetail => draw_event_detail(f, app, chunks[1]),
        ViewMode::ProcessDetail => draw_process_detail(f, app, chunks[1]),
        ViewMode::About => draw_about(f, app, chunks[1]),
    }
    draw_footer(f, app, chunks[2]);
}

fn draw_event_detail(f: &mut Frame, app: &App, area: Rect) {
    let detail = if let Some(idx) = app.event_table_state.selected() {
        if let Some(err) = app.system_errors.get(idx) {
            format!(
                "TIME   : {}\nID     : {}\nSOURCE : {}\n\nMESSAGE:\n{}",
                err.time, err.id, err.source, err.message
            )
        } else {
            app.t("Error not found.", "Erreur non trouvée.")
        }
    } else {
        app.t("No event selected.", "Aucun événement sélectionné.")
    };

    let p = Paragraph::new(detail)
        .block(Block::default().borders(Borders::ALL).title(app.t("System Event Detail", "Détail de l'événement Système"))
            .style(Style::default().bg(Color::Rgb(0,0,0)).fg(Color::Red)))
        .style(Style::default().bg(Color::Rgb(0,0,0)).fg(Color::White))
        .wrap(ratatui::widgets::Wrap { trim: true });
    f.render_widget(p, area);
}

fn draw_process_detail(f: &mut Frame, app: &App, area: Rect) {
    let detail = if let Some(pid) = &app.selected_process_pid {
        // Find process by PID instead of index, so it stays consistent across refreshes
        if let Some(proc) = app.processes.iter().find(|p| &p.pid == pid) {
            let virt_mb = proc.virt_mem / 1024 / 1024;
            let res_mb = proc.res_mem / 1024 / 1024;
            
            match app.lang {
                Language::Fr => format!(
                    "PID          : {}\nNOM          : {}\nUTILISATEUR  : {}\nSTATUT       : {}\nCPU          : {:.1}%\nMÉMOIRE      : {:.1}% ({} MB)\nMÉM VIRTUELLE: {} MB\n\nCOMMANDE:\n{}",
                    proc.pid,
                    proc.name,
                    proc.user,
                    proc.status,
                    proc.cpu,
                    proc.mem_percent,
                    res_mb,
                    virt_mb,
                    proc.cmd
                ),
                Language::En => format!(
                    "PID          : {}\nNAME         : {}\nUSER         : {}\nSTATUS       : {}\nCPU          : {:.1}%\nMEMORY       : {:.1}% ({} MB)\nVIRTUAL MEM  : {} MB\n\nCOMMAND:\n{}",
                    proc.pid,
                    proc.name,
                    proc.user,
                    proc.status,
                    proc.cpu,
                    proc.mem_percent,
                    res_mb,
                    virt_mb,
                    proc.cmd
                ),
            }
        } else {
            app.t("Process not found (terminated?).", "Processus non trouvé (terminé ?).")
        }
    } else {
        app.t("No process selected.", "Aucun processus sélectionné.")
    };

    let p = Paragraph::new(detail)
        .block(Block::default().borders(Borders::ALL).title(app.t("Process Detail", "Détail du Processus"))
            .style(Style::default().bg(Color::Rgb(0,0,0)).fg(Color::Cyan)))
        .style(Style::default().bg(Color::Rgb(0,0,0)).fg(Color::White))
        .wrap(ratatui::widgets::Wrap { trim: true });
    f.render_widget(p, area);
}

fn draw_wifi_details(f: &mut Frame, app: &App, area: Rect) {
    let mut details = String::new();
    if let Some(wifi) = &app.wifi_info {
        details.push_str(&format!("SSID            : {}\n", wifi.ssid));
        details.push_str(&format!("BSSID           : {}\n", wifi.bssid));
        details.push_str(&format!("Standard        : {}\n", wifi.standard));
        details.push_str(&format!("Channel         : {}\n", wifi.channel));
        details.push_str(&format!("Frequency       : {}\n", wifi.frequency));
        details.push_str(&format!("Auth            : {}\n", wifi.auth));
        details.push_str(&format!("Cipher          : {}\n", wifi.cipher));
        details.push_str(&format!("Signal          : {}\n", wifi.signal));
        details.push_str(&format!("Rx Rate         : {}\n", wifi.rx_rate));
        details.push_str(&format!("Tx Rate         : {}\n", wifi.tx_rate));
        details.push_str(&format!("\n\n{}", app.t("Esc: Back", "Esc: Retour")));
    } else {
        details.push_str(&app.t("No WiFi info available.", "Aucune information WiFi disponible."));
    }

    let p = Paragraph::new(details)
        .block(Block::default().borders(Borders::ALL).title(app.t("WiFi Details", "Détails WiFi"))
            .style(Style::default().bg(Color::Rgb(0,0,0)).fg(Color::Cyan)))
        .style(Style::default().bg(Color::Rgb(0,0,0)).fg(Color::Cyan));
    f.render_widget(p, area);
}

fn draw_header(f: &mut Frame, app: &App, area: Rect) {
    let main_chunks = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(33), Constraint::Percentage(33), Constraint::Percentage(34)].as_ref())
        .split(area);

    let cpus = app.system.cpus();
    let max_cpus = main_chunks[0].height.saturating_sub(2) as usize;
    let cpu_count = cpus.len().min(max_cpus);
    let cpu_chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints({
            let mut v = vec![Constraint::Length(1)];
            v.extend(vec![Constraint::Length(1); cpu_count]);
            v
        })
        .split(main_chunks[0]);

    f.render_widget(Paragraph::new(app.t("CPU USAGE", "UTILISATION CPU"))
        .style(Style::default().bg(Color::Rgb(0,0,0)).fg(Color::Cyan).add_modifier(Modifier::BOLD)), cpu_chunks[0]);
    
    for (i, cpu) in cpus.iter().enumerate().take(cpu_count) {
        let usage = cpu.cpu_usage();
        let label = format!("CPU{} {:>5.1}%", i, usage);
        f.render_widget(Gauge::default()
            .gauge_style(Style::default().bg(Color::Rgb(0,0,0)).fg(Color::Cyan))
            .style(Style::default().bg(Color::Rgb(0,0,0)))
            .percent(usage as u16).label(label), cpu_chunks[i+1]);
    }

    let mid_chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(1), // Mem
            Constraint::Length(1), // Swap
            Constraint::Length(1), // Uptime
            Constraint::Length(1), // OS
            Constraint::Length(1), // Host
            Constraint::Length(1), // Spacer
            Constraint::Length(1), // Disks Title
            Constraint::Length(3), // Disks List
            Constraint::Length(1), // Spacer
            Constraint::Length(1), // Events Title
            Constraint::Min(0)     // Events List
        ].as_ref())
        .split(main_chunks[1]);

    let mem_used = app.system.used_memory();
    let mem_total = app.system.total_memory();
    let mem_percent = if mem_total > 0 { (mem_used as f64 / mem_total as f64 * 100.0) as u16 } else { 0 };
    f.render_widget(Gauge::default()
        .gauge_style(Style::default().bg(Color::Rgb(0,0,0)).fg(Color::Green))
        .style(Style::default().bg(Color::Rgb(0,0,0)))
        .percent(mem_percent).label(format!("Mem  [{:3}%] {}MB/{}MB", mem_percent, mem_used / 1024 / 1024, mem_total / 1024 / 1024)), mid_chunks[0]);

    let swap_used = app.system.used_swap();
    let swap_total = app.system.total_swap();
    let swap_percent = if swap_total > 0 { (swap_used as f64 / swap_total as f64 * 100.0) as u16 } else { 0 };
    f.render_widget(Gauge::default()
        .gauge_style(Style::default().bg(Color::Rgb(0,0,0)).fg(Color::Yellow))
        .style(Style::default().bg(Color::Rgb(0,0,0)))
        .percent(swap_percent).label(format!("Swap [{:3}%] {}MB/{}MB", swap_percent, swap_used / 1024 / 1024, swap_total / 1024 / 1024)), mid_chunks[1]);

    let uptime_secs = System::uptime();
    let uptime_str = format!("{}d {:02}h {:02}m", uptime_secs / 86400, (uptime_secs % 86400) / 3600, (uptime_secs % 3600) / 60);
    f.render_widget(Paragraph::new(format!("{}: {}", app.t("Uptime", "Disponibilité"), uptime_str))
        .style(Style::default().bg(Color::Rgb(0,0,0)).fg(Color::White)), mid_chunks[2]);
    
    f.render_widget(Paragraph::new(format!("OS: {}", app.os_info))
        .style(Style::default().bg(Color::Rgb(0,0,0)).fg(Color::White)), mid_chunks[3]);
    
    let privilege_badge = if app.is_admin {
        if app.supports_utf8 {
            match app.lang {
                Language::Fr => " [🔒 ADMIN]",
                Language::En => " [🔒 ADMIN]",
            }
        } else {
            " [ADMIN]"
        }
    } else if app.supports_utf8 {
        match app.lang {
            Language::Fr => " [👤 Utilisateur]",
            Language::En => " [👤 User]",
        }
    } else {
        " [User]"
    };
    let privilege_color = if app.is_admin { Color::Yellow } else { Color::White };
    
    f.render_widget(Paragraph::new(format!("Host: {} | User: {}{}", app.host_info, app.username, privilege_badge))
        .style(Style::default().bg(Color::Rgb(0,0,0)).fg(privilege_color)), mid_chunks[4]);

    if let Some(ccm) = &app.ccm_status {
        let status_color = if ccm.running { Color::Green } else { Color::Red };
        let error_text = if ccm.has_errors { " | Errors!" } else { "" };
        let info = format!("CCM: {} | Actions: {}{}", ccm.status, ccm.pending_actions, error_text);
        f.render_widget(Paragraph::new(info)
            .style(Style::default().bg(Color::Rgb(0,0,0)).fg(status_color)), mid_chunks[5]);
    } else {
        // Service non installé, afficher un spacer vide ou rien
        f.render_widget(Paragraph::new("").style(Style::default().bg(Color::Rgb(0,0,0))), mid_chunks[5]);
    }

    f.render_widget(Paragraph::new(app.t("DISKS (FREE SPACE)", "DISQUES (ESPACE LIBRE)")).style(Style::default().bg(Color::Rgb(0,0,0)).fg(Color::Yellow).add_modifier(Modifier::BOLD)), mid_chunks[6]);
    let mut disk_info = String::new();
    for disk in app.disks.iter().take(3) {
        let free = disk.available_space() / 1024 / 1024 / 1024;
        let total = disk.total_space() / 1024 / 1024 / 1024;
        let name = disk.mount_point().to_string_lossy();
        disk_info.push_str(&format!("{}: {}G/{}G free\n", name, free, total));
    }
    f.render_widget(Paragraph::new(disk_info).style(Style::default().bg(Color::Rgb(0,0,0)).fg(Color::White)), mid_chunks[7]);

    let event_title = if matches!(app.view_mode, ViewMode::SystemEvents) { 
        app.t("SYSTEM ERRORS (DETAILED)", "ERREURS SYSTÈME (DÉTAILLÉ)") 
    } else { 
        app.t("SYSTEM ERRORS (CLICK/E FOR DETAILS)", "ERREURS SYSTÈME (CLIC/E POUR DÉTAILS)") 
    };
    f.render_widget(Paragraph::new(event_title).style(Style::default().bg(Color::Rgb(0,0,0)).fg(Color::Red).add_modifier(Modifier::BOLD)), mid_chunks[9]);
    
    let mut err_text = String::new();
    for err in app.system_errors.iter().take(2) {
        let truncated = if err.message.len() > 50 { format!("{}...", &err.message[..47]) } else { err.message.clone() };
        err_text.push_str(&format!("• {}: {}\n", err.time, truncated));
    }
    if err_text.is_empty() { err_text = app.t("No recent errors found.", "Aucune erreur récente trouvée."); }
    f.render_widget(Paragraph::new(err_text).style(Style::default().bg(Color::Rgb(0,0,0)).fg(Color::Gray)), mid_chunks[10]);

    let net_chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(1), Constraint::Min(0)].as_ref())
        .split(main_chunks[2]);

    f.render_widget(Paragraph::new(app.t("NETWORK / WIFI (CLICK FOR DETAILS)", "RÉSEAU / WIFI (CLIC POUR DÉTAILS)")).style(Style::default().bg(Color::Rgb(0,0,0)).fg(Color::Magenta).add_modifier(Modifier::BOLD)), net_chunks[0]);
    let mut net_info = String::new();
    if let Some(wifi) = &app.wifi_info {
        net_info.push_str(&format!("SSID  : {}\n", wifi.ssid));
        net_info.push_str(&format!("Signal: {}\n", wifi.signal));
        net_info.push_str(&format!("Auth  : {}\n", wifi.auth));
        net_info.push_str(&format!("Cipher: {}\n", wifi.cipher));
        net_info.push_str(&format!("Rate  : R:{} / T:{}\n", wifi.rx_rate, wifi.tx_rate));
        net_info.push_str(&format!("IP    : {}\n", wifi.ip_address));
        net_info.push_str("-------------------\n");
        // Log details can be multiple lines, we just append them
        net_info.push_str(&format!("{}\n", wifi.log_details));
        net_info.push_str("-------------------\n");
    }
    for (name, data) in &app.networks {
        if data.received() > 0 || data.transmitted() > 0 {
            net_info.push_str(&format!("{}: R:{:.1}K T:{:.1}K\n", name, data.received() as f32 / 1024.0, data.transmitted() as f32 / 1024.0));
        }
    }
    f.render_widget(Paragraph::new(net_info).style(Style::default().bg(Color::Rgb(0,0,0)).fg(Color::White)), net_chunks[1]);
}

fn draw_process_table(f: &mut Frame, app: &mut App, area: Rect) {
    let header_cells = ["PID", "USER", "PRI", "VIRT", "RES", "S", "CPU%", "MEM%", "Command"]
        .iter()
        .map(|h| Cell::from(*h).style(Style::default().fg(Color::Green).add_modifier(Modifier::BOLD)));
    let header = Row::new(header_cells).style(Style::default().bg(Color::Rgb(20,20,20))).height(1);

    let rows = app.processes.iter().map(|item| {
        Row::new(vec![
            Cell::from(item.pid.clone()),
            Cell::from(item.user.clone()),
            Cell::from(item.priority.clone()),
            Cell::from(format!("{}M", item.virt_mem / 1024 / 1024)),
            Cell::from(format!("{}M", item.res_mem / 1024 / 1024)),
            Cell::from(item.status.clone()),
            Cell::from(format!("{:.1}", item.cpu)),
            Cell::from(format!("{:.1}", item.mem_percent)),
            Cell::from(item.cmd.clone()),
        ]).style(Style::default().bg(Color::Rgb(0,0,0)).fg(Color::White)).height(1)
    });

    let t = Table::new(rows, [
        Constraint::Length(7),
        Constraint::Length(12),
        Constraint::Length(4),
        Constraint::Length(7),
        Constraint::Length(7),
        Constraint::Length(2),
        Constraint::Length(6),
        Constraint::Length(6),
        Constraint::Min(40),
    ])
    .header(header)
    .block(Block::default().borders(Borders::ALL).title(app.t("Processes (P: Sort CPU, M: Sort Mem, K: Kill)", "Processus (P: Trier CPU, M: Mem, K: Kill)"))
        .style(Style::default().bg(Color::Rgb(0,0,0)).fg(Color::White)))
    .row_highlight_style(Style::default().bg(Color::Rgb(40,40,40)).add_modifier(Modifier::BOLD))
    .highlight_symbol("> ");

    f.render_stateful_widget(t, area, &mut app.process_table_state);
}

fn draw_event_table(f: &mut Frame, app: &mut App, area: Rect) {
    let sep_style = Style::default().fg(Color::DarkGray); // Gris foncé pour les séparateurs
    let header_cells = vec![
        Cell::from("TIME").style(Style::default().fg(Color::Red).add_modifier(Modifier::BOLD)),
        Cell::from("│").style(sep_style),
        Cell::from("ID").style(Style::default().fg(Color::Red).add_modifier(Modifier::BOLD)),
        Cell::from("│").style(sep_style),
        Cell::from("SOURCE").style(Style::default().fg(Color::Red).add_modifier(Modifier::BOLD)),
        Cell::from("│").style(sep_style),
        Cell::from("MESSAGE").style(Style::default().fg(Color::Red).add_modifier(Modifier::BOLD)),
    ];
    let header = Row::new(header_cells).style(Style::default().bg(Color::Rgb(20,20,20))).height(1);

    let rows = app.system_errors.iter().map(|item| {
        Row::new(vec![
            Cell::from(item.time.clone()),
            Cell::from("│").style(sep_style),
            Cell::from(item.id.clone()),
            Cell::from("│").style(sep_style),
            Cell::from(item.source.clone()),
            Cell::from("│").style(sep_style),
            Cell::from(item.message.clone()),
        ]).style(Style::default().bg(Color::Rgb(0,0,0)).fg(Color::White)).height(1)
    });

    // Calcule des largeurs dynamiques basées sur le contenu visible
    let max_time_len = app.system_errors.iter().map(|e| e.time.len()).max().unwrap_or(15).clamp(10, 15) as u16;
    let max_source_len = app.system_errors.iter().map(|e| e.source.len()).max().unwrap_or(20).clamp(10, 40) as u16;

    let t = Table::new(rows, [
        Constraint::Length(max_time_len), // Dynamic Time
        Constraint::Length(1),            // Separator
        Constraint::Length(6),            // ID
        Constraint::Length(1),            // Separator
        Constraint::Length(max_source_len), // Dynamic Source
        Constraint::Length(1),            // Separator
        Constraint::Min(50),              // Message
    ])
    .header(header)
    .column_spacing(0) // Espacement 0 car on utilise des séparateurs manuels
    .block(Block::default().borders(Borders::ALL).title(app.t("System Events (Esc: Back to Proc)", "Événements Système (Esc: Retour)"))
        .style(Style::default().bg(Color::Rgb(0,0,0)).fg(Color::White)))
    .row_highlight_style(Style::default().bg(Color::Rgb(40,40,40)).add_modifier(Modifier::BOLD))
    .highlight_symbol("> ");

    f.render_stateful_widget(t, area, &mut app.event_table_state);
}

fn draw_about(f: &mut Frame, app: &App, area: Rect) {
    let version = env!("CARGO_PKG_VERSION");
    
    let content = match app.lang {
        Language::Fr => format!(
            r#"╔══════════════════════════════════════════════════════════════════════════════╗
║                              HtopRust v{}                                    ║
╚══════════════════════════════════════════════════════════════════════════════╝

📖 À PROPOS

HtopRust est un moniteur système moderne pour Windows, inspiré du célèbre outil 
'htop' sur Linux. Entièrement écrit en Rust, il apporte la puissance et l'élégance 
de la surveillance en terminal à Windows avec des performances natives et zéro 
dépendance.

👤 AUTEUR

Créé par Olivier Noblanc en 2026 comme projet personnel pour apporter une 
surveillance système de niveau professionnel à Windows dans un package léger 
et portable.

✨ FONCTIONNALITÉS PRINCIPALES

  • Surveillance en temps réel des processus (CPU, mémoire, statut)
  • Graphiques d'utilisation CPU multi-cœurs
  • Surveillance mémoire et swap
  • Informations complètes Wi-Fi avec détection 802.1x
  • Intégration du journal d'événements Windows
  • Support bilingue (EN/FR) avec détection automatique
  • Détection UTF-8 avec repli ASCII pour terminaux anciens
  • Détection des privilèges Admin/Utilisateur
  • Support souris (défilement, navigation par clic)
  • Taux de rafraîchissement configurable (1s/2s/5s)

⌨️  RACCOURCIS CLAVIER

  q / F10    Quitter                    ↑ ↓        Naviguer
  e          Basculer Événements        Enter      Voir détails
  a / h      Afficher À propos          Esc        Retour
  k          Tuer processus (admin)     s          Changer taux rafraîch.
  p          Trier par PID              c          Trier par CPU
  m          Trier par Mémoire          n          Trier par Nom

📄 LICENCE

MIT License - Copyright (c) 2026 Olivier Noblanc

🔧 TECHNIQUE

  Langage    : Rust (édition 2024)
  Framework  : Ratatui 0.30 + Crossterm 0.29
  Optimisé   : LTO + élimination code mort
  Portable   : Binaire unique, aucune dépendance runtime
  Compatible : Windows 7+
"#,
            version
        ),
        Language::En => format!(
            r#"╔══════════════════════════════════════════════════════════════════════════════╗
║                              HtopRust v{}                                    ║
╚══════════════════════════════════════════════════════════════════════════════╝

📖 ABOUT

HtopRust is a modern system monitor for Windows, inspired by the popular 'htop' 
tool on Linux. Built entirely in Rust, it brings the power and elegance of 
terminal-based monitoring to Windows with native performance and zero dependencies.

👤 AUTHOR

Created by Olivier Noblanc in 2026 as a personal project to bring professional-
grade system monitoring to Windows in a lightweight, portable package.

✨ KEY FEATURES

  • Real-time process monitoring (CPU, memory, status)
  • Multi-core CPU usage graphs
  • Memory and swap monitoring
  • Complete Wi-Fi information with 802.1x detection
  • Windows Event Log integration
  • Bilingual support (EN/FR) with auto-detection
  • UTF-8 detection with ASCII fallback for legacy terminals
  • Admin/User privilege detection
  • Mouse support (scroll, click navigation)
  • Configurable refresh rate (1s/2s/5s)

⌨️  KEYBOARD SHORTCUTS

  q / F10    Quit                       ↑ ↓        Navigate
  e          Toggle Events              Enter      View details
  a / h      Show About                 Esc        Go back
  k          Kill process (admin)       s          Change refresh rate
  p          Sort by PID                c          Sort by CPU
  m          Sort by Memory             n          Sort by Name

📄 LICENSE

MIT License - Copyright (c) 2026 Olivier Noblanc

🔧 TECHNICAL

  Language   : Rust (edition 2024)
  Framework  : Ratatui 0.30 + Crossterm 0.29
  Optimized  : LTO + dead code elimination
  Portable   : Single binary, no runtime dependencies
  Compatible : Windows 7+
"#,
            version
        ),
    };

    let p = Paragraph::new(content)
        .block(Block::default().borders(Borders::ALL)
            .title(app.t("About HtopRust", "À propos de HtopRust")))
        .style(Style::default().bg(Color::Rgb(0,0,0)).fg(Color::White))
        .wrap(ratatui::widgets::Wrap { trim: false });
    f.render_widget(p, area);
}

fn draw_footer(f: &mut Frame, app: &App, area: Rect) {
    let refresh_display = format!("{}s", app.refresh_rate.as_secs());
    
    let mut help = match app.view_mode {
        ViewMode::Processes => app.t(
            &format!(" q:Quit | ↑↓:Nav | e:Events | a/h:About | p:CPU | m:MEM | k:Kill | {}", refresh_display),
            &format!(" q:Quitter | ↑↓:Nav | e:Events | a/h:À propos | p:CPU | m:MEM | k:Kill | {}", refresh_display)
        ),
        ViewMode::SystemEvents => app.t(
            " q:Quit | Esc:Back | Enter:Detail | ↑↓:Nav | 30s",
            " q:Quitter | Esc:Retour | Enter:Détail | ↑↓:Nav | 30s"
        ),
        ViewMode::WifiDetails => app.t(
            " q:Quit | Esc:Back | 10s",
            " q:Quitter | Esc:Retour | 10s"
        ),
        ViewMode::EventDetail => app.t(
            " q:Quit | Esc:Back | 30s",
            " q:Quitter | Esc:Retour | 30s"
        ),
        ViewMode::ProcessDetail => app.t(
            " q:Quit | Esc:Back",
            " q:Quitter | Esc:Retour"
        ),
        ViewMode::About => app.t(
            " q:Quit | Esc:Back | a/h:Toggle About",
            " q:Quitter | Esc:Retour | a/h:Basculer À propos"
        ),
    };

    if let Some(time) = app.message_time
        && time.elapsed() < Duration::from_secs(5) {
            help = format!(" *** {} ***", app.message);
        }

    let p = Paragraph::new(help).style(Style::default().bg(Color::Rgb(30,30,30)).fg(Color::White));
    f.render_widget(p, area);
}
