use chrono::{DateTime, Duration as ChronoDuration, Local};
use regex::Regex;
use once_cell::sync::Lazy;

#[derive(Clone)]
pub struct EventInfo {
    pub time: String,
    pub raw_time: String,
    pub source: String,
    pub id: String,
    pub message: String,
}

pub struct EventManager;

// Compile Regexes once
static RE_TIME: Lazy<Regex> = Lazy::new(|| Regex::new(r#"TimeCreated SystemTime=['"]([^'"]+)['"]"#).unwrap());
static RE_PROVIDER: Lazy<Regex> = Lazy::new(|| Regex::new(r#"Provider Name=['"]([^'"]+)['"]"#).unwrap());
static RE_EVENTID: Lazy<Regex> = Lazy::new(|| Regex::new(r#"<EventID[^>]*>(\d+)</EventID>"#).unwrap());

impl EventManager {
    pub fn new() -> Self {
        Self
    }

    // SAFETY: We use raw FFI for Windows Event Log access.
    // Handles are properly closed with EvtClose.
    #[allow(unsafe_code)]
    pub fn get_system_errors_detailed(&self) -> Vec<EventInfo> {
        use windows::Win32::System::EventLog::{EvtQuery, EvtNext, EVT_HANDLE, EvtRender, EvtClose, EvtFormatMessage};

        // We can define a helper to fetch events from a channel
        let fetch_channel = |channel_name: &str| -> Vec<EventInfo> {
            unsafe {
                let query = windows::core::w!("*[System[(Level=1 or Level=2)]]"); // Errors & Criticals only
                let channel_wide = windows::core::HSTRING::from(channel_name);
                let channel_pcwstr = windows::core::PCWSTR(channel_wide.as_ptr());

                let query_handle = match EvtQuery(None, channel_pcwstr, query, 0x201u32) { // EvtQueryChannelPath | EvtQueryReverseDirection
                    Ok(handle) => handle,
                    Err(e) => {
                        // eprintln!("Failed to query {channel_name}: {e:?}");
                        return vec![EventInfo {
                            time: "Error".to_string(),
                            raw_time: String::new(),
                            source: channel_name.to_string(),
                            id: "ERR".to_string(),
                            message: format!("Failed to query {channel_name} log: {e:?}"),
                        }];
                    }
                };

                let cutoff_time = Local::now() - ChronoDuration::try_hours(48).unwrap_or(ChronoDuration::hours(48));
                let mut channel_events = Vec::new();
                let mut events_buf: [isize; 10] = [0; 10]; // Array to hold event handles (isize/HANDLE)
                let mut returned: u32 = 0;

                // Limit to 50 events per channel for performance
                while channel_events.len() < 50 {
                    let result = EvtNext(query_handle, &mut events_buf, 0, 0, &raw mut returned);
                    if result.is_err() || returned == 0 {
                        break;
                    }

                    for &event_raw in events_buf.iter().take(returned as usize) {
                        let event_handle = EVT_HANDLE(event_raw);
                        let mut buffer_size: u32 = 0;
                        let mut buffer_used: u32 = 0;
                        let mut property_count: u32 = 0;

                        // First call to get buffer size
                        let _ = EvtRender(None, event_handle, 1u32, buffer_size, None, &raw mut buffer_used, &raw mut property_count);
                        
                        buffer_size = buffer_used;
                        let mut buffer: Vec<u16> = vec![0; (buffer_size / 2) as usize];
                        
                        let render_result = EvtRender(None, event_handle, 1u32, buffer_size, Some(buffer.as_mut_ptr().cast()), &raw mut buffer_used, &raw mut property_count);

                        if render_result.is_ok() {
                            let xml = String::from_utf16_lossy(&buffer);
                            
                            // Parse XML using Regex
                            if let Some(parsed) = Self::parse_event_xml_regex(&xml) {
                                // Check time first
                                if let Ok(dt) = DateTime::parse_from_rfc3339(&parsed.raw_time) {
                                    if dt < cutoff_time {
                                        let _ = EvtClose(event_handle);
                                        // Since we fetch in reverse order, key assumption: 
                                        // If we hit an event older than cutoff, we can stop fetching from this channel.
                                        // We must close pending handles in the buffer first.
                                        for &pending_raw in events_buf.iter().take(returned as usize) {
                                            if pending_raw != event_raw {
                                                let _ = EvtClose(EVT_HANDLE(pending_raw));
                                            }
                                        }
                                        let _ = EvtClose(query_handle);
                                        return channel_events; 
                                    }
                                }

                                let mut msg_buffer_used: u32 = 0;
                                let _ = EvtFormatMessage(None, Some(event_handle), 0, None, 1u32, None, &raw mut msg_buffer_used);
                                
                                let msg_buffer_size = msg_buffer_used;
                                let mut msg_buffer: Vec<u16> = vec![0; msg_buffer_size as usize];
                                
                                let mut full_message = String::new();
                                let mut found_msg = false;

                                if msg_buffer_size > 0
                                    && EvtFormatMessage(None, Some(event_handle), 0, None, 1u32, Some(&mut msg_buffer), &raw mut msg_buffer_used).is_ok() {
                                        let msg = String::from_utf16_lossy(&msg_buffer);
                                        let clean_msg = msg.trim_end_matches('\0').trim().to_string();
                                        if !clean_msg.is_empty() {
                                            full_message = clean_msg;
                                            found_msg = true;
                                        }
                                    }

                                if !found_msg {
                                    full_message = format!("Event {} from {}", parsed.event_id, parsed.provider);
                                }

                                let display_source = if channel_name == "Application" {
                                    format!("[APP] {}", parsed.provider)
                                } else {
                                    parsed.provider
                                };

                                // Format time for display
                                let time_fmt = if let Ok(dt) = DateTime::parse_from_rfc3339(&parsed.raw_time) {
                                    dt.with_timezone(&Local).format("%d/%m %H:%M").to_string()
                                } else {
                                    parsed.raw_time.clone()
                                };

                                channel_events.push(EventInfo {
                                    time: time_fmt,
                                    raw_time: parsed.raw_time,
                                    source: display_source,
                                    id: parsed.event_id,
                                    message: full_message,
                                });
                            }
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
        
        all_events
    }

    fn parse_event_xml_regex(xml: &str) -> Option<ParsedEvent> {
        let raw_time = RE_TIME.captures(xml)
            .and_then(|cap| cap.get(1))
            .map(|m| m.as_str().to_string())?;

        let provider = RE_PROVIDER.captures(xml)
            .and_then(|cap| cap.get(1))
            .map(|m| m.as_str().to_string())
            .unwrap_or_else(|| "Unknown".to_string());

        let event_id = RE_EVENTID.captures(xml)
            .and_then(|cap| cap.get(1))
            .map(|m| m.as_str().to_string())
            .unwrap_or_else(|| "0".to_string());

        Some(ParsedEvent {
            event_id,
            provider,
            raw_time,
        })
    }
}

struct ParsedEvent {
    event_id: String,
    provider: String,
    raw_time: String,
}
