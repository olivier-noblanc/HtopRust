use chrono::{DateTime, Duration as ChronoDuration, Local};
use quick_xml::events::{BytesStart, Event};
use quick_xml::Reader;

#[derive(Clone)]
pub struct EventInfo {
    pub time: String,
    pub raw_time: String,
    pub source: String,
    pub id: String,
    pub message: String,
}

pub struct EventManager;

impl EventManager {
    pub fn new() -> Self {
        Self
    }

    // SAFETY: We use raw FFI for Windows Event Log access.
    // Handles are properly closed with EvtClose.
    #[allow(unsafe_code)]
    pub fn get_system_errors_detailed(&self) -> Vec<EventInfo> {
        use windows::Win32::System::EventLog::{EvtQuery, EvtNext, EVT_HANDLE, EvtRender, EvtClose, EvtFormatMessage};

        let mut fetch_channel = |channel_name: &str| -> Vec<EventInfo> {
            unsafe {
                let query = windows::core::w!("*[System[(Level=1 or Level=2)]]"); // Errors & Criticals only
                let channel_wide = windows::core::HSTRING::from(channel_name);
                let channel_pcwstr = windows::core::PCWSTR(channel_wide.as_ptr());

                let query_handle = match EvtQuery(None, channel_pcwstr, query, 0x201u32) {
                    Ok(handle) => handle,
                    Err(e) => {
                        eprintln!("Failed to query {channel_name}: {e:?}");
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
                let mut events_buf: [isize; 10] = [0; 10];
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

                        let _ = EvtRender(None, event_handle, 1u32, buffer_size, None, &raw mut buffer_used, &raw mut property_count);
                        
                        buffer_size = buffer_used;
                        let mut buffer: Vec<u16> = vec![0; (buffer_size / 2) as usize];
                        
                        let render_result = EvtRender(None, event_handle, 1u32, buffer_size, Some(buffer.as_mut_ptr().cast()), &raw mut buffer_used, &raw mut property_count);

                        if render_result.is_ok() {
                            let xml = String::from_utf16_lossy(&buffer);
                            
                            // Parse XML using quick-xml
                            if let Some(parsed) = Self::parse_event_xml(&xml) {
                                // Check time first
                                if let Ok(dt) = DateTime::parse_from_rfc3339(&parsed.raw_time) {
                                    if dt < cutoff_time {
                                        let _ = EvtClose(event_handle);
                                        // Since we fetch in reverse order, if we hit an old event, we can stop.
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
                                    // Use data items from parsed XML if message formatting failed
                                    full_message = if parsed.data_items.is_empty() { 
                                        format!("Event {} from {}", parsed.event_id, parsed.provider) 
                                    } else { 
                                        parsed.data_items.join(" ") 
                                    };
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

    fn parse_event_xml(xml_str: &str) -> Option<ParsedEvent> {
        let mut reader = Reader::from_str(xml_str);
        reader.config_mut().trim_text(true);

        let mut event_id = String::new();
        let mut provider = String::new();
        let mut raw_time = String::new();
        let mut data_items = Vec::new();

        loop {
            match reader.read_event() {
                Ok(Event::Start(ref e)) => {
                    match e.name().as_ref() {
                        b"TimeCreated" => {
                            if let Some(attr) = e.attributes().find(|a| a.as_ref().map(|a| a.key.as_ref() == b"SystemTime").unwrap_or(false)) {
                                if let Ok(a) = attr {
                                    raw_time = String::from_utf8_lossy(&a.value).to_string();
                                }
                            }
                        }
                        b"Provider" => {
                            if let Some(attr) = e.attributes().find(|a| a.as_ref().map(|a| a.key.as_ref() == b"Name").unwrap_or(false)) {
                                if let Ok(a) = attr {
                                    provider = String::from_utf8_lossy(&a.value).to_string();
                                }
                            }
                        }
                        b"EventID" => {
                            if let Ok(txt) = reader.read_text(e.name()) {
                                event_id = txt.to_string();
                            }
                        }
                        b"Data" => {
                             if let Ok(txt) = reader.read_text(e.name()) {
                                let txt_str = txt.to_string();
                                if !txt_str.is_empty() {
                                    data_items.push(txt_str);
                                }
                            }
                        }
                        _ => {}
                    }
                }
                Ok(Event::Empty(ref e)) => {
                    match e.name().as_ref() {
                        b"TimeCreated" => {
                            if let Some(attr) = e.attributes().find(|a| a.as_ref().map(|a| a.key.as_ref() == b"SystemTime").unwrap_or(false)) {
                                if let Ok(a) = attr {
                                    raw_time = String::from_utf8_lossy(&a.value).to_string();
                                }
                            }
                        }
                        b"Provider" => {
                            if let Some(attr) = e.attributes().find(|a| a.as_ref().map(|a| a.key.as_ref() == b"Name").unwrap_or(false)) {
                                if let Ok(a) = attr {
                                    provider = String::from_utf8_lossy(&a.value).to_string();
                                }
                            }
                        }
                        _ => {}
                    }
                }
                Ok(Event::Eof) => break,
                Err(_) => return None,
                _ => {}
            }
        }

        Some(ParsedEvent {
            event_id,
            provider,
            raw_time,
            data_items,
        })
    }
}

struct ParsedEvent {
    event_id: String,
    provider: String,
    raw_time: String,
    data_items: Vec<String>,
}
