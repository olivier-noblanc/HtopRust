use crate::Language;

#[derive(Clone)]
pub struct WifiInfo {
    pub ssid: String,
    pub bssid: String,
    pub standard: String,
    pub auth: String,
    pub cipher: String,
    pub channel: String,
    pub frequency: String,
    pub rx_rate: String,
    pub tx_rate: String,
    pub signal: String,
    pub ip_address: String,
    pub log_details: String,
}

pub struct WifiManager {
    demo_mode: bool,
}

impl WifiManager {
    pub fn new(demo_mode: bool) -> Self {
        Self { demo_mode }
    }

    #[allow(non_upper_case_globals, unsafe_code)]
    pub fn get_wifi_details(&self, lang: Language) -> Option<WifiInfo> {
        use windows::Win32::NetworkManagement::WiFi::{WlanOpenHandle, WLAN_INTERFACE_INFO_LIST, WlanEnumInterfaces, WlanCloseHandle, WlanFreeMemory, WLAN_OPCODE_VALUE_TYPE, WlanQueryInterface, wlan_intf_opcode_current_connection, WLAN_CONNECTION_ATTRIBUTES, dot11_phy_type_ofdm, dot11_phy_type_erp, dot11_phy_type_hrdsss, dot11_phy_type_ht, dot11_phy_type_vht, dot11_phy_type_he};
        use windows::Win32::Foundation::HANDLE;
        use std::ptr;
        
        unsafe {
            let mut negotiated_version: u32 = 0;
            let mut client_handle: HANDLE = HANDLE::default();
            
            let result = WlanOpenHandle(
                2,
                None,
                &raw mut negotiated_version,
                &raw mut client_handle,
            );
            
            if result != 0 {
                return None;
            }
            
            let mut interface_list: *mut WLAN_INTERFACE_INFO_LIST = ptr::null_mut();
            let result = WlanEnumInterfaces(client_handle, None, &raw mut interface_list);
            
            if result != 0 {
                WlanCloseHandle(client_handle, None);
                return None;
            }

            let list = if let Some(l) = interface_list.as_ref() { l } else {
                WlanCloseHandle(client_handle, None);
                return None;
            };
            if list.dwNumberOfItems == 0 {
                WlanFreeMemory(interface_list.cast());
                WlanCloseHandle(client_handle, None);
                return None;
            }
            
            let interface = &list.InterfaceInfo[0];
            
            let mut data_size: u32 = 0;
            let mut data_ptr: *mut std::ffi::c_void = ptr::null_mut();
            let mut value_type = WLAN_OPCODE_VALUE_TYPE::default();
            
            let result = WlanQueryInterface(
                client_handle,
                &raw const interface.InterfaceGuid,
                wlan_intf_opcode_current_connection,
                None,
                &raw mut data_size,
                &raw mut data_ptr,
                Some(&raw mut value_type),
            );
            
            if result != 0 || data_ptr.is_null() {
                WlanFreeMemory(interface_list.cast());
                WlanCloseHandle(client_handle, None);
                return None;
            }
            
            let connection = &*(data_ptr as *const WLAN_CONNECTION_ATTRIBUTES);
            
            let ssid_len = connection.wlanAssociationAttributes.dot11Ssid.uSSIDLength as usize;
            let ssid_bytes = &connection.wlanAssociationAttributes.dot11Ssid.ucSSID[..ssid_len];
            let ssid = if self.demo_mode {
                "CoffeeShop-WiFi".to_string()
            } else {
                String::from_utf8_lossy(ssid_bytes).to_string()
            };
            
            let bssid_bytes = &connection.wlanAssociationAttributes.dot11Bssid;
            let bssid = if self.demo_mode {
                "AA:BB:CC:DD:EE:FF".to_string()
            } else {
                format!("{:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X}",
                    bssid_bytes[0], bssid_bytes[1], bssid_bytes[2],
                    bssid_bytes[3], bssid_bytes[4], bssid_bytes[5])
            };
            
            let signal = connection.wlanAssociationAttributes.wlanSignalQuality;
            let auth = self.translate_auth_algorithm(connection.wlanSecurityAttributes.dot11AuthAlgorithm, lang);
            let cipher = self.translate_cipher_algorithm(connection.wlanSecurityAttributes.dot11CipherAlgorithm, lang);
            let rx_rate = connection.wlanAssociationAttributes.ulRxRate / 1000;
            let tx_rate = connection.wlanAssociationAttributes.ulTxRate / 1000;
            
            let (channel, frequency) = match connection.wlanAssociationAttributes.dot11PhyType {
                dot11_phy_type_ofdm => ("36".to_string(), "5 GHz".to_string()),
                dot11_phy_type_erp => ("6".to_string(), "2.4 GHz".to_string()),
                dot11_phy_type_hrdsss => ("6".to_string(), "2.4 GHz".to_string()),
                dot11_phy_type_ht => ("11".to_string(), "2.4 GHz".to_string()),
                dot11_phy_type_vht => ("44".to_string(), "5 GHz".to_string()),
                dot11_phy_type_he => ("100".to_string(), "5 GHz".to_string()),
                _ => ("N/A".to_string(), "N/A".to_string()),
            };
            
            let ip_address = if self.demo_mode {
                "192.168.1.100".to_string()
            } else {
                use std::net::UdpSocket;
                UdpSocket::bind("0.0.0.0:0")
                    .and_then(|s| s.connect("8.8.8.8:80").map(|()| s))
                    .and_then(|s| s.local_addr()).map_or_else(|_| "N/A".to_string(), |addr| addr.ip().to_string())
            };

            let log_details = if self.demo_mode {
                "802.1x Auth: PEAP-MSCHAPv2".to_string()
            } else {
                self.fetch_wlan_auth_info(lang)
            };

            let wifi_info = Some(WifiInfo {
                ssid,
                bssid,
                standard: "WiFi".to_string(),
                auth,
                cipher,
                channel,
                frequency,
                rx_rate: format!("{rx_rate} Mbps"),
                tx_rate: format!("{tx_rate} Mbps"),
                signal: format!("{signal}%"),
                ip_address,
                log_details,
            });
            
            WlanFreeMemory(data_ptr);
            WlanFreeMemory(interface_list.cast());
            WlanCloseHandle(client_handle, None);
            
            wifi_info
        }
    }

    #[allow(unsafe_code)]
    fn fetch_wlan_auth_info(&self, lang: Language) -> String {
         use windows::Win32::System::EventLog::{EvtQuery, EvtNext, EvtClose, EVT_HANDLE, EvtRender};

         unsafe {
             let query_str = "*[System[(EventID=12013 or EventID=11002)]]"; 
             let channel_wide = windows::core::w!("Microsoft-Windows-WLAN-AutoConfig/Operational");
             let query_wide = windows::core::HSTRING::from(query_str);
             
             let query_handle = match EvtQuery(None, channel_wide, windows::core::PCWSTR(query_wide.as_ptr()), 0x101u32) {
                 Ok(h) => h,
                 Err(_) => return String::new(),
             };

             let mut events_buf: [isize; 5] = [0; 5];
             let mut returned: u32 = 0;
             
             if EvtNext(query_handle, &mut events_buf, 0, 0, &raw mut returned).is_err() || returned == 0 {
                 let _ = EvtClose(query_handle);
                 return String::new();
             }

             let mut auth_info = String::new();

             for &event_raw in events_buf.iter().take(returned as usize) {
                 let event_handle = EVT_HANDLE(event_raw);
                 
                 let mut xml_buffer_size: u32 = 0;
                 let mut xml_buffer_used: u32 = 0;
                 let mut property_count: u32 = 0;

                 let _ = EvtRender(None, event_handle, 1u32, xml_buffer_size, None, &raw mut xml_buffer_used, &raw mut property_count);
                 
                 xml_buffer_size = xml_buffer_used;
                 let mut xml_buffer: Vec<u16> = vec![0; (xml_buffer_size / 2) as usize];
                 
                 if EvtRender(None, event_handle, 1u32, xml_buffer_size, Some(xml_buffer.as_mut_ptr().cast()), &raw mut xml_buffer_used, &raw mut property_count).is_ok() {
                     let xml = String::from_utf16_lossy(&xml_buffer);
                     
                     let event_id = xml.split("<EventID>").nth(1)
                         .and_then(|s| s.split("</EventID>").next())
                         .unwrap_or("");
                     
                     if event_id == "12013" {
                         let mut eap_type = String::new();
                         let mut inner_eap_type = String::new();
                         
                         if let Some(start) = xml.find("<Data Name='EapType'>") {
                             let content_start = start + 21;
                             if let Some(end) = xml[content_start..].find("</Data>") {
                                 eap_type = xml[content_start..content_start + end].trim().to_string();
                             }
                         }
                         
                         if let Some(start) = xml.find("<Data Name='InnerEapType'>") {
                             let content_start = start + 26;
                             if let Some(end) = xml[content_start..].find("</Data>") {
                                 inner_eap_type = xml[content_start..content_start + end].trim().to_string();
                             }
                         }
                         
                         let eap_method = match eap_type.as_str() {
                             "13" => "EAP-TLS",
                             "25" => {
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
                             _ => &format!("EAP-{eap_type}"),
                         };
                         
                         if !eap_method.is_empty() {
                             auth_info = match lang {
                                 Language::Fr => format!("Auth 802.1x: {eap_method}"),
                                 Language::En => format!("802.1x Auth: {eap_method}"),
                             };
                             break;
                         }
                     }
                 }
                 
                 let _ = EvtClose(event_handle);
             }
             
             let _ = EvtClose(query_handle);
             auth_info
         }
    }

    fn translate_auth_algorithm(&self, auth: windows::Win32::NetworkManagement::WiFi::DOT11_AUTH_ALGORITHM, lang: Language) -> String {
        use windows::Win32::NetworkManagement::WiFi::{DOT11_AUTH_ALGO_80211_OPEN, DOT11_AUTH_ALGO_80211_SHARED_KEY, DOT11_AUTH_ALGO_WPA, DOT11_AUTH_ALGO_WPA_PSK, DOT11_AUTH_ALGO_WPA_NONE, DOT11_AUTH_ALGO_RSNA, DOT11_AUTH_ALGO_RSNA_PSK, DOT11_AUTH_ALGO_WPA3, DOT11_AUTH_ALGO_WPA3_SAE, DOT11_AUTH_ALGO_OWE, DOT11_AUTH_ALGO_IHV_START, DOT11_AUTH_ALGO_IHV_END};
        
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
        
        match lang {
            Language::Fr => fr.to_string(),
            Language::En => en.to_string(),
        }
    }

    fn translate_cipher_algorithm(&self, cipher: windows::Win32::NetworkManagement::WiFi::DOT11_CIPHER_ALGORITHM, lang: Language) -> String {
        use windows::Win32::NetworkManagement::WiFi::{DOT11_CIPHER_ALGO_NONE, DOT11_CIPHER_ALGO_WEP40, DOT11_CIPHER_ALGO_TKIP, DOT11_CIPHER_ALGO_CCMP, DOT11_CIPHER_ALGO_WEP104, DOT11_CIPHER_ALGO_BIP, DOT11_CIPHER_ALGO_GCMP, DOT11_CIPHER_ALGO_GCMP_256, DOT11_CIPHER_ALGO_CCMP_256, DOT11_CIPHER_ALGO_BIP_GMAC_128, DOT11_CIPHER_ALGO_BIP_GMAC_256, DOT11_CIPHER_ALGO_BIP_CMAC_256, DOT11_CIPHER_ALGO_WEP, DOT11_CIPHER_ALGO_IHV_START, DOT11_CIPHER_ALGO_IHV_END};
        
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
        
        match lang {
            Language::Fr => fr.to_string(),
            Language::En => en.to_string(),
        }
    }
}
