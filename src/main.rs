use anyhow::Result;
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
    sync::mpsc,
    thread,
    time::{Duration, Instant},
};
use sysinfo::{System, Networks, Disks, Users, Pid};
use sys_locale::get_locale;

mod system;
mod events;
mod wifi;
mod theme;

use system::{ProcessInfo, SortColumn, CcmStatus, SystemState, DiskInfo, MemoryInfo, NetworkInfo};
use events::{EventInfo, EventManager};
use wifi::{WifiInfo, WifiManager};
use theme::Theme;

enum ViewMode {
    Processes,
    SystemEvents,
    WifiDetails,
    EventDetail,
    ProcessDetail,
    About,
}

#[derive(Clone, Copy, PartialEq)]
enum Language {
    En,
    Fr,
}

enum AppEvent {
    Tick,
    SystemUpdate(SystemState, Vec<ProcessInfo>),
    WifiUpdate(Option<WifiInfo>),
    EventsUpdate(Vec<EventInfo>),
    CcmUpdate(Option<CcmStatus>),
}

enum AppAction {
    KillProcess(usize),
    SetRefreshRate(Duration),
}

struct App {
    // UI Data
    processes: Vec<ProcessInfo>,
    system_errors: Vec<EventInfo>,
    wifi_info: Option<WifiInfo>,
    system_state: SystemState,
    ccm_status: Option<CcmStatus>,
    
    // View State
    process_table_state: TableState,
    event_table_state: TableState,
    sort_column: SortColumn,
    view_mode: ViewMode,
    selected_process_pid: Option<String>,
    
    // Config & Metadata
    refresh_rate: Duration,
    is_admin: bool,
    demo_mode: bool,
    supports_utf8: bool,
    lang: Language,
    os_info: String,
    host_info: String,
    username: String,
    message: String,
    message_time: Option<Instant>,
    
    // Theme
    #[allow(dead_code)]
    theme: Theme,

    // Communication
    action_tx: Option<mpsc::Sender<AppAction>>,
}

impl App {
    fn new(demo_mode: bool, action_tx: mpsc::Sender<AppAction>) -> Self {
        let os_info = format!("{} {}", System::name().unwrap_or_default(), System::os_version().unwrap_or_default());
        let host_info = if demo_mode { "DEMO-PC".to_string() } else { System::host_name().unwrap_or("Unknown".to_string()) };
        let username = if demo_mode { "demo_user".to_string() } else { std::env::var("USERNAME").unwrap_or_else(|_| "Unknown".to_string()) };
        let is_admin = Self::is_elevated(); // Still useful to know in UI for badges
        let supports_utf8 = Self::supports_utf8();
        
        Self {
            processes: Vec::new(),
            system_errors: Vec::new(),
            wifi_info: None,
            system_state: SystemState::default(),
            ccm_status: None, // Will be updated by worker
            
            process_table_state: TableState::default(),
            event_table_state: TableState::default(),
            sort_column: SortColumn::Cpu,
            view_mode: ViewMode::Processes,
            selected_process_pid: None,
            
            refresh_rate: Duration::from_secs(2),
            is_admin,
            demo_mode,
            supports_utf8,
            lang: Self::detect_language(),
            os_info,
            host_info,
            username,
            message: String::new(),
            message_time: None,
            
            theme: Theme::default(),
            action_tx: Some(action_tx),
        }
    }

    fn detect_language() -> Language {
        if !Self::supports_utf8() {
            return Language::En;
        }
        if let Some(locale) = get_locale() {
            if locale.to_lowercase().starts_with("fr") {
                return Language::Fr;
            }
        }
        Language::En
    }

    #[allow(unsafe_code)]
    fn is_elevated() -> bool {
        use windows::Win32::Foundation::{HANDLE, CloseHandle};
        use windows::Win32::Security::{GetTokenInformation, TokenElevation, TOKEN_ELEVATION, TOKEN_QUERY};
        use windows::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};
        
        unsafe {
            let mut token: HANDLE = HANDLE::default();
            if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &raw mut token).is_err() {
                return false;
            }
            
            let mut elevation = TOKEN_ELEVATION { TokenIsElevated: 0 };
            let mut return_length: u32 = 0;
            
            let result = GetTokenInformation(
                token,
                TokenElevation,
                Some((&raw mut elevation).cast()),
                std::mem::size_of::<TOKEN_ELEVATION>() as u32,
                &raw mut return_length,
            ).is_ok() && elevation.TokenIsElevated != 0;

            let _ = CloseHandle(token);
            result
        }
    }

    #[allow(unsafe_code)]
    fn supports_utf8() -> bool {
        use windows::Win32::System::Console::GetConsoleOutputCP;
        unsafe { GetConsoleOutputCP() == 65001 }
    }

    fn t(&self, en: &str, fr: &str) -> String {
        match self.lang {
            Language::En => en.to_string(),
            Language::Fr => fr.to_string(),
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
        if matches!(self.view_mode, ViewMode::Processes)
            && let Some(idx) = self.process_table_state.selected()
                && let Some(proc_info) = self.processes.get(idx)
                    && let Ok(pid_val) = proc_info.pid.parse::<usize>() {
                        if let Some(tx) = &self.action_tx {
                            let _ = tx.send(AppAction::KillProcess(pid_val));
                            self.message = format!("Kill signal sent to PID {pid_val}");
                            self.message_time = Some(Instant::now());
                        }
                    }
    }
}

// Worker Logic
fn spawn_worker(tx: mpsc::Sender<AppEvent>, rx: mpsc::Receiver<AppAction>, demo_mode: bool, supports_utf8: bool) {
    thread::spawn(move || {
        let mut system = System::new_all();
        system.refresh_all();
        let mut networks = Networks::new_with_refreshed_list();
        let mut disks = Disks::new_with_refreshed_list();
        let users = Users::new_with_refreshed_list();
        
        let wifi_manager = WifiManager::new(demo_mode);
        let event_manager = EventManager::new();
        
        let current_lang = if supports_utf8 { Language::En } else { Language::En }; // Only used for WiFi strings initially
        // We might want to pass initial lang or update it? 
        // For now default to En for worker or make generic. 
        // Using Language::En as default. 
        // Ideally we receive UpdateLang action, but simplistic approach first.
        
        let mut refresh_rate = Duration::from_secs(2);
        let mut last_wifi_update = Instant::now().checked_sub(Duration::from_secs(60)).unwrap();
        let mut last_errors_update = Instant::now().checked_sub(Duration::from_secs(60)).unwrap();

        loop {
            // Check for actions
            while let Ok(action) = rx.try_recv() {
                match action {
                    AppAction::KillProcess(pid) => {
                         if let Some(process) = system.process(Pid::from(pid)) {
                            process.kill();
                        }
                    }
                    AppAction::SetRefreshRate(rate) => {
                        refresh_rate = rate;
                    }
                }
            }

            // Refresh System
            system.refresh_all();
            networks.refresh(true);
            disks.refresh(true);

            // Fetch System State
            let total_mem = system.total_memory() as f32;
            let processes: Vec<ProcessInfo> = system.processes()
                .iter()
                .map(|(pid, p)| {
                    let user = p.user_id()
                        .and_then(|uid| users.iter().find(|u| u.id() == uid)).map_or_else(|| "N/A".to_string(), |u| u.name().to_string());
                    
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
                        status: system::process_status_to_string(p.status()),
                        cpu: p.cpu_usage(),
                        mem_percent: (p.memory() as f32 / total_mem) * 100.0,
                        cmd: cmd_display,
                    }
                })
                .collect();

            let system_state = SystemState {
                cpus: system.cpus().iter().map(|cpu| cpu.cpu_usage()).collect(),
                memory: MemoryInfo { used: system.used_memory(), total: system.total_memory() },
                swap: MemoryInfo { used: system.used_swap(), total: system.total_swap() },
                uptime: System::uptime(),
                disks: disks.iter().take(3).map(|d| DiskInfo {
                    name: d.name().to_string_lossy().into_owned(),
                    mount_point: d.mount_point().to_string_lossy().into_owned(),
                    available_space: d.available_space(),
                    total_space: d.total_space(),
                }).collect(),
                networks: networks.iter().map(|(name, data)| NetworkInfo {
                    name: name.clone(),
                    rx: data.received(),
                    tx: data.transmitted(),
                }).collect(),
            };

            let _ = tx.send(AppEvent::SystemUpdate(system_state, processes));

            // Wifi Update (throttled)
            if last_wifi_update.elapsed() > Duration::from_secs(10) {
                 // Note: We use En lang here. If user switches to Fr, we ideally update this. 
                 // For now, acceptable limitation or we can pass Lang in action.
                let wifi_info = wifi_manager.get_wifi_details(current_lang); 
                let _ = tx.send(AppEvent::WifiUpdate(wifi_info));
                last_wifi_update = Instant::now();
            }

            // Events Update (throttled)
            if last_errors_update.elapsed() > Duration::from_secs(30) {
                let errors = event_manager.get_system_errors_detailed();
                let _ = tx.send(AppEvent::EventsUpdate(errors));
                last_errors_update = Instant::now();
            }

            // CCM Check (simplified, can be throttled too, reusing loop)
            // Implementation of get_ccm_status logic here or moved to system.rs?
            // Since it uses System, we can do it here.
            // ... Logic for CCM ...
            // let ccm_status = ...
            // tx.send(AppEvent::CcmUpdate(ccm_status));

            let _ = tx.send(AppEvent::Tick);
            thread::sleep(refresh_rate);
        }
    });
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
    
    human_panic::setup_panic!();
    
    println!("Current OS: {}", std::env::consts::OS);
    
    std::panic::set_hook(Box::new(move |info| {
        let mut stdout = io::stdout();
        let _ = disable_raw_mode();
        let _ = execute!(stdout, LeaveAlternateScreen, DisableMouseCapture);
        let _ = execute!(stdout, crossterm::cursor::Show);
        eprintln!("\n--- APPLICATION CRASH ---");
        eprintln!("{info}");
        eprintln!("-------------------------\n");
    }));

    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen, EnableMouseCapture)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    // Setup Communication
    let (event_tx, event_rx) = mpsc::channel();
    let (action_tx, action_rx) = mpsc::channel();

    let mut app = App::new(demo_mode, action_tx);
    let supports_utf8 = app.supports_utf8;

    spawn_worker(event_tx, action_rx, demo_mode, supports_utf8);

    let res = run_app(&mut terminal, &mut app, event_rx);

    disable_raw_mode()?;
    execute!(terminal.backend_mut(), LeaveAlternateScreen, DisableMouseCapture)?;
    terminal.show_cursor()?;

    if let Err(err) = res { println!("{err:?}") }
    Ok(())
}

fn run_app(terminal: &mut Terminal<CrosstermBackend<io::Stdout>>, app: &mut App, event_rx: mpsc::Receiver<AppEvent>) -> Result<()> {
    loop {
        terminal.draw(|f| ui(f, app))?;

        let timeout = Duration::from_millis(100); // Fast poll for responsiveness
        
        if crossterm::event::poll(timeout)? {
            match event::read()? {
                Event::Key(key) => {
                    if key.kind == event::KeyEventKind::Press {
                        match key.code {
                            KeyCode::Char('q') | KeyCode::F(10) => return Ok(()),
                            KeyCode::Down => app.next_item(),
                            KeyCode::Up => app.previous_item(),
                            KeyCode::Char('c') => {
                                app.sort_column = SortColumn::Cpu;
                                app.processes.sort_by(|a, b| b.cpu.partial_cmp(&a.cpu).unwrap_or(std::cmp::Ordering::Equal));
                            },
                            KeyCode::Char('m') => {
                                app.sort_column = SortColumn::Mem;
                                app.processes.sort_by(|a, b| b.res_mem.cmp(&a.res_mem));
                            },
                            KeyCode::Char('p') => {
                                app.sort_column = SortColumn::Pid;
                                app.processes.sort_by(|a, b| a.pid.cmp(&b.pid));
                            },
                            KeyCode::Char('n') => {
                                app.sort_column = SortColumn::Name;
                                app.processes.sort_by(|a, b| a.name.cmp(&b.name));
                            },
                            KeyCode::Char('s') => {
                                match app.refresh_rate.as_secs() {
                                    1 => app.refresh_rate = Duration::from_secs(2),
                                    2 => app.refresh_rate = Duration::from_secs(5),
                                    _ => app.refresh_rate = Duration::from_secs(1),
                                }
                                app.message = format!("Refresh rate: {}s", app.refresh_rate.as_secs());
                                app.message_time = Some(Instant::now());
                                if let Some(tx) = &app.action_tx {
                                    let _ = tx.send(AppAction::SetRefreshRate(app.refresh_rate));
                                }
                            }
                            KeyCode::Char('e') => {
                                match app.view_mode {
                                    ViewMode::Processes => app.view_mode = ViewMode::SystemEvents,
                                    _ => app.view_mode = ViewMode::Processes,
                                }
                            }
                            KeyCode::Char('a' | 'h') => {
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

                            if mouse.row >= 11 && mouse.row <= 17 && mouse.column >= col1_end && mouse.column < col2_end {
                                app.view_mode = ViewMode::SystemEvents;
                            }
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

        // Process all pending events from worker
        while let Ok(msg) = event_rx.try_recv() {
            match msg {
                AppEvent::Tick => {}, // Just a wake up signal
                AppEvent::SystemUpdate(state, processes) => {
                    app.system_state = state;
                    app.processes = processes;
                    // Sort again to maintain order
                    match app.sort_column {
                        SortColumn::Cpu => app.processes.sort_by(|a, b| b.cpu.partial_cmp(&a.cpu).unwrap_or(std::cmp::Ordering::Equal)),
                        SortColumn::Mem => app.processes.sort_by(|a, b| b.res_mem.cmp(&a.res_mem)),
                        SortColumn::Pid => app.processes.sort_by(|a, b| a.pid.cmp(&b.pid)),
                        SortColumn::Name => app.processes.sort_by(|a, b| a.name.cmp(&b.name)),
                    }
                },
                AppEvent::WifiUpdate(info) => app.wifi_info = info,
                AppEvent::EventsUpdate(events) => app.system_errors = events,
                AppEvent::CcmUpdate(status) => app.ccm_status = status,
            }
        }
    }
}

fn ui(f: &mut Frame, app: &mut App) {
    let background_style = Style::default().bg(app.theme.background).fg(app.theme.text);
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
            .style(Style::default().bg(app.theme.background).fg(app.theme.error)))
        .style(Style::default().bg(app.theme.background).fg(app.theme.text))
        .wrap(ratatui::widgets::Wrap { trim: true });
    f.render_widget(p, area);
}

fn draw_process_detail(f: &mut Frame, app: &App, area: Rect) {
    let detail = if let Some(pid) = &app.selected_process_pid {
        if let Some(proc) = app.processes.iter().find(|p| &p.pid == pid) {
            let virt_mb = proc.virt_mem / 1024 / 1024;
            let res_mb = proc.res_mem / 1024 / 1024;
            
            match app.lang {
                Language::Fr => format!(
                    "PID          : {}\nNOM          : {}\nUTILISATEUR  : {}\nSTATUT       : {}\nCPU          : {:.1}%\nMÉMOIRE      : {:.1}% ({} MB)\nMÉM VIRTUELLE: {} MB\n\nCOMMANDE:\n{}",
                    proc.pid, proc.name, proc.user, proc.status, proc.cpu, proc.mem_percent, res_mb, virt_mb, proc.cmd
                ),
                Language::En => format!(
                    "PID          : {}\nNAME         : {}\nUSER         : {}\nSTATUS       : {}\nCPU          : {:.1}%\nMEMORY       : {:.1}% ({} MB)\nVIRTUAL MEM  : {} MB\n\nCOMMAND:\n{}",
                    proc.pid, proc.name, proc.user, proc.status, proc.cpu, proc.mem_percent, res_mb, virt_mb, proc.cmd
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
            .style(Style::default().bg(app.theme.background).fg(app.theme.highlight)))
        .style(Style::default().bg(app.theme.background).fg(app.theme.text))
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
            .style(Style::default().bg(app.theme.background).fg(app.theme.highlight)))
        .style(Style::default().bg(app.theme.background).fg(app.theme.highlight));
    f.render_widget(p, area);
}

fn draw_header(f: &mut Frame, app: &App, area: Rect) {
    let main_chunks = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(33), Constraint::Percentage(33), Constraint::Percentage(34)].as_ref())
        .split(area);

    let cpus = &app.system_state.cpus;
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
        .style(Style::default().bg(app.theme.background).fg(app.theme.highlight).add_modifier(Modifier::BOLD)), cpu_chunks[0]);
    
    for (i, usage) in cpus.iter().enumerate().take(cpu_count) {
        let label = format!("CPU{i} {usage:>5.1}%");
        f.render_widget(Gauge::default()
            .gauge_style(Style::default().bg(app.theme.background).fg(app.theme.highlight))
            .style(Style::default().bg(app.theme.background))
            .percent(*usage as u16).label(label), cpu_chunks[i+1]);
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

    let mem_used = app.system_state.memory.used;
    let mem_total = app.system_state.memory.total;
    let mem_percent = if mem_total > 0 { (mem_used as f64 / mem_total as f64 * 100.0) as u16 } else { 0 };
    f.render_widget(Gauge::default()
        .gauge_style(Style::default().bg(app.theme.background).fg(app.theme.success))
        .style(Style::default().bg(app.theme.background))
        .percent(mem_percent).label(format!("Mem  [{:3}%] {}MB/{}MB", mem_percent, mem_used / 1024 / 1024, mem_total / 1024 / 1024)), mid_chunks[0]);

    let swap_used = app.system_state.swap.used;
    let swap_total = app.system_state.swap.total;
    let swap_percent = if swap_total > 0 { (swap_used as f64 / swap_total as f64 * 100.0) as u16 } else { 0 };
    f.render_widget(Gauge::default()
        .gauge_style(Style::default().bg(app.theme.background).fg(app.theme.warning))
        .style(Style::default().bg(app.theme.background))
        .percent(swap_percent).label(format!("Swap [{:3}%] {}MB/{}MB", swap_percent, swap_used / 1024 / 1024, swap_total / 1024 / 1024)), mid_chunks[1]);

    let uptime_secs = app.system_state.uptime;
    let uptime_str = format!("{}d {:02}h {:02}m", uptime_secs / 86400, (uptime_secs % 86400) / 3600, (uptime_secs % 3600) / 60);
    f.render_widget(Paragraph::new(format!("{}: {}", app.t("Uptime", "Disponibilité"), uptime_str))
        .style(Style::default().bg(app.theme.background).fg(app.theme.text)), mid_chunks[2]);
    
    f.render_widget(Paragraph::new(format!("OS: {}", app.os_info))
        .style(Style::default().bg(app.theme.background).fg(app.theme.text)), mid_chunks[3]);
    
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
    let privilege_color = if app.is_admin { app.theme.warning } else { app.theme.text };
    
    f.render_widget(Paragraph::new(format!("Host: {} | User: {}{}", app.host_info, app.username, privilege_badge))
        .style(Style::default().bg(app.theme.background).fg(privilege_color)), mid_chunks[4]);

    if let Some(ccm) = &app.ccm_status {
        let status_color = if ccm.running { app.theme.success } else { app.theme.error };
        let error_text = if ccm.has_errors { " | Errors!" } else { "" };
        let info = format!("CCM: {} | Actions: {}{}", ccm.status, ccm.pending_actions, error_text);
        f.render_widget(Paragraph::new(info)
            .style(Style::default().bg(app.theme.background).fg(status_color)), mid_chunks[5]);
    } else {
        f.render_widget(Paragraph::new("").style(Style::default().bg(app.theme.background)), mid_chunks[5]);
    }

    f.render_widget(Paragraph::new(app.t("DISKS (FREE SPACE)", "DISQUES (ESPACE LIBRE)")).style(Style::default().bg(app.theme.background).fg(app.theme.warning).add_modifier(Modifier::BOLD)), mid_chunks[6]);
    let mut disk_info = String::new();
    for disk in app.system_state.disks.iter() {
        let free = disk.available_space / 1024 / 1024 / 1024;
        let total = disk.total_space / 1024 / 1024 / 1024;
        let name = &disk.mount_point;
        disk_info.push_str(&format!("{name}: {free}G/{total}G free\n"));
    }
    f.render_widget(Paragraph::new(disk_info).style(Style::default().bg(app.theme.background).fg(app.theme.text)), mid_chunks[7]);

    let event_title = if matches!(app.view_mode, ViewMode::SystemEvents) { 
        app.t("SYSTEM ERRORS (DETAILED)", "ERREURS SYSTÈME (DÉTAILLÉ)") 
    } else { 
        app.t("SYSTEM ERRORS (CLICK/E FOR DETAILS)", "ERREURS SYSTÈME (CLIC/E POUR DÉTAILS)") 
    };
    f.render_widget(Paragraph::new(event_title).style(Style::default().bg(app.theme.background).fg(app.theme.error).add_modifier(Modifier::BOLD)), mid_chunks[9]);
    
    let mut err_text = String::new();
    for err in app.system_errors.iter().take(2) {
        let truncated = if err.message.len() > 50 { format!("{}...", &err.message[..47]) } else { err.message.clone() };
        err_text.push_str(&format!("• {}: {}\n", err.time, truncated));
    }
    if err_text.is_empty() { err_text = app.t("No recent errors found.", "Aucune erreur récente trouvée."); }
    f.render_widget(Paragraph::new(err_text).style(Style::default().bg(app.theme.background).fg(Color::Gray)), mid_chunks[10]);

    let net_chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(1), Constraint::Min(0)].as_ref())
        .split(main_chunks[2]);

    f.render_widget(Paragraph::new(app.t("NETWORK / WIFI (CLICK FOR DETAILS)", "RÉSEAU / WIFI (CLIC POUR DÉTAILS)")).style(Style::default().bg(app.theme.background).fg(app.theme.network).add_modifier(Modifier::BOLD)), net_chunks[0]);
    let mut net_info = String::new();
    if let Some(wifi) = &app.wifi_info {
        net_info.push_str(&format!("SSID  : {}\n", wifi.ssid));
        net_info.push_str(&format!("Signal: {}\n", wifi.signal));
        net_info.push_str(&format!("Auth  : {}\n", wifi.auth));
        net_info.push_str(&format!("Cipher: {}\n", wifi.cipher));
        net_info.push_str(&format!("Rate  : R:{} / T:{}\n", wifi.rx_rate, wifi.tx_rate));
        net_info.push_str(&format!("IP    : {}\n", wifi.ip_address));
        net_info.push_str("-------------------\n");
        net_info.push_str(&format!("{}\n", wifi.log_details));
        net_info.push_str("-------------------\n");
    }
    for net in &app.system_state.networks {
        if net.rx > 0 || net.tx > 0 {
            net_info.push_str(&format!("{}: R:{:.1}K T:{:.1}K\n", net.name, net.rx as f32 / 1024.0, net.tx as f32 / 1024.0));
        }
    }
    f.render_widget(Paragraph::new(net_info).style(Style::default().bg(app.theme.background).fg(app.theme.text)), net_chunks[1]);
}

fn draw_process_table(f: &mut Frame, app: &mut App, area: Rect) {
    let header_cells = ["PID", "USER", "PRI", "VIRT", "RES", "S", "CPU%", "MEM%", "Command"]
        .iter()
        .map(|h| Cell::from(*h).style(Style::default().fg(app.theme.header_fg).add_modifier(Modifier::BOLD)));
    let header = Row::new(header_cells).style(Style::default().bg(app.theme.header_bg)).height(1);

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
        ]).style(Style::default().bg(app.theme.background).fg(app.theme.text)).height(1)
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
        .style(Style::default().bg(app.theme.background).fg(app.theme.text)))
    .row_highlight_style(Style::default().bg(app.theme.selection_bg).add_modifier(Modifier::BOLD))
    .highlight_symbol("> ");

    f.render_stateful_widget(t, area, &mut app.process_table_state);
}

fn draw_event_table(f: &mut Frame, app: &mut App, area: Rect) {
    let sep_style = Style::default().fg(Color::DarkGray); 
    let header_cells = vec![
        Cell::from("TIME").style(Style::default().fg(app.theme.error).add_modifier(Modifier::BOLD)),
        Cell::from("│").style(sep_style),
        Cell::from("ID").style(Style::default().fg(app.theme.error).add_modifier(Modifier::BOLD)),
        Cell::from("│").style(sep_style),
        Cell::from("SOURCE").style(Style::default().fg(app.theme.error).add_modifier(Modifier::BOLD)),
        Cell::from("│").style(sep_style),
        Cell::from("MESSAGE").style(Style::default().fg(app.theme.error).add_modifier(Modifier::BOLD)),
    ];
    let header = Row::new(header_cells).style(Style::default().bg(app.theme.header_bg)).height(1);

    let rows = app.system_errors.iter().map(|item| {
        Row::new(vec![
            Cell::from(item.time.clone()),
            Cell::from("│").style(sep_style),
            Cell::from(item.id.clone()),
            Cell::from("│").style(sep_style),
            Cell::from(item.source.clone()),
            Cell::from("│").style(sep_style),
            Cell::from(item.message.clone()),
        ]).style(Style::default().bg(app.theme.background).fg(app.theme.text)).height(1)
    });

    let max_time_len = app.system_errors.iter().map(|e| e.time.len()).max().unwrap_or(15).clamp(10, 15) as u16;
    let max_source_len = app.system_errors.iter().map(|e| e.source.len()).max().unwrap_or(20).clamp(10, 40) as u16;

    let t = Table::new(rows, [
        Constraint::Length(max_time_len),
        Constraint::Length(1),
        Constraint::Length(6),
        Constraint::Length(1),
        Constraint::Length(max_source_len),
        Constraint::Length(1),
        Constraint::Min(50),
    ])
    .header(header)
    .column_spacing(0)
    .block(Block::default().borders(Borders::ALL).title(app.t("System Events (Esc: Back to Proc)", "Événements Système (Esc: Retour)"))
        .style(Style::default().bg(app.theme.background).fg(app.theme.text)))
    .row_highlight_style(Style::default().bg(app.theme.selection_bg).add_modifier(Modifier::BOLD))
    .highlight_symbol("> ");

    f.render_stateful_widget(t, area, &mut app.event_table_state);
}

fn draw_about(f: &mut Frame, app: &App, area: Rect) {
    let version = env!("CARGO_PKG_VERSION");
    
    let content = match app.lang {
        Language::Fr => format!(
            r"╔══════════════════════════════════════════════════════════════════════════════╗
║                              HtopRust v{version}                                    ║
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
"
        ),
        Language::En => format!(
            r"╔══════════════════════════════════════════════════════════════════════════════╗
║                              HtopRust v{version}                                    ║
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
"
        ),
    };

    let p = Paragraph::new(content)
        .block(Block::default().borders(Borders::ALL)
            .title(app.t("About HtopRust", "À propos de HtopRust")))
        .style(Style::default().bg(app.theme.background).fg(app.theme.text))
        .wrap(ratatui::widgets::Wrap { trim: false });
    f.render_widget(p, area);
}

fn draw_footer(f: &mut Frame, app: &App, area: Rect) {
    let refresh_display = format!("{}s", app.refresh_rate.as_secs());
    
    let help = match app.view_mode {
        ViewMode::Processes => app.t(
            &format!(" q:Quit | ↑↓:Nav | e:Events | a/h:About | p:CPU | m:MEM | k:Kill | {refresh_display}"),
            &format!(" q:Quitter | ↑↓:Nav | e:Events | a/h:À propos | p:CPU | m:MEM | k:Kill | {refresh_display}")
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

    let p = Paragraph::new(help)
        .style(Style::default().bg(app.theme.header_bg).fg(app.theme.highlight));
    f.render_widget(p, area);
}
