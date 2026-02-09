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
use std::time::{Duration, Instant};
use std::sync::{Arc, RwLock, mpsc};
use std::thread;
use std::io;
use sysinfo::{System, Networks, Disks, Users, Pid};

mod system;
mod events;
mod wifi;
mod theme;


use system::{ProcessInfo, SortColumn, CcmStatus, SystemState, DiskInfo, MemoryInfo, NetworkInfo};
use events::{EventInfo, EventManager};
use wifi::{WifiInfo, WifiManager};
use theme::Theme;
use rust_i18n::t;

rust_i18n::i18n!("locales");

struct AppState {
    processes: Vec<ProcessInfo>,
    events: Vec<EventInfo>,
    wifi_info: Option<WifiInfo>,
    system_state: SystemState,
    ccm_status: Option<CcmStatus>,
}

#[derive(Clone, Copy, PartialEq)]
enum ViewMode {
    Processes,
    ProcessDetail,
    SystemEvents,
    EventDetail,
    WifiDetails,
    About,
}
// Removed AppEvent enum as we are moving to shared state
// But we might still need some events if we want TUI to react to things? 
// No, the user said "Native API Only ... Zero-copy memory sharing". 
// The UI loop reads from Arc<RwLock>.
// We might keep Action enum for UI->Worker communication if needed?
// The user example kept Action channel? No, user example didn't show actions much.
// But we have "KillProcess" action. We probably still need a channel for User Actions -> Worker.

enum AppAction {
    KillProcess(String), // Use String PID for simplicity
    SetRefreshRate(Duration),
}



struct App {
    state: Arc<RwLock<AppState>>,
    
    // View State
    process_table_state: TableState,
    event_table_state: TableState,
    sort_column: SortColumn,
    view_mode: ViewMode,
    selected_process_pid: Option<String>,
    
    // Config & Metadata
    refresh_rate: Duration,
    is_admin: bool,
    #[allow(dead_code)]
    demo_mode: bool,
    #[allow(dead_code)]
    supports_utf8: bool,
    // lang: Language, // Removed
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
    fn new(demo_mode: bool, action_tx: mpsc::Sender<AppAction>, state: Arc<RwLock<AppState>>) -> Self {
        let os_info = format!("{} {}", System::name().unwrap_or_default(), System::os_version().unwrap_or_default());
        let host_info = if demo_mode { "DEMO-PC".to_string() } else { System::host_name().unwrap_or("Unknown".to_string()) };
        let username = if demo_mode { "demo_user".to_string() } else { std::env::var("USERNAME").unwrap_or_else(|_| "Unknown".to_string()) };
        let is_admin = Self::is_elevated(); 
        let supports_utf8 = Self::supports_utf8();
        
        // Language detection and setting moved to main()
        
        Self {
            state,
            
            process_table_state: TableState::default(),
            event_table_state: TableState::default(),
            sort_column: SortColumn::Cpu,
            view_mode: ViewMode::Processes,
            selected_process_pid: None,
            
            refresh_rate: Duration::from_secs(2),
            is_admin,
            demo_mode,
            supports_utf8,
            os_info,
            host_info,
            username,
            message: String::new(),
            message_time: None,
            
            theme: Theme::default(),
            action_tx: Some(action_tx),
        }
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

    fn next_item(&mut self) {
        let state = self.state.read().unwrap();
        match self.view_mode {
            ViewMode::Processes | ViewMode::ProcessDetail => {
                let i = match self.process_table_state.selected() {
                    Some(i) => if i >= state.processes.len().saturating_sub(1) { 0 } else { i + 1 },
                    None => 0,
                };
                self.process_table_state.select(Some(i));
                if matches!(self.view_mode, ViewMode::ProcessDetail) {
                    if let Some(proc) = state.processes.get(i) {
                        self.selected_process_pid = Some(proc.pid.clone());
                    }
                }
            }
            ViewMode::SystemEvents | ViewMode::EventDetail => {
                let i = match self.event_table_state.selected() {
                    Some(i) => if i >= state.events.len().saturating_sub(1) { 0 } else { i + 1 },
                    None => 0,
                };
                self.event_table_state.select(Some(i));
            }
            ViewMode::WifiDetails | ViewMode::About => {}
        }
    }

    fn previous_item(&mut self) {
        let state = self.state.read().unwrap();
        match self.view_mode {
            ViewMode::Processes | ViewMode::ProcessDetail => {
                let i = match self.process_table_state.selected() {
                    Some(i) => if i == 0 { state.processes.len().saturating_sub(1) } else { i - 1 },
                    None => 0,
                };
                self.process_table_state.select(Some(i));
                if matches!(self.view_mode, ViewMode::ProcessDetail) {
                    if let Some(proc) = state.processes.get(i) {
                        self.selected_process_pid = Some(proc.pid.clone());
                    }
                }
            }
            ViewMode::SystemEvents | ViewMode::EventDetail => {
                let i = match self.event_table_state.selected() {
                    Some(i) => if i == 0 { state.events.len().saturating_sub(1) } else { i - 1 },
                    None => 0,
                };
                self.event_table_state.select(Some(i));
            }
            ViewMode::WifiDetails | ViewMode::About => {}
        }
    }

    fn kill_selected_process(&mut self) {
        if matches!(self.view_mode, ViewMode::Processes) {
            let state = self.state.read().unwrap();
            if let Some(idx) = self.process_table_state.selected() {
                if let Some(proc_info) = state.processes.get(idx) {
                    {
                         // Wait, AppAction::KillProcess takes usize or String?
                         // I defined it as KillProcess(String) in lines 60-63.
                         // So I should pass String.
                         // `process.kill()` in sysinfo might need Pid (which wraps usize/u32).
                         // `Pid::from(usize)` is common.
                         // Let's check AppAction definition I kept.
                         // It was KillProcess(String).
                         if let Some(tx) = &self.action_tx {
                            let _ = tx.send(AppAction::KillProcess(proc_info.pid.clone()));
                            self.message = format!("Kill signal sent to PID {}", proc_info.pid);
                            self.message_time = Some(Instant::now());
                         }
                    }
                }
            }
        }
    }
}

// Worker Logic Refactored
fn spawn_worker(state: Arc<RwLock<AppState>>, rx: mpsc::Receiver<AppAction>, demo_mode: bool) {
    thread::spawn(move || {
        let mut system = System::new_all();
        system.refresh_all();
        let mut networks = Networks::new_with_refreshed_list();
        let mut disks = Disks::new_with_refreshed_list();
        let users = Users::new_with_refreshed_list();
        
        let wifi_manager = WifiManager::new(demo_mode);
        let event_manager = EventManager::new();
        
        let mut refresh_rate = Duration::from_secs(2);
        // let mut last_wifi_update = Instant::now().checked_sub(Duration::from_secs(60)).unwrap();
        // let mut last_errors_update = Instant::now().checked_sub(Duration::from_secs(60)).unwrap();

        // Use loops with sleep, but check Rx for actions
        // To avoid complex select!, we can do a non-blocking recv in the loop
        
        loop {
            // Process Actions
            while let Ok(action) = rx.try_recv() {
                match action {
                     AppAction::KillProcess(pid_str) => {
                         if let Ok(pid) = pid_str.parse::<usize>() {
                             if let Some(process) = system.process(Pid::from(pid)) {
                                process.kill();
                            }
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

            // prepare ProcessInfo vector
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
            
            // Gather other info
            let cpus = system.cpus().iter().map(|cpu| cpu.cpu_usage()).collect();
            let memory = MemoryInfo { used: system.used_memory(), total: system.total_memory() };
            let swap = MemoryInfo { used: system.used_swap(), total: system.total_swap() };
            let uptime = System::uptime();
            
            let disks_info: Vec<DiskInfo> = disks.iter().take(3).map(|d| DiskInfo {
                    name: d.name().to_string_lossy().into_owned(),
                    mount_point: d.mount_point().to_string_lossy().into_owned(),
                    available_space: d.available_space(),
                    total_space: d.total_space(),
            }).collect();

            let networks_info: Vec<NetworkInfo> = networks.iter().map(|(name, data)| NetworkInfo {
                    name: name.clone(),
                    rx: data.received(),
                    tx: data.transmitted(),
                }).collect();
            
            // Expensive calls - maybe throttle these if needed?
            // For now, let's just do them. EventManager should handle its own throttling if needed or be fast.
            // The user plan suggests separate "lazy" updates? 
            // The user provided efficient code for events. I'll implement EventManager efficient logic later.
            // Here we just call it.
            let events = event_manager.get_system_errors_detailed();
            let wifi = wifi_manager.get_wifi_details(); 

            // Update Shared State
            if let Ok(mut s) = state.write() {
                // We overwrite the vectors (or we could swap if we want to be fancy/optimized to avoid allocation, 
                // but Vec::clone or replace is fine for now given typical sizes)
                // Actually, the user suggested `std::mem::swap` with local buffers to avoid repeated alloc, 
                // but here we just created new vecs.
                // Let's just assign for clarity first.
                
                s.processes = processes;
                s.events = events; 
                s.wifi_info = wifi; 
                s.system_state = SystemState {
                    cpus,
                    memory,
                    swap,
                    uptime,
                    disks: disks_info,
                    networks: networks_info,
                };
                // s.ccm_status = ...;
            }

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
    
    // Define locale
    let sys_lang = if let Some(l) = sys_locale::get_locale() { l } else { "en".to_string() };
    let lang = if sys_lang.to_lowercase().starts_with("fr") { "fr" } else { "en" };
    rust_i18n::set_locale(lang);

    if demo_mode {
        println!("Running in DEMO MODE - Anonymized data for screenshots");
    }
    
    human_panic::setup_panic!();
    
    println!("Current OS: {}", std::env::consts::OS);
    
    // Panic hook...
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

    // Shared State
    let initial_state = AppState {
        processes: Vec::new(),
        events: Vec::new(),
        wifi_info: None,
        system_state: SystemState::default(),
        ccm_status: None,
    };
    let state = Arc::new(RwLock::new(initial_state));
    let worker_state = state.clone();

    // Setup Communication
    let (action_tx, action_rx) = mpsc::channel();

    let mut app = App::new(demo_mode, action_tx, state);

    spawn_worker(worker_state, action_rx, demo_mode);

    let res = run_app(&mut terminal, &mut app);

    disable_raw_mode()?;
    execute!(terminal.backend_mut(), LeaveAlternateScreen, DisableMouseCapture)?;
    terminal.show_cursor()?;

    if let Err(err) = res { println!("{err:?}") }
    Ok(())
}

fn run_app(terminal: &mut Terminal<CrosstermBackend<io::Stdout>>, app: &mut App) -> Result<()> {
    loop {
        // 1. Read Shared State
        // Keep lock as short as possible. We clone what we need or pass refs to drawing.
        // For drawing, we can hold the read lock during the draw call.
        {
            let state_arc = app.state.clone();
            let state = state_arc.read().unwrap();
            terminal.draw(|f| ui(f, app, &state))?;
        }

        let timeout = Duration::from_millis(100); 
        
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
                                // Sorting needs to happen on local view or request worker?
                                // Actually, with Arc<RwLock>, the worker updates the data.
                                // If we sort here, we are modifying the shared state?? NO.
                                // We can't easily modify the shared vector from UI thread if worker is writing to it.
                                // RWLock allows only one writer.
                                // If we want to sort, we should probably sort a LOCAL copy or 
                                // have a "View" structure that holds indices.
                                
                                // Simplified approach: We sort the display only?
                                // Or we just accept that data might change order.
                                
                                // User plan said: "UI state (pagination, selection) remains local and lightweight"
                                // "For performance, we iterate on the ReadGuard directly."
                                // If we want to sort, we need a way.
                                // Maybe we just change the sort order and the worker respects it? 
                                // But worker doesn't know about UI state.
                                
                                // Actually, let's just sort the data in the worker?
                                // Or, we copy the data to a local vector for display and sort it? 
                                // Copying 500 items is fast. 
                                
                                // Let's try to pass the sort column to the worker via Action? 
                                // No, that's slow.
                                
                                // Best approach for now:
                                // Read state, Clone processes (it's Vec<ProcessInfo>, should be fast enough), Sort locally, Draw.
                                // In the 'ui' function.
                                
                                // But wait, run_app loop needs to handle input.
                                // next_item / previous_item needs to know the list length.
                                
                            },

                            KeyCode::Char('m') => {
                                app.sort_column = SortColumn::Mem;
                            },
                            KeyCode::Char('p') => {
                                app.sort_column = SortColumn::Pid;
                            },
                            KeyCode::Char('n') => {
                                app.sort_column = SortColumn::Name;
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
                                        let state = app.state.read().unwrap();
                                        if let Some(idx) = app.process_table_state.selected() {
                                            if idx < state.processes.len() {
                                                // Issue: If we sort in UI, the index here might mismatch if we don't use the same sorted list.
                                                // For now, let's assume we sort in UI and here we might get it wrong if we don't replicate sort.
                                                // To fix this properly: UI should return the selected PID or we need a stable way to map index.
                                                // Let's just grab the PID from the list *as displayed*? 
                                                // But we don't have the list here easily without sorting again.
                                                
                                                // Correct fix: run_app should get a snapshot of processes for the frame?
                                                // Or we accept that for now.
                                                // Let's rely on the fact that if we aren't sorting in worker, the order in state is "random" (pid usually).
                                                // If UI sorts, we need to sort here too to match.
                                                
                                                // Let's just create a helper to get sorted processes from state.
                                                let mut processes = state.processes.clone();
                                                sort_processes(&mut processes, app.sort_column);
                                                
                                                if let Some(proc) = processes.get(idx) {
                                                     app.selected_process_pid = Some(proc.pid.clone());
                                                     app.view_mode = ViewMode::ProcessDetail;
                                                }
                                            }
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
                                        let state = app.state.read().unwrap();
                                        if idx < state.processes.len() {
                                            app.process_table_state.select(Some(idx));
                                        }
                                    }
                                    ViewMode::SystemEvents => {
                                        let state = app.state.read().unwrap();
                                        if idx < state.events.len() {
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

        // No event_rx processing loop anymore
    }
}

fn sort_processes(processes: &mut Vec<ProcessInfo>, sort_col: SortColumn) {
    match sort_col {
        SortColumn::Cpu => processes.sort_by(|a, b| b.cpu.partial_cmp(&a.cpu).unwrap_or(std::cmp::Ordering::Equal)),
        SortColumn::Mem => processes.sort_by(|a, b| b.res_mem.cmp(&a.res_mem)),
        SortColumn::Pid => processes.sort_by(|a, b| split_pid(&a.pid).cmp(&split_pid(&b.pid))), // Improved PID sort (numeric)
        SortColumn::Name => processes.sort_by(|a, b| a.name.cmp(&b.name)),
    }
}
// Helper to sort PIDs numerically
fn split_pid(pid: &str) -> u32 {
    pid.parse().unwrap_or(0)
}

fn ui(f: &mut Frame, app: &mut App, state: &AppState) {
    let background_style = Style::default().bg(app.theme.background).fg(app.theme.text);
    f.render_widget(Block::default().style(background_style), f.area());

    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(18), Constraint::Min(0), Constraint::Length(1)].as_ref())
        .split(f.area());

    draw_header(f, app, state, chunks[0]);
    match app.view_mode {
        ViewMode::Processes => draw_process_table(f, app, state, chunks[1]),
        ViewMode::SystemEvents => draw_event_table(f, app, state, chunks[1]),
        ViewMode::WifiDetails => draw_wifi_details(f, app, state, chunks[1]),
        ViewMode::EventDetail => draw_event_detail(f, app, state, chunks[1]),
        ViewMode::ProcessDetail => draw_process_detail(f, app, state, chunks[1]),
        ViewMode::About => draw_about(f, app, chunks[1]),
    }
    draw_footer(f, app, chunks[2]);
}


fn draw_event_detail(f: &mut Frame, app: &App, state: &AppState, area: Rect) {
    let detail = if let Some(idx) = app.event_table_state.selected() {
        if let Some(err) = state.events.get(idx) {
            format!(
                "TIME   : {}\nID     : {}\nSOURCE : {}\n\nMESSAGE:\n{}",
                err.time, err.id, err.source, err.message
            )
        } else {
            t!("events.detail_not_found").to_string()
        }
    } else {
        t!("events.no_selection").to_string()
    };

    let p = Paragraph::new(detail)
        .block(Block::default().borders(Borders::ALL).title(t!("events.detail"))
            .style(Style::default().bg(app.theme.background).fg(app.theme.error)))
        .style(Style::default().bg(app.theme.background).fg(app.theme.text))
        .wrap(ratatui::widgets::Wrap { trim: true });
    f.render_widget(p, area);
}


fn draw_process_detail(f: &mut Frame, app: &App, state: &AppState, area: Rect) {
    let detail = if let Some(pid) = &app.selected_process_pid {
        if let Some(proc) = state.processes.iter().find(|p| &p.pid == pid) {
            let virt_mb = proc.virt_mem / 1024 / 1024;
            let res_mb = proc.res_mem / 1024 / 1024;
            
            format!(
                "PID          : {}\nNAME         : {}\nUSER         : {}\nSTATUS       : {}\nCPU          : {:.1}%\nMEMORY       : {:.1}% ({} MB)\nVIRTUAL MEM  : {} MB\n\nCOMMAND:\n{}",
                proc.pid, proc.name, proc.user, proc.status, proc.cpu, proc.mem_percent, res_mb, virt_mb, proc.cmd
            )
        } else {
            t!("processes.not_found").to_string()
        }
    } else {
         t!("processes.no_selection").to_string()
    };

    let p = Paragraph::new(detail)
        .block(Block::default().borders(Borders::ALL).title(t!("processes.detail_title"))
            .style(Style::default().bg(app.theme.background).fg(app.theme.highlight)))
        .style(Style::default().bg(app.theme.background).fg(app.theme.text))
        .wrap(ratatui::widgets::Wrap { trim: true });
    f.render_widget(p, area);
}


fn draw_wifi_details(f: &mut Frame, app: &App, state: &AppState, area: Rect) {
    let mut details = String::new();
    if let Some(wifi) = &state.wifi_info {
        details.push_str(&t!("wifi.ssid", ssid = wifi.ssid));
        details.push_str("\n");
        details.push_str(&t!("wifi.bssid", bssid = wifi.bssid));
        details.push_str("\n");
        details.push_str(&t!("wifi.standard", standard = wifi.standard));
        details.push_str("\n");
        details.push_str(&t!("wifi.channel", channel = wifi.channel));
        details.push_str("\n");
        details.push_str(&t!("wifi.frequency", frequency = wifi.frequency));
        details.push_str("\n");
        details.push_str(&t!("wifi.auth_label", auth = wifi.auth));
        details.push_str("\n");
        details.push_str(&t!("wifi.cipher", cipher = wifi.cipher));
        details.push_str("\n");
        details.push_str(&t!("wifi.signal", signal = wifi.signal));
        details.push_str("\n");
        details.push_str(&t!("wifi.rx_rate", rx = wifi.rx_rate));
        details.push_str("\n");
        details.push_str(&t!("wifi.tx_rate", tx = wifi.tx_rate));
        details.push_str("\n");
        details.push_str(&t!("wifi.esc_back"));
    } else {
        details.push_str(&t!("wifi.no_info"));
    }

    let p = Paragraph::new(details)
        .block(Block::default().borders(Borders::ALL).title(t!("wifi.details_title"))
            .style(Style::default().bg(app.theme.background).fg(app.theme.highlight)))
        .style(Style::default().bg(app.theme.background).fg(app.theme.highlight));
    f.render_widget(p, area);
}


fn draw_header(f: &mut Frame, app: &App, state: &AppState, area: Rect) {
    let main_chunks = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(33), Constraint::Percentage(33), Constraint::Percentage(34)].as_ref())
        .split(area);

    let cpus = &state.system_state.cpus;
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

    f.render_widget(Paragraph::new(t!("header.cpu"))
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

    let mem_used = state.system_state.memory.used;
    let mem_total = state.system_state.memory.total;
    let mem_percent = if mem_total > 0 { (mem_used as f64 / mem_total as f64 * 100.0) as u16 } else { 0 };
    f.render_widget(Gauge::default()
        .gauge_style(Style::default().bg(app.theme.background).fg(app.theme.success))
        .style(Style::default().bg(app.theme.background))
        .percent(mem_percent).label(format!("Mem  [{:3}%] {}MB/{}MB", mem_percent, mem_used / 1024 / 1024, mem_total / 1024 / 1024)), mid_chunks[0]);

    let swap_used = state.system_state.swap.used;
    let swap_total = state.system_state.swap.total;
    let swap_percent = if swap_total > 0 { (swap_used as f64 / swap_total as f64 * 100.0) as u16 } else { 0 };
    f.render_widget(Gauge::default()
        .gauge_style(Style::default().bg(app.theme.background).fg(app.theme.warning))
        .style(Style::default().bg(app.theme.background))
        .percent(swap_percent).label(format!("Swap [{:3}%] {}MB/{}MB", swap_percent, swap_used / 1024 / 1024, swap_total / 1024 / 1024)), mid_chunks[1]);

    let uptime_secs = state.system_state.uptime;
    let uptime_str = format!("{}d {:02}h {:02}m", uptime_secs / 86400, (uptime_secs % 86400) / 3600, (uptime_secs % 3600) / 60);
    f.render_widget(Paragraph::new(format!("{}: {}", t!("header.uptime"), uptime_str))
        .style(Style::default().bg(app.theme.background).fg(app.theme.text)), mid_chunks[2]);
    
    f.render_widget(Paragraph::new(format!("OS: {}", app.os_info))
        .style(Style::default().bg(app.theme.background).fg(app.theme.text)), mid_chunks[3]);
    
    let privilege_badge = if app.is_admin {
        format!(" [🔒 {}]", t!("ui.admin"))
    } else {
        format!(" [👤 {}]", t!("ui.user"))
    };
    let privilege_color = if app.is_admin { app.theme.warning } else { app.theme.text };
    
    f.render_widget(Paragraph::new(format!("Host: {} | User: {}{}", app.host_info, app.username, privilege_badge))
        .style(Style::default().bg(app.theme.background).fg(privilege_color)), mid_chunks[4]);

    if let Some(ccm) = &state.ccm_status {
        let status_color = if ccm.running { app.theme.success } else { app.theme.error };
        let error_text = if ccm.has_errors { " | Errors!" } else { "" };
        let info = format!("CCM: {} | Actions: {}{}", ccm.status, ccm.pending_actions, error_text);
        f.render_widget(Paragraph::new(info)
            .style(Style::default().bg(app.theme.background).fg(status_color)), mid_chunks[5]);
    } else {
        f.render_widget(Paragraph::new("").style(Style::default().bg(app.theme.background)), mid_chunks[5]);
    }

    f.render_widget(Paragraph::new(t!("header.disks")).style(Style::default().bg(app.theme.background).fg(app.theme.warning).add_modifier(Modifier::BOLD)), mid_chunks[6]);
    let mut disk_info = String::new();
    for disk in state.system_state.disks.iter() {
        let free = disk.available_space / 1024 / 1024 / 1024;
        let total = disk.total_space / 1024 / 1024 / 1024;
        let name = &disk.mount_point;
        disk_info.push_str(&format!("{name}: {free}G/{total}G free\n"));
    }
    f.render_widget(Paragraph::new(disk_info).style(Style::default().bg(app.theme.background).fg(app.theme.text)), mid_chunks[7]);

    let event_title = if matches!(app.view_mode, ViewMode::SystemEvents) { 
        t!("events.title_detailed")
    } else { 
        t!("header.events")
    };
    f.render_widget(Paragraph::new(event_title).style(Style::default().bg(app.theme.background).fg(app.theme.error).add_modifier(Modifier::BOLD)), mid_chunks[9]);
    
    let mut err_text = String::new();
    for err in state.events.iter().take(2) {
        let truncated = if err.message.len() > 50 { format!("{}...", &err.message[..47]) } else { err.message.clone() };
        err_text.push_str(&format!("• {}: {}\n", err.time, truncated));
    }
    if err_text.is_empty() { err_text = t!("events.no_events").to_string(); }
    f.render_widget(Paragraph::new(err_text).style(Style::default().bg(app.theme.background).fg(Color::Gray)), mid_chunks[10]);

    let net_chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(1), Constraint::Min(0)].as_ref())
        .split(main_chunks[2]);

    f.render_widget(Paragraph::new(t!("header.network")).style(Style::default().bg(app.theme.background).fg(app.theme.network).add_modifier(Modifier::BOLD)), net_chunks[0]);
    let mut net_info = String::new();
    if let Some(wifi) = &state.wifi_info {
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
    for net in &state.system_state.networks {
        if net.rx > 0 || net.tx > 0 {
            net_info.push_str(&format!("{}: R:{:.1}K T:{:.1}K\n", net.name, net.rx as f32 / 1024.0, net.tx as f32 / 1024.0));
        }
    }
    f.render_widget(Paragraph::new(net_info).style(Style::default().bg(app.theme.background).fg(app.theme.text)), net_chunks[1]);
}

fn draw_process_table(f: &mut Frame, app: &mut App, state: &AppState, area: Rect) {
    // Better approach:
    let headers = [
        "PID", "USER", "PRI", "VIRT", "RES", "S", "CPU%", "MEM%", "CMD"
    ];
    // For example: "PID", "USER", "PRI", "VIRT", "RES", "S", "CPU%", "MEM%", "CMD"
    // We use a fixed list for now to simplify column management.
    let header_row = Row::new(headers.iter().map(|h| Cell::from(*h).style(Style::default().fg(app.theme.highlight))))
        .height(1)
        .bottom_margin(1);
    
    // NOTE: Ideally we should use localized headers. 
    // I'll stick to English headers for now to avoid parsing issues, 
    // OR I can use t!("processes.title") which IS a string.

    // Let's try to fetch processes to display.
    // We need to sort them locally to match what the user sees (since we sorted in run_app potentially?)
    // Actually, in `run_app`, I added `sort_processes`. Use that helper here?
    // But `run_app` doesn't persist the sorted list to `app`. `app` doesn't have `processes`.
    // `state` has the raw list from worker.
    // So we MUST sort here to display correctly.
    
    let mut display_procs = state.processes.clone();
    sort_processes(&mut display_procs, app.sort_column);

    let rows = display_procs.iter().map(|p| {
        let virt_str = if p.virt_mem > 1024*1024*1024 {
            format!("{:.1}G", p.virt_mem as f64 / 1024.0 / 1024.0 / 1024.0)
        } else {
             format!("{}M", p.virt_mem / 1024 / 1024)
        };
        let res_str = if p.res_mem > 1024*1024*1024 {
             format!("{:.1}G", p.res_mem as f64 / 1024.0 / 1024.0 / 1024.0)
        } else {
             format!("{}M", p.res_mem / 1024 / 1024)
        };

        let color = if p.cpu > 50.0 { app.theme.error } else if p.cpu > 20.0 { app.theme.warning } else { app.theme.text };
        
        Row::new(vec![
            Cell::from(p.pid.clone()),
            Cell::from(p.user.clone()),
            Cell::from(p.priority.clone()),
            Cell::from(virt_str),
            Cell::from(res_str),
            Cell::from(p.status.clone()),
            Cell::from(format!("{:.1}", p.cpu)).style(Style::default().fg(color)),
            Cell::from(format!("{:.1}", p.mem_percent)),
            Cell::from(p.cmd.clone()),
        ])
    });

    let t = Table::new(rows, [
        Constraint::Length(6),
        Constraint::Length(10),
        Constraint::Length(4),
        Constraint::Length(6),
        Constraint::Length(6),
        Constraint::Length(3),
        Constraint::Length(6),
        Constraint::Length(6),
        Constraint::Min(10),
    ].as_ref())
    .header(header_row)
    .block(Block::default().borders(Borders::ALL).title(t!("processes.title")))
    .row_highlight_style(Style::default().bg(app.theme.highlight).fg(Color::Black).add_modifier(Modifier::BOLD));
    
    f.render_stateful_widget(t, area, &mut app.process_table_state);
}

fn draw_event_table(f: &mut Frame, app: &mut App, state: &AppState, area: Rect) {
    let header_cells = ["TIME", "SOURCE", "ID", "MESSAGE"].iter().map(|h| {
        Cell::from(*h).style(Style::default().fg(app.theme.highlight))
    });
    let header = Row::new(header_cells).height(1).bottom_margin(1);
    
    let rows = state.events.iter().map(|e| {
        Row::new(vec![
            Cell::from(e.time.clone()),
            Cell::from(e.source.clone()),
            Cell::from(e.id.clone()),
            Cell::from(e.message.clone()),
        ])
    });

    let t = Table::new(rows, [
        Constraint::Length(15),
        Constraint::Length(20),
        Constraint::Length(10),
        Constraint::Min(30),
    ])
    .header(header)
    .block(Block::default().borders(Borders::ALL).title(t!("events.title")))
    .row_highlight_style(Style::default().bg(app.theme.highlight).fg(Color::Black));
    
    f.render_stateful_widget(t, area, &mut app.event_table_state);
}

fn draw_about(f: &mut Frame, app: &App, area: Rect) {
    let version = env!("CARGO_PKG_VERSION");
    let content = t!("about.content", version = version);

    let p = Paragraph::new(content)
        .block(Block::default().borders(Borders::ALL)
            .title(t!("about.title")))
        .style(Style::default().bg(app.theme.background).fg(app.theme.text))
        .wrap(ratatui::widgets::Wrap { trim: false });
    f.render_widget(p, area);
}

fn draw_footer(f: &mut Frame, app: &App, area: Rect) {
    let refresh_display = format!("{}s", app.refresh_rate.as_secs());
    
    let help = match app.view_mode {
        ViewMode::Processes => t!("footer.processes", refresh = refresh_display).to_string(),
        ViewMode::SystemEvents => t!("footer.system_events").to_string(),
        ViewMode::WifiDetails => t!("footer.wifi_details").to_string(),
        ViewMode::EventDetail => t!("footer.event_detail").to_string(),
        ViewMode::ProcessDetail => t!("footer.process_detail").to_string(),
        ViewMode::About => t!("footer.about").to_string(),
    };

    let p = Paragraph::new(help)
        .style(Style::default().bg(app.theme.header_bg).fg(app.theme.highlight));
    f.render_widget(p, area);
}
