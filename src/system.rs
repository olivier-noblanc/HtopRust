use sysinfo::ProcessStatus;

#[derive(PartialEq, Clone, Copy)]
pub enum SortColumn {
    Pid,
    Name,
    Cpu,
    Mem,
}

#[derive(Clone)]
pub struct ProcessInfo {
    pub pid: String,
    pub name: String,
    pub user: String,
    pub priority: String,
    pub virt_mem: u64,
    pub res_mem: u64,
    pub status: String,
    pub cpu: f32,
    pub mem_percent: f32,
    pub cmd: String,
}

#[derive(Clone)]
pub struct CcmStatus {
    pub running: bool,
    pub status: String,
    pub has_errors: bool,
    pub pending_actions: u32,
}

impl CcmStatus {
    pub fn new(running: bool, status: String, has_errors: bool, pending_actions: u32) -> Self {
        Self {
            running,
            status,
            has_errors,
            pending_actions,
        }
    }
}

pub fn process_status_to_string(status: ProcessStatus) -> String {
    match status {
        ProcessStatus::Run => "R",
        ProcessStatus::Sleep => "S",
        ProcessStatus::Idle => "I",
        ProcessStatus::Dead => "D",
        ProcessStatus::Stop => "T",
        _ => "?",
    }.to_string()
}

// New structs for UI state
#[derive(Clone, Default)]
pub struct SystemState {
    pub cpus: Vec<f32>, // Usage % per core
    pub memory: MemoryInfo,
    pub swap: MemoryInfo,
    pub uptime: u64,
    pub disks: Vec<DiskInfo>,
    pub networks: Vec<NetworkInfo>,
}

#[derive(Clone, Default)]
pub struct MemoryInfo {
    pub used: u64,
    pub total: u64,
}

#[derive(Clone)]
pub struct DiskInfo {
    pub name: String,
    pub mount_point: String,
    pub available_space: u64,
    pub total_space: u64,
}

#[derive(Clone)]
pub struct NetworkInfo {
    pub name: String,
    pub rx: u64,
    pub tx: u64,
}
