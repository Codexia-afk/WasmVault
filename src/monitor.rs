use serde::{Deserialize, Serialize};
use tokio::sync::mpsc;
use colored::*;
use comfy_table::Table;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum MonitorEvent {
    ExecutionStarted {
        plugin_name: String,
        version: String,
    },
    SyscallExecuted {
        name: String,
        target: String,
    },
    BlockedSyscall {
        name: String,
        target: String,
        reason: String,
    },
    ResourceExceeded {
        resource: String,
        limit: String,
        actual: String,
    },
    ExecutionFinished {
        duration_ms: u64,
        exit_code: i32,
    },
}

#[derive(Debug, Clone)]
pub struct MonitorChannel {
    tx: mpsc::UnboundedSender<MonitorEvent>,
}

impl MonitorChannel {
    pub fn new() -> (Self, mpsc::UnboundedReceiver<MonitorEvent>) {
        let (tx, rx) = mpsc::unbounded_channel();
        (Self { tx }, rx)
    }

    pub fn emit(&self, event: MonitorEvent) {
        let _ = self.tx.send(event);
    }
}

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct ExecutionReport {
    pub plugin_name: String,
    pub version: String,
    pub duration_ms: u64,
    pub exit_code: i32,
    pub allowed_calls: usize,
    pub blocked_calls: Vec<BlockedCallLog>,
    pub resource_violations: Vec<ResourceViolationLog>,
    pub memory_peak_mb: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlockedCallLog {
    pub name: String,
    pub target: String,
    pub reason: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResourceViolationLog {
    pub resource: String,
    pub limit: String,
    pub actual: String,
}

impl ExecutionReport {
    pub fn render_terminal(&self) {
        println!("\n{}", "============================================================".bright_blue().bold());
        println!("              {}", "WASMVAULT EXECUTION REPORT".bold().bright_cyan());
        println!("{}", "============================================================".bright_blue().bold());
        println!("Plugin Name:    {}", self.plugin_name.bold());
        println!("Version:        {}", self.version);
        println!("Execution Time: {} ms", self.duration_ms);
        println!("Exit Code:      {}", if self.exit_code == 0 { "0 (Success)".green() } else { format!("{}", self.exit_code).red() });
        println!("Allowed Calls:  {}", self.allowed_calls.to_string().green());
        println!("Blocked Calls:  {}", if self.blocked_calls.is_empty() { "0".green() } else { self.blocked_calls.len().to_string().bright_red().bold() });

        if !self.blocked_calls.is_empty() {
            println!("\n{}", "[BLOCKED SYSCALL ATTEMPTS]".bold().bright_red());
            let mut table = Table::new();
            table.set_header(vec!["Syscall", "Target / Descriptor", "Security Policy Reason"]);
            for b in &self.blocked_calls {
                table.add_row(vec![
                    b.name.clone().red().to_string(),
                    b.target.clone().yellow().to_string(),
                    b.reason.clone().bright_red().to_string(),
                ]);
            }
            println!("{table}");
        }

        if !self.resource_violations.is_empty() {
            println!("\n{}", "[RESOURCE LIMIT VIOLATIONS]".bold().bright_yellow());
            let mut table = Table::new();
            table.set_header(vec!["Resource", "Limit", "Actual Attempt"]);
            for v in &self.resource_violations {
                table.add_row(vec![v.resource.clone(), v.limit.clone(), v.actual.clone()]);
            }
            println!("{table}");
        }
        println!("{}\n", "============================================================".bright_blue().bold());
    }
}
