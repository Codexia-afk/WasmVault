use crate::manifest::CapabilityManifest;
use anyhow::{Context, Result};
use colored::*;
use comfy_table::Table;
use serde::{Deserialize, Serialize};
use wasmparser::{Parser, Payload};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WasmImport {
    pub module: String,
    pub field: String,
    pub is_network: bool,
    pub is_filesystem: bool,
    pub is_process: bool,
    pub is_env: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StaticAnalysisReport {
    pub declared_manifest: CapabilityManifest,
    pub actual_imports: Vec<WasmImport>,
    pub risk_score: u32,
    pub risk_level: RiskLevel,
    pub mismatches: Vec<PermissionMismatch>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum RiskLevel {
    Low,
    Medium,
    High,
}

impl std::fmt::Display for RiskLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RiskLevel::Low => write!(f, "LOW (Safe)"),
            RiskLevel::Medium => write!(f, "MEDIUM (Caution)"),
            RiskLevel::High => write!(f, "HIGH (DANGER)"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PermissionMismatch {
    pub capability: String,
    pub manifest_claimed: String,
    pub binary_imported: String,
    pub severity: String,
}

pub struct Scanner;

impl Scanner {
    pub fn analyze(wasm_bytes: &[u8], manifest: &CapabilityManifest) -> Result<StaticAnalysisReport> {
        let mut actual_imports = Vec::new();
        let parser = Parser::new(0);

        for payload in parser.parse_all(wasm_bytes) {
            let payload = payload.context("Failed to parse WASM binary structure")?;
            if let Payload::ImportSection(reader) = payload {
                for import in reader {
                    let import = import.context("Failed to read import entry")?;
                    let module = import.module.to_string();
                    let field = import.name.to_string();

                    let is_net = field.contains("sock") || field.contains("connect") || field.contains("socket") || field.contains("net");
                    let is_fs = field.contains("path") || field.contains("fd_") || field.contains("file");
                    let is_proc = (field.contains("proc") && field != "proc_exit") || field.contains("exec") || field.contains("spawn") || field.contains("system");
                    let is_env = field.contains("env") || field.contains("environ");

                    actual_imports.push(WasmImport {
                        module,
                        field,
                        is_network: is_net,
                        is_filesystem: is_fs,
                        is_process: is_proc,
                        is_env: is_env,
                    });
                }
            }
        }

        // Detect Mismatches
        let mut mismatches = Vec::new();
        let imports_net = actual_imports.iter().any(|i| i.is_network);
        let imports_proc = actual_imports.iter().any(|i| i.is_process);

        if imports_net && !manifest.permissions.network {
            mismatches.push(PermissionMismatch {
                capability: "Network Sockets".to_string(),
                manifest_claimed: "network = false".to_string(),
                binary_imported: "Imports socket/connect functions".to_string(),
                severity: "HIGH - Stealth Network Attempt".to_string(),
            });
        }

        if imports_proc && !manifest.permissions.process {
            mismatches.push(PermissionMismatch {
                capability: "Process Execution".to_string(),
                manifest_claimed: "process = false".to_string(),
                binary_imported: "Imports proc_exit/exec functions".to_string(),
                severity: "HIGH - Process Control".to_string(),
            });
        }

        // Calculate Risk Score
        let mut risk: u32 = 0;

        if manifest.permissions.network || imports_net {
            risk += 30;
        }
        if manifest.permissions.process || imports_proc {
            risk += 30;
        }
        if manifest.permissions.environment != crate::manifest::EnvironmentPermissions::Bool(false) {
            risk += 15;
        }

        let fs_unrestricted = manifest.permissions.filesystem.is_unrestricted();
        let fs_scoped = !manifest.permissions.filesystem.allowed_paths().is_empty();
        if fs_unrestricted {
            risk += 15;
        } else if fs_scoped {
            risk += 5;
        }

        if manifest.package.signature.is_none() {
            risk += 10;
        }

        if !mismatches.is_empty() {
            risk += 25;
        }

        let risk_score = risk.min(100);
        let risk_level = match risk_score {
            0..=30 => RiskLevel::Low,
            31..=60 => RiskLevel::Medium,
            _ => RiskLevel::High,
        };

        Ok(StaticAnalysisReport {
            declared_manifest: manifest.clone(),
            actual_imports,
            risk_score,
            risk_level,
            mismatches,
        })
    }
}

impl StaticAnalysisReport {
    pub fn print_inspect(&self) {
        println!("\n{}", "============================================================".bright_blue().bold());
        println!("             {}", "WASMSCANNER STATIC ANALYSIS REPORT".bold().bright_cyan());
        println!("{}", "============================================================".bright_blue().bold());
        println!("Package Name:      {}", self.declared_manifest.package.name.bold());
        println!("Publisher:         {}", self.declared_manifest.package.publisher);
        println!("Signature Status:  {}", if self.declared_manifest.package.signature.is_some() { "VERIFIED".green() } else { "UNSIGNED / UNVERIFIED".yellow() });
        
        let score_str = match self.risk_level {
            RiskLevel::Low => format!("{} / 100 [{}]", self.risk_score, self.risk_level).green().bold(),
            RiskLevel::Medium => format!("{} / 100 [{}]", self.risk_score, self.risk_level).yellow().bold(),
            RiskLevel::High => format!("{} / 100 [{}]", self.risk_score, self.risk_level).bright_red().bold(),
        };
        println!("Risk Score:        {}", score_str);

        if !self.mismatches.is_empty() {
            println!("\n{}", "[MISMATCH WARNINGS DETECTED]".bold().bright_red());
            let mut table = Table::new();
            table.set_header(vec!["Capability", "Manifest Claim", "Actual WASM Imports", "Severity"]);
            for m in &self.mismatches {
                table.add_row(vec![
                    m.capability.clone(),
                    m.manifest_claimed.clone().green().to_string(),
                    m.binary_imported.clone().red().to_string(),
                    m.severity.clone().bright_red().bold().to_string(),
                ]);
            }
            println!("{table}");
        }

        println!("\n{}", "[DECLARED VS IMPORTED CAPABILITIES]".bold());
        let mut table = Table::new();
        table.set_header(vec!["Capability", "Manifest Permitted", "Binary Imports"]);
        
        let fs_str = format!("{:?}", self.declared_manifest.permissions.filesystem);
        table.add_row(vec!["Filesystem", &fs_str, if self.actual_imports.iter().any(|i| i.is_filesystem) { "Imports FS APIs" } else { "None" }]);
        table.add_row(vec!["Network", if self.declared_manifest.permissions.network { "Allowed" } else { "Denied" }, if self.actual_imports.iter().any(|i| i.is_network) { "Imports Sockets" } else { "None" }]);
        table.add_row(vec!["Process", if self.declared_manifest.permissions.process { "Allowed" } else { "Denied" }, if self.actual_imports.iter().any(|i| i.is_process) { "Imports Process APIs" } else { "None" }]);
        table.add_row(vec!["Environment", if self.declared_manifest.permissions.environment != crate::manifest::EnvironmentPermissions::Bool(false) { "Allowed" } else { "Denied" }, if self.actual_imports.iter().any(|i| i.is_env) { "Imports Env APIs" } else { "None" }]);

        println!("{table}");
        println!("{}\n", "============================================================".bright_blue().bold());
    }
}
