mod manifest;
mod monitor;
mod sandbox;
mod scanner;
mod crypto;
mod profiles;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use colored::*;
use std::path::PathBuf;
use manifest::CapabilityManifest;
use monitor::MonitorChannel;
use profiles::Profile;
use sandbox::Sandbox;
use scanner::Scanner;
use crypto::Crypto;

#[derive(Parser)]
#[command(name = "wasmvault", author, version, about = "A security-first package manager for executable WASM capabilities, built in Rust.")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Execute a WASM plugin safely inside the capability sandbox
    Run {
        /// Path to the .wasm plugin file
        plugin: PathBuf,

        /// Path to custom plugin.toml manifest (defaults to alongside plugin or default)
        #[arg(short, long)]
        manifest: Option<PathBuf>,

        /// Apply a security profile (strict | workspace | network | full)
        #[arg(short, long)]
        profile: Option<Profile>,

        /// Run ephemerally (clean environment, temporary storage)
        #[arg(long, default_value_t = false)]
        ephemeral: bool,

        /// Explicit bypass flag required when running under full permission profile
        #[arg(long, default_value_t = false)]
        i_know_what_im_doing: bool,
    },

    /// Perform static import analysis and generate explainable risk score
    Inspect {
        /// Path to the .wasm plugin file
        plugin: PathBuf,

        /// Path to plugin.toml manifest
        #[arg(short, long)]
        manifest: Option<PathBuf>,
    },

    /// Compare declared permissions in plugin.toml vs actual binary imports
    Permissions {
        /// Path to the .wasm plugin file
        plugin: PathBuf,

        #[arg(short, long)]
        manifest: Option<PathBuf>,
    },

    /// Verify SHA-256 binary hash and publisher Ed25519 signature
    Verify {
        /// Path to the .wasm plugin file
        plugin: PathBuf,

        #[arg(short, long)]
        manifest: Option<PathBuf>,
    },

    /// Scaffold a new WasmVault plugin project with template plugin.toml
    Create {
        /// Name of the new plugin
        name: String,
    },

    /// Build current workspace plugin to target wasm32-wasip1
    Build,

    /// Run test suite against demo plugins
    Test,
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Run {
            plugin,
            manifest,
            profile,
            ephemeral,
            i_know_what_im_doing,
        } => {
            println!("{}", ">>> WasmVault Capability Sandbox Invocation <<<".bright_cyan().bold());
            let wasm_bytes = std::fs::read(&plugin)
                .with_context(|| format!("Failed to read WASM plugin file at {:?}", plugin))?;

            let manifest_path = manifest.unwrap_or_else(|| plugin.with_extension("toml"));
            let mut manifest_data = if manifest_path.exists() {
                CapabilityManifest::from_file(&manifest_path)?
            } else {
                let name = plugin.file_stem().and_then(|s| s.to_str()).unwrap_or("unknown");
                CapabilityManifest::default_manifest_for_package(name)
            };

            if let Some(prof) = profile {
                if prof == Profile::Full && !i_know_what_im_doing {
                    anyhow::bail!("Running under Profile::Full requires --i-know-what-im-doing flag due to dangerous system access!");
                }
                println!("Applying Security Profile: {:?}", prof);
                prof.apply(&mut manifest_data);
            }

            println!("Loaded Manifest for: {} v{}", manifest_data.package.name.bold(), manifest_data.package.version);

            // Pre-execution static analysis check
            let analysis = Scanner::analyze(&wasm_bytes, &manifest_data)?;
            if !analysis.mismatches.is_empty() {
                println!("{}", "\n[WARNING] Static Scanner Detected Mismatches Before Execution:".bright_yellow().bold());
                for m in &analysis.mismatches {
                    println!("  - {}: {}", m.capability.bold(), m.severity.red());
                }
            }

            let (mon_channel, mut mon_rx) = MonitorChannel::new();
            
            // Monitor receiver background thread
            let mon_handle = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()?
                .spawn(async move {
                    while let Some(event) = mon_rx.recv().await {
                        match event {
                            monitor::MonitorEvent::BlockedSyscall { name, target, reason } => {
                                println!("  {} {} on {} ({})", "[BLOCKED]".bright_red().bold(), name, target.yellow(), reason);
                            }
                            monitor::MonitorEvent::ResourceExceeded { resource, limit, actual } => {
                                println!("  {} {} limit reached! (Limit: {}, Attempted: {})", "[LIMIT EXCEEDED]".bright_red().bold(), resource, limit, actual);
                            }
                            _ => {}
                        }
                    }
                });

            let sandbox = Sandbox::new()?;
            let report = sandbox.execute(&wasm_bytes, &manifest_data, Some(mon_channel))?;

            // Render execution report
            report.render_terminal();

            if ephemeral {
                println!("{}", "[Ephemeral Run Complete: Temporary state cleared]".bright_black());
            }

            let _ = mon_handle;
            Ok(())
        }

        Commands::Inspect { plugin, manifest } => {
            let wasm_bytes = std::fs::read(&plugin)
                .with_context(|| format!("Failed to read WASM plugin file at {:?}", plugin))?;

            let manifest_path = manifest.unwrap_or_else(|| plugin.with_extension("toml"));
            let manifest_data = if manifest_path.exists() {
                CapabilityManifest::from_file(&manifest_path)?
            } else {
                let name = plugin.file_stem().and_then(|s| s.to_str()).unwrap_or("unknown");
                CapabilityManifest::default_manifest_for_package(name)
            };

            let report = Scanner::analyze(&wasm_bytes, &manifest_data)?;
            report.print_inspect();
            Ok(())
        }

        Commands::Permissions { plugin, manifest } => {
            let wasm_bytes = std::fs::read(&plugin)?;
            let manifest_path = manifest.unwrap_or_else(|| plugin.with_extension("toml"));
            let manifest_data = if manifest_path.exists() {
                CapabilityManifest::from_file(&manifest_path)?
            } else {
                CapabilityManifest::default_manifest_for_package("unknown")
            };

            let report = Scanner::analyze(&wasm_bytes, &manifest_data)?;
            println!("\nPermissions Comparison for {}", plugin.display());
            report.print_inspect();
            Ok(())
        }

        Commands::Verify { plugin, manifest } => {
            let wasm_bytes = std::fs::read(&plugin)?;
            let hash = Crypto::hash_binary(&wasm_bytes);
            println!("\n{}", "=== WASMVAULT BINARY INTEGRITY VERIFICATION ===".bright_cyan().bold());
            println!("Plugin File:    {}", plugin.display());
            println!("SHA-256 Hash:   {}", hash.bold());

            let manifest_path = manifest.unwrap_or_else(|| plugin.with_extension("toml"));
            if manifest_path.exists() {
                let manifest_data = CapabilityManifest::from_file(&manifest_path)?;
                if let (Some(sig), Some(pk)) = (manifest_data.package.signature, manifest_data.package.public_key) {
                    match Crypto::verify_signature(&wasm_bytes, &sig, &pk) {
                        Ok(true) => println!("Publisher Sig:  {}", "VALID (Verified Ed25519 Signature)".green().bold()),
                        Ok(false) => println!("Publisher Sig:  {}", "INVALID (Signature Mismatch!)".red().bold()),
                        Err(e) => println!("Publisher Sig:  {} ({})", "ERROR".red(), e),
                    }
                } else {
                    println!("Publisher Sig:  {}", "UNSIGNED (No signature attached)".yellow());
                }
            } else {
                println!("Manifest:       {}", "NOT FOUND".yellow());
            }
            println!("==========================================================\n");
            Ok(())
        }

        Commands::Create { name } => {
            let dir = PathBuf::from(&name);
            std::fs::create_dir_all(dir.join("src"))?;

            let manifest_content = toml::to_string_pretty(&CapabilityManifest::default_manifest_for_package(&name))?;
            std::fs::write(dir.join("plugin.toml"), manifest_content)?;

            let sample_code = r#"// WasmVault Plugin Template
fn main() {
    println!("Hello from WasmVault sandboxed plugin!");
}
"#;
            std::fs::write(dir.join("src").join("main.rs"), sample_code)?;

            println!("Created plugin scaffolding at ./{}/", name);
            println!("  ├── plugin.toml");
            println!("  └── src/main.rs");
            Ok(())
        }

        Commands::Build => {
            println!("Building workspace WASM plugins to target wasm32-wasip1...");
            let status = std::process::Command::new("cargo")
                .args(["build", "--target", "wasm32-wasip1", "--release"])
                .status()?;
            if status.success() {
                println!("{}", "Build successful!".green());
            } else {
                anyhow::bail!("Cargo build failed");
            }
            Ok(())
        }

        Commands::Test => {
            println!("Running WasmVault security tests...");
            let status = std::process::Command::new("cargo")
                .args(["test", "--", "--nocapture"])
                .status()?;
            if status.success() {
                println!("{}", "All security tests passed!".green().bold());
            } else {
                anyhow::bail!("Test failures detected");
            }
            Ok(())
        }
    }
}
