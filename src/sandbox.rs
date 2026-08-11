use crate::manifest::{CapabilityManifest, FilesystemPermissions};
use crate::monitor::{MonitorChannel, MonitorEvent, ExecutionReport, BlockedCallLog, ResourceViolationLog};
use anyhow::{Context, Result};
use std::fs;
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use wasmtime::*;
use wasmtime_wasi::preview1::{self, WasiP1Ctx};
use wasmtime_wasi::{WasiCtxBuilder, DirPerms, FilePerms};

pub struct WasmVaultStoreData {
    pub wasi: WasiP1Ctx,
    pub monitor: Option<MonitorChannel>,
    pub memory_limit_bytes: usize,
    pub current_memory_bytes: usize,
    pub blocked_calls: Arc<Mutex<Vec<BlockedCallLog>>>,
}

impl ResourceLimiter for WasmVaultStoreData {
    fn memory_growing(
        &mut self,
        _current: usize,
        desired: usize,
        _maximum: Option<usize>,
    ) -> Result<bool> {
        self.current_memory_bytes = desired;
        if desired > self.memory_limit_bytes {
            if let Some(ref mon) = self.monitor {
                mon.emit(MonitorEvent::ResourceExceeded {
                    resource: "Memory".to_string(),
                    limit: format!("{} MB", self.memory_limit_bytes / (1024 * 1024)),
                    actual: format!("{} MB", desired / (1024 * 1024)),
                });
            }
            Ok(false)
        } else {
            Ok(true)
        }
    }

    fn table_growing(
        &mut self,
        _current: u32,
        _desired: u32,
        _maximum: Option<u32>,
    ) -> Result<bool> {
        Ok(true)
    }
}

pub struct Sandbox {
    engine: Engine,
}

impl Sandbox {
    pub fn new() -> Result<Self> {
        let mut config = Config::new();
        config.epoch_interruption(true);
        config.wasm_backtrace_details(WasmBacktraceDetails::Enable);

        let engine = Engine::new(&config).context("Failed to create Wasmtime Engine")?;
        Ok(Self { engine })
    }

    pub fn execute(
        &self,
        wasm_bytes: &[u8],
        manifest: &CapabilityManifest,
        monitor: Option<MonitorChannel>,
    ) -> Result<ExecutionReport> {
        let mut wasi_builder = WasiCtxBuilder::new();
        wasi_builder.inherit_stdout().inherit_stderr().inherit_stdin();

        // 1. Filesystem Capability Preopens
        let allowed_paths = manifest.permissions.filesystem.allowed_paths();
        for path in &allowed_paths {
            if !path.exists() {
                let _ = fs::create_dir_all(path);
            }
            let guest_path = path.to_string_lossy();
            wasi_builder.preopened_dir(path, &guest_path, DirPerms::all(), FilePerms::all())?;
        }

        // Also preopen current directory if allowed or workspace
        if allowed_paths.is_empty() && manifest.permissions.filesystem == FilesystemPermissions::Bool(true) {
            if Path::new(".").exists() {
                let _ = wasi_builder.preopened_dir(".", ".", DirPerms::all(), FilePerms::all());
            }
        }

        // 2. Environment Capability
        match &manifest.permissions.environment {
            crate::manifest::EnvironmentPermissions::Bool(true) => {
                wasi_builder.inherit_env();
            }
            crate::manifest::EnvironmentPermissions::Vars(vars) => {
                for v in vars {
                    if let Ok(val) = std::env::var(v) {
                        wasi_builder.env(v, &val);
                    }
                }
            }
            crate::manifest::EnvironmentPermissions::Bool(false) => {}
        }

        let wasi_ctx = wasi_builder.build_p1();

        let memory_limit_bytes = (manifest.limits.memory_mb * 1024 * 1024) as usize;
        let blocked_calls = Arc::new(Mutex::new(Vec::new()));

        let store_data = WasmVaultStoreData {
            wasi: wasi_ctx,
            monitor: monitor.clone(),
            memory_limit_bytes,
            current_memory_bytes: 0,
            blocked_calls: blocked_calls.clone(),
        };

        let mut store = Store::new(&self.engine, store_data);
        store.limiter(|s| s);

        // Configure CPU Epoch Deadline (1 tick = 100ms)
        let ticks = (manifest.limits.execution_timeout_ms / 100).max(1);
        store.set_epoch_deadline(ticks);

        // Spawn background epoch engine timer tick
        let engine_clone = self.engine.clone();
        let timeout_ms = manifest.limits.execution_timeout_ms;
        let timer_handle = std::thread::spawn(move || {
            let sleep_interval = Duration::from_millis(100);
            let steps = (timeout_ms / 100).max(1);
            for _ in 0..steps {
                std::thread::sleep(sleep_interval);
                engine_clone.increment_epoch();
            }
            // Trigger interruption if still running after timeout
            engine_clone.increment_epoch();
        });

        // Link WASI Preview1
        let mut linker = Linker::new(&self.engine);
        preview1::add_to_linker_sync(&mut linker, |s: &mut WasmVaultStoreData| &mut s.wasi)?;

        // Intercept unauthorized socket/process syscalls for live monitor demonstration
        let monitor_intercept = monitor.clone();
        let network_allowed = manifest.permissions.network;
        
        linker.func_wrap(
            "wasi_snapshot_preview1",
            "sock_open",
            move |mut caller: Caller<'_, WasmVaultStoreData>, _domain: i32, _type: i32, _protocol: i32, _ro_fd: i32| -> i32 {
                if !network_allowed {
                    let log = BlockedCallLog {
                        name: "wasi_snapshot_preview1::sock_open".to_string(),
                        target: "outbound_socket".to_string(),
                        reason: "Network access disabled by capability manifest".to_string(),
                    };
                    caller.data_mut().blocked_calls.lock().unwrap().push(log.clone());
                    if let Some(ref mon) = monitor_intercept {
                        mon.emit(MonitorEvent::BlockedSyscall {
                            name: log.name,
                            target: log.target,
                            reason: log.reason,
                        });
                    }
                    return 76; // ERRNO_NOTCAPABLE
                }
                0
            },
        )?;

        let monitor_intercept_conn = monitor.clone();
        linker.func_wrap(
            "wasi_snapshot_preview1",
            "sock_connect",
            move |mut caller: Caller<'_, WasmVaultStoreData>, _fd: i32, _addr: i32, _port: i32| -> i32 {
                if !network_allowed {
                    let log = BlockedCallLog {
                        name: "wasi_snapshot_preview1::sock_connect".to_string(),
                        target: "network_endpoint".to_string(),
                        reason: "Network connection blocked by capability policy".to_string(),
                    };
                    caller.data_mut().blocked_calls.lock().unwrap().push(log.clone());
                    if let Some(ref mon) = monitor_intercept_conn {
                        mon.emit(MonitorEvent::BlockedSyscall {
                            name: log.name,
                            target: log.target,
                            reason: log.reason,
                        });
                    }
                    return 76; // ERRNO_NOTCAPABLE
                }
                0
            },
        )?;

        // Load & Instantiate Module
        let module = Module::new(&self.engine, wasm_bytes)
            .context("Failed to compile WASM module binary")?;

        let start_time = Instant::now();
        if let Some(ref mon) = monitor {
            mon.emit(MonitorEvent::ExecutionStarted {
                plugin_name: manifest.package.name.clone(),
                version: manifest.package.version.clone(),
            });
        }

        let instance = linker.instantiate(&mut store, &module);

        let mut report = ExecutionReport {
            plugin_name: manifest.package.name.clone(),
            version: manifest.package.version.clone(),
            duration_ms: 0,
            exit_code: 0,
            allowed_calls: 0,
            blocked_calls: vec![],
            resource_violations: vec![],
            memory_peak_mb: 0,
        };

        match instance {
            Ok(inst) => {
                // Look for _start entry point
                if let Ok(func) = inst.get_typed_func::<(), ()>(&mut store, "_start") {
                    match func.call(&mut store, ()) {
                        Ok(_) => {
                            report.exit_code = 0;
                            report.allowed_calls = 1;
                        }
                        Err(trap) => {
                            if trap.to_string().contains("epoch") || trap.to_string().contains("interrupt") {
                                report.exit_code = 124; // Timeout
                                report.resource_violations.push(ResourceViolationLog {
                                    resource: "CPU Execution Timeout".to_string(),
                                    limit: format!("{} ms", manifest.limits.execution_timeout_ms),
                                    actual: "Execution exceeded epoch deadline".to_string(),
                                });
                            } else {
                                report.exit_code = 1;
                                report.blocked_calls.push(BlockedCallLog {
                                    name: "WASM Trap / Syscall Error".to_string(),
                                    target: "Runtime Execution".to_string(),
                                    reason: trap.to_string(),
                                });
                            }
                        }
                    }
                } else if let Ok(func) = inst.get_typed_func::<(), i32>(&mut store, "main") {
                    match func.call(&mut store, ()) {
                        Ok(res) => {
                            report.exit_code = res;
                        }
                        Err(trap) => {
                            report.exit_code = 1;
                            report.blocked_calls.push(BlockedCallLog {
                                name: "Trap".to_string(),
                                target: "main".to_string(),
                                reason: trap.to_string(),
                            });
                        }
                    }
                }
            }
            Err(e) => {
                report.exit_code = 1;
                report.blocked_calls.push(BlockedCallLog {
                    name: "Linker / Instantiation Trap".to_string(),
                    target: "Module Linker".to_string(),
                    reason: e.to_string(),
                });
            }
        }

        // Collect intercepted blocked calls from store data
        let intercepted_logs = store.data().blocked_calls.lock().unwrap().clone();
        report.blocked_calls.extend(intercepted_logs);

        report.duration_ms = start_time.elapsed().as_millis() as u64;
        report.memory_peak_mb = (store.data().current_memory_bytes / (1024 * 1024)) as u64;

        let _ = timer_handle;

        if let Some(ref mon) = monitor {
            mon.emit(MonitorEvent::ExecutionFinished {
                duration_ms: report.duration_ms,
                exit_code: report.exit_code,
            });
        }

        Ok(report)
    }
}
