# WasmVault 🛡️⚡

**A security-first package manager for executable WASM capabilities, built in Rust.**

> **"Install code you don't trust. Run it safely anyway."**

[![Rust](https://img.shields.io/badge/Rust-1.97%2B-orange.svg)](https://www.rust-lang.org/)
[![Wasmtime](https://img.shields.io/badge/Wasmtime-24.0.0-blue.svg)](https://wasmtime.dev/)
[![WASI Target](https://img.shields.io/badge/WASI-wasm32--wasip1-green.svg)](https://wasi.dev/)
[![License](https://img.shields.io/badge/License-MIT-brightgreen.svg)](LICENSE)

---

## 1. The Pitch

- **The Problem:** Installing third-party code (`npm install`, `cargo install`, plugins, arbitrary scripts) hands it full, unrestricted access to your filesystem, network, and environment by default. There is no equivalent of a phone's permission prompt for CLI executables.
- **The Insight:** WebAssembly (WASM) + WASI's capability-based security model means a host can grant *strictly and exclusively* the resources a plugin declares needing in its capability manifest — nothing else is reachable, not because of soft runtime policies, but because the plugin lacks a file descriptor handle to it.
- **The Solution:** **WasmVault** — A CLI package manager and execution engine where every executable ships a **Capability Manifest (`plugin.toml`)**, gets **statically scanned** for risk before execution, and is **monitored live** while running — with unauthorized access attempts visibly blocked and surfaced in real time.

---

## 2. Architecture Overview

```text
                    WASMVAULT
                       │
        ┌──────────────┼──────────────┐
        ↓              ↓              ↓
    CLI Client      Web Registry    SDK (v2)
        │              │
        └───────┬──────┘
                ↓
        Package Resolver
                ↓
        Security Scanner        ← static analysis, risk score calculation
                ↓
        Trust / Signature       ← SHA-256 + Ed25519 publisher signature
                ↓
       Capability Engine        ← parses plugin.toml manifest
                ↓
       Permission Policy        ← diffs requested vs. granted
                ↓
           Wasmtime             ← sandboxed execution engine (v24.0)
                ↓
         WASI Sandbox           ← preview1 compatibility bridge over preview2 host
                ↓
       Runtime Monitor          ← live syscall/resource tracking & interceptor
                ↓
        Execution Report        ← real-time summary of allowed & blocked calls
```

---

## 3. Core Features

### 3.1 Capability Manifest (`plugin.toml`)
Every plugin ships a manifest defining its identity, requested permissions, and resource constraints:

```toml
[package]
name = "image-resizer"
version = "1.4.2"
publisher = "example-dev"
description = "Legitimate workspace image/file processing plugin"

[permissions]
filesystem = ["./workspace/input", "./workspace/output"]
network = false
process = false
environment = false
clipboard = false

[limits]
memory_mb = 64
cpu_ms = 1000
execution_timeout_ms = 2000
```

### 3.2 Static Import Scanner (`Scanner`)
Analyzes raw WASM binary import sections using `wasmparser` to catch disingenuous plugins that claim low risk in `plugin.toml` but secretly import high-risk system functions (e.g. `wasi_snapshot_preview1::sock_open`).

Calculates an explainable **Risk Score (0–100)**:
- **LOW (0–30)**: Scoped filesystem access, no network/process access.
- **MEDIUM (31–60)**: Network or environment access requested.
- **HIGH (61–100)**: Undeclared import mismatches, process execution, or unrestricted filesystem access (`/`).

### 3.3 Host-Enforced WASI Sandbox (`Sandbox`)
- Uses `wasmtime 24.0` with `wasmtime_wasi::preview1` compatibility shim (`WasiP1Ctx`).
- Preopens directory handles strictly matching declared paths (`DirPerms::all()`, `FilePerms::all()`).
- Traps memory allocation explosions using custom `ResourceLimiter`.
- Enforces execution deadlines using epoch-based CPU timer ticks (`store.set_epoch_deadline`).

### 3.4 Live Interception & Runtime Monitor (`MonitorChannel`)
Intercepts unauthorized syscall attempts at the host WASI bridge, streams `MonitorEvent` notifications, and renders visual **WasmVault Execution Reports** showing exact blocked syscalls, target descriptors, and security policy reasons.

### 3.5 Security Profiles & Signature Verification
- **Profiles (`--profile`)**: Preset security modes (`strict`, `workspace`, `network`, `full`).
- **Signature Check (`verify`)**: Verifies SHA-256 binary hash and Ed25519 publisher signatures.

---

## 4. Quickstart & Installation

### Prerequisites
- Rust `1.97+` (`cargo`, `rustc`)
- WebAssembly WASI target:
  ```bash
  rustup target add wasm32-wasip1
  ```

### Build WasmVault
```bash
# Clone the repository
git clone https://github.com/Codexia-afk/WasmVault.git
cd WasmVault

# Build optimized release binary
cargo build --release

# The compiled binary is available at:
./target/release/wasmvault --version
```

### Build Demo Plugin Suite
```bash
./scripts/build_plugins.sh
```
This compiles the demo plugins into `target/wasm_plugins/`:
- `image-resizer.wasm`
- `malicious-network.wasm`
- `permission-escalation.wasm`
- `resource-bomb.wasm`

---

## 5. CLI Reference & Usage

### 5.1 Run a Plugin Safely
```bash
wasmvault run target/wasm_plugins/image-resizer.wasm
```

Apply a preset security profile:
```bash
wasmvault run target/wasm_plugins/image-resizer.wasm --profile=workspace
wasmvault run target/wasm_plugins/image-resizer.wasm --profile=strict
```

Ephemeral mode (clean run, temporary state):
```bash
wasmvault run target/wasm_plugins/image-resizer.wasm --ephemeral
```

### 5.2 Inspect Plugin & Static Risk Score
```bash
wasmvault inspect target/wasm_plugins/malicious-network.wasm
```

### 5.3 Compare Declared vs. Actual Capability Diff
```bash
wasmvault permissions target/wasm_plugins/malicious-network.wasm
```

### 5.4 Verify SHA-256 Hash & Ed25519 Publisher Signature
```bash
wasmvault verify target/wasm_plugins/image-resizer.wasm
```

### 5.5 Scaffold a New Plugin
```bash
wasmvault create my-plugin
```

### 5.6 Run Automated Security Tests
```bash
cargo test --all -- --nocapture
```

---

## 6. Demonstration & Attack Simulation Output

### 1. Static Mismatch Detection (`wasmvault inspect malicious-network.wasm`)
```text
============================================================
             WASMSCANNER STATIC ANALYSIS REPORT
============================================================
Package Name:      malicious-network
Publisher:         stealth-actor
Signature Status:  UNSIGNED / UNVERIFIED
Risk Score:        65 / 100 [HIGH (DANGER)]

[MISMATCH WARNINGS DETECTED]
+-----------------+-----------------+----------------------------------+--------------------------------+
| Capability      | Manifest Claim  | Actual WASM Imports              | Severity                       |
+=======================================================================================================+
| Network Sockets | network = false | Imports socket/connect functions | HIGH - Stealth Network Attempt |
+-----------------+-----------------+----------------------------------+--------------------------------+
```

### 2. Live Blocked Call Interception (`wasmvault run malicious-network.wasm`)
```text
>>> WasmVault Capability Sandbox Invocation <<<
Loaded Manifest for: malicious-network v1.0.0

[WARNING] Static Scanner Detected Mismatches Before Execution:
  - Network Sockets: HIGH - Stealth Network Attempt
[malicious-network] Attempting stealth network socket creation...
[malicious-network] Socket creation call returned error code: 76

============================================================
              WASMVAULT EXECUTION REPORT
============================================================
Plugin Name:    malicious-network
Version:        1.0.0
Execution Time: 0 ms
Exit Code:      0 (Success)
Allowed Calls:  1
Blocked Calls:  1

[BLOCKED SYSCALL ATTEMPTS]
+-----------------------------------+---------------------+------------------------------------------------+
| Syscall                           | Target / Descriptor | Security Policy Reason                         |
+==========================================================================================================+
| wasi_snapshot_preview1::sock_open | outbound_socket     | Network access disabled by capability manifest |
+-----------------------------------+---------------------+------------------------------------------------+
============================================================
```

### 3. Resource Bomb Limitation (`wasmvault run resource-bomb.wasm`)
```text
>>> WasmVault Capability Sandbox Invocation <<<
Loaded Manifest for: resource-bomb v1.0.0
[resource-bomb] Starting CPU loop and memory allocation attack...
[resource-bomb] Allocated 1 MB memory...
[LIMIT EXCEEDED] Memory limit reached! (Limit: 16 MB, Attempted: 17 MB)

============================================================
              WASMVAULT EXECUTION REPORT
============================================================
Plugin Name:    resource-bomb
Version:        1.0.0
Execution Time: 1 ms
Exit Code:      1
```

---

## 7. Project Structure

```text
WasmVault/
├── Cargo.toml                  # Workspace dependencies & binary manifest
├── Cargo.lock                  # Pinned dependency lockfile
├── README.md                   # Project documentation & spec
├── src/
│   ├── main.rs                 # CLI entrypoint & subcommand handlers
│   ├── lib.rs                  # Module exports for integration testing
│   ├── manifest.rs             # plugin.toml data model & validation
│   ├── sandbox.rs              # Wasmtime engine & WASI capability sandbox
│   ├── scanner.rs              # wasmparser static import scanner & risk scoring
│   ├── monitor.rs              # Real-time event monitor & execution reports
│   ├── crypto.rs               # SHA-256 & Ed25519 signature verification
│   └── profiles.rs             # Preset security profiles (strict, workspace, network, full)
├── plugins/                    # Attack simulation & test plugin source files
│   ├── image-resizer/          # Legitimate workspace file transformation plugin
│   ├── malicious-network/      # Undeclared socket attempt plugin
│   ├── permission-escalation/  # Path traversal attempt plugin
│   └── resource-bomb/          # Memory ballooning & CPU loop attack plugin
├── scripts/
│   └── build_plugins.sh        # WASM plugin compilation script
└── tests/
    └── integration_tests.rs    # Comprehensive security & sandbox test suite
```

---

## 8. License

This project is licensed under the [MIT License](LICENSE).
