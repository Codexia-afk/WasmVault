# WasmVault 🛡️⚡

**A security-first package manager for executable WASM capabilities, built in Rust.**

> **"Install code you don't trust. Run it safely anyway."**

[![Rust](https://img.shields.io/badge/Rust-1.97%2B-orange.svg)](https://www.rust-lang.org/)
[![Wasmtime](https://img.shields.io/badge/Wasmtime-24.0.0-blue.svg)](https://wasmtime.dev/)
[![WASI Target](https://img.shields.io/badge/WASI-wasm32--wasip1-green.svg)](https://wasi.dev/)
[![Version](https://img.shields.io/badge/Version-v0.2.0-brightgreen.svg)](https://github.com/Codexia-afk/WasmVault/releases)
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

### 3.1 3-Second Host Security Selftest (`selftest`)
Verify WasmVault's sandbox enforcement on your host machine in under 3 seconds without reading source code:
```bash
wasmvault selftest
```

### 3.2 Formal Threat Model (`THREATMODEL.md`)
Read our explicit security boundary specification in [`THREATMODEL.md`](THREATMODEL.md) detailing in-scope threat mitigations (stealth sockets, path traversal, memory OOM, CPU loops) vs. out-of-scope microarchitectural limits.

### 3.3 Capability Manifest (`plugin.toml`)
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

### 3.4 Static Import Scanner (`Scanner`)
Analyzes raw WASM binary import sections using `wasmparser` to catch disingenuous plugins that claim low risk in `plugin.toml` but secretly import high-risk system functions (e.g. `wasi_snapshot_preview1::sock_open`).

Calculates an explainable **Risk Score (0–100)**:
- **LOW (0–30)**: Scoped filesystem access, no network/process access.
- **MEDIUM (31–60)**: Network or environment access requested.
- **HIGH (61–100)**: Undeclared import mismatches, process execution, or unrestricted filesystem access (`/`).

### 3.5 Host-Enforced WASI Sandbox (`Sandbox`)
- Uses `wasmtime 24.0` with `wasmtime_wasi::preview1` compatibility shim (`WasiP1Ctx`).
- Preopens directory handles strictly matching declared paths (`DirPerms::all()`, `FilePerms::all()`).
- Traps memory allocation explosions using custom `ResourceLimiter`.
- Enforces execution deadlines using epoch-based CPU timer ticks (`store.set_epoch_deadline`).

### 3.6 Live Interception & Runtime Monitor (`MonitorChannel`)
Intercepts unauthorized syscall attempts at the host WASI bridge, streams `MonitorEvent` notifications, and renders visual **WasmVault Execution Reports** showing exact blocked syscalls, target descriptors, and security policy reasons.

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

# Run instant 3-second security selftest
./target/release/wasmvault selftest
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

### 5.1 Run 3-Second Security Selftest
```bash
wasmvault selftest
```

### 5.2 Run a Plugin Safely
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

### 5.3 Inspect Plugin & Static Risk Score
```bash
wasmvault inspect target/wasm_plugins/malicious-network.wasm
```

### 5.4 Compare Declared vs. Actual Capability Diff
```bash
wasmvault permissions target/wasm_plugins/malicious-network.wasm
```

### 5.5 Verify SHA-256 Hash & Ed25519 Publisher Signature
```bash
wasmvault verify target/wasm_plugins/image-resizer.wasm
```

### 5.6 Scaffold a New Plugin
```bash
wasmvault create my-plugin
```

### 5.7 Run Automated Security Tests
```bash
cargo test --all -- --nocapture
```

---

## 6. Demonstration & Attack Simulation Output

### 1. Security Selftest Output (`wasmvault selftest`)
```text
============================================================
            WASMVAULT 3-SECOND SECURITY SELFTEST
============================================================
Auditing local host capability enforcement runtime...

  ✓ [PASS] Scoped Filesystem Isolation verified (preopened path boundary active)
  ✓ [PASS] Network Interceptor verified (blocked stealth sock_open call)
  ✓ [PASS] Resource Limiter Defense verified (trapped allocation at 16MB)

------------------------------------------------------------
RESULT: ALL HOST SECURITY CONTROLS ACTIVE & VERIFIED
============================================================
```

### 2. Static Mismatch Detection (`wasmvault inspect malicious-network.wasm`)
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

### 3. Live Blocked Call Interception (`wasmvault run malicious-network.wasm`)
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

---

## 7. License

This project is licensed under the [MIT License](LICENSE).
