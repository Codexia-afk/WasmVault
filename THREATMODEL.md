# WasmVault Security Threat Model & Boundary Specification (`THREATMODEL.md`)

This document defines the security guarantees, threat model, assumptions, and explicit non-goals for **WasmVault**.

---

## 1. Security Philosophy & Claim

WasmVault enforces **Capability-Based Security** using WebAssembly (WASM) and the WebAssembly System Interface (WASI).

> **Core Guarantee**: An untrusted WebAssembly binary executed inside WasmVault cannot access host OS resources (filesystem, network sockets, environment variables, or sub-processes) unless explicit handles to those resources are granted by the host host runtime via `plugin.toml`.

Security is enforced at the **WASM runtime instantiation boundary**, not via soft userland path filtering or string sanitization.

---

## 2. In-Scope Threat Protections

WasmVault provides deterministic mitigation against the following attack vectors:

| Attack Vector | Threat Description | WasmVault Defense Mechanism |
|---|---|---|
| **Stealth Network Access** | Binary imports socket functions (`sock_open`, `sock_connect`) while claiming `network = false`. | **Static Analysis**: `wasmparser` flags import mismatches before execution.<br>**Runtime Interceptor**: Host WASI bridge rejects unauthorized socket calls with `ERRNO_NOTCAPABLE` (76). |
| **Filesystem Escape & Traversal** | Binary attempts `../` traversal or reading `/etc/passwd`. | **WASI Preopens**: Host grants capability handles *only* for specified directories. Attempts outside preopens fail with native WASI OS errors (`os error 44` / `os error 63`). |
| **Environment Leakage** | Binary attempts reading host environment variables (AWS keys, tokens). | Environment inheritance is disabled by default (`EnvironmentPermissions::Bool(false)`). |
| **Resource Starvation (OOM)** | Binary attempts allocating memory to exhaust host RAM. | Wasmtime `ResourceLimiter` intercepts `memory_growing` and traps allocations breaching `limits.memory_mb`. |
| **Infinite CPU Loops** | Binary executes `loop {}` to lock host CPU cores. | Wasmtime epoch deadline interruption (`set_epoch_deadline`) traps execution exceeding `limits.execution_timeout_ms`. |
| **Unsigned Package Alteration** | Tampered or modified binary delivered to execution engine. | `wasmvault verify` computes SHA-256 binary hash and validates Ed25519 publisher signature. |

---

## 3. Out-of-Scope Security Non-Goals & Limitations

WasmVault is **not** a silver bullet and does **not** protect against the following scenarios:

1. **Malicious Logic Within Permitted Scope**: If a plugin is explicitly granted `./workspace/output` filesystem permission, WasmVault cannot prevent the plugin from corrupting files *inside* `./workspace/output`.
2. **CPU Speculative Execution Side-Channels**: Microarchitectural side-channel vulnerabilities (Spectre, Meltdown, L1TF) are properties of hardware CPU hardware and host kernel isolation, not the WebAssembly capability layer.
3. **Zero-Day Vulnerabilities in Wasmtime Engine**: Security relies on Wasmtime's sandbox isolation. A zero-day memory corruption vulnerability in Wasmtime itself could theoretically compromise host isolation.
4. **Supply Chain Attacks in Compiler Toolchain**: If the Rust/C compiler compiling the WASM binary embeds malicious logic, WasmVault enforces capability limits on that binary, but cannot audit high-level business logic semantics inside allowed boundaries.

---

## 4. Vulnerability Disclosure Policy

If you discover a sandbox escape or security vulnerability in WasmVault, please report it privately via GitHub Security Advisories or email `security@wasmvault.io`.

- **Do NOT file public issues for zero-day sandbox escapes.**
- All reported vulnerabilities will be acknowledged within 24 hours.
