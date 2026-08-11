#[cfg(test)]
mod tests {
    use wasmvault::manifest::{CapabilityManifest, FilesystemPermissions};
    use wasmvault::scanner::{Scanner, RiskLevel};
    use wasmvault::crypto::Crypto;
    use wasmvault::profiles::Profile;
    use wasmvault::sandbox::Sandbox;
    use std::path::Path;

    #[test]
    fn test_manifest_parsing_and_validation() {
        let toml_data = r#"
        [package]
        name = "test-plugin"
        version = "1.0.0"
        publisher = "test-pub"

        [permissions]
        filesystem = ["./workspace/input"]
        network = false
        process = false

        [limits]
        memory_mb = 32
        cpu_ms = 500
        execution_timeout_ms = 1000
        "#;

        let manifest = CapabilityManifest::from_toml_str(toml_data).expect("Should parse valid manifest");
        assert_eq!(manifest.package.name, "test-plugin");
        assert_eq!(manifest.permissions.filesystem.allowed_paths().len(), 1);
        assert_eq!(manifest.limits.memory_mb, 32);
    }

    #[test]
    fn test_profile_application() {
        let mut manifest = CapabilityManifest::default_manifest_for_package("demo");
        
        Profile::Strict.apply(&mut manifest);
        assert_eq!(manifest.permissions.network, false);
        assert_eq!(manifest.permissions.filesystem, FilesystemPermissions::Bool(false));

        Profile::Workspace.apply(&mut manifest);
        assert_eq!(manifest.permissions.filesystem.allowed_paths().len(), 1);

        Profile::Full.apply(&mut manifest);
        assert_eq!(manifest.permissions.network, true);
        assert_eq!(manifest.permissions.process, true);
    }

    #[test]
    fn test_crypto_hashing() {
        let data = b"hello wasm world";
        let hash = Crypto::hash_binary(data);
        assert_eq!(hash.len(), 64);
    }

    #[test]
    fn test_scanner_detects_malicious_network_import() {
        let plugin_path = Path::new("target/wasm_plugins/malicious-network.wasm");
        let manifest_path = Path::new("target/wasm_plugins/malicious-network.toml");

        if plugin_path.exists() && manifest_path.exists() {
            let wasm_bytes = std::fs::read(plugin_path).unwrap();
            let manifest = CapabilityManifest::from_file(manifest_path).unwrap();
            
            let report = Scanner::analyze(&wasm_bytes, &manifest).unwrap();
            assert_eq!(report.risk_level, RiskLevel::High);
            assert!(!report.mismatches.is_empty(), "Scanner must flag network import mismatch!");
        }
    }

    #[test]
    fn test_legitimate_plugin_sandbox_execution() {
        let plugin_path = Path::new("target/wasm_plugins/image-resizer.wasm");
        let manifest_path = Path::new("target/wasm_plugins/image-resizer.toml");

        if plugin_path.exists() && manifest_path.exists() {
            let wasm_bytes = std::fs::read(plugin_path).unwrap();
            let manifest = CapabilityManifest::from_file(manifest_path).unwrap();
            
            let sandbox = Sandbox::new().unwrap();
            let report = sandbox.execute(&wasm_bytes, &manifest, None).unwrap();
            
            assert_eq!(report.exit_code, 0, "Legitimate plugin should execute cleanly");
            assert!(Path::new("./workspace/output/processed.txt").exists(), "Plugin output should exist in scoped directory");
        }
    }

    #[test]
    fn test_sandbox_blocks_stealth_network_attempt() {
        let plugin_path = Path::new("target/wasm_plugins/malicious-network.wasm");
        let manifest_path = Path::new("target/wasm_plugins/malicious-network.toml");

        if plugin_path.exists() && manifest_path.exists() {
            let wasm_bytes = std::fs::read(plugin_path).unwrap();
            let manifest = CapabilityManifest::from_file(manifest_path).unwrap();
            
            let (mon_channel, _rx) = wasmvault::monitor::MonitorChannel::new();
            let sandbox = Sandbox::new().unwrap();
            let report = sandbox.execute(&wasm_bytes, &manifest, Some(mon_channel)).unwrap();
            
            assert!(report.blocked_calls.iter().any(|b| b.name.contains("sock_open") || b.reason.contains("Network")), "Network attempt must be blocked and logged!");
        }
    }

    #[test]
    fn test_sandbox_traps_resource_bomb() {
        let plugin_path = Path::new("target/wasm_plugins/resource-bomb.wasm");
        let manifest_path = Path::new("target/wasm_plugins/resource-bomb.toml");

        if plugin_path.exists() && manifest_path.exists() {
            let wasm_bytes = std::fs::read(plugin_path).unwrap();
            let manifest = CapabilityManifest::from_file(manifest_path).unwrap();
            
            let sandbox = Sandbox::new().unwrap();
            let report = sandbox.execute(&wasm_bytes, &manifest, None).unwrap();
            
            assert!(report.exit_code != 0, "Resource bomb must be trapped!");
        }
    }
}
