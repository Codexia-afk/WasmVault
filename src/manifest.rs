use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use anyhow::{Context, Result};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CapabilityManifest {
    pub package: PackageMetadata,
    pub permissions: PermissionsConfig,
    #[serde(default)]
    pub limits: ResourceLimits,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PackageMetadata {
    pub name: String,
    pub version: String,
    #[serde(default = "default_publisher")]
    pub publisher: String,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub signature: Option<String>,
    #[serde(default)]
    pub public_key: Option<String>,
}

fn default_publisher() -> String {
    "anonymous".to_string()
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct PermissionsConfig {
    #[serde(default)]
    pub filesystem: FilesystemPermissions,
    #[serde(default)]
    pub network: bool,
    #[serde(default)]
    pub process: bool,
    #[serde(default)]
    pub environment: EnvironmentPermissions,
    #[serde(default)]
    pub clipboard: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(untagged)]
pub enum FilesystemPermissions {
    Bool(bool),
    Paths(Vec<String>),
}

impl Default for FilesystemPermissions {
    fn default() -> Self {
        FilesystemPermissions::Bool(false)
    }
}

impl FilesystemPermissions {
    pub fn allowed_paths(&self) -> Vec<PathBuf> {
        match self {
            FilesystemPermissions::Bool(false) => vec![],
            FilesystemPermissions::Bool(true) => vec![PathBuf::from(".")],
            FilesystemPermissions::Paths(paths) => paths.iter().map(PathBuf::from).collect(),
        }
    }

    pub fn is_unrestricted(&self) -> bool {
        match self {
            FilesystemPermissions::Bool(true) => true,
            FilesystemPermissions::Paths(paths) => {
                paths.iter().any(|p| p == "/" || p == "*" || p == "C:\\")
            }
            FilesystemPermissions::Bool(false) => false,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(untagged)]
pub enum EnvironmentPermissions {
    Bool(bool),
    Vars(Vec<String>),
}

impl Default for EnvironmentPermissions {
    fn default() -> Self {
        EnvironmentPermissions::Bool(false)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ResourceLimits {
    #[serde(default = "default_memory_mb")]
    pub memory_mb: u64,
    #[serde(default = "default_cpu_ms")]
    pub cpu_ms: u64,
    #[serde(default = "default_timeout_ms")]
    pub execution_timeout_ms: u64,
}

fn default_memory_mb() -> u64 { 64 }
fn default_cpu_ms() -> u64 { 1000 }
fn default_timeout_ms() -> u64 { 2000 }

impl Default for ResourceLimits {
    fn default() -> Self {
        Self {
            memory_mb: default_memory_mb(),
            cpu_ms: default_cpu_ms(),
            execution_timeout_ms: default_timeout_ms(),
        }
    }
}

impl CapabilityManifest {
    pub fn from_file<P: AsRef<Path>>(path: P) -> Result<Self> {
        let content = std::fs::read_to_string(&path)
            .with_context(|| format!("Failed to read manifest file at {:?}", path.as_ref()))?;
        Self::from_toml_str(&content)
    }

    pub fn from_toml_str(content: &str) -> Result<Self> {
        let manifest: CapabilityManifest = toml::from_str(content)
            .context("Failed to parse TOML capability manifest")?;
        manifest.validate()?;
        Ok(manifest)
    }

    pub fn validate(&self) -> Result<()> {
        if self.package.name.trim().is_empty() {
            anyhow::bail!("Package name cannot be empty");
        }
        if self.limits.memory_mb == 0 {
            anyhow::bail!("Memory limit must be greater than 0 MB");
        }
        Ok(())
    }

    pub fn default_manifest_for_package(name: &str) -> Self {
        Self {
            package: PackageMetadata {
                name: name.to_string(),
                version: "0.1.0".to_string(),
                publisher: "local-dev".to_string(),
                description: Some("WasmVault Capability Managed Plugin".to_string()),
                signature: None,
                public_key: None,
            },
            permissions: PermissionsConfig {
                filesystem: FilesystemPermissions::Paths(vec!["./workspace/input".to_string(), "./workspace/output".to_string()]),
                network: false,
                process: false,
                environment: EnvironmentPermissions::Bool(false),
                clipboard: false,
            },
            limits: ResourceLimits::default(),
        }
    }
}
