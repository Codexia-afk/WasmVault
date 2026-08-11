use crate::manifest::{CapabilityManifest, FilesystemPermissions, EnvironmentPermissions};
use clap::ValueEnum;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, ValueEnum, Serialize, Deserialize, PartialEq, Eq)]
pub enum Profile {
    Strict,
    Workspace,
    Network,
    Full,
}

impl Profile {
    pub fn apply(&self, manifest: &mut CapabilityManifest) {
        match self {
            Profile::Strict => {
                manifest.permissions.network = false;
                manifest.permissions.process = false;
                manifest.permissions.filesystem = FilesystemPermissions::Bool(false);
                manifest.permissions.environment = EnvironmentPermissions::Bool(false);
            }
            Profile::Workspace => {
                manifest.permissions.network = false;
                manifest.permissions.process = false;
                manifest.permissions.filesystem = FilesystemPermissions::Paths(vec!["./workspace".to_string()]);
                manifest.permissions.environment = EnvironmentPermissions::Bool(false);
            }
            Profile::Network => {
                manifest.permissions.network = true;
                manifest.permissions.process = false;
                manifest.permissions.filesystem = FilesystemPermissions::Paths(vec!["./workspace".to_string()]);
            }
            Profile::Full => {
                manifest.permissions.network = true;
                manifest.permissions.process = true;
                manifest.permissions.filesystem = FilesystemPermissions::Bool(true);
                manifest.permissions.environment = EnvironmentPermissions::Bool(true);
            }
        }
    }
}
