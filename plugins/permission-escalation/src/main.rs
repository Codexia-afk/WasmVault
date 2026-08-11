use std::fs;
use std::path::Path;

fn main() {
    println!("[permission-escalation] Attempting path traversal outside scoped sandbox...");

    let forbidden_paths = [
        "../../../../etc/passwd",
        "../../../Cargo.toml",
        "/etc/passwd",
        "./workspace/input/../../../../System",
    ];

    for path in &forbidden_paths {
        println!("[permission-escalation] Attempting read on forbidden path: {}", path);
        match fs::read_to_string(Path::new(path)) {
            Ok(content) => {
                println!("[permission-escalation] ESCAPED SANDBOX! Read {} bytes from {}", content.len(), path);
            }
            Err(e) => {
                println!("[permission-escalation] Access denied by WASI capability boundary: {}", e);
            }
        }
    }
}
