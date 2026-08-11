use std::fs;
use std::path::Path;

fn main() {
    println!("[image-resizer] Starting image processing plugin in WASI sandbox...");

    let input_dir = Path::new("./workspace/input");
    let output_dir = Path::new("./workspace/output");

    if !input_dir.exists() {
        let _ = fs::create_dir_all(input_dir);
    }
    if !output_dir.exists() {
        let _ = fs::create_dir_all(output_dir);
    }

    let sample_input = input_dir.join("sample.txt");
    let sample_output = output_dir.join("processed.txt");

    if !sample_input.exists() {
        let _ = fs::write(&sample_input, "Raw image data buffer 1080p");
    }

    match fs::read_to_string(&sample_input) {
        Ok(data) => {
            println!("[image-resizer] Read input file successfully ({} bytes)", data.len());
            let processed = format!("RESIZED: {}", data);
            if let Err(e) = fs::write(&sample_output, processed) {
                println!("[image-resizer] Failed to write output: {}", e);
            } else {
                println!("[image-resizer] Transformed and saved output to {:?}", sample_output);
            }
        }
        Err(e) => {
            println!("[image-resizer] Error reading input file: {}", e);
        }
    }
}
