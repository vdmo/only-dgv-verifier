use only_core::{generate_signs, Sign};
use only_memory::GhostMemory;
use std::time::Instant;

fn main() {
    let signs: Vec<Sign> = generate_signs(4).collect();
    let data = 42.0;
    let mut field = GhostMemory::encode_4(&signs, data);
    let iters = 100_000;
    let start = Instant::now();
    let mut acc = 0.0f64;
    for _ in 0..iters {
        acc += GhostMemory::reveal_4(&signs, &field);
        field[2] = 0.0;
        field[2] = (data / 2.0 + 1.0).sqrt();
    }
    let dur = start.elapsed();
    println!(
        "bench_reveal: iters={} elapsed={:?} acc={}",
        iters, dur, acc
    );
}
