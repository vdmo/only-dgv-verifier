use only_core::{compute_residual, generate_signs, Sign};
use std::time::Instant;

fn main() {
    let n = 1024;
    let signs: Vec<Sign> = generate_signs(n).collect();
    let mut values = vec![1.0f64; n];
    let iters = 100_000;
    let start = Instant::now();
    let mut acc = 0.0f64;
    for i in 0..iters {
        values[i % n] = (i as f64 % 10.0) - 5.0;
        acc += compute_residual(&signs, &values);
    }
    let dur = start.elapsed();
    println!(
        "bench_residual: iters={} elapsed={:?} acc={}",
        iters, dur, acc
    );
}
