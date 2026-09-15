use only_core::{generate_signs, Sign};
use only_evolution::solve_for_equilibrium;
use std::time::Instant;

fn main() {
    let n = 1024;
    let signs: Vec<Sign> = generate_signs(n).collect();
    let target = n / 2;
    let base = 2.0f64;
    let mut known = Vec::new();
    for i in 0..n {
        if i != target {
            known.push((i, base));
        }
    }
    let iters = 100_000;
    let start = Instant::now();
    let mut acc = 0.0f64;
    for i in 0..iters {
        let v = solve_for_equilibrium(&signs, &known, target);
        acc += v + (i as f64);
    }
    let dur = start.elapsed();
    println!("bench_solve: iters={} elapsed={:?} acc={}", iters, dur, acc);
}
