use criterion::{black_box, criterion_group, criterion_main, Criterion};
use only_core::generate_signs;
use only_lang_ir::{compile, execute};

fn bench_ir_execute(c: &mut Criterion) {
    let signs: Vec<only_core::Sign> = generate_signs(4).collect();
    let source = "harmony(0.001) corrupt(2) if_broken { evolve(2) } residual() report()";

    let mut g = c.benchmark_group("ir_execute");
    g.bench_function("compiled_ir", |b| {
        let program = compile(source).unwrap();
        b.iter(|| {
            let mut field = [104.69, 101.0, 99.0, 95.31];
            black_box(execute(&program, &signs, &mut field));
        });
    });
    g.finish();
}

criterion_group!(benches, bench_ir_execute);
criterion_main!(benches);
