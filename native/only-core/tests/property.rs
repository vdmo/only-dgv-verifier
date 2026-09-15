use only_core::{
    check_equilibrium, compute_residual, generate_signs, make_balanced_field_in_place,
};

fn lcg(seed: u64) -> impl Iterator<Item = u64> {
    let mut x = seed;
    std::iter::repeat_with(move || {
        x = x.wrapping_mul(6364136223846793005).wrapping_add(1);
        x
    })
}

#[test]
fn property_sweep_equilibrium_constructed_fields() {
    for n in 2..16 {
        let signs: Vec<_> = generate_signs(n).collect();
        let mut values = vec![0.0; n];
        let mut seq = lcg(12345);
        for _ in 0..50 {
            let base = ((seq.next().unwrap() >> 16) as f64 % 5.0) + 1.0;
            make_balanced_field_in_place(&signs, &mut values, base).unwrap();
            let r = compute_residual(&signs, &values);
            assert!(r.abs() < 1e-9);
            assert!(check_equilibrium(&signs, &values, 1e-9));
        }
    }
}
