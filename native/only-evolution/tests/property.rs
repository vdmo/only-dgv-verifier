use only_core::{check_equilibrium, generate_signs, Sign};
use only_evolution::solve_for_equilibrium;

#[test]
fn property_sweep_heal_single_missing() {
    for n in 4..12 {
        let signs: Vec<Sign> = generate_signs(n).collect();
        let mut values = vec![2.0f64; n];
        for idx in 0..n {
            let mut corrupted = values.clone();
            corrupted[idx] = 0.0;
            let known = (0..n)
                .filter(|&i| i != idx)
                .map(|i| (i, corrupted[i]))
                .collect::<Vec<_>>();
            let healed = solve_for_equilibrium(&signs, &known, idx);
            corrupted[idx] = healed;
            assert!(check_equilibrium(&signs, &corrupted, 1e-9));
        }
    }
}
