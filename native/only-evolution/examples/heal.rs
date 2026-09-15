use only_core::{compute_residual, generate_signs, Sign};
use only_evolution::solve_for_equilibrium;

fn main() {
    let n = 6;
    let signs: Vec<Sign> = generate_signs(n).collect();
    let mut values = vec![2.0f64; n];
    // Wipe index 3
    values[3] = 0.0;

    println!("ONLY-Evolution Example");
    println!("corrupted values={:?}", values);
    println!("residual_before={}", compute_residual(&signs, &values));

    // Heal index 3 using known others
    let known = (0..n)
        .filter(|&i| i != 3)
        .map(|i| (i, values[i]))
        .collect::<Vec<_>>();
    let healed = solve_for_equilibrium(&signs, &known, 3);
    values[3] = healed;

    println!("healed_value={}", healed);
    println!("values={:?}", values);
    println!("residual_after={}", compute_residual(&signs, &values));
}
