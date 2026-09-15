use only_core::{check_equilibrium, compute_residual, generate_signs};
use only_evolution::solve_for_equilibrium;
use only_memory::GhostMemory;

#[test]
fn scenario_boot_heal_reveal_default() {
    let signs: Vec<_> = generate_signs(4).collect();
    let secret = 42.0;
    let mut field = GhostMemory::encode_4(&signs, secret);
    assert!(check_equilibrium(&signs, &field, 1e-10));
    let r0 = compute_residual(&signs, &field);
    assert!(r0.abs() < 1e-10);
    field[2] = 0.0;
    assert!(!check_equilibrium(&signs, &field, 1e-12));
    let known = (0..4)
        .filter(|&i| i != 2)
        .map(|i| (i, field[i]))
        .collect::<Vec<_>>();
    let healed = solve_for_equilibrium(&signs, &known, 2);
    field[2] = healed;
    assert!(check_equilibrium(&signs, &field, 1e-10));
    let revealed = GhostMemory::reveal_4(&signs, &field);
    assert!((revealed - secret).abs() < 1e-10);
}
