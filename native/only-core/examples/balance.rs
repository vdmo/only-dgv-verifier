use only_core::{compute_residual, generate_signs, make_balanced_field_in_place, Sign};

fn main() {
    let n = 6;
    let signs: Vec<Sign> = generate_signs(n).collect();
    let mut values = vec![0.0f64; n];
    make_balanced_field_in_place(&signs, &mut values, 2.0).unwrap();
    let residual = compute_residual(&signs, &values);
    println!("ONLY-Core Example");
    println!("signs={:?}", signs);
    println!("values={:?}", values);
    println!("residual={}", residual);
}
