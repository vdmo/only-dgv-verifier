use only_core::{check_equilibrium, generate_signs, Sign};
use only_memory::GhostMemory;

fn main() {
    let signs: Vec<Sign> = generate_signs(4).collect();
    let secret = 42.0;
    let field = GhostMemory::encode_4(&signs, secret);
    println!("ONLY-Memory Example");
    println!("signs={:?}", signs);
    println!("field={:?}", field);
    println!("equilibrium={}", check_equilibrium(&signs, &field, 1e-12));
    let revealed = GhostMemory::reveal_4(&signs, &field);
    println!("revealed={}", revealed);
}
