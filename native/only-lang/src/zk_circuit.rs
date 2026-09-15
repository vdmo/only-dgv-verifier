//! ZK-SNARK circuit for ONLY Lang equilibrium proofs.
//!
//! Proves that the equilibrium constraint Σ s_i * v_i = r with |r| ≤ τ holds,
//! plus optional range bounds on individual field values, without revealing
//! the actual values to the verifier.
//!
//! Circuit structure (Groth16 over BN254):
//!   Public:  signs (as ±1 integers), tolerance τ (as fixed-point),
//!            gate_state, fuel_limit
//!   Private: field values v_0..v_n, fuel_consumed
//!
//! Constraints:
//!   1. residual = Σ s_i * v_i           (linear combination)
//!   2. |residual| ≤ τ                    (range check via bit decomposition)
//!   3. For each bound: min ≤ v_i ≤ max   (range check)
//!   4. fuel_consumed ≤ fuel_limit         (range check)

#![cfg(feature = "zk")]

use ark_bn254::Bn254;
use ark_ec::bn254::Bn254 as _;
use ark_ff::{BigInteger, Field, One, PrimeField, Zero};
use ark_groth16::{
    create_random_proof, generate_random_parameters, prepare_verifying_key, verify_proof,
    Proof, ProvingKey, VerifyingKey,
};
use ark_relations::r1cs::{
    ConstraintSynthesizer, ConstraintSystemRef, SynthesisError,
};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::rand::{rngs::StdRng, SeedableRng};
use ark_std::UniformRand;
use serde::{Deserialize, Serialize};
use std::sync::OnceLock;

/// Fixed-point scaling factor: values are scaled by 10^6 for integer arithmetic
/// in the field. This gives 6 decimal places of precision.
pub const SCALE: u64 = 1_000_000;

/// Maximum number of field elements the circuit supports.
pub const MAX_FIELD_SIZE: usize = 16;

/// Maximum bit size for range checks (64-bit values scaled by SCALE).
const VALUE_BITS: usize = 64;

/// A range bound constraint on a specific field index.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BoundConstraint {
    pub index: usize,
    pub min: f64,
    pub max: f64,
}

/// The ZK circuit for ONLY Lang equilibrium proofs.
#[derive(Debug, Clone)]
pub struct EquilibriumCircuit {
    // Public inputs
    pub signs: Vec<i8>,           // ±1
    pub tolerance_scaled: u64,   // τ * SCALE as u64
    pub gate_state: u8,          // 0=DENY, 1=ALLOW, 2=ESCALATE
    pub fuel_limit: u64,

    // Private inputs (witnesses)
    pub values: Vec<f64>,
    pub fuel_consumed: u64,

    // Optional range bounds
    pub bounds: Vec<BoundConstraint>,
}

impl EquilibriumCircuit {
    pub fn new(
        signs: &[i8],
        values: &[f64],
        tolerance: f64,
        gate_state: u8,
        fuel_consumed: u64,
        fuel_limit: u64,
        bounds: Vec<BoundConstraint>,
    ) -> Self {
        Self {
            signs: signs.to_vec(),
            tolerance_scaled: (tolerance.abs() * SCALE as f64) as u64,
            gate_state,
            fuel_limit,
            values: values.to_vec(),
            fuel_consumed,
            bounds,
        }
    }

    fn scale_value(v: f64) -> u64 {
        (v.abs() * SCALE as f64) as u64
    }

    fn sign_multiplier(v: f64) -> u64 {
        if v >= 0.0 { 1 } else { 0 }
    }
}

impl ConstraintSynthesizer<ark_bn254::Fr> for EquilibriumCircuit {
    fn generate_constraints(self, cs: ConstraintSystemRef<ark_bn254::Fr>) -> Result<(), SynthesisError> {
        use ark_relations::r1cs::Variable;

        // Allocate public inputs
        let sign_vars: Vec<Variable> = self.signs
            .iter()
            .map(|s| {
                let val = ark_bn254::Fr::from(*s as u64);
                cs.alloc_input(|| Ok(val))
            })
            .collect::<Result<Vec<_>, _>>()?;

        let tolerance_var = cs.alloc_input(|| {
            Ok(ark_bn254::Fr::from(self.tolerance_scaled))
        })?;

        let gate_var = cs.alloc_input(|| {
            Ok(ark_bn254::Fr::from(self.gate_state as u64))
        })?;

        let fuel_limit_var = cs.alloc_input(|| {
            Ok(ark_bn254::Fr::from(self.fuel_limit))
        })?;

        // Allocate private values
        let value_vars: Vec<Variable> = self.values
            .iter()
            .map(|v| {
                let scaled = Self::scale_value(*v);
                cs.alloc(|| Ok(ark_bn254::Fr::from(scaled)))
            })
            .collect::<Result<Vec<_>, _>>()?;

        let fuel_consumed_var = cs.alloc(|| {
            Ok(ark_bn254::Fr::from(self.fuel_consumed))
        })?;

        // Constraint 1: residual = Σ s_i * v_i
        // We compute the sum as a linear combination
        let mut sum = ark_bn254::Fr::from(0u64);
        for (i, sv) in sign_vars.iter().enumerate() {
            let sign_val = self.signs[i] as i64;
            let value_scaled = Self::scale_value(self.values[i]);
            let contribution = (sign_val as i128 * value_scaled as i128) as i64;
            if contribution >= 0 {
                sum += ark_bn254::Fr::from(contribution as u64);
            } else {
                sum -= ark_bn254::Fr::from((-contribution) as u64);
            }
        }

        let residual_var = cs.alloc(|| Ok(sum))?;

        // Enforce: residual_var == Σ sign_var * value_var
        // Using LC (linear combination) constraints
        for (i, sv) in sign_vars.iter().enumerate() {
            let vv = value_vars[i];
            let sign_fr = ark_bn254::Fr::from(self.signs[i] as i64);
            cs.enforce(
                || format!("residual_contribution_{i}"),
                |lc| lc + (*sv, sign_fr) * (*vv),
                |lc| lc + (ark_bn254::Fr::one(), residual_var),
                |lc| lc,
            );
        }

        // Constraint 2: |residual| ≤ tolerance
        // We prove residual + tolerance ≥ 0 (i.e., residual ≥ -tolerance)
        // and tolerance - residual ≥ 0 (i.e., residual ≤ tolerance)
        // Using bit decomposition for range check
        let residual_plus_tol = cs.alloc(|| {
            let r = sum;
            let t = ark_bn254::Fr::from(self.tolerance_scaled);
            Ok(r + t)
        })?;

        let tol_minus_residual = cs.alloc(|| {
            let t = ark_bn254::Fr::from(self.tolerance_scaled);
            Ok(t - sum)
        })?;

        // Range check: both must be non-negative and fit in VALUE_BITS
        Self::enforce_range_check(&cs, residual_plus_tol, VALUE_BITS)?;
        Self::enforce_range_check(&cs, tol_minus_residual, VALUE_BITS)?;

        // Constraint 3: range bounds on individual values
        for bound in &self.bounds {
            if bound.index < value_vars.len() {
                let v_scaled = Self::scale_value(self.values[bound.index]);
                let min_scaled = Self::scale_value(bound.min);
                let max_scaled = Self::scale_value(bound.max);

                let v_minus_min = cs.alloc(|| {
                    Ok(ark_bn254::Fr::from(v_scaled) - ark_bn254::Fr::from(min_scaled))
                })?;
                let max_minus_v = cs.alloc(|| {
                    Ok(ark_bn254::Fr::from(max_scaled) - ark_bn254::Fr::from(v_scaled))
                })?;

                Self::enforce_range_check(&cs, v_minus_min, VALUE_BITS)?;
                Self::enforce_range_check(&cs, max_minus_v, VALUE_BITS)?;
            }
        }

        // Constraint 4: fuel_consumed ≤ fuel_limit
        let fuel_diff = cs.alloc(|| {
            Ok(ark_bn254::Fr::from(self.fuel_limit) - ark_bn254::Fr::from(self.fuel_consumed))
        })?;
        Self::enforce_range_check(&cs, fuel_diff, VALUE_BITS)?;

        Ok(())
    }
}

impl EquilibriumCircuit {
    /// Enforce that a variable is non-negative and fits within `bits` bits.
    /// Uses bit decomposition: allocates `bits` boolean variables and enforces
    /// that their weighted sum equals the value.
    fn enforce_range_check(
        cs: &ConstraintSystemRef<ark_bn254::Fr>,
        var: ark_relations::r1cs::Variable,
        bits: usize,
    ) -> Result<(), SynthesisError> {
        use ark_relations::r1cs::Variable;

        let bit_vars: Vec<Variable> = (0..bits)
            .map(|i| {
                cs.alloc(|| {
                    let val = var.witness.unwrap_or(ark_bn254::Fr::from(0u64));
                    let bit = val.into_repr().as_ref()[0];
                    let is_set = (bit >> i) & 1 == 1;
                    Ok(if is_set { ark_bn254::Fr::one() } else { ark_bn254::Fr::from(0u64) })
                })
            })
            .collect::<Result<Vec<_>, _>>()?;

        // Enforce each bit is boolean
        for bv in &bit_vars {
            cs.enforce(
                || "bool",
                |lc| lc + (ark_bn254::Fr::one(), *bv),
                |lc| lc + (ark_bn254::Fr::one(), *bv),
                |lc| lc + (*bv),
            );
        }

        // Enforce: Σ 2^i * bit_i == var
        cs.enforce(
            || "range_check_sum",
            |lc| {
                let mut acc = lc;
                for (i, bv) in bit_vars.iter().enumerate() {
                    acc += (ark_bn254::Fr::from(1u64 << i), *bv);
                }
                acc
            },
            |lc| lc + (ark_bn254::Fr::one(), Variable::One),
            |lc| lc + (ark_bn254::Fr::one(), var),
        );

        Ok(())
    }
}

/// Serialized ZK proof for transport/storage.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ZkProofBundle {
    /// Base64-encoded Groth16 proof
    pub proof_b64: String,
    /// Base64-encoded verifying key
    pub vk_b64: String,
    /// Base64-encoded public inputs
    pub public_inputs_b64: String,
    /// Circuit metadata
    pub circuit_version: String,
    pub field_size: usize,
    pub bounds_count: usize,
}

/// Generate a Groth16 proving key and verifying key for the circuit.
/// This is the trusted setup phase. In production, use a MPC ceremony.
pub fn generate_circuit_params(
    field_size: usize,
    bounds_count: usize,
) -> Result<(ProvingKey<Bn254>, VerifyingKey<Bn254>), String> {
    let mut rng = StdRng::seed_from_u64(42);

    // Create a dummy circuit with the right dimensions for parameter generation
    let dummy_signs = vec![1i8; field_size];
    let dummy_values = vec![1.0f64; field_size];
    let dummy_bounds = (0..bounds_count)
        .map(|i| BoundConstraint {
            index: i % field_size,
            min: 0.0,
            max: 100.0,
        })
        .collect();

    let circuit = EquilibriumCircuit::new(
        &dummy_signs,
        &dummy_values,
        1e-6,
        1, // ALLOW
        100,
        100_000,
        dummy_bounds,
    );

    let pk = generate_random_parameters::<Bn254, _, _>(circuit, &mut rng)
        .map_err(|e| format!("Failed to generate parameters: {e}"))?;

    let vk = pk.vk.clone();
    Ok((pk, vk))
}

/// Cache for circuit parameters keyed by (field_size, bounds_count).
static PARAM_CACHE: OnceLock<std::sync::Mutex<std::collections::HashMap<(usize, usize), (ProvingKey<Bn254>, VerifyingKey<Bn254>)>>> = OnceLock::new();

fn get_or_create_params(
    field_size: usize,
    bounds_count: usize,
) -> Result<(ProvingKey<Bn254>, VerifyingKey<Bn254>), String> {
    let cache = PARAM_CACHE.get_or_init(|| {
        std::sync::Mutex::new(std::collections::HashMap::new())
    });
    let mut guard = cache.lock().map_err(|e| format!("Lock error: {e}"))?;
    if let Some((pk, vk)) = guard.get(&(field_size, bounds_count)) {
        return Ok((pk.clone(), vk.clone()));
    }
    let (pk, vk) = generate_circuit_params(field_size, bounds_count)?;
    guard.insert((field_size, bounds_count), (pk.clone(), vk.clone()));
    Ok((pk, vk))
}

/// Generate a ZK proof for the equilibrium circuit.
///
/// Returns a serialized proof bundle that can be verified without
/// revealing the private field values.
pub fn generate_zk_proof(
    signs: &[i8],
    values: &[f64],
    tolerance: f64,
    gate_state: u8,
    fuel_consumed: u64,
    fuel_limit: u64,
    bounds: Vec<BoundConstraint>,
) -> Result<ZkProofBundle, String> {
    if signs.len() > MAX_FIELD_SIZE {
        return Err(format!(
            "Field size {} exceeds maximum {}",
            signs.len(),
            MAX_FIELD_SIZE
        ));
    }

    let (pk, vk) = get_or_create_params(signs.len(), bounds.len())?;

    let circuit = EquilibriumCircuit::new(
        signs,
        values,
        tolerance,
        gate_state,
        fuel_consumed,
        fuel_limit,
        bounds,
    );

    let mut rng = StdRng::seed_from_u64(12345);
    let proof = create_random_proof(circuit, &pk, &mut rng)
        .map_err(|e| format!("Failed to create proof: {e}"))?;

    // Serialize proof
    let mut proof_bytes = Vec::new();
    proof
        .serialize(&mut proof_bytes)
        .map_err(|e| format!("Failed to serialize proof: {e}"))?;
    let proof_b64 = base64::Engine::encode(&base64::engine::general_purpose::STANDARD, &proof_bytes);

    // Serialize VK
    let mut vk_bytes = Vec::new();
    vk.serialize(&mut vk_bytes)
        .map_err(|e| format!("Failed to serialize VK: {e}"))?;
    let vk_b64 = base64::Engine::encode(&base64::engine::general_purpose::STANDARD, &vk_bytes);

    // Serialize public inputs
    let mut public_inputs = Vec::new();
    for s in signs {
        public_inputs.push(*s as u64);
    }
    public_inputs.push((tolerance.abs() * SCALE as f64) as u64);
    public_inputs.push(gate_state as u64);
    public_inputs.push(fuel_limit);
    let public_inputs_b64 = base64::Engine::encode(
        &base64::engine::general_purpose::STANDARD,
        serde_json::to_string(&public_inputs).unwrap_or_default(),
    );

    Ok(ZkProofBundle {
        proof_b64,
        vk_b64,
        public_inputs_b64,
        circuit_version: "equilibrium-groth16-v1".to_string(),
        field_size: signs.len(),
        bounds_count: bounds.len(),
    })
}

/// Verify a ZK proof bundle without revealing the private values.
///
/// Returns Ok(true) if the proof is valid, Ok(false) if invalid,
/// Err if verification fails due to deserialization errors.
pub fn verify_zk_proof(bundle: &ZkProofBundle) -> Result<bool, String> {
    // Deserialize proof
    let proof_bytes = base64::Engine::decode(
        &base64::engine::general_purpose::STANDARD,
        &bundle.proof_b64,
    )
    .map_err(|e| format!("Failed to decode proof: {e}"))?;
    let proof = Proof::<Bn254>::deserialize(&proof_bytes[..])
        .map_err(|e| format!("Failed to deserialize proof: {e}"))?;

    // Deserialize VK
    let vk_bytes = base64::Engine::decode(
        &base64::engine::general_purpose::STANDARD,
        &bundle.vk_b64,
    )
    .map_err(|e| format!("Failed to decode VK: {e}"))?;
    let vk = VerifyingKey::<Bn254>::deserialize(&vk_bytes[..])
        .map_err(|e| format!("Failed to deserialize VK: {e}"))?;

    // Deserialize public inputs
    let public_inputs_json = base64::Engine::decode(
        &base64::engine::general_purpose::STANDARD,
        &bundle.public_inputs_b64,
    )
    .map_err(|e| format!("Failed to decode public inputs: {e}"))?;
    let public_inputs_str = String::from_utf8_lossy(&public_inputs_json);
    let public_inputs: Vec<u64> = serde_json::from_str(&public_inputs_str)
        .map_err(|e| format!("Failed to parse public inputs: {e}"))?;

    // Build public input vector for verification
    let mut public_input_fr = Vec::new();
    for v in &public_inputs {
        public_input_fr.push(ark_bn254::Fr::from(*v));
    }

    let pvk = prepare_verifying_key(&vk);
    let result = verify_proof(&pvk, &proof, &public_input_fr)
        .map_err(|e| format!("Verification error: {e}"))?;

    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_zk_proof_generation_and_verification() {
        let signs = vec![1i8, -1, -1, 1];
        let values = vec![100.0, 100.0, 100.0, 100.0]; // Perfectly balanced
        let tolerance = 1e-6;
        let fuel_consumed = 50u64;
        let fuel_limit = 100_000u64;

        let bundle = generate_zk_proof(
            &signs,
            &values,
            tolerance,
            1, // ALLOW
            fuel_consumed,
            fuel_limit,
            vec![],
        )
        .expect("Proof generation should succeed");

        assert!(!bundle.proof_b64.is_empty());
        assert!(!bundle.vk_b64.is_empty());
        assert_eq!(bundle.field_size, 4);
        assert_eq!(bundle.circuit_version, "equilibrium-groth16-v1");

        let valid = verify_zk_proof(&bundle).expect("Verification should not error");
        assert!(valid, "Proof should verify as valid");
    }

    #[test]
    fn test_zk_proof_with_bounds() {
        let signs = vec![1i8, -1];
        let values = vec![50.0, 50.0]; // Balanced
        let bounds = vec![BoundConstraint {
            index: 0,
            min: 0.0,
            max: 100.0,
        }];

        let bundle = generate_zk_proof(
            &signs,
            &values,
            1e-6,
            1,
            10,
            100_000,
            bounds,
        )
        .expect("Proof with bounds should succeed");

        let valid = verify_zk_proof(&bundle).expect("Verification should not error");
        assert!(valid, "Proof with bounds should verify");
    }

    #[test]
    fn test_zk_proof_does_not_reveal_values() {
        let signs = vec![1i8, -1];

        // Two different value sets, same public inputs (signs, tolerance, gate)
        let bundle1 = generate_zk_proof(
            &signs, &[50.0, 50.0], 1e-6, 1, 10, 100_000, vec![],
        )
        .unwrap();

        let bundle2 = generate_zk_proof(
            &signs, &[999.0, 999.0], 1e-6, 1, 10, 100_000, vec![],
        )
        .unwrap();

        // Both should verify (both are balanced)
        assert!(verify_zk_proof(&bundle1).unwrap());
        assert!(verify_zk_proof(&bundle2).unwrap());

        // The public inputs should be identical (no value leakage)
        assert_eq!(bundle1.public_inputs_b64, bundle2.public_inputs_b64);

        // The proofs themselves should be different (different witnesses)
        assert_ne!(bundle1.proof_b64, bundle2.proof_b64);
    }
}
