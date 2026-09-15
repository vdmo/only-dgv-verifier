extern crate alloc;
use alloc::vec::Vec;
use alloc::string::String;
use crate::GhostMemory;
use only_core::{check_equilibrium, Sign};

#[inline]
fn round(x: f64) -> f64 {
    libm::round(x)
}

/// Encodes a UTF-8 string into a Ghost Memory Matrix
/// Returns a vector of 4-element invariant arrays.
pub fn encode_string(text: &str, signs: &[Sign]) -> Result<Vec<[f64; 4]>, ()> {
    let bytes = text.as_bytes();
    let len = bytes.len() as u32;
    
    let mut matrix = Vec::new();
    
    // Chunk 0: Length of the string
    let len_field = GhostMemory::try_encode_4(signs, len as f64)?;
    matrix.push(len_field);
    
    // Chunk the bytes into 4-byte u32s
    let mut i = 0;
    while i < bytes.len() {
        let mut chunk = [0u8; 4];
        let end = core::cmp::min(i + 4, bytes.len());
        chunk[..end - i].copy_from_slice(&bytes[i..end]);
        
        let val = u32::from_le_bytes(chunk) as f64;
        let field = GhostMemory::try_encode_4(signs, val)?;
        matrix.push(field);
        
        i += 4;
    }
    
    Ok(matrix)
}

/// Reveals and reconstructs a UTF-8 string from a Ghost Memory Matrix
/// Mathematically verifies the 1st-order equilibrium of each chunk before decoding.
pub fn reveal_string(matrix: &[[f64; 4]], signs: &[Sign]) -> Result<String, ()> {
    if matrix.is_empty() {
        return Err(());
    }
    
    // Verify and decode length
    if !check_equilibrium(signs, &matrix[0], 1e-8) {
        return Err(()); // Memory corrupted
    }
    let len_f = GhostMemory::reveal_4(signs, &matrix[0]);
    let len = round(len_f) as usize;
    
    let mut bytes = Vec::with_capacity(len);
    
    // Verify and decode each chunk
    for field in matrix.iter().skip(1) {
        if !check_equilibrium(signs, field, 1e-8) {
            return Err(()); // Memory corrupted
        }
        let val_f = GhostMemory::reveal_4(signs, field);
        let val_u32 = round(val_f) as u32;
        
        let chunk_bytes = val_u32.to_le_bytes();
        bytes.extend_from_slice(&chunk_bytes);
    }
    
    // Truncate padding bytes
    if bytes.len() > len {
        bytes.truncate(len);
    }
    
    String::from_utf8(bytes).map_err(|_| ())
}

#[cfg(test)]
mod tests {
    use super::*;
    use only_core::generate_signs;

    #[test]
    fn test_ghost_string_roundtrip() {
        let signs: Vec<Sign> = generate_signs(4).collect();
        let original_text = "fn main() { println!(\"TPNN Closed Loop!\"); }";
        
        let matrix = encode_string(original_text, &signs).expect("Failed to encode string");
        let revealed = reveal_string(&matrix, &signs).expect("Failed to reveal string");
        
        assert_eq!(original_text, revealed);
    }
    
    #[test]
    fn test_ghost_string_corruption() {
        let signs: Vec<Sign> = generate_signs(4).collect();
        let mut matrix = encode_string("Secret Data", &signs).unwrap();
        
        // Corrupt one float
        matrix[1][2] = 0.0; 
        
        // Decryption should fail due to 1st-order equilibrium breach
        let res = reveal_string(&matrix, &signs);
        assert!(res.is_err());
    }
}
