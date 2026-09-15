//! ONLY Lang IR — Compiled bytecode for sub-microsecond equilibrium checks
//!
//! The interpreter-based `only-lang` parses scripts at runtime using `nom`,
//! adding ~50-100µs of parse overhead per script execution. This crate
//! pre-compiles scripts into a compact bytecode IR that executes in <1µs
//! for equilibrium checks, making it suitable for real-time embedded use.
//!
//! # IR Format
//!
//! Each instruction is 1-9 bytes:
//!   [opcode: u8] [operand: 0-8 bytes depending on opcode]
//!
//! Opcodes:
//!   0x00 NOP           — no operation
//!   0x01 HARMONY(f64)  — set tolerance, check equilibrium
//!   0x02 EVOLVE(u8)    — heal index
//!   0x03 DATA(f64)     — set expected data value
//!   0x04 CORRUPT(u8)   — zero out index
//!   0x05 RESIDUAL      — push current residual to history
//!   0x06 REPORT        — request report
//!   0x07 REPORT_COMPACT
//!   0x08 REPORT_VERBOSE
//!   0x09 REPORT_JSON
//!   0x0A REPORT_TO(u8) — string table index for path (std only)
//!   0x0B LOG_LEVEL(u8)
//!   0x0C BUDGET_LIMIT(f64)
//!   0x0D TIME_WINDOW(u64)
//!   0x0E VOLATILITY_LIMIT(f64)
//!   0x0F MAX_EXPOSURE(f64)
//!   0x10 IF_BROKEN(offset: u16) — jump forward if equilibrium fails
//!   0x11 HALT          — end execution

#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

use alloc::string::String;
use alloc::vec::Vec;
use only_core::{check_equilibrium, compute_residual, Sign};
use only_evolution::solve_for_equilibrium;
use only_memory::GhostMemory;

// ─── Opcodes ─────────────────────────────────────────────────────────────────

pub const OP_NOP: u8 = 0x00;
pub const OP_HARMONY: u8 = 0x01;
pub const OP_EVOLVE: u8 = 0x02;
pub const OP_DATA: u8 = 0x03;
pub const OP_CORRUPT: u8 = 0x04;
pub const OP_RESIDUAL: u8 = 0x05;
pub const OP_REPORT: u8 = 0x06;
pub const OP_REPORT_COMPACT: u8 = 0x07;
pub const OP_REPORT_VERBOSE: u8 = 0x08;
pub const OP_REPORT_JSON: u8 = 0x09;
pub const OP_REPORT_TO: u8 = 0x0A;
pub const OP_LOG_LEVEL: u8 = 0x0B;
pub const OP_BUDGET_LIMIT: u8 = 0x0C;
pub const OP_TIME_WINDOW: u8 = 0x0D;
pub const OP_VOLATILITY_LIMIT: u8 = 0x0E;
pub const OP_MAX_EXPOSURE: u8 = 0x0F;
pub const OP_IF_BROKEN: u8 = 0x10;
pub const OP_HALT: u8 = 0x11;

// ─── IR Program ──────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct IrProgram {
    pub bytecode: Vec<u8>,
    pub string_table: Vec<String>,
}

impl IrProgram {
    pub fn new() -> Self {
        IrProgram {
            bytecode: Vec::new(),
            string_table: Vec::new(),
        }
    }

    pub fn from_bytes(bytecode: Vec<u8>, string_table: Vec<String>) -> Self {
        IrProgram { bytecode, string_table }
    }

    pub fn serialize(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(
            8 + self.bytecode.len()
                + self.string_table.iter().map(|s| s.len() + 4).sum::<usize>(),
        );
        out.extend_from_slice(&(self.bytecode.len() as u32).to_le_bytes());
        out.extend_from_slice(&(self.string_table.len() as u32).to_le_bytes());
        out.extend_from_slice(&self.bytecode);
        for s in &self.string_table {
            out.extend_from_slice(&(s.len() as u32).to_le_bytes());
            out.extend_from_slice(s.as_bytes());
        }
        out
    }

    pub fn deserialize(data: &[u8]) -> Result<Self, &'static str> {
        if data.len() < 8 {
            return Err("Data too short for IR header");
        }
        let bc_len = u32::from_le_bytes(data[0..4].try_into().unwrap()) as usize;
        let str_count = u32::from_le_bytes(data[4..8].try_into().unwrap()) as usize;
        if data.len() < 8 + bc_len {
            return Err("Data too short for bytecode");
        }
        let bytecode = data[8..8 + bc_len].to_vec();
        let mut offset = 8 + bc_len;
        let mut string_table = Vec::with_capacity(str_count);
        for _ in 0..str_count {
            if offset + 4 > data.len() {
                return Err("Truncated string table");
            }
            let slen = u32::from_le_bytes(data[offset..offset + 4].try_into().unwrap()) as usize;
            offset += 4;
            if offset + slen > data.len() {
                return Err("Truncated string entry");
            }
            string_table.push(
                String::from_utf8(data[offset..offset + slen].to_vec())
                    .map_err(|_| "Invalid UTF-8 in string table")?,
            );
            offset += slen;
        }
        Ok(IrProgram { bytecode, string_table })
    }

    pub fn size(&self) -> usize {
        self.bytecode.len()
    }
}

// ─── Tokenizer ───────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq)]
enum Token {
    Ident(String),
    Number(f64),
    StringLit(String),
    LParen,
    RParen,
    LBrace,
    RBrace,
}

fn tokenize(input: &str) -> Result<Vec<Token>, &'static str> {
    let mut tokens = Vec::new();
    let bytes = input.as_bytes();
    let mut i = 0;

    while i < bytes.len() {
        let c = bytes[i];
        match c {
            b' ' | b'\t' | b'\n' | b'\r' => i += 1,
            b'(' => { tokens.push(Token::LParen); i += 1; }
            b')' => { tokens.push(Token::RParen); i += 1; }
            b'{' => { tokens.push(Token::LBrace); i += 1; }
            b'}' => { tokens.push(Token::RBrace); i += 1; }
            b'"' => {
                i += 1;
                let start = i;
                while i < bytes.len() && bytes[i] != b'"' { i += 1; }
                if i >= bytes.len() {
                    return Err("Unterminated string literal");
                }
                let s = String::from_utf8(bytes[start..i].to_vec())
                    .map_err(|_| "Invalid UTF-8 in string literal")?;
                tokens.push(Token::StringLit(s));
                i += 1;
            }
            c if c.is_ascii_alphabetic() || c == b'_' => {
                let start = i;
                while i < bytes.len() && (bytes[i].is_ascii_alphanumeric() || bytes[i] == b'_') {
                    i += 1;
                }
                let ident = String::from_utf8(bytes[start..i].to_vec())
                    .map_err(|_| "Invalid UTF-8 in identifier")?;
                tokens.push(Token::Ident(ident));
            }
            c if c.is_ascii_digit() || c == b'-' || c == b'.' => {
                let start = i;
                if c == b'-' { i += 1; }
                while i < bytes.len()
                    && (bytes[i].is_ascii_digit()
                        || bytes[i] == b'.'
                        || bytes[i] == b'e'
                        || bytes[i] == b'E'
                        || bytes[i] == b'+'
                        || bytes[i] == b'-')
                {
                    i += 1;
                }
                let num_str = String::from_utf8(bytes[start..i].to_vec())
                    .map_err(|_| "Invalid UTF-8 in number")?;
                let val: f64 = num_str.parse().map_err(|_| "Invalid number literal")?;
                tokens.push(Token::Number(val));
            }
            _ => return Err("Unexpected character in input"),
        }
    }
    Ok(tokens)
}

// ─── Compiler ────────────────────────────────────────────────────────────────

pub fn compile(source: &str) -> Result<IrProgram, &'static str> {
    let tokens = tokenize(source)?;
    let mut program = IrProgram::new();
    let mut pos = 0;
    compile_block(&tokens, &mut pos, &mut program)?;
    program.bytecode.push(OP_HALT);
    Ok(program)
}

fn compile_block(
    tokens: &[Token],
    pos: &mut usize,
    program: &mut IrProgram,
) -> Result<(), &'static str> {
    while *pos < tokens.len() {
        match &tokens[*pos] {
            Token::RBrace => return Ok(()),
            Token::Ident(name) => {
                *pos += 1;
                match name.as_str() {
                    "if_broken" => {
                        expect_token(tokens, pos, &Token::LBrace)?;
                        let patch_pos = program.bytecode.len();
                        program.bytecode.push(OP_IF_BROKEN);
                        program.bytecode.push(0);
                        program.bytecode.push(0);
                        compile_block(tokens, pos, program)?;
                        expect_token(tokens, pos, &Token::RBrace)?;
                        let offset = (program.bytecode.len() - patch_pos - 3) as u16;
                        program.bytecode[patch_pos + 1] = (offset >> 8) as u8;
                        program.bytecode[patch_pos + 2] = (offset & 0xFF) as u8;
                    }
                    "harmony" => {
                        expect_token(tokens, pos, &Token::LParen)?;
                        let val = expect_number(tokens, pos)?;
                        expect_token(tokens, pos, &Token::RParen)?;
                        program.bytecode.push(OP_HARMONY);
                        program.bytecode.extend_from_slice(&val.to_le_bytes());
                    }
                    "evolve" => {
                        expect_token(tokens, pos, &Token::LParen)?;
                        let val = expect_number(tokens, pos)?;
                        expect_token(tokens, pos, &Token::RParen)?;
                        program.bytecode.push(OP_EVOLVE);
                        program.bytecode.push(val as u8);
                    }
                    "data" => {
                        expect_token(tokens, pos, &Token::LParen)?;
                        let val = expect_number(tokens, pos)?;
                        expect_token(tokens, pos, &Token::RParen)?;
                        program.bytecode.push(OP_DATA);
                        program.bytecode.extend_from_slice(&val.to_le_bytes());
                    }
                    "corrupt" => {
                        expect_token(tokens, pos, &Token::LParen)?;
                        let val = expect_number(tokens, pos)?;
                        expect_token(tokens, pos, &Token::RParen)?;
                        program.bytecode.push(OP_CORRUPT);
                        program.bytecode.push(val as u8);
                    }
                    "residual" => {
                        expect_token(tokens, pos, &Token::LParen)?;
                        skip_optional_number(tokens, pos);
                        expect_token(tokens, pos, &Token::RParen)?;
                        program.bytecode.push(OP_RESIDUAL);
                    }
                    "report" => {
                        expect_token(tokens, pos, &Token::LParen)?;
                        skip_optional_number(tokens, pos);
                        expect_token(tokens, pos, &Token::RParen)?;
                        program.bytecode.push(OP_REPORT);
                    }
                    "report_compact" => {
                        expect_token(tokens, pos, &Token::LParen)?;
                        skip_optional_number(tokens, pos);
                        expect_token(tokens, pos, &Token::RParen)?;
                        program.bytecode.push(OP_REPORT_COMPACT);
                    }
                    "report_verbose" => {
                        expect_token(tokens, pos, &Token::LParen)?;
                        skip_optional_number(tokens, pos);
                        expect_token(tokens, pos, &Token::RParen)?;
                        program.bytecode.push(OP_REPORT_VERBOSE);
                    }
                    "report_json" => {
                        expect_token(tokens, pos, &Token::LParen)?;
                        skip_optional_number(tokens, pos);
                        expect_token(tokens, pos, &Token::RParen)?;
                        program.bytecode.push(OP_REPORT_JSON);
                    }
                    "report_to" => {
                        expect_token(tokens, pos, &Token::LParen)?;
                        if let Some(Token::StringLit(s)) = tokens.get(*pos) {
                            let idx = program.string_table.len();
                            program.string_table.push(s.clone());
                            *pos += 1;
                            expect_token(tokens, pos, &Token::RParen)?;
                            program.bytecode.push(OP_REPORT_TO);
                            program.bytecode.push(idx as u8);
                        } else {
                            return Err("report_to expects a string argument");
                        }
                    }
                    "log_level" => {
                        expect_token(tokens, pos, &Token::LParen)?;
                        let val = expect_number(tokens, pos)?;
                        expect_token(tokens, pos, &Token::RParen)?;
                        program.bytecode.push(OP_LOG_LEVEL);
                        program.bytecode.push(val as u8);
                    }
                    "budget_limit" => {
                        expect_token(tokens, pos, &Token::LParen)?;
                        let val = expect_number(tokens, pos)?;
                        expect_token(tokens, pos, &Token::RParen)?;
                        program.bytecode.push(OP_BUDGET_LIMIT);
                        program.bytecode.extend_from_slice(&val.to_le_bytes());
                    }
                    "time_window" => {
                        expect_token(tokens, pos, &Token::LParen)?;
                        let val = expect_number(tokens, pos)?;
                        expect_token(tokens, pos, &Token::RParen)?;
                        program.bytecode.push(OP_TIME_WINDOW);
                        program.bytecode.extend_from_slice(&(val as u64).to_le_bytes());
                    }
                    "volatility_limit" => {
                        expect_token(tokens, pos, &Token::LParen)?;
                        let val = expect_number(tokens, pos)?;
                        expect_token(tokens, pos, &Token::RParen)?;
                        program.bytecode.push(OP_VOLATILITY_LIMIT);
                        program.bytecode.extend_from_slice(&val.to_le_bytes());
                    }
                    "max_exposure" => {
                        expect_token(tokens, pos, &Token::LParen)?;
                        let val = expect_number(tokens, pos)?;
                        expect_token(tokens, pos, &Token::RParen)?;
                        program.bytecode.push(OP_MAX_EXPOSURE);
                        program.bytecode.extend_from_slice(&val.to_le_bytes());
                    }
                    _ => return Err("Unknown command"),
                }
            }
            _ => return Err("Expected command identifier"),
        }
    }
    Ok(())
}

fn expect_token(tokens: &[Token], pos: &mut usize, expected: &Token) -> Result<(), &'static str> {
    if *pos >= tokens.len() || &tokens[*pos] != expected {
        return Err("Unexpected token");
    }
    *pos += 1;
    Ok(())
}

fn expect_number(tokens: &[Token], pos: &mut usize) -> Result<f64, &'static str> {
    if *pos >= tokens.len() {
        return Err("Expected number");
    }
    match &tokens[*pos] {
        Token::Number(v) => { *pos += 1; Ok(*v) }
        _ => Err("Expected number"),
    }
}

fn skip_optional_number(tokens: &[Token], pos: &mut usize) {
    if *pos < tokens.len() {
        if let Token::Number(_) = &tokens[*pos] { *pos += 1; }
    }
}

// ─── IR Execution Result ─────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct IrResult {
    pub pass: bool,
    pub residual: f64,
    pub healed_index: Option<usize>,
    pub revealed: Option<f64>,
    pub residual_history: Vec<f64>,
    pub indices_healed: Vec<usize>,
    pub budget_limit: Option<f64>,
    pub time_window: Option<u64>,
    pub volatility_limit: Option<f64>,
    pub max_exposure: Option<f64>,
    pub cycles: usize,
}

impl IrResult {
    pub fn new(initial_residual: f64) -> Self {
        IrResult {
            pass: true,
            residual: initial_residual,
            healed_index: None,
            revealed: None,
            residual_history: Vec::new(),
            indices_healed: Vec::new(),
            budget_limit: None,
            time_window: None,
            volatility_limit: None,
            max_exposure: None,
            cycles: 0,
        }
    }
}

// ─── IR Virtual Machine ──────────────────────────────────────────────────────

#[inline]
pub fn execute(
    program: &IrProgram,
    signs: &[Sign],
    field: &mut [f64],
) -> IrResult {
    let mut result = IrResult::new(compute_residual(signs, field));
    let mut tolerance: f64 = 1e-12;
    let bc = &program.bytecode;
    let mut pc: usize = 0;

    while pc < bc.len() {
        let opcode = bc[pc];
        pc += 1;
        result.cycles += 1;

        match opcode {
            OP_NOP => {}
            OP_HARMONY => {
                let val = f64::from_le_bytes(bc[pc..pc + 8].try_into().unwrap());
                pc += 8;
                tolerance = val;
                result.pass = check_equilibrium(signs, field, tolerance);
            }
            OP_EVOLVE => {
                let idx = bc[pc] as usize;
                pc += 1;
                let mut k: Vec<(usize, f64)> = Vec::with_capacity(3);
                for i in 0..field.len() {
                    if i != idx {
                        k.push((i, field[i]));
                        if k.len() == 3 { break; }
                    }
                }
                let v = solve_for_equilibrium(signs, &k, idx);
                field[idx] = v;
                result.healed_index = Some(idx);
                result.indices_healed.push(idx);
                result.residual = compute_residual(signs, field);
            }
            OP_DATA => {
                let _val = f64::from_le_bytes(bc[pc..pc + 8].try_into().unwrap());
                pc += 8;
                let rev = GhostMemory::reveal_4(signs, field);
                result.revealed = Some(rev);
            }
            OP_CORRUPT => {
                let idx = bc[pc] as usize;
                pc += 1;
                field[idx] = 0.0;
                result.residual = compute_residual(signs, field);
                result.pass = check_equilibrium(signs, field, tolerance);
            }
            OP_RESIDUAL => {
                result.residual_history.push(compute_residual(signs, field));
            }
            OP_REPORT | OP_REPORT_COMPACT | OP_REPORT_VERBOSE | OP_REPORT_JSON => {}
            OP_REPORT_TO => { pc += 1; }
            OP_LOG_LEVEL => { pc += 1; }
            OP_BUDGET_LIMIT => {
                let val = f64::from_le_bytes(bc[pc..pc + 8].try_into().unwrap());
                pc += 8;
                result.budget_limit = Some(val);
            }
            OP_TIME_WINDOW => {
                let val = u64::from_le_bytes(bc[pc..pc + 8].try_into().unwrap());
                pc += 8;
                result.time_window = Some(val);
            }
            OP_VOLATILITY_LIMIT => {
                let val = f64::from_le_bytes(bc[pc..pc + 8].try_into().unwrap());
                pc += 8;
                result.volatility_limit = Some(val);
            }
            OP_MAX_EXPOSURE => {
                let val = f64::from_le_bytes(bc[pc..pc + 8].try_into().unwrap());
                pc += 8;
                result.max_exposure = Some(val);
            }
            OP_IF_BROKEN => {
                let offset = ((bc[pc] as u16) << 8) | (bc[pc + 1] as u16);
                pc += 2;
                if check_equilibrium(signs, field, tolerance) {
                    pc += offset as usize;
                }
            }
            OP_HALT => break,
            _ => break,
        }
    }

    result.residual = compute_residual(signs, field);
    result.pass = check_equilibrium(signs, field, tolerance);
    result
}

pub fn execute_with_report(
    program: &IrProgram,
    signs: &[Sign],
    field: &mut [f64],
) -> (IrResult, Option<String>) {
    let result = execute(program, signs, field);
    let report = if !result.indices_healed.is_empty() || !result.residual_history.is_empty() {
        Some(format!(
            "IR Execution: residual={:.6}, pass={}, cycles={}, healed={:?}",
            result.residual, result.pass, result.cycles, result.indices_healed
        ))
    } else {
        None
    };
    (result, report)
}

// ─── Disassembler ────────────────────────────────────────────────────────────

pub fn disassemble(program: &IrProgram) -> String {
    let mut out = String::new();
    let bc = &program.bytecode;
    let mut pc = 0;

    while pc < bc.len() {
        let opcode = bc[pc];
        pc += 1;
        match opcode {
            OP_NOP => out.push_str("NOP\n"),
            OP_HARMONY => {
                let val = f64::from_le_bytes(bc[pc..pc+8].try_into().unwrap());
                pc += 8;
                out.push_str(&format!("HARMONY({})\n", val));
            }
            OP_EVOLVE => { let idx = bc[pc]; pc += 1; out.push_str(&format!("EVOLVE({})\n", idx)); }
            OP_DATA => {
                let val = f64::from_le_bytes(bc[pc..pc+8].try_into().unwrap());
                pc += 8;
                out.push_str(&format!("DATA({})\n", val));
            }
            OP_CORRUPT => { let idx = bc[pc]; pc += 1; out.push_str(&format!("CORRUPT({})\n", idx)); }
            OP_RESIDUAL => out.push_str("RESIDUAL\n"),
            OP_REPORT => out.push_str("REPORT\n"),
            OP_REPORT_COMPACT => out.push_str("REPORT_COMPACT\n"),
            OP_REPORT_VERBOSE => out.push_str("REPORT_VERBOSE\n"),
            OP_REPORT_JSON => out.push_str("REPORT_JSON\n"),
            OP_REPORT_TO => {
                let idx = bc[pc] as usize; pc += 1;
                let path = program.string_table.get(idx).map(|s| s.as_str()).unwrap_or("?");
                out.push_str(&format!("REPORT_TO(\"{}\")\n", path));
            }
            OP_LOG_LEVEL => { let val = bc[pc]; pc += 1; out.push_str(&format!("LOG_LEVEL({})\n", val)); }
            OP_BUDGET_LIMIT => {
                let val = f64::from_le_bytes(bc[pc..pc+8].try_into().unwrap());
                pc += 8;
                out.push_str(&format!("BUDGET_LIMIT({})\n", val));
            }
            OP_TIME_WINDOW => {
                let val = u64::from_le_bytes(bc[pc..pc+8].try_into().unwrap());
                pc += 8;
                out.push_str(&format!("TIME_WINDOW({})\n", val));
            }
            OP_VOLATILITY_LIMIT => {
                let val = f64::from_le_bytes(bc[pc..pc+8].try_into().unwrap());
                pc += 8;
                out.push_str(&format!("VOLATILITY_LIMIT({})\n", val));
            }
            OP_MAX_EXPOSURE => {
                let val = f64::from_le_bytes(bc[pc..pc+8].try_into().unwrap());
                pc += 8;
                out.push_str(&format!("MAX_EXPOSURE({})\n", val));
            }
            OP_IF_BROKEN => {
                let offset = ((bc[pc] as u16) << 8) | (bc[pc+1] as u16);
                pc += 2;
                out.push_str(&format!("IF_BROKEN(+{})\n", offset));
            }
            OP_HALT => out.push_str("HALT\n"),
            _ => out.push_str(&format!("UNKNOWN(0x{:02x})\n", opcode)),
        }
    }
    out
}

// ─── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use only_core::generate_signs;

    #[test]
    fn test_compile_and_execute() {
        let signs: Vec<Sign> = generate_signs(4).collect();
        let mut field = [104.69, 101.0, 99.0, 95.31];

        let source = "harmony(0.1) report()";
        let program = compile(source).unwrap();
        let result = execute(&program, &signs, &mut field);

        assert!(result.pass);
        assert!(result.residual.abs() < 0.1);
    }

    #[test]
    fn test_corrupt_heal_pipeline() {
        let signs: Vec<Sign> = generate_signs(4).collect();
        let mut field = [104.69, 101.0, 99.0, 95.31];

        let source = "corrupt(2) if_broken { evolve(2) } harmony(0.001) report()";
        let program = compile(source).unwrap();
        let result = execute(&program, &signs, &mut field);

        assert!(result.pass);
        assert_eq!(result.healed_index, Some(2));
        assert!(result.residual.abs() < 0.001);
    }

    #[test]
    fn test_serialize_deserialize() {
        let source = "harmony(0.01) corrupt(1) if_broken { evolve(1) } report()";
        let program = compile(source).unwrap();
        let serialized = program.serialize();
        let deserialized = IrProgram::deserialize(&serialized).unwrap();

        assert_eq!(program.bytecode, deserialized.bytecode);
        assert_eq!(program.string_table, deserialized.string_table);
    }

    #[test]
    fn test_disassemble() {
        let source = "harmony(0.1) corrupt(2) if_broken { evolve(2) } report()";
        let program = compile(source).unwrap();
        let disasm = disassemble(&program);
        assert!(disasm.contains("HARMONY"));
        assert!(disasm.contains("CORRUPT"));
        assert!(disasm.contains("IF_BROKEN"));
        assert!(disasm.contains("EVOLVE"));
        assert!(disasm.contains("HALT"));
    }

    #[test]
    fn test_sub_microsecond_execution() {
        let signs: Vec<Sign> = generate_signs(4).collect();
        let source = "harmony(0.001) corrupt(2) if_broken { evolve(2) } residual() report()";
        let program = compile(source).unwrap();

        // Warm up
        for _ in 0..1000 {
            let mut field = [104.69, 101.0, 99.0, 95.31];
            let _ = execute(&program, &signs, &mut field);
        }

        // Measure
        let iterations = 100_000u64;
        let start = std::time::Instant::now();
        for _ in 0..iterations {
            let mut field = [104.69, 101.0, 99.0, 95.31];
            let result = execute(&program, &signs, &mut field);
            std::hint::black_box(result);
        }
        let elapsed = start.elapsed();
        let per_call_ns = elapsed.as_nanos() as u64 / iterations;

        println!("IR execution: {} ns/call ({} cycles)", per_call_ns, 6);
        assert!(per_call_ns < 1000, "IR execution should be sub-microsecond, got {}ns", per_call_ns);
    }

    #[test]
    fn test_budget_and_limits() {
        let signs: Vec<Sign> = generate_signs(4).collect();
        let mut field = [104.69, 101.0, 99.0, 95.31];

        let source = "budget_limit(1000.0) time_window(3600) volatility_limit(0.05) max_exposure(500.0) harmony(0.1)";
        let program = compile(source).unwrap();
        let result = execute(&program, &signs, &mut field);

        assert_eq!(result.budget_limit, Some(1000.0));
        assert_eq!(result.time_window, Some(3600));
        assert_eq!(result.volatility_limit, Some(0.05));
        assert_eq!(result.max_exposure, Some(500.0));
        assert!(result.pass);
    }
}
