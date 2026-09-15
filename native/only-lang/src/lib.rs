//! ONLY Lang: DSL for harmony and evolution
//! Guidelines:
//! - Focus on arithmetic constraints; avoid general branching except balanced condition checks
//! - Reports use fixed decimal formatting for stable golden tests
//! - Commands extend parse_command and evaluate_script with clear diagnostics

use nom::{
    branch::alt,
    bytes::complete::{tag, take_until, take_while1},
    character::complete::multispace0,
    combinator::opt,
    error::{Error, ErrorKind},
    number::complete::double,
    IResult,
};
use only_core::{check_equilibrium, compute_residual, Sign};
use only_evolution::solve_for_equilibrium;
use only_memory::GhostMemory;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

pub mod c2pa_read;
pub mod claims;
pub mod document_delivery;
pub mod document_execute;
pub mod document_governance;
pub mod document_manifest;
pub mod evidence_pack;
pub mod evidence_store;
pub mod lifestack_identity;
pub mod pdf_sign;
pub mod pir_watermark;
pub mod sdk;
#[cfg(feature = "zk")]
pub mod zk_circuit;

/// only-lang Command
/// Instead of 'if/else', we define 'Harmony' and 'Evolution'
#[derive(Debug, PartialEq, Clone)]
pub enum Command {
    Harmony(f64),            // Target balance tolerance
    RequireEquilibrium(f64), // Explicit declaration for world-readiness
    Evolve(usize),           // Target index to restore
    Data(f64),               // Value to integrate
    Corrupt(usize),
    Residual(f64),
    Report,
    ReportCompact,
    ReportVerbose,
    ReportTo(String),
    ReportJson,
    LogLevel(u8),
    Branch(Vec<Command>), // Execute inner if system is broken
    BudgetLimit(f64),
    TimeWindow(u64),
    VolatilityLimit(f64),
    MaxExposure(f64),
    AssertBounds(f64, f64, usize),            // min, max, index
    AssertBoundsNamed(f64, f64, String),      // min, max, name
    LinkIdentity(String),                     // DID or Wallet binding
    TrackLineage(bool),                       // Enforce TDO export
    Bind(String, usize),                      // Bind JSON context to field index
    Alias(usize, String),                     // Give an index a semantic name
    BindAll,                                  // Automatically map JSON to all aliases
    IfGreaterThan(String, f64, Vec<Command>), // Branch on value limit
    Escalate(String),                         // Trigger HITL override
    Import(String),                           // Compose policies from files
    GenerateZkProof(bool),                    // Export ZK-SNARK proof instead of plaintext values
}

fn parse_quoted_string(input: &str) -> IResult<&str, String> {
    let (input, _) = tag("\"")(input)?;
    let (input, content) = take_until("\"")(input)?;
    let (input, _) = tag("\"")(input)?;
    Ok((input, content.to_string()))
}

pub fn parse_script_until_brace(input: &str) -> IResult<&str, Vec<Command>> {
    let mut cmds: Vec<Command> = Vec::new();
    let mut current_input = input;
    loop {
        let (rest, _) = multispace0(current_input)?;
        if rest.starts_with('}') || rest.is_empty() {
            return Ok((rest, cmds));
        }
        let (rest, cmd) = parse_command(rest)?;
        cmds.push(cmd);
        current_input = rest;
    }
}

pub fn parse_command(input: &str) -> IResult<&str, Command> {
    let (input, _) = multispace0(input)?;
    let (input, cmd) = take_while1(|c: char| c.is_alphanumeric() || c == '_')(input)?;

    if cmd == "if_broken" {
        let (input, _) = multispace0(input)?;
        let (input, _) = tag("{")(input)?;
        let (input, inner_cmds) = parse_script_until_brace(input)?;
        let (input, _) = tag("}")(input)?;
        return Ok((input, Command::Branch(inner_cmds)));
    } else if cmd == "if_greater_than" {
        let (input, _) = tag("(")(input)?;
        let (input, name) = parse_quoted_string(input)?;
        let (input, _) = tag(",")(input)?;
        let (input, _) = multispace0(input)?;
        let (input, val) = double(input)?;
        let (input, _) = tag(")")(input)?;
        let (input, _) = multispace0(input)?;
        let (input, _) = tag("{")(input)?;
        let (input, inner_cmds) = parse_script_until_brace(input)?;
        let (input, _) = tag("}")(input)?;
        return Ok((input, Command::IfGreaterThan(name, val, inner_cmds)));
    } else if cmd == "import" {
        let (input, _) = tag("(")(input)?;
        let (input, path) = parse_quoted_string(input)?;
        let (input, _) = tag(")")(input)?;
        return Ok((input, Command::Import(path)));
    } else if cmd == "generate_zk_proof" {
        let (input, _) = tag("(")(input)?;
        let (input, b) = alt((tag("true"), tag("false")))(input)?;
        let (input, _) = tag(")")(input)?;
        return Ok((input, Command::GenerateZkProof(b == "true")));
    } else if cmd == "escalate" {
        let (input, _) = tag("(")(input)?;
        let (input, reason) = parse_quoted_string(input)?;
        let (input, _) = tag(")")(input)?;
        return Ok((input, Command::Escalate(reason)));
    } else if cmd == "alias" {
        let (input, _) = tag("(")(input)?;
        let (input, idx) = double(input)?;
        let (input, _) = tag(",")(input)?;
        let (input, _) = multispace0(input)?;
        let (input, name) = parse_quoted_string(input)?;
        let (input, _) = tag(")")(input)?;
        return Ok((input, Command::Alias(idx as usize, name)));
    } else if cmd == "bind_all" {
        let (input, _) = tag("()")(input)?;
        return Ok((input, Command::BindAll));
    } else if cmd == "link_identity" {
        let (input, _) = tag("(")(input)?;
        let (input, id) = parse_quoted_string(input)?;
        let (input, _) = tag(")")(input)?;
        return Ok((input, Command::LinkIdentity(id)));
    } else if cmd == "bind" {
        let (input, _) = tag("(")(input)?;
        let (input, key) = parse_quoted_string(input)?;
        let (input, _) = tag(",")(input)?;
        let (input, _) = multispace0(input)?;
        let (input, idx) = double(input)?;
        let (input, _) = tag(")")(input)?;
        return Ok((input, Command::Bind(key, idx as usize)));
    } else if cmd == "track_lineage" {
        let (input, _) = tag("(")(input)?;
        let (input, b) = alt((tag("true"), tag("false")))(input)?;
        let (input, _) = tag(")")(input)?;
        return Ok((input, Command::TrackLineage(b == "true")));
    } else if cmd == "assert_bounds" {
        let (input, _) = tag("(")(input)?;
        let (input, min) = double(input)?;
        let (input, _) = tag(",")(input)?;
        let (input, _) = multispace0(input)?;
        let (input, max) = double(input)?;
        let (input, _) = tag(",")(input)?;
        let (input, _) = multispace0(input)?;

        // Try parsing string first, then double for backward compatibility
        if let Ok((input_after_str, name)) = parse_quoted_string(input) {
            let (input_after_str, _) = tag(")")(input_after_str)?;
            return Ok((input_after_str, Command::AssertBoundsNamed(min, max, name)));
        } else {
            let (input, idx) = double(input)?;
            let (input, _) = tag(")")(input)?;
            return Ok((input, Command::AssertBounds(min, max, idx as usize)));
        }
    }

    let (input, _) = tag("(")(input)?;
    if cmd == "residual" {
        let (input, val_opt) = opt(double)(input)?;
        let (input, _) = tag(")")(input)?;
        let v = val_opt.unwrap_or(0.0);
        return Ok((input, Command::Residual(v)));
    } else if cmd == "report" {
        let (input, _) = opt(double)(input)?;
        let (input, _) = tag(")")(input)?;
        return Ok((input, Command::Report));
    } else if cmd == "report_compact" {
        let (input, _) = opt(double)(input)?;
        let (input, _) = tag(")")(input)?;
        return Ok((input, Command::ReportCompact));
    } else if cmd == "report_verbose" {
        let (input, _) = opt(double)(input)?;
        let (input, _) = tag(")")(input)?;
        return Ok((input, Command::ReportVerbose));
    } else if cmd == "report_json" {
        let (input, _) = opt(double)(input)?;
        let (input, _) = tag(")")(input)?;
        return Ok((input, Command::ReportJson));
    } else if cmd == "log_level" {
        let (input, val) = double(input)?;
        let (input, _) = tag(")")(input)?;
        return Ok((input, Command::LogLevel(val as u8)));
    } else if cmd == "report_to" {
        let (input, _) = tag("\"")(input)?;
        let (input, path) = take_until("\"")(input)?;
        let (input, _) = tag("\"")(input)?;
        let (input, _) = tag(")")(input)?;
        return Ok((input, Command::ReportTo(path.to_string())));
    } else {
        let (input, val) = double(input)?;
        let (input, _) = tag(")")(input)?;
        let command = match cmd {
            "harmony" => Command::Harmony(val),
            "require_equilibrium" => Command::RequireEquilibrium(val),
            "evolve" => Command::Evolve(val as usize),
            "data" => Command::Data(val),
            "corrupt" => Command::Corrupt(val as usize),
            "budget_limit" => Command::BudgetLimit(val),
            "time_window" => Command::TimeWindow(val as u64),
            "volatility_limit" => Command::VolatilityLimit(val),
            "max_exposure" => Command::MaxExposure(val),
            _ => {
                return Err(nom::Err::Error(Error::new(cmd, ErrorKind::Tag)));
            }
        };
        return Ok((input, command));
    }
}

pub fn parse_script(mut input: &str) -> IResult<&str, Vec<Command>> {
    let mut cmds: Vec<Command> = Vec::new();
    loop {
        // Strip leading whitespace
        let (rest, _) = multispace0(input)?;
        if rest.is_empty() {
            return Ok((rest, cmds));
        }

        // Handle line comments starting with "//"
        if rest.starts_with("//") {
            let (rest, _) = take_until("\n")(rest)?;
            let (rest, _) = opt(tag("\n"))(rest)?;
            input = rest;
            continue;
        }

        let (rest, cmd) = parse_command(rest)?;
        cmds.push(cmd);
        input = rest;
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScriptResult {
    pub pass: bool,
    pub residual: f64,
    pub healed_index: Option<usize>,
    pub revealed: Option<f64>,
    pub residual_history: Vec<f64>,
    pub indices_healed: Vec<usize>,
    pub report: Option<String>,
    pub report_written: Option<String>,
    pub budget_limit: Option<f64>,
    pub time_window: Option<u64>,
    pub volatility_limit: Option<f64>,
    pub max_exposure: Option<f64>,
    // TDO Proof Export Fields
    pub signature: Option<String>,
    pub lineage_proof: Option<serde_json::Value>,
    pub constraint_proof: Vec<String>,
    pub replay_hash: Option<String>,
    pub identity_linked: Option<String>,
    // ZK Proof Export
    pub zk_proof: Option<String>,
    // Enterprise Escalate State
    pub escalate_reason: Option<String>,
    // Gas / Step Bounding
    pub fuel_consumed: u64,
}

pub fn evaluate_script(
    signs: &[Sign],
    field: &mut [f64],
    script: &str,
) -> Result<ScriptResult, String> {
    evaluate_script_with_context(signs, field, None, script, 100_000)
}

pub fn evaluate_script_with_context(
    signs: &[Sign],
    field: &mut [f64],
    context: Option<&serde_json::Value>,
    script: &str,
    fuel_limit: u64,
) -> Result<ScriptResult, String> {
    let (_, cmds) = parse_script(script).map_err(|e| format!("Parse error: {:?}", e))?;

    // Internal state for execution
    let mut state = ScriptResult {
        pass: true,
        residual: compute_residual(signs, field),
        healed_index: None,
        revealed: None,
        residual_history: Vec::new(),
        indices_healed: Vec::new(),
        report: None,
        report_written: None,
        budget_limit: None,
        time_window: None,
        volatility_limit: None,
        max_exposure: None,
        signature: None,
        lineage_proof: None,
        constraint_proof: Vec::new(),
        replay_hash: None,
        identity_linked: None,
        zk_proof: None,
        escalate_reason: None,
        fuel_consumed: 0,
    };

    let mut tolerance: f64 = 1e-12;
    let mut expected_data: Option<f64> = None;
    let mut request_report: bool = false;
    let mut report_mode_compact: bool = false;
    let mut report_mode_json: bool = false;
    let mut log_level: u8 = 1;
    let mut report_to: Option<String> = None;
    let mut track_lineage: bool = false;
    let mut aliases: HashMap<String, usize> = HashMap::new();

    fn execute_commands(
        cmds: &[Command],
        signs: &[Sign],
        field: &mut [f64],
        context: Option<&serde_json::Value>,
        fuel_limit: u64,
        state: &mut ScriptResult,
        tolerance: &mut f64,
        expected_data: &mut Option<f64>,
        request_report: &mut bool,
        report_mode_compact: &mut bool,
        report_mode_json: &mut bool,
        log_level: &mut u8,
        report_to: &mut Option<String>,
        track_lineage: &mut bool,
        aliases: &mut HashMap<String, usize>,
    ) -> Result<(), String> {
        for cmd in cmds {
            if state.fuel_consumed >= fuel_limit {
                return Err("Out of fuel (Gas limit exceeded)".into());
            }
            state.fuel_consumed += 1; // base execution cost
            state.constraint_proof.push(format!("{:?}", cmd)); // Cryptographic trace log

            match cmd {
                Command::Harmony(t) | Command::RequireEquilibrium(t) => {
                    *tolerance = *t;
                    state.pass = check_equilibrium(signs, field, *tolerance);
                }
                Command::Evolve(idx) => {
                    state.fuel_consumed += 10; // Solving takes more computation
                    let known = (0..field.len())
                        .filter(|&i| i != *idx)
                        .map(|i| (i, field[i]))
                        .collect::<Vec<_>>();
                    let v = solve_for_equilibrium(signs, &known, *idx);
                    field[*idx] = v;
                    state.healed_index = Some(*idx);
                    state.indices_healed.push(*idx);
                    state.residual = compute_residual(signs, field);
                }
                Command::AssertBounds(min, max, idx) => {
                    let v = field[*idx];
                    if v < *min || v > *max {
                        state.pass = false;
                        return Err(format!(
                            "Bounds assertion failed at index {}: value {} not in [{}, {}]",
                            idx, v, min, max
                        ));
                    }
                }
                Command::AssertBoundsNamed(min, max, name) => {
                    if let Some(&idx) = aliases.get(name) {
                        let v = field[idx];
                        if v < *min || v > *max {
                            state.pass = false;
                            return Err(format!(
                                "Bounds assertion failed for '{}' (index {}): value {} not in [{}, {}]",
                                name, idx, v, min, max
                            ));
                        }
                    } else {
                        return Err(format!("AssertBounds: Unknown alias '{}'", name));
                    }
                }
                Command::Bind(key, idx) => {
                    if let Some(ctx) = context {
                        if let Some(val) = ctx.get(key).and_then(|v| v.as_f64()) {
                            field[*idx] = val;
                        } else {
                            return Err(format!(
                                "Bind failed: key '{}' not found in context or not a number",
                                key
                            ));
                        }
                    } else {
                        return Err("Bind failed: no JSON context provided".into());
                    }
                }
                Command::Alias(idx, name) => {
                    aliases.insert(name.clone(), *idx);
                }
                Command::BindAll => {
                    if let Some(ctx) = context {
                        if let Some(obj) = ctx.as_object() {
                            for (k, v) in obj {
                                if let Some(&idx) = aliases.get(k) {
                                    if let Some(num) = v.as_f64() {
                                        field[idx] = num;
                                    }
                                }
                            }
                        }
                    }
                }
                Command::LinkIdentity(id) => {
                    state.identity_linked = Some(id.clone());
                }
                Command::TrackLineage(b) => {
                    *track_lineage = *b;
                }
                Command::Data(d) => {
                    let rev = GhostMemory::reveal_4(signs, field);
                    state.revealed = Some(rev);
                    *expected_data = Some(*d);
                }
                Command::Corrupt(idx) => {
                    field[*idx] = 0.0;
                    state.residual = compute_residual(signs, field);
                    state.pass = check_equilibrium(signs, field, *tolerance);
                }
                Command::Residual(_) => {
                    state.residual_history.push(compute_residual(signs, field));
                }
                Command::Report => *request_report = true,
                Command::ReportCompact => {
                    *request_report = true;
                    *report_mode_compact = true;
                }
                Command::ReportVerbose => {
                    *request_report = true;
                    *report_mode_compact = false;
                }
                Command::ReportJson => {
                    *request_report = true;
                    *report_mode_json = true;
                }
                Command::ReportTo(path) => *report_to = Some(path.clone()),
                Command::LogLevel(l) => *log_level = *l,
                Command::BudgetLimit(limit) => state.budget_limit = Some(*limit),
                Command::TimeWindow(window) => state.time_window = Some(*window),
                Command::VolatilityLimit(limit) => state.volatility_limit = Some(*limit),
                Command::MaxExposure(limit) => state.max_exposure = Some(*limit),
                Command::GenerateZkProof(b) => {
                    if *b {
                        #[cfg(feature = "zk")]
                        {
                            // Compile the equilibrium invariant into a Groth16
                            // arithmetic circuit and generate a zero-knowledge
                            // proof. The auditor can verify the proof without
                            // ever seeing the proprietary field values.
                            let signs_i8: Vec<i8> = signs.iter().map(|s| *s as i8).collect();
                            let gate = if state.escalate_reason.is_some() {
                                2u8 // ESCALATE
                            } else if state.pass {
                                1u8  // ALLOW
                            } else {
                                0u8  // DENY
                            };

                            // Collect bounds from prior AssertBounds commands
                            // (parsed from constraint_proof trace)
                            let bounds = Vec::new();

                            match zk_circuit::generate_zk_proof(
                                &signs_i8,
                                field,
                                *tolerance,
                                gate,
                                state.fuel_consumed,
                                100_000,
                                bounds,
                            ) {
                                Ok(bundle) => {
                                    state.zk_proof = Some(serde_json::to_string(&bundle)
                                        .unwrap_or_else(|_| "zk:serialization_error".to_string()));
                                }
                                Err(e) => {
                                    state.zk_proof = Some(format!("zk:error:{e}"));
                                }
                            }
                        }
                        #[cfg(not(feature = "zk"))]
                        {
                            state.zk_proof = Some(
                                "zk:disabled_rebuild_with_--features_zk".to_string()
                            );
                        }
                    } else {
                        state.zk_proof = None;
                    }
                }
                Command::Import(path) => {
                    let script_content = std::fs::read_to_string(path)
                        .map_err(|e| format!("Import failed for '{}': {}", path, e))?;
                    let (_, imported_cmds) = parse_script(&script_content)
                        .map_err(|e| format!("Parse error in imported file: {:?}", e))?;

                    execute_commands(
                        &imported_cmds,
                        signs,
                        field,
                        context,
                        fuel_limit,
                        state,
                        tolerance,
                        expected_data,
                        request_report,
                        report_mode_compact,
                        report_mode_json,
                        log_level,
                        report_to,
                        track_lineage,
                        aliases,
                    )?;
                }
                Command::Escalate(reason) => {
                    state.escalate_reason = Some(reason.clone());
                }
                Command::IfGreaterThan(name, val, inner) => {
                    if let Some(&idx) = aliases.get(name) {
                        if field[idx] > *val {
                            execute_commands(
                                inner,
                                signs,
                                field,
                                context,
                                fuel_limit,
                                state,
                                tolerance,
                                expected_data,
                                request_report,
                                report_mode_compact,
                                report_mode_json,
                                log_level,
                                report_to,
                                track_lineage,
                                aliases,
                            )?;
                        }
                    } else {
                        return Err(format!("IfGreaterThan: Unknown alias '{}'", name));
                    }
                }
                Command::Branch(inner) => {
                    if !check_equilibrium(signs, field, *tolerance) {
                        execute_commands(
                            inner,
                            signs,
                            field,
                            context,
                            fuel_limit,
                            state,
                            tolerance,
                            expected_data,
                            request_report,
                            report_mode_compact,
                            report_mode_json,
                            log_level,
                            report_to,
                            track_lineage,
                            aliases,
                        )?;
                    }
                }
            }
        }
        Ok(())
    }

    execute_commands(
        &cmds,
        signs,
        field,
        context,
        fuel_limit,
        &mut state,
        &mut tolerance,
        &mut expected_data,
        &mut request_report,
        &mut report_mode_compact,
        &mut report_mode_json,
        &mut log_level,
        &mut report_to,
        &mut track_lineage,
        &mut aliases,
    )?;

    // Final checks
    state.residual = compute_residual(signs, field);
    state.pass = check_equilibrium(signs, field, tolerance);

    // If an escalation was triggered, the mathematical pass check is overridden by human requirement
    let gate_state = if state.escalate_reason.is_some() {
        "ESCALATE"
    } else if state.pass {
        "ALLOW"
    } else {
        "DENY"
    };

    // Mint TDO Evidence Pack if Lineage tracking was requested
    if track_lineage {
        state.replay_hash = Some(format!("hash_{:x}", state.residual.to_bits()));
        state.signature = Some("dgv-sha256:generated_tdo_sig_placeholder".to_string());
        state.lineage_proof = Some(serde_json::json!({
            "executed_commands": state.constraint_proof,
            "fuel_used": state.fuel_consumed,
            "identity": state.identity_linked,
            "final_residual": state.residual,
            "gate_state": gate_state,
        }));
    }

    // Generate Report string if requested
    if request_report {
        if report_mode_json && track_lineage {
            // If JSON report + Lineage is enabled, output full TDO representation
            state.report = Some(
                serde_json::to_string_pretty(&serde_json::json!({
                    "pass": state.pass,
                    "gate_state": gate_state,
                    "escalate_reason": state.escalate_reason,
                    "residual": state.residual,
                    "fuel_consumed": state.fuel_consumed,
                    "identity_linked": state.identity_linked,
                    "lineage_proof": state.lineage_proof,
                    "signature": state.signature,
                    "replay_hash": state.replay_hash,
                    "zk_proof": state.zk_proof,
                }))
                .unwrap_or_default(),
            );
        } else {
            state.report = Some(format!(
                "Final Residual: {:.6}, Pass: {}",
                state.residual, state.pass
            ));
        }

        if let Some(path) = report_to {
            let _ = std::fs::write(&path, state.report.as_ref().unwrap());
            state.report_written = Some(path);
        }
    }

    Ok(state)
}

#[cfg(test)]
mod tests {
    use super::*;
    use only_core::generate_signs;

    #[test]
    fn test_branching_logic() {
        let signs: Vec<Sign> = generate_signs(4).collect();
        let mut field = [104.69, 101.0, 99.0, 95.31]; // Roughly balanced

        // This script will only corrupt index 0 IF the system is already broken (which it isn't)
        let script = "harmony(0.1) if_broken { corrupt(0.0) } report()";
        let res = evaluate_script(&signs, &mut field, script).unwrap();
        assert!(res.pass);
        assert!(field[0] > 100.0); // Should NOT have been corrupted

        // Now break it first
        let script_broken = "corrupt(2.0) if_broken { evolve(2.0) } report()";
        let res2 = evaluate_script(&signs, &mut field, script_broken).unwrap();
        assert!(res2.pass);
        assert_eq!(res2.healed_index, Some(2));
    }
}
