use js_sys::{Array, Float64Array, Object, Reflect};
use only_core::generate_signs;
use only_lang::{parse_script, Command};
use wasm_bindgen::prelude::*;

fn validate_commands(cmds: &[Command], n: usize) -> Result<(), String> {
    for c in cmds {
        match c {
            Command::Harmony(_) => {}
            Command::RequireEquilibrium(_) => {}
            Command::Residual(_) => {}
            Command::Report => {}
            Command::Evolve(i) => {
                if *i >= n {
                    return Err(format!("evolve index out of range: {i}"));
                }
            }
            Command::Corrupt(i) => {
                if *i >= n {
                    return Err(format!("corrupt index out of range: {i}"));
                }
            }
            Command::Branch(inner) => validate_commands(inner, n)?,
            Command::IfGreaterThan(_, _, inner) => validate_commands(inner, n)?,
            Command::ReportTo(_) => return Err("report_to is not allowed in wasm".to_string()),
            Command::ReportCompact => {
                return Err("report_compact is not allowed in wasm".to_string())
            }
            Command::ReportVerbose => {
                return Err("report_verbose is not allowed in wasm".to_string())
            }
            Command::ReportJson => return Err("report_json is not allowed in wasm".to_string()),
            Command::LogLevel(_) => return Err("log_level is not allowed in wasm".to_string()),
            Command::Data(_) => return Err("data is not allowed in wasm".to_string()),
            Command::BudgetLimit(_) => {}
            Command::TimeWindow(_) => {}
            Command::VolatilityLimit(_) => {}
            Command::MaxExposure(_) => {}
            Command::AssertBounds(_, _, idx) => {
                if *idx >= n {
                    return Err(format!("assert_bounds index out of range: {idx}"));
                }
            }
            Command::AssertBoundsNamed(_, _, _) => {}
            Command::LinkIdentity(_) => {}
            Command::TrackLineage(_) => {}
            Command::Bind(_, idx) => {
                if *idx >= n {
                    return Err(format!("bind index out of range: {idx}"));
                }
            }
            Command::Alias(idx, _) => {
                if *idx >= n {
                    return Err(format!("alias index out of range: {idx}"));
                }
            }
            Command::BindAll => {}
            Command::Escalate(_) => {}
            Command::Import(_) => return Err("import is not allowed in wasm".to_string()),
            Command::GenerateZkProof(_) => {}
            // L8/L9 governance commands — pure evaluation, safe in wasm
            Command::BindContext(_, _) => {}
            Command::CheckContextDrift => {}
            Command::BindAuthority(_, _, _) => {}
            Command::RevokeAuthority(_, _) => {}
            Command::CheckAuthority(_) => {}
            Command::CheckRevocation => {}
            Command::LinkLineage(_) => {}
            Command::RequireContinuousLineage => {}
            Command::BindObjective(_, _) => {}
            Command::CheckObjectiveDrift(_) => {}
        }
    }
    Ok(())
}

#[wasm_bindgen]
pub fn evaluate_script_wasm(script: String, field: Vec<f64>) -> Result<JsValue, JsValue> {
    let n = field.len();

    let (_, cmds) =
        parse_script(&script).map_err(|e| JsValue::from_str(&format!("parse error: {e:?}")))?;

    validate_commands(&cmds, n).map_err(|e| JsValue::from_str(&e))?;

    let signs: Vec<only_core::Sign> = generate_signs(n).collect();
    let mut f = field;

    let res =
        only_lang::evaluate_script(&signs, &mut f, &script).map_err(|e| JsValue::from_str(&e))?;

    let obj = Object::new();

    Reflect::set(
        &obj,
        &JsValue::from_str("pass"),
        &JsValue::from_bool(res.pass),
    )?;
    Reflect::set(
        &obj,
        &JsValue::from_str("residual"),
        &JsValue::from_f64(res.residual),
    )?;

    let healed = Array::new();
    for i in res.indices_healed.iter() {
        healed.push(&JsValue::from_f64(*i as f64));
    }
    Reflect::set(&obj, &JsValue::from_str("indices_healed"), &healed)?;

    let hist = Array::new();
    for v in res.residual_history.iter() {
        hist.push(&JsValue::from_f64(*v));
    }
    Reflect::set(&obj, &JsValue::from_str("residual_history"), &hist)?;

    if let Some(report) = res.report {
        Reflect::set(
            &obj,
            &JsValue::from_str("report"),
            &JsValue::from_str(&report),
        )?;
    }

    let out_field = Float64Array::from(f.as_slice());
    Reflect::set(&obj, &JsValue::from_str("field"), &out_field)?;

    Ok(obj.into())
}
