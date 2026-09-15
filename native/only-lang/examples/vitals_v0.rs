use only_core::Sign::Plus;
use only_core::{compute_residual, Sign};
use only_lang::evaluate_script;
use only_lang::evidence_pack::{now_unix_ms, run_id_unix_ms, write_evidence_pack, EvidencePack};
use serde_json::json;
use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
use std::path::PathBuf;

fn escape_html(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    for ch in input.chars() {
        match ch {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            _ => out.push(ch),
        }
    }
    out
}

fn sign_to_i8(s: Sign) -> i8 {
    match s {
        Sign::Plus => 1,
        Sign::Minus => -1,
    }
}

fn hash_u64_hex(parts: &[String]) -> String {
    let mut h = DefaultHasher::new();
    for p in parts {
        p.hash(&mut h);
    }
    format!("{:016x}", h.finish())
}

fn svg_report(title: &str, residuals: &[f64]) -> String {
    let width: f64 = 920.0;
    let height: f64 = 300.0;

    let margin_l: f64 = 70.0;
    let margin_r: f64 = 25.0;
    let margin_t: f64 = 40.0;
    let margin_b: f64 = 55.0;

    let plot_w = width - margin_l - margin_r;
    let plot_h = height - margin_t - margin_b;

    let mut min_y = 0.0;
    let mut max_y = 0.0;
    if !residuals.is_empty() {
        min_y = residuals[0];
        max_y = residuals[0];
        for &v in residuals.iter() {
            if v < min_y {
                min_y = v;
            }
            if v > max_y {
                max_y = v;
            }
        }
    }

    if (max_y - min_y).abs() < 1e-12 {
        max_y = min_y + 1.0;
    }

    let n = residuals.len().max(1);
    let x_step = if n > 1 {
        plot_w / ((n - 1) as f64)
    } else {
        0.0
    };

    let mut points = String::new();
    for (i, &v) in residuals.iter().enumerate() {
        let x = margin_l + (i as f64) * x_step;
        let y = margin_t + (max_y - v) / (max_y - min_y) * plot_h;
        if !points.is_empty() {
            points.push(' ');
        }
        points.push_str(&format!("{:.2},{:.2}", x, y));
    }

    let x0 = margin_l;
    let y0 = margin_t + plot_h;
    let x1 = margin_l + plot_w;
    let y1 = margin_t;

    let title = escape_html(title);

    format!(
        r##"<svg xmlns="http://www.w3.org/2000/svg" width="{w}" height="{h}" viewBox="0 0 {w} {h}">
  <rect x="0" y="0" width="{w}" height="{h}" fill="#0b1020" />
  <text x="18" y="24" fill="#e6e8ef" font-family="ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, 'Liberation Mono', 'Courier New', monospace" font-size="16">{title}</text>

  <rect x="{pl}" y="{pt}" width="{pw}" height="{ph}" fill="#0f1730" stroke="#2b365a" stroke-width="1" />
  <line x1="{x0}" y1="{y0}" x2="{x1}" y2="{y0}" stroke="#2b365a" stroke-width="1" />
  <line x1="{x0}" y1="{y0}" x2="{x0}" y2="{y1}" stroke="#2b365a" stroke-width="1" />

  <text x="{x0}" y="{y_label}" fill="#aab2d5" font-family="ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, 'Liberation Mono', 'Courier New', monospace" font-size="12">Residual over time</text>
  <text x="{x0}" y="{min_y_text}" fill="#93a4d6" font-family="ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, 'Liberation Mono', 'Courier New', monospace" font-size="11">min={min_y:.6}</text>
  <text x="{x0}" y="{max_y_text}" fill="#93a4d6" font-family="ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, 'Liberation Mono', 'Courier New', monospace" font-size="11">max={max_y:.6}</text>

  <polyline fill="none" stroke="#61dafb" stroke-width="2" points="{points}" />
</svg>"##,
        w = width,
        h = height,
        pl = margin_l,
        pt = margin_t,
        pw = plot_w,
        ph = plot_h,
        x0 = x0,
        y0 = y0,
        x1 = x1,
        y1 = y1,
        y_label = margin_t + plot_h + 30.0,
        min_y_text = margin_t + plot_h + 46.0,
        max_y_text = margin_t + plot_h + 62.0,
        min_y = min_y,
        max_y = max_y,
        points = points,
        title = title,
    )
}

fn html_report(
    title: &str,
    script: &str,
    signs: &[Sign],
    field_before: &[f64],
    field_after: &[f64],
    residuals: &[f64],
    indices_healed: &[usize],
    extra_summary: &str,
    svg_inline: &str,
    svg_filename: &str,
) -> String {
    let title_esc = escape_html(title);
    let script_esc = escape_html(script.trim());
    let extra_esc = escape_html(extra_summary);

    let healed = if indices_healed.is_empty() {
        "(none)".to_string()
    } else {
        indices_healed
            .iter()
            .map(|i| i.to_string())
            .collect::<Vec<_>>()
            .join(", ")
    };

    let residual_list = if residuals.is_empty() {
        "(none)".to_string()
    } else {
        residuals
            .iter()
            .map(|v| format!("{:.6}", v))
            .collect::<Vec<_>>()
            .join(", ")
    };

    let mut table_rows = String::new();
    for i in 0..signs.len().min(field_before.len()).min(field_after.len()) {
        table_rows.push_str(&format!(
            "<tr><td>{}</td><td>{}</td><td>{:.6}</td><td>{:.6}</td></tr>",
            i,
            sign_to_i8(signs[i]),
            field_before[i],
            field_after[i]
        ));
    }

    format!(
        r##"<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>{title}</title>
  <style>
    :root {{ color-scheme: dark; }}
    body {{ margin: 0; padding: 24px; background: #0b1020; color: #e6e8ef; font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, 'Liberation Mono', 'Courier New', monospace; }}
    a {{ color: #61dafb; }}
    .card {{ max-width: 980px; margin: 0 auto; }}
    h1 {{ font-size: 18px; margin: 0 0 10px 0; }}
    .meta {{ color: #aab2d5; margin: 0 0 18px 0; }}
    .block {{ background: #0f1730; border: 1px solid #2b365a; border-radius: 10px; padding: 14px; margin: 12px 0; }}
    pre {{ white-space: pre-wrap; word-break: break-word; margin: 0; color: #e6e8ef; }}
    table {{ width: 100%; border-collapse: collapse; }}
    th, td {{ border-bottom: 1px solid #2b365a; padding: 8px; text-align: left; }}
    th {{ color: #aab2d5; font-weight: 600; }}
  </style>
</head>
<body>
  <div class="card">
    <h1>{title}</h1>
    <div class="meta">healed_indices=[{healed}]</div>

    <div class="block">
      <div style="margin-bottom: 8px; color: #aab2d5;">Summary</div>
      <pre>{extra}</pre>
    </div>

    <div class="block">
      {svg}
      <div style="margin-top:10px;"><a href="{svg_filename}">Open SVG file</a></div>
    </div>

    <div class="block">
      <div style="margin-bottom: 8px; color: #aab2d5;">Residual history</div>
      <pre>{residual_list}</pre>
    </div>

    <div class="block">
      <div style="margin-bottom: 8px; color: #aab2d5;">Field (before vs after)</div>
      <table>
        <thead>
          <tr><th>index</th><th>sign</th><th>before</th><th>after</th></tr>
        </thead>
        <tbody>
          {rows}
        </tbody>
      </table>
    </div>

    <div class="block">
      <div style="margin-bottom: 8px; color: #aab2d5;">Script</div>
      <pre>{script}</pre>
    </div>
  </div>
</body>
</html>"##,
        title = title_esc,
        healed = escape_html(&healed),
        extra = extra_esc,
        svg = svg_inline,
        svg_filename = escape_html(svg_filename),
        residual_list = escape_html(&residual_list),
        rows = table_rows,
        script = script_esc,
    )
}

fn write_report_card(
    base: &PathBuf,
    slug: &str,
    title: &str,
    script: &str,
    signs: &[Sign],
    field_before: &[f64],
    field_after: &[f64],
    residuals: &[f64],
    indices_healed: &[usize],
    extra_summary: &str,
) -> (String, String) {
    let out_dir = base.join("report_cards");
    std::fs::create_dir_all(&out_dir).unwrap();

    let svg_path = out_dir.join(format!("{slug}.svg"));
    let html_path = out_dir.join(format!("{slug}.html"));

    let svg = svg_report(title, residuals);
    std::fs::write(&svg_path, &svg).unwrap();

    let svg_filename = svg_path
        .file_name()
        .unwrap_or_default()
        .to_string_lossy()
        .to_string();

    let html = html_report(
        title,
        script,
        signs,
        field_before,
        field_after,
        residuals,
        indices_healed,
        extra_summary,
        &svg,
        &svg_filename,
    );
    std::fs::write(&html_path, html).unwrap();

    (
        svg_path.display().to_string(),
        html_path.display().to_string(),
    )
}

fn parse_f64_or_nan(i: usize) -> f64 {
    std::env::args()
        .nth(i)
        .and_then(|v| v.parse::<f64>().ok())
        .unwrap_or(f64::NAN)
}

fn parse_f64_or(i: usize, default: f64) -> f64 {
    std::env::args()
        .nth(i)
        .and_then(|v| v.parse::<f64>().ok())
        .unwrap_or(default)
}

fn solve_scaled_average_block(
    base: &PathBuf,
    slug: &str,
    label: &str,
    raw: f64,
    prev: f64,
) -> (f64, f64, String, String) {
    let signs = [Plus, Plus, Sign::Minus];
    let script = "harmony(1e-12) residual() evolve(2) residual() report()";

    let raw_scaled = raw * 0.5;
    let prev_scaled = prev * 0.5;

    let mut field = [raw_scaled, prev_scaled, 0.0];
    let field_before = field;

    let res = evaluate_script(&signs, &mut field, script).unwrap();

    let residual_before = compute_residual(&signs, &field_before);
    let residual_after = compute_residual(&signs, &field);

    let mut residual_series = res.residual_history.clone();
    if residual_series.is_empty() {
        residual_series.push(residual_before);
        residual_series.push(residual_after);
    }

    let smooth = field[2];

    let title = format!("Vitals v0: {label} smooth");
    let summary = format!("raw={raw:.3}\nprev={prev:.3}\nsmooth={smooth:.3}");

    let (svg, html) = write_report_card(
        base,
        slug,
        &title,
        script,
        &signs,
        &field_before,
        &field,
        &residual_series,
        &res.indices_healed,
        &summary,
    );

    (smooth, residual_after, svg, html)
}

fn solve_sum3_block(
    base: &PathBuf,
    slug: &str,
    title: &str,
    a: f64,
    b: f64,
    c: f64,
) -> (f64, f64, String, String) {
    let signs = [Plus, Plus, Plus, Sign::Minus];
    let script = "harmony(1e-12) residual() evolve(3) residual() report()";

    let mut field = [a, b, c, 0.0];
    let field_before = field;

    let res = evaluate_script(&signs, &mut field, script).unwrap();

    let residual_before = compute_residual(&signs, &field_before);
    let residual_after = compute_residual(&signs, &field);

    let mut residual_series = res.residual_history.clone();
    if residual_series.is_empty() {
        residual_series.push(residual_before);
        residual_series.push(residual_after);
    }

    let out = field[3];
    let summary = format!("a={a:.6}\nb={b:.6}\nc={c:.6}\nout={out:.6}");

    let (svg, html) = write_report_card(
        base,
        slug,
        title,
        script,
        &signs,
        &field_before,
        &field,
        &residual_series,
        &res.indices_healed,
        &summary,
    );

    (out, residual_after, svg, html)
}

fn main() {
    let hr = parse_f64_or_nan(1);
    let glucose = parse_f64_or_nan(2);
    let bp_sys = parse_f64_or_nan(3);
    let bp_dia = parse_f64_or_nan(4);

    let sensor_quality = parse_f64_or(5, 1.0);
    let dt_minutes = parse_f64_or(6, 5.0);

    let hr_prev = parse_f64_or(7, if hr.is_nan() { 0.0 } else { hr });
    let glu_prev = parse_f64_or(8, if glucose.is_nan() { 0.0 } else { glucose });
    let sys_prev = parse_f64_or(9, if bp_sys.is_nan() { 0.0 } else { bp_sys });
    let dia_prev = parse_f64_or(10, if bp_dia.is_nan() { 0.0 } else { bp_dia });

    let mut missing_count = 0usize;

    let hr_in = if hr.is_nan() {
        missing_count += 1;
        hr_prev
    } else {
        hr
    };

    let glu_in = if glucose.is_nan() {
        missing_count += 1;
        glu_prev
    } else {
        glucose
    };

    let sys_in = if bp_sys.is_nan() {
        missing_count += 1;
        sys_prev
    } else {
        bp_sys
    };

    let dia_in = if bp_dia.is_nan() {
        missing_count += 1;
        dia_prev
    } else {
        bp_dia
    };

    let base = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let run_ts = run_id_unix_ms();
    let evidence_run_id = format!("{run_ts}_vitals_v0");

    let (hr_smooth, hr_residual, hr_svg, hr_html) =
        solve_scaled_average_block(&base, "vitals_v0_hr", "HR", hr_in, hr_prev);
    let (glu_smooth, glu_residual, glu_svg, glu_html) =
        solve_scaled_average_block(&base, "vitals_v0_glucose", "Glucose", glu_in, glu_prev);
    let (sys_smooth, sys_residual, sys_svg, sys_html) =
        solve_scaled_average_block(&base, "vitals_v0_bp_sys", "BP_SYS", sys_in, sys_prev);
    let (dia_smooth, dia_residual, dia_svg, dia_html) =
        solve_scaled_average_block(&base, "vitals_v0_bp_dia", "BP_DIA", dia_in, dia_prev);

    let hr_n = hr_smooth / 200.0;
    let glu_n = glu_smooth / 200.0;
    let bp_n = sys_smooth / 200.0;

    let (risk_score, risk_residual, risk_svg, risk_html) = solve_sum3_block(
        &base,
        "vitals_v0_risk",
        "Vitals v0: risk_score",
        hr_n,
        glu_n,
        bp_n,
    );

    let r = risk_residual.abs();
    let r_ref = 1e-6;

    let w_r = 0.6;
    let w_m = 0.3;
    let w_q = 0.1;

    let anomaly_score = w_r * (r / r_ref).min(1.0)
        + w_m * (missing_count as f64)
        + w_q * (1.0 - sensor_quality.clamp(0.0, 1.0));

    let evidence_svg = std::fs::read_to_string(&risk_svg).unwrap();
    let evidence_html = std::fs::read_to_string(&risk_html).unwrap();
    let decision_hash = hash_u64_hex(&vec![
        format!("risk_score={:.6}", risk_score),
        format!("risk_residual={:.6}", risk_residual),
        format!("anomaly_score={:.6}", anomaly_score),
        format!("missing_count={}", missing_count),
    ]);
    let pack = EvidencePack {
        run_id: evidence_run_id.clone(),
        created_unix_ms: now_unix_ms(),
        request: json!({
            "vitals": {
                "hr": hr_in,
                "glucose": glu_in,
                "bp_sys": sys_in,
                "bp_dia": dia_in
            },
            "sensor_quality": sensor_quality,
            "dt_minutes": dt_minutes,
            "missing_count": missing_count
        }),
        policy_version: "vitals_v0".to_string(),
        decision: json!({
            "risk_score": risk_score,
            "anomaly_score": anomaly_score
        }),
        decision_hash,
        replay_inputs: json!({
            "reports": {
                "hr_html": hr_html,
                "glucose_html": glu_html,
                "bp_sys_html": sys_html,
                "bp_dia_html": dia_html,
                "risk_html": risk_html
            }
        }),
        tool_proposals: vec![],
        tool_outcomes: vec![],
        event_type: "unknown".to_string(),
        token_id: None,
        agent_id: None,
        actor: None,
    };
    let evidence_artifacts = write_evidence_pack(
        base.as_path(),
        &evidence_run_id,
        &evidence_svg,
        &evidence_html,
        &pack,
    )
    .unwrap();

    println!("evidence_html={}", evidence_artifacts.html_path.display());
    println!("evidence_json={}", evidence_artifacts.json_path.display());

    println!("inputs={{hr:{hr_in:.3}, glucose:{glu_in:.3}, bp_sys:{sys_in:.3}, bp_dia:{dia_in:.3}, dq:{sensor_quality:.3}, dt_min:{dt_minutes:.3}, missing_count:{missing_count}}}");
    println!("smooth={{hr:{hr_smooth:.3}, glucose:{glu_smooth:.3}, bp_sys:{sys_smooth:.3}, bp_dia:{dia_smooth:.3}}}");
    println!("risk_score={risk_score:.6}");
    println!("anomaly_score={anomaly_score:.6}");

    println!("kernel_residuals={{hr:{hr_residual:.6}, glucose:{glu_residual:.6}, bp_sys:{sys_residual:.6}, bp_dia:{dia_residual:.6}, risk:{risk_residual:.6}}}");

    println!("report_hr_svg={hr_svg}");
    println!("report_hr_html={hr_html}");
    println!("report_glucose_svg={glu_svg}");
    println!("report_glucose_html={glu_html}");
    println!("report_bp_sys_svg={sys_svg}");
    println!("report_bp_sys_html={sys_html}");
    println!("report_bp_dia_svg={dia_svg}");
    println!("report_bp_dia_html={dia_html}");
    println!("report_risk_svg={risk_svg}");
    println!("report_risk_html={risk_html}");
}
