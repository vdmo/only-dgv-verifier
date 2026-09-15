use only_core::Sign::{Minus, Plus};
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
    svg_inline: &str,
    svg_filename: &str,
) -> String {
    let title_esc = escape_html(title);
    let script_esc = escape_html(script.trim());

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
        &svg,
        &svg_filename,
    );
    std::fs::write(&html_path, html).unwrap();

    (
        svg_path.display().to_string(),
        html_path.display().to_string(),
    )
}

fn solve_sum_with_report(base: &PathBuf, slug: &str, x: f64, y: f64) -> (f64, String, String) {
    let signs = [Plus, Plus, Minus];
    let script = "harmony(1e-12) residual() evolve(2) residual() report()";

    let mut field = [x, y, 0.0];
    let field_before = field;
    let res = evaluate_script(&signs, &mut field, script).unwrap();

    let residual_before = compute_residual(&signs, &field_before);
    let residual_after = compute_residual(&signs, &field);

    let mut residual_series = res.residual_history.clone();
    if residual_series.is_empty() {
        residual_series.push(residual_before);
        residual_series.push(residual_after);
    }

    let title = format!("ONLY Lang Sum: {x} + {y} = {:.6}", field[2]);

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
    );

    (field[2], svg, html)
}

fn parse_arg(i: usize, default: f64) -> f64 {
    std::env::args()
        .nth(i)
        .and_then(|v| v.parse::<f64>().ok())
        .unwrap_or(default)
}

fn main() {
    let a = parse_arg(1, 10.0);
    let b = parse_arg(2, 32.0);
    let c = parse_arg(3, 5.0);
    let d = parse_arg(4, 7.0);

    let base = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let run_ts = run_id_unix_ms();
    let evidence_run_id = format!("{run_ts}_sum_calculator");

    let (s1, s1_svg, s1_html) = solve_sum_with_report(&base, "sum_calc_stage1_s1", a, b);
    let (s2, s2_svg, s2_html) = solve_sum_with_report(&base, "sum_calc_stage2_s2", c, d);
    let (total, total_svg, total_html) =
        solve_sum_with_report(&base, "sum_calc_stage3_total", s1, s2);

    let evidence_svg = std::fs::read_to_string(&total_svg).unwrap();
    let evidence_html = std::fs::read_to_string(&total_html).unwrap();
    let decision_hash = hash_u64_hex(&vec![
        format!("a={}", a),
        format!("b={}", b),
        format!("c={}", c),
        format!("d={}", d),
        format!("total={}", total),
    ]);
    let pack = EvidencePack {
        run_id: evidence_run_id.clone(),
        created_unix_ms: now_unix_ms(),
        request: json!({"a": a, "b": b, "c": c, "d": d}),
        policy_version: "sum_calculator_v0".to_string(),
        decision: json!({"s1": s1, "s2": s2, "total": total}),
        decision_hash,
        replay_inputs: json!({
            "reports": {"s1_html": s1_html, "s2_html": s2_html, "total_html": total_html}
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

    println!("inputs={{a:{a}, b:{b}, c:{c}, d:{d}}}");
    println!("s1={s1}");
    println!("s2={s2}");
    println!("total={total}");
    println!("stage1_report_svg={s1_svg}");
    println!("stage1_report_html={s1_html}");
    println!("stage2_report_svg={s2_svg}");
    println!("stage2_report_html={s2_html}");
    println!("stage3_report_svg={total_svg}");
    println!("stage3_report_html={total_html}");
}
