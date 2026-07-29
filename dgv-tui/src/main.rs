use std::io;
use std::path::{Path, PathBuf};
use clap::Parser;
use crossterm::event::{self, Event, KeyCode, KeyModifiers};

mod parser;
mod app;
mod tui;
mod ui;
mod runner;

use app::{App, TestStatus, DetailMode};
use tui::Tui;
use runner::TestRunner;

#[derive(Parser, Debug)]
#[command(name = "dgv-tui", version = "1.3.0", author = "onlyOS Devs")]
struct Args {
    #[arg(short, long, default_value = "/home/vdmo/pir/only-engine/dgv/test_cards")]
    test_cards: String,

    #[arg(short, long, default_value = "/home/vdmo/pir/only-engine/dgv/evidence")]
    evidence: String,

    #[arg(short, long, default_value = "/home/vdmo/pir/only-engine")]
    project_root: String,

    #[arg(long, default_value = "false")]
    headless: bool,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();
    
    let mut app = App::new(&args.test_cards, &args.evidence);
    if let Err(e) = app.load_data() {
        eprintln!("Error loading data: {}", e);
        std::process::exit(1);
    }

    let project_root_path = Path::new(&args.project_root);
    let runner = match TestRunner::new(project_root_path) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("Error initializing runner: {}", e);
            std::process::exit(1);
        }
    };

    if args.headless {
        println!("Starting DGV Verification Suite (Headless mode)...");
        let mut overall_success = true;
        for card in &app.cards {
            println!("Running Card {} - {}...", card.id, card.claim_name);
            match runner.run_card(card).await {
                Ok(ev) => {
                    println!("  Result: PASSED");
                    app.statuses.insert(card.id.clone(), TestStatus::Passed);
                    app.evidence.insert(card.id.clone(), ev);
                }
                Err(e) => {
                    println!("  Result: FAILED - {}", e);
                    app.statuses.insert(card.id.clone(), TestStatus::Failed);
                    overall_success = false;
                }
            }
        }
        
        let (passed, failed, total) = app.get_progress();
        println!("\nVerification Complete: {}/{} passed ({} failed).", passed, total, failed);
        if overall_success {
            println!("System is DGV compliant.");
            std::process::exit(0);
        } else {
            println!("System failed compliance.");
            std::process::exit(1);
        }
    }

    // Interactive TUI Mode
    let mut tui = Tui::new()?;
    tui.enter()?;

    let mut last_tick = std::time::Instant::now();
    let tick_rate = std::time::Duration::from_millis(100);

    loop {
        // Render TUI
        tui.terminal().draw(|f| ui::draw(f, &mut app))?;

        // Handle events
        let timeout = tick_rate
            .checked_sub(last_tick.elapsed())
            .unwrap_or(std::time::Duration::from_secs(0));

        if event::poll(timeout)? {
            if let Event::Key(key) = event::read()? {
                if key.modifiers == KeyModifiers::CONTROL && key.code == KeyCode::Char('c') {
                    break;
                }
                match key.code {
                    KeyCode::Char('q') | KeyCode::Esc => {
                        break;
                    }
                    KeyCode::Down => {
                        app.select_next();
                    }
                    KeyCode::Up => {
                        app.select_previous();
                    }
                    KeyCode::Char('d') => {
                        app.detail_mode = match app.detail_mode {
                            DetailMode::CardSpec => DetailMode::DecisionPath,
                            DetailMode::DecisionPath => DetailMode::CardSpec,
                        };
                        app.log(format!("Toggled detail view to: {:?}", app.detail_mode));
                    }
                    KeyCode::Enter => {
                        if let Some(card) = app.get_selected_card() {
                            let card_clone = card.clone();
                            app.statuses.insert(card_clone.id.clone(), TestStatus::Running);
                            app.log(format!("Running selected test: {}", card_clone.id));
                            tui.terminal().draw(|f| ui::draw(f, &mut app))?;
                            
                            match runner.run_card(&card_clone).await {
                                Ok(ev) => {
                                    app.statuses.insert(card_clone.id.clone(), TestStatus::Passed);
                                    app.evidence.insert(card_clone.id.clone(), ev);
                                    app.log(format!("Test {} PASSED", card_clone.id));
                                }
                                Err(e) => {
                                    app.statuses.insert(card_clone.id.clone(), TestStatus::Failed);
                                    app.log(format!("Test {} FAILED: {}", card_clone.id, e));
                                    // Reload evidence to pick up failed trace
                                    let _ = app.load_data();
                                }
                            }
                        }
                    }
                    KeyCode::Char('r') => {
                        app.log("Running all tests...".to_string());
                        let cards = app.cards.clone();
                        for card in cards {
                            app.selected_index = app.cards.iter().position(|c| c.id == card.id).unwrap_or(0);
                            app.statuses.insert(card.id.clone(), TestStatus::Running);
                            app.log(format!("Running test: {}", card.id));
                            tui.terminal().draw(|f| ui::draw(f, &mut app))?;
                            
                            match runner.run_card(&card).await {
                                Ok(ev) => {
                                    app.statuses.insert(card.id.clone(), TestStatus::Passed);
                                    app.evidence.insert(card.id.clone(), ev);
                                    app.log(format!("Test {} PASSED", card.id));
                                }
                                Err(e) => {
                                    app.statuses.insert(card.id.clone(), TestStatus::Failed);
                                    app.log(format!("Test {} FAILED: {}", card.id, e));
                                }
                            }
                        }
                        // Reload data after running all to sync evidence mappings
                        let _ = app.load_data();
                        app.log("All tests execution complete.".to_string());
                    }
                    _ => {}
                }
            }
        }

        if last_tick.elapsed() >= tick_rate {
            last_tick = std::time::Instant::now();
        }
    }

    tui.exit()?;
    Ok(())
}
