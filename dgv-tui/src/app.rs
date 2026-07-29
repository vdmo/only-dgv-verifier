use std::collections::HashMap;
use std::path::Path;
use crate::parser::{TestCard, EvidencePackage, scan_evidence_dir};

#[derive(Debug, Clone, PartialEq)]
pub enum TestStatus {
    Pending,
    Running,
    Passed,
    Failed,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum DetailMode {
    CardSpec,
    DecisionPath,
}

pub struct App {
    pub cards: Vec<TestCard>,
    pub selected_index: usize,
    pub statuses: HashMap<String, TestStatus>,
    pub evidence: HashMap<String, EvidencePackage>,
    pub log_messages: Vec<String>,
    pub test_cards_dir: String,
    pub evidence_dir: String,
    pub should_quit: bool,
    pub detail_mode: DetailMode,
}

impl App {
    pub fn new(test_cards_dir: &str, evidence_dir: &str) -> Self {
        Self {
            cards: Vec::new(),
            selected_index: 0,
            statuses: HashMap::new(),
            evidence: HashMap::new(),
            log_messages: vec!["App initialized. Press 'r' to run all tests, 'd' to toggle Decision Path, Arrow keys to navigate, 'q' to quit.".to_string()],
            test_cards_dir: test_cards_dir.to_string(),
            evidence_dir: evidence_dir.to_string(),
            should_quit: false,
            detail_mode: DetailMode::CardSpec,
        }
    }

    pub fn load_data(&mut self) -> Result<(), String> {
        let cards_path = Path::new(&self.test_cards_dir);
        let evidence_path = Path::new(&self.evidence_dir);

        let cards = crate::parser::load_test_cards(cards_path)
            .map_err(|e| format!("Failed to load test cards: {}", e))?;
        
        let evidence_map = scan_evidence_dir(evidence_path);

        self.cards = cards;
        self.evidence = evidence_map;

        // Initialize statuses based on scanned evidence
        for card in &self.cards {
            if let Some(ev) = self.evidence.get(&card.id) {
                let status = if ev.status == "passed" {
                    TestStatus::Passed
                } else {
                    TestStatus::Failed
                };
                self.statuses.insert(card.id.clone(), status);
            } else {
                self.statuses.insert(card.id.clone(), TestStatus::Pending);
            }
        }

        self.log_messages.push(format!("Loaded {} test cards.", self.cards.len()));
        Ok(())
    }

    pub fn select_next(&mut self) {
        if !self.cards.is_empty() {
            self.selected_index = (self.selected_index + 1) % self.cards.len();
        }
    }

    pub fn select_previous(&mut self) {
        if !self.cards.is_empty() {
            if self.selected_index == 0 {
                self.selected_index = self.cards.len() - 1;
            } else {
                self.selected_index -= 1;
            }
        }
    }

    pub fn get_selected_card(&self) -> Option<&TestCard> {
        self.cards.get(self.selected_index)
    }

    pub fn get_progress(&self) -> (usize, usize, usize) {
        let mut passed = 0;
        let mut failed = 0;
        for status in self.statuses.values() {
            match status {
                TestStatus::Passed => passed += 1,
                TestStatus::Failed => failed += 1,
                _ => {}
            }
        }
        (passed, failed, self.cards.len())
    }

    pub fn log(&mut self, message: String) {
        self.log_messages.push(message);
        if self.log_messages.len() > 100 {
            self.log_messages.remove(0);
        }
    }
}
