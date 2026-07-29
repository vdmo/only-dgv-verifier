use std::io;
use crossterm::{
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use ratatui::backend::CrosstermBackend;
use ratatui::Terminal;

pub struct Tui {
    terminal: Terminal<CrosstermBackend<io::Stdout>>,
}

impl Tui {
    pub fn new() -> Result<Self, io::Error> {
        let stdout = io::stdout();
        let backend = CrosstermBackend::new(stdout);
        let terminal = Terminal::new(backend)?;
        Ok(Self { terminal })
    }

    pub fn enter(&mut self) -> Result<(), io::Error> {
        enable_raw_mode()?;
        execute!(io::stdout(), EnterAlternateScreen)?;
        self.terminal.clear()?;
        Ok(())
    }

    pub fn exit(&mut self) -> Result<(), io::Error> {
        disable_raw_mode()?;
        execute!(io::stdout(), LeaveAlternateScreen)?;
        self.terminal.show_cursor()?;
        Ok(())
    }

    pub fn terminal(&mut self) -> &mut Terminal<CrosstermBackend<io::Stdout>> {
        &mut self.terminal
    }
}
