mod app;

pub use app::{App, Mode, SecretRow, UnlockState};

use std::io;
use std::time::Duration;

use anyhow::Result;
use crossterm::{
    event::{
        self, DisableMouseCapture, EnableMouseCapture, Event, KeyCode, KeyEvent, KeyEventKind,
        KeyModifiers,
    },
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use ratatui::prelude::*;

pub fn run() -> Result<()> {
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen, EnableMouseCapture)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    let mut app = App::new();
    crate::core::discovery::populate(&mut app)?;

    let result = event_loop(&mut terminal, &mut app);

    disable_raw_mode()?;
    execute!(
        terminal.backend_mut(),
        LeaveAlternateScreen,
        DisableMouseCapture
    )?;
    terminal.show_cursor()?;

    result
}

fn event_loop<B: Backend>(terminal: &mut Terminal<B>, app: &mut App) -> Result<()> {
    let tick = Duration::from_millis(250);

    while !app.should_quit {
        terminal.draw(|f| app.render(f))?;

        if event::poll(tick)?
            && let Event::Key(key) = event::read()?
            && key.kind == KeyEventKind::Press
        {
            handle_key(app, key)?;
        }
    }
    Ok(())
}

fn handle_key(app: &mut App, key: KeyEvent) -> Result<()> {
    if key.modifiers.contains(KeyModifiers::CONTROL) && key.code == KeyCode::Char('c') {
        app.should_quit = true;
        return Ok(());
    }

    match app.mode {
        Mode::Normal => handle_normal(app, key)?,
        Mode::Help => {
            if matches!(
                key.code,
                KeyCode::Esc | KeyCode::Char('?') | KeyCode::Char('q')
            ) {
                app.mode = Mode::Normal;
            }
        }
        _ => {
            if key.code == KeyCode::Esc {
                app.mode = Mode::Normal;
            }
        }
    }
    Ok(())
}

fn handle_normal(app: &mut App, key: KeyEvent) -> Result<()> {
    match key.code {
        KeyCode::Char('q') => app.should_quit = true,
        KeyCode::Up | KeyCode::Char('k') => app.select_prev_row(),
        KeyCode::Down | KeyCode::Char('j') => app.select_next_row(),
        KeyCode::Char('t') => app.cycle_env_next(),
        KeyCode::Char('T') => app.cycle_env_prev(),
        KeyCode::Char(' ') => app.reveal = !app.reveal,
        KeyCode::Char('e') => app.mode = Mode::EditValue,
        KeyCode::Char('a') => app.mode = Mode::AddSecret,
        KeyCode::Char('d') => crate::core::ops::confirm_delete(app)?,
        KeyCode::Char('o') => crate::core::ops::toggle_scoped(app)?,
        KeyCode::Char('s') => app.mode = Mode::SchemaEdit,
        KeyCode::Char('r') => app.mode = Mode::Recipients,
        KeyCode::Char('i') => app.mode = Mode::ImportWizard,
        KeyCode::Char('D') => app.mode = Mode::DiffView,
        KeyCode::Char('R') => crate::core::ops::reload_from_disk(app)?,
        KeyCode::Char('L') => crate::crypto::identity::lock(app)?,
        KeyCode::Char('U') => crate::crypto::identity::unlock(app)?,
        KeyCode::Char('?') | KeyCode::F(1) => app.mode = Mode::Help,
        _ => {}
    }
    Ok(())
}
