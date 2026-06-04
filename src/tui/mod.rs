mod app;

pub use app::{ActivityLine, App, Mode, SecretRow, UnlockState};

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
        Mode::EditValue => handle_edit_value(app, key)?,
        Mode::AddSecret => handle_add_secret(app, key)?,
        _ => {
            if key.code == KeyCode::Esc {
                app.mode = Mode::Normal;
            }
        }
    }
    Ok(())
}

fn handle_edit_value(app: &mut App, key: KeyEvent) -> Result<()> {
    match key.code {
        KeyCode::Esc => reset_edit_buffer(app),
        KeyCode::Enter if !key.modifiers.contains(KeyModifiers::SHIFT) => {
            crate::core::ops::commit_edit(app)?;
            reset_edit_buffer(app);
        }
        _ => {
            app.edit_buffer.input(key);
        }
    }
    Ok(())
}

fn handle_add_secret(app: &mut App, key: KeyEvent) -> Result<()> {
    match key.code {
        KeyCode::Esc => reset_edit_buffer(app),
        KeyCode::Enter if !key.modifiers.contains(KeyModifiers::SHIFT) => {
            crate::core::ops::commit_new_secret(app)?;
            reset_edit_buffer(app);
        }
        _ => {
            app.edit_buffer.input(key);
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
        KeyCode::Char('e') => enter_edit_value(app),
        KeyCode::Char('a') => enter_add_secret(app),
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

fn enter_edit_value(app: &mut App) {
    let Some(idx) = app.row_state.selected() else {
        return;
    };
    let Some(row) = app.rows.get(idx) else {
        return;
    };
    let mut ta = tui_textarea::TextArea::default();
    if let Some(secret) = &row.shared {
        use secrecy::ExposeSecret;
        let exposed: &str = secret.expose_secret();
        ta.insert_str(exposed);
    }
    app.edit_buffer = ta;
    app.edit_key_name = Some(row.key.clone());
    app.mode = Mode::EditValue;
}

fn enter_add_secret(app: &mut App) {
    let mut ta = tui_textarea::TextArea::default();
    ta.set_placeholder_text("KEY=value");
    app.edit_buffer = ta;
    app.edit_key_name = None;
    app.mode = Mode::AddSecret;
}

fn reset_edit_buffer(app: &mut App) {
    app.edit_buffer = tui_textarea::TextArea::default();
    app.edit_key_name = None;
    app.mode = Mode::Normal;
}
