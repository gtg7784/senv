mod app;

pub use app::{
    ActivityLine, App, DiffEntry, DiffKind, ImportPreview, Mode, Recipient, SecretRow, UnlockState,
};

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
        Mode::DiffView => handle_diff_view(app, key)?,
        Mode::ImportWizard => handle_import_wizard(app, key)?,
        Mode::SchemaEdit => handle_schema_edit(app, key)?,
        Mode::Recipients => handle_recipients(app, key)?,
    }
    Ok(())
}

fn handle_import_wizard(app: &mut App, key: KeyEvent) -> Result<()> {
    match key.code {
        KeyCode::Esc => {
            app.import_preview = None;
            app.mode = Mode::Normal;
        }
        KeyCode::Enter => {
            if let Some(preview) = app.import_preview.clone() {
                let count = crate::core::ops::import_silent(&preview.source)?;
                crate::core::ops::reload_from_disk(app)?;
                let msg = format!("imported {} entries from {}", count, preview.source.display());
                app.activity.push(crate::tui::ActivityLine {
                    time: short_clock(),
                    message: msg,
                });
            }
            app.import_preview = None;
            app.mode = Mode::Normal;
        }
        _ => {}
    }
    Ok(())
}

fn short_clock() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let h = (secs / 3600) % 24;
    let m = (secs / 60) % 60;
    format!("{:02}:{:02}", h, m)
}

fn handle_diff_view(app: &mut App, key: KeyEvent) -> Result<()> {
    match key.code {
        KeyCode::Esc => app.mode = Mode::Normal,
        KeyCode::Up | KeyCode::Char('k') => {
            if !app.diff_entries.is_empty() {
                let i = app.diff_state.selected().unwrap_or(0);
                let next = if i == 0 {
                    app.diff_entries.len() - 1
                } else {
                    i - 1
                };
                app.diff_state.select(Some(next));
            }
        }
        KeyCode::Down | KeyCode::Char('j') => {
            if !app.diff_entries.is_empty() {
                let i = app.diff_state.selected().unwrap_or(0);
                let next = if i + 1 >= app.diff_entries.len() {
                    0
                } else {
                    i + 1
                };
                app.diff_state.select(Some(next));
            }
        }
        _ => {}
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
        KeyCode::Char('s') => enter_schema_edit(app),
        KeyCode::Char('r') => enter_recipients(app),
        KeyCode::Char('i') => enter_import_wizard(app),
        KeyCode::Char('D') => enter_diff_view(app),
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

fn enter_diff_view(app: &mut App) {
    app.diff_entries = crate::core::ops::compute_diff(app);
    app.diff_state = ratatui::widgets::ListState::default();
    if !app.diff_entries.is_empty() {
        app.diff_state.select(Some(0));
    }
    app.mode = Mode::DiffView;
}

fn enter_import_wizard(app: &mut App) {
    let path = std::path::Path::new(".env");
    app.import_preview = if path.exists() {
        crate::core::ops::build_import_preview(path).ok()
    } else {
        None
    };
    app.mode = Mode::ImportWizard;
}

fn enter_recipients(app: &mut App) {
    let mut state = ratatui::widgets::ListState::default();
    if !app.recipients.is_empty() {
        state.select(Some(0));
    }
    app.recipients_state = state;
    app.recipients_input_active = false;
    app.edit_buffer = tui_textarea::TextArea::default();
    app.mode = Mode::Recipients;
}

fn handle_recipients(app: &mut App, key: KeyEvent) -> Result<()> {
    if app.recipients_input_active {
        match key.code {
            KeyCode::Esc => {
                app.recipients_input_active = false;
                app.edit_buffer = tui_textarea::TextArea::default();
            }
            KeyCode::Enter if !key.modifiers.contains(KeyModifiers::SHIFT) => {
                let raw = app.edit_buffer.lines().join("").trim().to_string();
                crate::core::ops::add_recipient(app, &raw)?;
                app.recipients_input_active = false;
                app.edit_buffer = tui_textarea::TextArea::default();
            }
            _ => {
                app.edit_buffer.input(key);
            }
        }
        return Ok(());
    }

    match key.code {
        KeyCode::Esc => app.mode = Mode::Normal,
        KeyCode::Up | KeyCode::Char('k') => {
            if !app.recipients.is_empty() {
                let i = app.recipients_state.selected().unwrap_or(0);
                let next = if i == 0 { app.recipients.len() - 1 } else { i - 1 };
                app.recipients_state.select(Some(next));
            }
        }
        KeyCode::Down | KeyCode::Char('j') => {
            if !app.recipients.is_empty() {
                let i = app.recipients_state.selected().unwrap_or(0);
                let next = if i + 1 >= app.recipients.len() { 0 } else { i + 1 };
                app.recipients_state.select(Some(next));
            }
        }
        KeyCode::Char('a') => {
            app.recipients_input_active = true;
            let mut ta = tui_textarea::TextArea::default();
            ta.set_placeholder_text("age1...");
            app.edit_buffer = ta;
        }
        KeyCode::Char('d') => {
            let Some(idx) = app.recipients_state.selected() else {
                return Ok(());
            };
            let pubkey = app
                .recipients
                .get(idx)
                .map(|r| r.pubkey.clone())
                .unwrap_or_default();
            if !pubkey.is_empty() {
                crate::core::ops::remove_recipient(app, &pubkey)?;
                let new_len = app.recipients.len();
                if new_len == 0 {
                    app.recipients_state.select(None);
                } else if idx >= new_len {
                    app.recipients_state.select(Some(new_len - 1));
                }
            }
        }
        _ => {}
    }
    Ok(())
}

fn enter_schema_edit(app: &mut App) {
    let Some(idx) = app.row_state.selected() else {
        return;
    };
    let Some(row) = app.rows.get(idx) else {
        return;
    };
    let mut ta = tui_textarea::TextArea::default();
    if let Some(desc) = app.schema.get(&row.key) {
        ta.insert_str(desc);
    }
    ta.set_placeholder_text("schema description (Shift+Enter for newline)");
    app.edit_buffer = ta;
    app.edit_key_name = Some(row.key.clone());
    app.mode = Mode::SchemaEdit;
}

fn handle_schema_edit(app: &mut App, key: KeyEvent) -> Result<()> {
    match key.code {
        KeyCode::Esc => reset_edit_buffer(app),
        KeyCode::Enter if !key.modifiers.contains(KeyModifiers::SHIFT) => {
            crate::core::ops::commit_schema_edit(app)?;
            reset_edit_buffer(app);
        }
        _ => {
            app.edit_buffer.input(key);
        }
    }
    Ok(())
}
