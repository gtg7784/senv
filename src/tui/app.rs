use ratatui::{
    prelude::*,
    widgets::{
        Block, Borders, Cell, Clear, List, ListItem, ListState, Paragraph, Row, Table, TableState,
    },
};
use secrecy::{ExposeSecret, SecretString};
use tui_textarea::TextArea;

pub struct SecretRow {
    pub key: String,
    pub shared: Option<SecretString>,
    pub scoped: Option<SecretString>,
    pub missing_in_example: bool,
}

pub struct Recipient {
    pub pubkey: String,
    pub display_name: Option<String>,
    pub is_self: bool,
}

pub struct ActivityLine {
    pub time: String,
    pub message: String,
}

#[derive(Clone, PartialEq, Eq)]
pub enum DiffKind {
    Missing,
    Extra,
    Match,
}

#[derive(Clone)]
pub struct DiffEntry {
    pub key: String,
    pub kind: DiffKind,
}

#[derive(Clone)]
pub struct ImportPreview {
    pub source: std::path::PathBuf,
    pub entries: Vec<(String, usize)>,
}

#[derive(PartialEq, Eq, Clone, Copy)]
pub enum Mode {
    Normal,
    EditValue,
    AddSecret,
    SchemaEdit,
    Recipients,
    DiffView,
    ImportWizard,
    Help,
}

#[derive(PartialEq, Eq, Clone, Copy)]
pub enum UnlockState {
    Locked,
    Unlocked,
    Expired,
}

pub struct App {
    pub project_name: String,
    pub git_remote: Option<String>,
    pub unlock: UnlockState,

    pub environments: Vec<String>,
    pub env_index: usize,

    pub rows: Vec<SecretRow>,
    pub row_state: TableState,
    pub reveal: bool,

    pub recipients: Vec<Recipient>,
    pub recipients_state: ListState,

    pub activity: Vec<ActivityLine>,

    pub mode: Mode,
    pub edit_buffer: TextArea<'static>,
    pub edit_key_name: Option<String>,

    pub diff_entries: Vec<DiffEntry>,
    pub diff_state: ListState,

    pub import_preview: Option<ImportPreview>,

    pub schema: std::collections::HashMap<String, String>,

    pub should_quit: bool,
}

impl Default for App {
    fn default() -> Self {
        Self::new()
    }
}

impl App {
    pub fn new() -> Self {
        let mut row_state = TableState::default();
        row_state.select(Some(0));
        Self {
            project_name: "—".to_string(),
            git_remote: None,
            unlock: UnlockState::Locked,
            environments: vec!["dev".to_string(), "staging".to_string(), "prod".to_string()],
            env_index: 0,
            rows: Vec::new(),
            row_state,
            reveal: false,
            recipients: Vec::new(),
            recipients_state: ListState::default(),
            activity: Vec::new(),
            mode: Mode::Normal,
            edit_buffer: TextArea::default(),
            edit_key_name: None,
            diff_entries: Vec::new(),
            diff_state: ListState::default(),
            import_preview: None,
            schema: std::collections::HashMap::new(),
            should_quit: false,
        }
    }

    pub fn select_prev_row(&mut self) {
        if self.rows.is_empty() {
            return;
        }
        let i = self.row_state.selected().unwrap_or(0);
        let next = if i == 0 { self.rows.len() - 1 } else { i - 1 };
        self.row_state.select(Some(next));
    }

    pub fn select_next_row(&mut self) {
        if self.rows.is_empty() {
            return;
        }
        let i = self.row_state.selected().unwrap_or(0);
        let next = if i + 1 >= self.rows.len() { 0 } else { i + 1 };
        self.row_state.select(Some(next));
    }

    pub fn cycle_env_next(&mut self) {
        if self.environments.is_empty() {
            return;
        }
        self.env_index = (self.env_index + 1) % self.environments.len();
    }

    pub fn cycle_env_prev(&mut self) {
        if self.environments.is_empty() {
            return;
        }
        self.env_index = if self.env_index == 0 {
            self.environments.len() - 1
        } else {
            self.env_index - 1
        };
    }

    pub fn effective<'a>(&self, row: &'a SecretRow) -> Option<&'a SecretString> {
        row.scoped.as_ref().or(row.shared.as_ref())
    }

    pub fn render(&mut self, f: &mut Frame) {
        let outer = Layout::vertical([
            Constraint::Length(1),
            Constraint::Min(0),
            Constraint::Length(1),
        ])
        .split(f.area());

        self.render_header(f, outer[0]);

        let body = Layout::horizontal([
            Constraint::Length(12),
            Constraint::Min(40),
            Constraint::Length(30),
        ])
        .split(outer[1]);

        self.render_env_tabs(f, body[0]);
        self.render_secret_table(f, body[1]);

        let sidebar =
            Layout::vertical([Constraint::Percentage(50), Constraint::Percentage(50)])
                .split(body[2]);
        self.render_recipients(f, sidebar[0]);
        self.render_activity(f, sidebar[1]);

        self.render_keymap_hint(f, outer[2]);

        match self.mode {
            Mode::Help => self.render_help_overlay(f),
            Mode::DiffView => self.render_diff_overlay(f),
            Mode::ImportWizard => self.render_import_overlay(f),
            Mode::Normal => {}
            _ => self.render_placeholder_modal(f),
        }
    }

    fn render_header(&self, f: &mut Frame, area: Rect) {
        let lock_span = match self.unlock {
            UnlockState::Locked => {
                Span::styled("🔒 locked", Style::new().fg(Color::Red).bold())
            }
            UnlockState::Unlocked => {
                Span::styled("🔓 unlocked", Style::new().fg(Color::Green).bold())
            }
            UnlockState::Expired => {
                Span::styled("⏰ expired", Style::new().fg(Color::Yellow).bold())
            }
        };

        let mut spans = vec![
            Span::styled(
                " senv ",
                Style::new().bg(Color::DarkGray).fg(Color::White).bold(),
            ),
            Span::raw(" │ "),
            Span::raw(format!("project: {}", self.project_name)),
        ];
        if let Some(remote) = &self.git_remote {
            spans.push(Span::raw(" "));
            spans.push(Span::styled(
                remote.clone(),
                Style::new().fg(Color::DarkGray).italic(),
            ));
        }
        spans.push(Span::raw(" │ "));
        spans.push(lock_span);

        f.render_widget(Paragraph::new(Line::from(spans)), area);
    }

    fn render_env_tabs(&self, f: &mut Frame, area: Rect) {
        let items: Vec<ListItem> = self
            .environments
            .iter()
            .enumerate()
            .map(|(i, name)| {
                let marker = if i == self.env_index { "▶" } else { " " };
                let line = format!("{} {}", marker, name);
                let style = if i == self.env_index {
                    Style::new().fg(Color::Cyan).bold()
                } else {
                    Style::new()
                };
                ListItem::new(line).style(style)
            })
            .collect();

        f.render_widget(
            List::new(items).block(Block::default().borders(Borders::ALL).title("Envs")),
            area,
        );
    }

    fn render_secret_table(&mut self, f: &mut Frame, area: Rect) {
        let env_name = self
            .environments
            .get(self.env_index)
            .cloned()
            .unwrap_or_default();

        let header = Row::new(vec!["KEY", "VALUE", "SOURCE", ""])
            .style(Style::new().fg(Color::DarkGray).bold());

        let reveal = self.reveal;
        let rows: Vec<Row> = self
            .rows
            .iter()
            .map(|row| {
                let effective = row.scoped.as_ref().or(row.shared.as_ref());
                let value_cell = render_value_cell(reveal, effective);
                let source = match (row.shared.is_some(), row.scoped.is_some()) {
                    (_, true) => Cell::from("yours").fg(Color::Magenta),
                    (true, _) => Cell::from("shared").fg(Color::Cyan),
                    _ => Cell::from("—").fg(Color::DarkGray),
                };
                let status = if row.missing_in_example {
                    Cell::from("⚠ missing").fg(Color::Yellow)
                } else {
                    Cell::from("")
                };
                Row::new(vec![Cell::from(row.key.clone()), value_cell, source, status])
            })
            .collect();

        let widths = [
            Constraint::Length(22),
            Constraint::Min(20),
            Constraint::Length(8),
            Constraint::Length(24),
        ];

        let title = format!("Secrets · {}", env_name);

        if self.rows.is_empty() {
            let empty = Paragraph::new(
                "\n  No secrets yet.\n\n  Press [i] to import .env  ·  [a] to add a secret",
            )
            .block(Block::default().borders(Borders::ALL).title(title));
            f.render_widget(empty, area);
        } else {
            let table = Table::new(rows, widths)
                .header(header)
                .block(Block::default().borders(Borders::ALL).title(title))
                .row_highlight_style(Style::new().bg(Color::DarkGray))
                .highlight_symbol("▸ ");
            f.render_stateful_widget(table, area, &mut self.row_state);
        }
    }

    fn render_recipients(&mut self, f: &mut Frame, area: Rect) {
        let items: Vec<ListItem> = self
            .recipients
            .iter()
            .map(|r| {
                let marker = if r.is_self { "★" } else { "·" };
                let name = r.display_name.as_deref().unwrap_or("(unnamed)");
                let suffix = if r.is_self { " (you)" } else { "" };
                ListItem::new(format!("{} {}{}", marker, name, suffix))
            })
            .collect();

        f.render_stateful_widget(
            List::new(items)
                .block(Block::default().borders(Borders::ALL).title("Recipients")),
            area,
            &mut self.recipients_state,
        );
    }

    fn render_activity(&self, f: &mut Frame, area: Rect) {
        let items: Vec<ListItem> = self
            .activity
            .iter()
            .rev()
            .take(20)
            .map(|a| ListItem::new(format!("{}  {}", a.time, a.message)))
            .collect();
        f.render_widget(
            List::new(items).block(Block::default().borders(Borders::ALL).title("Activity")),
            area,
        );
    }

    fn render_keymap_hint(&self, f: &mut Frame, area: Rect) {
        let hint = match self.mode {
            Mode::Normal => " [↑↓/jk] nav  [space] reveal  [e] edit  [a] add  [t] env  [s] schema  [r] recipients  [i] import  [?] help  [q] quit ",
            Mode::EditValue => " [Enter] save  [Esc] cancel ",
            Mode::AddSecret => " [Tab] focus  [Enter] save  [Esc] cancel ",
            Mode::SchemaEdit => " [Tab] field  [Enter] save  [Esc] cancel ",
            Mode::Recipients => " [space] toggle  [a] add by pubkey  [g] github:user  [Enter] confirm  [Esc] cancel ",
            Mode::ImportWizard => " [Tab] choose  [Enter] confirm  [Esc] cancel ",
            Mode::DiffView => " [↑↓] nav  [Esc] back ",
            Mode::Help => " [Esc] close ",
        };
        f.render_widget(
            Paragraph::new(hint).style(Style::new().bg(Color::DarkGray).fg(Color::White)),
            area,
        );
    }

    fn render_diff_overlay(&mut self, f: &mut Frame) {
        let area = centered_rect(70, 70, f.area());
        f.render_widget(Clear, area);

        let missing = self
            .diff_entries
            .iter()
            .filter(|e| e.kind == DiffKind::Missing)
            .count();
        let extra = self
            .diff_entries
            .iter()
            .filter(|e| e.kind == DiffKind::Extra)
            .count();
        let title = format!(
            " Diff vs .env.example · {} missing · {} extra ",
            missing, extra
        );
        let block = Block::default().borders(Borders::ALL).title(title);
        let inner = block.inner(area);
        f.render_widget(block, area);

        if self.diff_entries.is_empty() {
            f.render_widget(
                Paragraph::new(
                    "\n  ✓ No differences (or .env.example not found)\n  Press Esc to return.",
                ),
                inner,
            );
            return;
        }

        let items: Vec<ListItem> = self
            .diff_entries
            .iter()
            .map(|e| {
                let (icon, color) = match e.kind {
                    DiffKind::Missing => ("⚠ MISSING", Color::Yellow),
                    DiffKind::Extra => ("+ EXTRA  ", Color::Green),
                    DiffKind::Match => ("✓ OK     ", Color::DarkGray),
                };
                ListItem::new(Line::from(vec![
                    Span::styled(icon, Style::new().fg(color)),
                    Span::raw("  "),
                    Span::raw(e.key.clone()),
                ]))
            })
            .collect();

        f.render_stateful_widget(
            List::new(items)
                .highlight_style(Style::new().bg(Color::DarkGray))
                .highlight_symbol("▸ "),
            inner,
            &mut self.diff_state,
        );
    }

    fn render_import_overlay(&self, f: &mut Frame) {
        let area = centered_rect(70, 60, f.area());
        f.render_widget(Clear, area);
        let title = " Import .env wizard ";
        let block = Block::default().borders(Borders::ALL).title(title);
        let inner = block.inner(area);
        f.render_widget(block, area);

        let Some(preview) = &self.import_preview else {
            f.render_widget(
                Paragraph::new(
                    "\n  No .env found in cwd.\n\n  Place a .env in the project root and re-open this wizard.\n  Press Esc to return.",
                ),
                inner,
            );
            return;
        };

        let chunks = Layout::vertical([Constraint::Length(3), Constraint::Min(1)]).split(inner);

        let header = format!(
            "  Source:  {}\n  Will encrypt {} entries into .env.age\n",
            preview.source.display(),
            preview.entries.len()
        );
        f.render_widget(Paragraph::new(header), chunks[0]);

        let items: Vec<ListItem> = preview
            .entries
            .iter()
            .map(|(k, len)| ListItem::new(format!("  🔒 {}  ({} bytes)", k, len)))
            .collect();
        f.render_widget(List::new(items), chunks[1]);
    }

    fn render_help_overlay(&self, f: &mut Frame) {
        let area = centered_rect(50, 70, f.area());
        f.render_widget(Clear, area);
        f.render_widget(
            Paragraph::new(HELP_TEXT)
                .block(Block::default().borders(Borders::ALL).title(" Help ")),
            area,
        );
    }

    fn render_placeholder_modal(&self, f: &mut Frame) {
        let area = centered_rect(70, 50, f.area());
        f.render_widget(Clear, area);
        let title: String = match self.mode {
            Mode::EditValue => match &self.edit_key_name {
                Some(k) => format!(" Edit value · {} ", k),
                None => " Edit value ".to_string(),
            },
            Mode::AddSecret => " Add secret · KEY=VALUE ".to_string(),
            Mode::SchemaEdit => match &self.edit_key_name {
                Some(k) => format!(" Schema · {} ", k),
                None => " Edit schema ".to_string(),
            },
            Mode::Recipients => " Recipients ".to_string(),
            Mode::ImportWizard => " Import .env wizard ".to_string(),
            Mode::DiffView => " Diff vs .env.example ".to_string(),
            _ => " Modal ".to_string(),
        };
        let block = Block::default().borders(Borders::ALL).title(title);
        let inner = block.inner(area);
        f.render_widget(block, area);

        match self.mode {
            Mode::EditValue | Mode::AddSecret | Mode::SchemaEdit => {
                f.render_widget(&self.edit_buffer, inner);
            }
            _ => {
                f.render_widget(
                    Paragraph::new(
                        "\n  Not implemented yet.\n  Press Esc to return.",
                    ),
                    inner,
                );
            }
        }
    }
}

fn render_value_cell(reveal: bool, effective: Option<&SecretString>) -> Cell<'static> {
    match effective {
        None => Cell::from("(empty)").fg(Color::DarkGray),
        Some(secret) => {
            if reveal {
                Cell::from(secret.expose_secret().to_string())
            } else {
                let len = secret.expose_secret().len().clamp(4, 12);
                Cell::from("●".repeat(len)).fg(Color::DarkGray)
            }
        }
    }
}

fn centered_rect(percent_x: u16, percent_y: u16, area: Rect) -> Rect {
    let vertical = Layout::vertical([
        Constraint::Percentage((100 - percent_y) / 2),
        Constraint::Percentage(percent_y),
        Constraint::Percentage((100 - percent_y) / 2),
    ])
    .split(area);
    Layout::horizontal([
        Constraint::Percentage((100 - percent_x) / 2),
        Constraint::Percentage(percent_x),
        Constraint::Percentage((100 - percent_x) / 2),
    ])
    .split(vertical[1])[1]
}

const HELP_TEXT: &str = "senv — encrypted .env replacement

Movement:
  ↑↓ / jk      Navigate rows
  t / T        Cycle env tab (next / prev)

Secrets:
  space        Reveal/mask current value
  e            Edit value
  a            Add secret
  d            Delete (confirm)
  o            Toggle 'yours' (scoped override)
  s            Edit schema

Team / sharing:
  r            Manage recipients

Discovery & sync:
  i            Import .env (migration wizard)
  D            Diff vs .env.example
  R            Reload from disk

Session:
  L            Lock now
  U            Unlock

Other:
  ?            This help
  q / Ctrl+C   Quit";
