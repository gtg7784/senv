use anyhow::Result;

pub fn run() -> Result<()> {
    let pairs = crate::core::ops::collect_env_pairs()?;
    for (key, value) in pairs {
        println!("export {}={}", key, shell_quote(&value));
    }
    Ok(())
}

fn shell_quote(s: &str) -> String {
    if !s.is_empty()
        && s.chars()
            .all(|c| c.is_ascii_alphanumeric() || "-_./".contains(c))
    {
        s.to_string()
    } else {
        format!("'{}'", s.replace('\'', "'\\''"))
    }
}
