use std::fmt::Write;

// ANSI color codes
const RESET: &str = "\x1b[0m";
const BOLD: &str = "\x1b[1m";
const DIM: &str = "\x1b[2m";
const CYAN: &str = "\x1b[36m";
const GREEN: &str = "\x1b[32m";
const YELLOW: &str = "\x1b[33m";
const RED: &str = "\x1b[31m";
const BRIGHT_CYAN: &str = "\x1b[96m";
const BRIGHT_GREEN: &str = "\x1b[92m";
const BRIGHT_YELLOW: &str = "\x1b[93m";

pub struct Colors {
    pub enabled: bool,
}

impl Colors {
    pub fn bold(&self) -> &str {
        if self.enabled { BOLD } else { "" }
    }
    pub fn dim(&self) -> &str {
        if self.enabled { DIM } else { "" }
    }
    pub fn reset(&self) -> &str {
        if self.enabled { RESET } else { "" }
    }
    pub fn cyan(&self) -> &str {
        if self.enabled { CYAN } else { "" }
    }
    pub fn green(&self) -> &str {
        if self.enabled { GREEN } else { "" }
    }
    pub fn yellow(&self) -> &str {
        if self.enabled { YELLOW } else { "" }
    }
    pub fn red(&self) -> &str {
        if self.enabled { RED } else { "" }
    }
    pub fn bright_cyan(&self) -> &str {
        if self.enabled { BRIGHT_CYAN } else { "" }
    }
    pub fn bright_green(&self) -> &str {
        if self.enabled { BRIGHT_GREEN } else { "" }
    }
    pub fn bright_yellow(&self) -> &str {
        if self.enabled { BRIGHT_YELLOW } else { "" }
    }
}

pub fn colors_from_env() -> Colors {
    let enabled = atty::is(atty::Stream::Stdout) && std::env::var("NO_COLOR").is_err();
    Colors { enabled }
}

pub fn format_size(bytes: u64) -> String {
    const KB: u64 = 1024;
    const MB: u64 = KB * 1024;
    const GB: u64 = MB * 1024;

    if bytes >= GB {
        format!("{:.2} GB", bytes as f64 / GB as f64)
    } else if bytes >= MB {
        format!("{:.2} MB", bytes as f64 / MB as f64)
    } else if bytes >= KB {
        format!("{:.2} KB", bytes as f64 / KB as f64)
    } else {
        format!("{} bytes", bytes)
    }
}

pub fn render_kv_block(out: &mut String, pairs: &[(&str, String)], indent: usize, colors: &Colors) {
    if pairs.is_empty() {
        return;
    }
    
    let indent_str = " ".repeat(indent);
    
    for (key, value) in pairs {
        writeln!(
            out,
            "{}{}{}{}{}: {}{}{}",
            indent_str,
            colors.bold(),
            colors.cyan(),
            key,
            colors.reset(),
            colors.bright_cyan(),
            value,
            colors.reset()
        )
        .unwrap();
    }
}

pub fn print_header(title: &str, colors: &Colors) {
    println!(
        "{}{}{}{}",
        colors.bold(),
        colors.bright_cyan(),
        title,
        colors.reset()
    );
    println!("{}{}{}", colors.cyan(), "=".repeat(title.len()), colors.reset());
    println!();
}

