//! Terminal helpers: styles, human-readable formatting and a progress line.

use std::fmt;
use std::io::{self, IsTerminal, Write};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use anstyle::{AnsiColor, Style};

pub const PLAIN: Style = Style::new();
pub const BOLD: Style = Style::new().bold();
pub const DIM: Style = Style::new().dimmed();
pub const LABEL: Style = AnsiColor::Cyan.on_default();
pub const VALUE: Style = AnsiColor::BrightCyan.on_default();
pub const HEADING: Style = AnsiColor::BrightCyan.on_default().bold();
pub const GOOD: Style = AnsiColor::BrightGreen.on_default();
pub const NOTICE: Style = AnsiColor::BrightYellow.on_default();
pub const MUTED_NOTICE: Style = AnsiColor::Yellow.on_default();
pub const BAD: Style = AnsiColor::Red.on_default();

/// A value rendered in a style. Colours are stripped by the output stream
/// when it is not a terminal or `NO_COLOR` is set.
pub struct Painted<T>(Style, T);

pub fn paint<T: fmt::Display>(style: Style, value: T) -> Painted<T> {
    Painted(style, value)
}

impl<T: fmt::Display> fmt::Display for Painted<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let Self(style, value) = self;
        write!(f, "{style}{value}{style:#}")
    }
}

/// Formats a byte count the way file managers do, e.g. `1.50 MB`.
pub fn format_size(bytes: u64) -> String {
    const UNITS: [(&str, u64); 3] = [("GB", 1 << 30), ("MB", 1 << 20), ("KB", 1 << 10)];
    match UNITS.iter().find(|&&(_, unit)| bytes >= unit) {
        Some(&(name, unit)) => format!("{:.2} {name}", bytes as f64 / unit as f64),
        None => format!("{bytes} bytes"),
    }
}

/// A UTC calendar timestamp, convertible from Unix time without a date library.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UtcTime {
    year: i64,
    month: u8,
    day: u8,
    hour: u8,
    minute: u8,
    second: u8,
}

impl UtcTime {
    pub fn from_unix(seconds: i64) -> Self {
        let days = seconds.div_euclid(86_400);
        let time_of_day = seconds.rem_euclid(86_400);

        // Days-to-civil conversion (Howard Hinnant's algorithm) on a calendar
        // whose years start in March, which puts the leap day last.
        let shifted = days + 719_468;
        let era = shifted.div_euclid(146_097);
        let day_of_era = shifted.rem_euclid(146_097);
        let year_of_era =
            (day_of_era - day_of_era / 1_460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
        let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
        let shifted_month = (5 * day_of_year + 2) / 153;
        let day = day_of_year - (153 * shifted_month + 2) / 5 + 1;
        let month = if shifted_month < 10 {
            shifted_month + 3
        } else {
            shifted_month - 9
        };

        Self {
            year: year_of_era + era * 400 + i64::from(month <= 2),
            month: month as u8,
            day: day as u8,
            hour: (time_of_day / 3_600) as u8,
            minute: (time_of_day / 60 % 60) as u8,
            second: (time_of_day % 60) as u8,
        }
    }

    pub fn from_system_time(time: SystemTime) -> Option<Self> {
        let seconds = time.duration_since(UNIX_EPOCH).ok()?.as_secs();
        Some(Self::from_unix(i64::try_from(seconds).ok()?))
    }

    /// RFC 3339 form, e.g. `2024-03-15T14:32:10+00:00`.
    pub fn rfc3339(&self) -> String {
        let Self {
            year,
            month,
            day,
            hour,
            minute,
            second,
        } = self;
        format!("{year:04}-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02}+00:00")
    }
}

/// Human form, e.g. `2024-03-15 14:32:10 UTC`.
impl fmt::Display for UtcTime {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let Self {
            year,
            month,
            day,
            hour,
            minute,
            second,
        } = self;
        write!(
            f,
            "{year:04}-{month:02}-{day:02} {hour:02}:{minute:02}:{second:02} UTC"
        )
    }
}

/// A single self-overwriting status line on stderr, shown only on terminals.
pub struct Progress {
    label: &'static str,
    total: usize,
    finished: usize,
    enabled: bool,
    /// Width of the line currently on screen, 0 if none.
    drawn: usize,
    last_draw: Option<Instant>,
}

impl Progress {
    const REDRAW_INTERVAL: Duration = Duration::from_millis(80);

    pub fn new(label: &'static str, total: usize) -> Self {
        Self {
            label,
            total,
            finished: 0,
            enabled: total > 0 && io::stderr().is_terminal(),
            drawn: 0,
            last_draw: None,
        }
    }

    /// Records progress and redraws if enough time has passed.
    pub fn set(&mut self, finished: usize) {
        self.finished = finished;
        let due = self
            .last_draw
            .is_none_or(|at| at.elapsed() >= Self::REDRAW_INTERVAL);
        if self.enabled && due {
            self.draw();
        }
    }

    /// Erases the line so that regular output can be written.
    pub fn clear(&mut self) {
        if self.drawn > 0 {
            let _ = write!(io::stderr(), "\r{:width$}\r", "", width = self.drawn);
            self.drawn = 0;
        }
    }

    /// Puts the line back after [`clear`](Self::clear), if it is in use.
    pub fn resume(&mut self) {
        if self.enabled && self.last_draw.is_some() && self.finished < self.total {
            self.draw();
        }
    }

    fn draw(&mut self) {
        let line = format!("{} {}/{}", self.label, self.finished, self.total);
        let padding = self.drawn.saturating_sub(line.len());
        let _ = write!(io::stderr(), "\r{line}{:padding$}", "");
        self.drawn = line.len();
        self.last_draw = Some(Instant::now());
    }
}

impl Drop for Progress {
    fn drop(&mut self) {
        self.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sizes() {
        assert_eq!(format_size(0), "0 bytes");
        assert_eq!(format_size(1023), "1023 bytes");
        assert_eq!(format_size(1024), "1.00 KB");
        assert_eq!(format_size(1_572_864), "1.50 MB");
        assert_eq!(format_size(3 << 30), "3.00 GB");
    }

    #[test]
    fn unix_time_conversion() {
        let cases = [
            (0, "1970-01-01 00:00:00 UTC"),
            (951_782_400, "2000-02-29 00:00:00 UTC"),
            (1_710_513_130, "2024-03-15 14:32:10 UTC"),
            (1_735_689_599, "2024-12-31 23:59:59 UTC"),
            (4_107_542_400, "2100-03-01 00:00:00 UTC"),
            (i64::from(u32::MAX), "2106-02-07 06:28:15 UTC"),
            (-1, "1969-12-31 23:59:59 UTC"),
        ];
        for (seconds, expected) in cases {
            assert_eq!(UtcTime::from_unix(seconds).to_string(), expected);
        }
        assert_eq!(
            UtcTime::from_unix(1_710_513_130).rfc3339(),
            "2024-03-15T14:32:10+00:00"
        );
    }
}
