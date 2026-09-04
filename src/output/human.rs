//! Formatting helpers for human output.

/// `1.2 GB` style, base 1000 like `du -h` on macOS and Kopia's own output.
pub fn bytes(n: u64) -> String {
    const UNITS: [&str; 6] = ["B", "KB", "MB", "GB", "TB", "PB"];
    if n < 1000 {
        return format!("{n} B");
    }
    let mut value = n as f64;
    let mut unit = 0;
    while value >= 1000.0 && unit < UNITS.len() - 1 {
        value /= 1000.0;
        unit += 1;
    }
    if value >= 100.0 {
        format!("{value:.0} {}", UNITS[unit])
    } else if value >= 10.0 {
        format!("{value:.1} {}", UNITS[unit])
    } else {
        format!("{value:.2} {}", UNITS[unit])
    }
}

pub fn count(n: u64, singular: &str, plural: &str) -> String {
    if n == 1 {
        format!("1 {singular}")
    } else {
        format!("{n} {plural}")
    }
}

/// Two-column key/value block with aligned values.
pub fn kv_block(rows: &[(String, String)]) -> String {
    let width = rows
        .iter()
        .map(|(k, _)| k.chars().count())
        .max()
        .unwrap_or(0);
    rows.iter()
        .map(|(k, v)| format!("  {k:<width$}  {v}"))
        .collect::<Vec<_>>()
        .join("\n")
}

/// Simple left-aligned table.
pub fn table(headers: &[&str], rows: &[Vec<String>]) -> String {
    let cols = headers.len();
    let mut widths: Vec<usize> = headers.iter().map(|h| h.chars().count()).collect();
    for row in rows {
        for (i, cell) in row.iter().enumerate().take(cols) {
            widths[i] = widths[i].max(cell.chars().count());
        }
    }
    let fmt_row = |cells: &[String]| -> String {
        cells
            .iter()
            .enumerate()
            .map(|(i, c)| {
                if i == cols - 1 {
                    c.clone()
                } else {
                    format!("{:<w$}", c, w = widths[i])
                }
            })
            .collect::<Vec<_>>()
            .join("  ")
            .trim_end()
            .to_string()
    };
    let mut out = vec![fmt_row(
        &headers.iter().map(|h| h.to_string()).collect::<Vec<_>>(),
    )];
    out.extend(rows.iter().map(|r| fmt_row(r)));
    out.join("\n")
}

/// "4 minutes old" style age.
pub fn age(seconds: i64) -> String {
    if seconds < 0 {
        return "in the future".into();
    }
    let s = seconds as u64;
    if s < 60 {
        format!("{s} seconds")
    } else if s < 3600 {
        count(s / 60, "minute", "minutes")
    } else if s < 86_400 {
        count(s / 3600, "hour", "hours")
    } else {
        count(s / 86_400, "day", "days")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn byte_formatting() {
        assert_eq!(bytes(0), "0 B");
        assert_eq!(bytes(999), "999 B");
        assert_eq!(bytes(1_000), "1.00 KB");
        assert_eq!(bytes(4_200_000_000), "4.20 GB");
        assert_eq!(bytes(25_700_000_000), "25.7 GB");
        assert_eq!(bytes(120_000_000), "120 MB");
    }

    #[test]
    fn table_alignment() {
        let t = table(
            &["ID", "STATUS"],
            &[vec!["a8f3c2".into(), "complete".into()]],
        );
        assert_eq!(t, "ID      STATUS\na8f3c2  complete");
    }

    #[test]
    fn ages() {
        assert_eq!(age(30), "30 seconds");
        assert_eq!(age(240), "4 minutes");
        assert_eq!(age(7200), "2 hours");
    }
}
