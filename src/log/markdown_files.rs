//! Write caller-assembled Markdown in a private session folder.
//! Escaping belongs to `markdown`; readable headings belong to `explain`.
//! Read `Session::write_summary` for atomic replacement of a running report.

use super::session::{Session, next_suffix, numbered, private_file, remember_problem};
use crate::{explain::log as wording, text};
use std::fs;
use std::io::{self, BufWriter, Write};
use std::path::PathBuf;

impl Session {
    /// Write a secret-free Markdown export without overwriting any existing file.
    /// Caller assembles structure and uses `markdown` helpers for every external
    /// value. ASCII letters/digits/`-`/`_` form a stem capped at 200 characters;
    /// an empty stem becomes `export`. Existing names get numbered suffixes.
    /// Failures are returned and retained in `problem`; later exports may retry.
    pub fn export_markdown(&mut self, stem: &str, markdown: &str) -> io::Result<PathBuf> {
        // Removing separators/dots prevents an export escaping its private folder.
        let stem: String = stem
            .chars()
            .filter(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_'))
            .take(200)
            .collect();
        let stem = if stem.is_empty() {
            wording::EXPORT_STEM
        } else {
            &stem
        };
        let mut suffix = 1;
        let result = (|| {
            let (path, file) = loop {
                let path = self.dir.join(numbered(stem, suffix, ".md"));
                match private_file(&path) {
                    Ok(file) => break (path, file),
                    Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
                        suffix = next_suffix(suffix)?
                    }
                    Err(error) => return Err(error),
                }
            };
            write_markdown(file, markdown)?;
            Ok(path)
        })();
        if let Err(error) = &result {
            remember_problem(&mut self.problem, stem, error);
        }
        result
    }

    /// Atomically replace `summary.md` through a private temporary file in this folder.
    /// Callers escape external values with `markdown` helpers before passing structure.
    /// An I/O failure preserves the previous report and the first `problem`.
    /// No output error stops packet processing; this function returns no error.
    pub fn write_summary(&mut self, markdown: &str) {
        let result = (|| {
            let mut suffix = 1;
            let (path, file) = loop {
                let path = self.dir.join(numbered(".summary", suffix, ".tmp"));
                match private_file(&path) {
                    Ok(file) => break (path, file),
                    Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
                        suffix = next_suffix(suffix)?
                    }
                    Err(error) => return Err(error),
                }
            };
            // Rename happens only after the complete write, so a viewer sees
            // either the previous report or the whole next one, never half a table.
            let result = write_markdown(file, markdown)
                .and_then(|()| fs::rename(&path, self.dir.join("summary.md")));
            if result.is_err() {
                let _ = fs::remove_file(&path);
            }
            result
        })();
        if let Err(error) = result {
            remember_problem(&mut self.problem, "summary.md", &error);
        }
    }
}

fn write_markdown(file: fs::File, markdown: &str) -> io::Result<()> {
    let mut writer = BufWriter::new(file);
    let result = (|| {
        // Structure and line breaks are trusted; remaining controls still need
        // escaping to prevent terminal injection when someone cats the report.
        for (index, line) in markdown.split('\n').enumerate() {
            if index > 0 {
                writer.write_all(b"\n")?;
            }
            // Callers already escape every external value. Keep only the fixed
            // microsecond unit while sanitising the rest of the assembled document.
            let line = line
                .split("µs")
                .map(|part| text::sanitise(part.as_bytes()))
                .collect::<Vec<_>>()
                .join("µs");
            writer.write_all(line.as_bytes())?;
        }
        writer.flush()
    })();
    // Do not retry a failed buffered write during Drop.
    let _ = writer.into_parts();
    result
}
