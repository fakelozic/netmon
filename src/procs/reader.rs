//! Bounded reads of procfs text.
//! Socket parsing stays in sockets.rs; this file does not interpret endpoints.
//! Read read_lines first for the limits applied to large tables.
//! Procfs socket tables describe kernel endpoints, rather than packet bytes.

use std::fs::File;
use std::io::{self, BufRead, BufReader, Read};
use std::path::Path;

// The 4 KiB ceiling bounds process names and each table line independently.
const MAX_SMALL_FILE_BYTES: usize = 4096;

/// Read up to 4 KiB; a missing or denied file returns its I/O error.
pub(super) fn read_small_file(path: &Path) -> io::Result<Vec<u8>> {
    let mut bytes = Vec::new();
    File::open(path)?
        .take(MAX_SMALL_FILE_BYTES as u64)
        .read_to_end(&mut bytes)?;
    Ok(bytes)
}

/// Bound both total input and individual lines, including malformed huge lines.
/// Tables are streamed; `comm` is the small file limited to 4 KiB in its entirety.
/// `remaining` counts lines across calls; read failures preserve prior visits.
pub(super) fn read_lines(path: &Path, remaining: &mut usize, mut visit: impl FnMut(&[u8])) {
    if *remaining == 0 {
        return;
    }
    let Ok(file) = File::open(path) else {
        return;
    };
    let max_bytes = (*remaining as u64).saturating_mul(MAX_SMALL_FILE_BYTES as u64);
    let mut reader = BufReader::new(file.take(max_bytes));
    let mut line = Vec::new();
    while *remaining > 0 {
        match read_bounded_line(&mut reader, &mut line) {
            Ok(Some(valid)) => {
                *remaining -= 1;
                if valid {
                    visit(&line);
                }
            }
            _ => break,
        }
    }
}

/// `Some(false)` consumes one overlong line without allocating for its tail.
fn read_bounded_line(reader: &mut impl BufRead, line: &mut Vec<u8>) -> io::Result<Option<bool>> {
    line.clear();
    let mut overlong = false;
    loop {
        let available = reader.fill_buf()?;
        if available.is_empty() {
            return Ok((!line.is_empty() || overlong).then_some(!overlong));
        }
        let newline = available.iter().position(|&byte| byte == b'\n');
        let length = newline.map_or(available.len(), |offset| offset + 1);
        if !overlong {
            if line.len().saturating_add(length) <= MAX_SMALL_FILE_BYTES {
                if let Some(bytes) = available.get(..length) {
                    line.extend_from_slice(bytes);
                }
            } else {
                line.clear();
                overlong = true;
            }
        }
        reader.consume(length);
        if newline.is_some() {
            if !overlong {
                line.pop();
            }
            return Ok(Some(!overlong));
        }
    }
}
