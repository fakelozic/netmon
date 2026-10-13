//! Generates the exact-match table of files compiled into the web server.
//! Request routing belongs to `src/web/assets.rs`; page wording belongs to `explain`.
//! Read `main` first. Runtime requests never use these paths to read the disk.

use std::env;
use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};

// Cap each embedded file so a stray large capture cannot inflate the binary.
const MAX_FILE_BYTES: u64 = 8 * 1024 * 1024;

fn main() -> io::Result<()> {
    println!("cargo:rerun-if-changed=web/dist");
    let root = PathBuf::from(env::var_os("CARGO_MANIFEST_DIR").unwrap_or_else(|| ".".into()))
        .canonicalize()?;
    let dist = root.join("web/dist");
    let mut files = Vec::new();
    if dist.is_dir() && !fs::symlink_metadata(&dist)?.file_type().is_symlink() {
        collect(&dist, &dist, &mut files)?;
    }
    files.sort_by(|a, b| a.0.cmp(&b.0));
    let out_dir = env::var_os("OUT_DIR").ok_or(io::ErrorKind::NotFound)?;
    let mut out = fs::File::create(Path::new(&out_dir).join("web_assets.rs"))?;
    writeln!(out, "pub(super) const FILES: &[(&str, &[u8])] = &[")?;
    if !files.iter().any(|(key, _)| key == "index.html") {
        writeln!(
            out,
            "(\"index.html\", crate::explain::web::UNBUILT_PAGE.as_bytes()),"
        )?;
    }
    for (key, path) in files {
        let Some(path) = path.to_str() else {
            continue;
        };
        // Rust debug strings escape quotes and backslashes in build-time paths.
        writeln!(out, "({key:?}, include_bytes!({:?})),", path)?;
    }
    writeln!(out, "];")
}

fn collect(root: &Path, dir: &Path, files: &mut Vec<(String, PathBuf)>) -> io::Result<()> {
    for entry in fs::read_dir(dir)? {
        let path = entry?.path();
        let relative = path
            .strip_prefix(root)
            .map_err(|_| io::ErrorKind::InvalidInput)?;
        let Some(key) = relative.to_str() else {
            continue;
        };
        if !key.is_ascii()
            || key.contains("..")
            || key.contains('\\')
            || key.bytes().any(|byte| !(0x20..=0x7e).contains(&byte))
        {
            continue;
        }
        let metadata = fs::symlink_metadata(&path)?;
        // Do not follow symlinks: embedding must not escape the page's build folder.
        if metadata.file_type().is_symlink() {
            continue;
        }
        if metadata.is_dir() {
            collect(root, &path, files)?;
        } else if metadata.is_file() && metadata.len() <= MAX_FILE_BYTES {
            files.push((key.to_owned(), path));
        }
    }
    Ok(())
}
