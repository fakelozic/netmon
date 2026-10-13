//! Runs the standalone standard-library embedding generator on temporary page files.
//! Static routing belongs to `src/web/routing_tests.rs`; no source-tree page is changed.
//! Read `embedding_and_fallback` first. Temporary inputs stay under Cargo's test folder.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

#[test]
fn embedding_and_fallback() {
    let root = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("web-embedding");
    if root.exists() {
        fs::remove_dir_all(&root).expect("old test inputs");
    }
    let out = root.join("generated");
    fs::create_dir_all(&out).expect("test output directory");
    let builder = root.join("builder");
    run(Command::new("rustc")
        .arg("--edition=2024")
        .arg("build.rs")
        .arg("-o")
        .arg(&builder));
    generate(&builder, &root, &out);
    let code = fs::read_to_string(out.join("web_assets.rs")).expect("fallback source");
    assert!(code.contains("crate::explain::web::UNBUILT_PAGE.as_bytes()"));
    check_compiles(
        &root,
        &out,
        "assert_eq!(FILES.len(), 1); assert_eq!(FILES[0].1, b\"fallback\");",
    );

    let dist = root.join("web/dist");
    fs::create_dir_all(dist.join("assets/fonts")).expect("page directory");
    generate(&builder, &root, &out);
    assert!(
        fs::read_to_string(out.join("web_assets.rs"))
            .unwrap()
            .contains("UNBUILT_PAGE")
    );
    fs::write(dist.join("index.html"), b"<p>test</p>").expect("HTML");
    fs::write(dist.join("assets/app.js"), b"app()").expect("script");
    fs::write(dist.join("assets/fonts/font.woff2"), b"font").expect("font");
    fs::write(dist.join("assets/bad..js"), b"skip").expect("unsafe name");
    fs::write(dist.join("assets/nonascii-µ.js"), b"skip").expect("non-ASCII name");
    fs::write(dist.join("assets/back\\slash.js"), b"skip").expect("backslash name");
    fs::File::create(dist.join("assets/oversized.bin"))
        .expect("sparse file")
        .set_len(8 * 1024 * 1024 + 1)
        .expect("oversized");
    fs::File::create(dist.join("assets/limit.bin"))
        .expect("boundary file")
        .set_len(8 * 1024 * 1024)
        .expect("exact bound");
    #[cfg(unix)]
    {
        std::os::unix::fs::symlink(root.join("builder"), dist.join("assets/link.bin"))
            .expect("file symlink");
        std::os::unix::fs::symlink(&out, dist.join("assets/linked-directory"))
            .expect("directory symlink");
    }
    generate(&builder, &root, &out);
    let code = fs::read_to_string(out.join("web_assets.rs")).expect("asset source");
    for key in [
        "index.html",
        "assets/app.js",
        "assets/fonts/font.woff2",
        "assets/limit.bin",
    ] {
        assert!(
            code.contains(&format!("({key:?}, include_bytes!(")),
            "{key}"
        );
    }
    for excluded in ["bad..", "nonascii", "back", "oversized", "link"] {
        assert!(!code.contains(excluded), "{excluded}");
    }
    check_compiles(
        &root,
        &out,
        "assert_eq!(FILES.len(), 4); assert_eq!(FILES[0].0, \"assets/app.js\"); assert_eq!(FILES[0].1, b\"app()\");",
    );
}

fn generate(builder: &Path, root: &Path, out: &Path) {
    let result = Command::new(builder)
        .env("CARGO_MANIFEST_DIR", root)
        .env("OUT_DIR", out)
        .output()
        .expect("run builder");
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    assert!(String::from_utf8_lossy(&result.stdout).contains("cargo:rerun-if-changed=web/dist"));
}

fn check_compiles(root: &Path, out: &Path, assertion: &str) {
    let source = root.join("check.rs");
    fs::write(&source, format!("mod explain {{ pub mod web {{ pub const UNBUILT_PAGE: &str = \"fallback\"; }} }} mod assets {{ include!({:?}); pub fn check() {{ {assertion} }} }} fn main() {{ assets::check(); }}", out.join("web_assets.rs"))).expect("check source");
    let binary = root.join("check");
    run(Command::new("rustc")
        .arg("--edition=2024")
        .arg(source)
        .arg("-o")
        .arg(&binary));
    run(&mut Command::new(binary));
}

fn run(command: &mut Command) {
    let output = command.output().expect("run tool");
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
}
