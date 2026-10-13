//! Check inert Markdown output and atomic report replacement.
//! JSON syntax and recording checks stay in their focused logging tests.
//! Read hostile_values_are_escaped_before_reaching_markdown_files first.

use crate::log_support::{START, TestDir, options};
use netmon::log::{
    EventKind, Session,
    markdown::{escape, fenced_block, table_row},
};
use std::{fs, os::unix::fs::PermissionsExt};

#[test]
fn hostile_values_are_escaped_before_reaching_markdown_files() {
    let values = [
        "<img src=x onerror=1>",
        "a|b",
        "`x`",
        "**bold**",
        "[link](http://example.invalid)",
        "![img](http://example.invalid/a.png)",
        "a\nb",
        "\\|`*_[]()<>&#!~",
    ];
    let base = TestDir::new();
    let mut session = Session::create(options(base.path()), START).unwrap();
    for value in values {
        session.event(START, EventKind::Note, value);
    }
    session.flush();
    let content = fs::read_to_string(session.dir().join("events.md")).unwrap();
    for value in values {
        assert!(content.contains(&escape(value)));
    }
    assert!(content.contains("&lt;img src=x onerror=1&gt;"));
    assert!(content.contains("a\\|b"));
    assert!(content.contains("\\`x\\`"));
    assert!(content.contains("\\*\\*bold\\*\\*"));
    assert!(content.contains("\\[link\\]\\(http&#58;//example.invalid\\)"));
    assert!(content.contains("\\!\\[img\\]\\(http&#58;//example.invalid/a.png\\)"));
    assert!(content.contains("a b"));
    assert!(!content.contains('<'));
    let row = table_row(&["a|b", "c\nd", "\\|"]);
    assert_eq!(row, "| a\\|b | c d | \\\\\\| |\n");
    assert_eq!(
        escape("See www.example.invalid or https://example.invalid or a@b.invalid"),
        "See www&#46;example.invalid or https&#58;//example.invalid or a&#64;b.invalid"
    );
}

#[test]
fn hostile_backtick_runs_cannot_close_export_fences() {
    let base = TestDir::new();
    let mut session = Session::create(options(base.path()), START).unwrap();
    for length in [3, 4, 5, 80] {
        let hostile = format!(
            "before\n{}\n![img](http://example.invalid/a.png)\n<img src=x onerror=1>\nafter",
            "`".repeat(length)
        );
        let block = fenced_block(&hostile);
        let opening = block.lines().next().unwrap().trim_end_matches("text");
        assert_eq!(opening.len(), length + 1);
        assert_eq!(block.lines().last().unwrap(), opening);
        assert_eq!(block.lines().filter(|line| *line == opening).count(), 1);
        assert!(!block.contains('<'));
        let path = session
            .export_markdown("fence", &format!("# Story\n\n{block}"))
            .unwrap();
        assert_eq!(
            fs::read_to_string(path).unwrap(),
            format!("# Story\n\n{block}")
        );
    }
}

#[test]
fn summary_replacement_is_private_complete_and_preserves_old_report_on_failure() {
    let base = TestDir::new();
    let mut session = Session::create(options(base.path()), START).unwrap();
    session.write_summary("# First\n\nAll present.\n");
    let target = session.dir().join("summary.md");
    fs::hard_link(&target, base.path().join("previous")).unwrap();
    session.write_summary("# Second\n\nAll replaced.\n");
    assert_eq!(
        fs::read_to_string(&target).unwrap(),
        "# Second\n\nAll replaced.\n"
    );
    assert_eq!(
        fs::read_to_string(base.path().join("previous")).unwrap(),
        "# First\n\nAll present.\n"
    );
    assert_eq!(
        fs::metadata(&target).unwrap().permissions().mode() & 0o777,
        0o600
    );
    fs::set_permissions(session.dir(), fs::Permissions::from_mode(0o500)).unwrap();
    session.write_summary("# Cannot replace\n");
    assert!(
        session
            .problem()
            .unwrap()
            .starts_with("Cannot write summary.md:")
    );
    assert_eq!(
        fs::read_to_string(&target).unwrap(),
        "# Second\n\nAll replaced.\n"
    );
    fs::set_permissions(session.dir(), fs::Permissions::from_mode(0o700)).unwrap();
    assert!(!fs::read_dir(session.dir()).unwrap().any(|entry| {
        entry
            .unwrap()
            .file_name()
            .to_string_lossy()
            .ends_with(".tmp")
    }));
}
