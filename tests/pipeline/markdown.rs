//! Check hostile network/process names in generated Markdown files.
//! Helper syntax checks belong to tests/log/markdown.rs.
//! Read hostile_names_stay_inert_in_events_summary_and_exports first.

use crate::pipeline_support::{
    proc::{fake_proc, ready},
    *,
};
use netmon::{explain::pipeline::story_markdown, log::markdown, pipeline::Pipeline};
use std::{fs, time::Duration};

#[test]
fn hostile_names_stay_inert_in_events_summary_and_exports() {
    for name in [
        "<img src=x onerror=1>",
        "a|b",
        "`x`",
        "**bold**",
        "[link](http://example.invalid)",
        "![img](http://example.invalid/a.png)",
        "a\nb",
        "```",
    ] {
        let base = TestDir::new();
        let root = fake_proc(&base, name);
        let mut opts = options(Some(&base));
        opts.proc_root = Some(root);
        let mut pipeline = ready(Pipeline::new(opts, Duration::ZERO));
        pipeline.push(&dns(1_000_000, false, name, 0));
        pipeline.push(&dns(1_000_001, true, name, 0));
        let request = format!("GET / HTTP/1.1\r\nHost: {name}\r\n\r\n");
        let row = pipeline.push(&tcp(
            1_000_002,
            false,
            [40000, 80],
            0x18,
            request.as_bytes(),
        ));
        let flow = pipeline.tracker().flow(row.flow.unwrap()).unwrap();
        let story = story_markdown(
            flow,
            pipeline.tracker().names(),
            pipeline.app_of(flow.id).map(|owner| owner.name.as_str()),
        );
        pipeline
            .session_mut()
            .unwrap()
            .export_markdown("story", &story)
            .unwrap();
        pipeline.finish();
        let dir = pipeline.session().unwrap().dir();
        for entry in fs::read_dir(dir).unwrap() {
            let path = entry.unwrap().path();
            let content = fs::read_to_string(&path).unwrap();
            assert!(!content.contains('<'), "{}: {content}", path.display());
            if path.extension().is_some_and(|ext| ext == "md") {
                check_tables(&content);
                if path.file_name().unwrap() != "story.md" {
                    assert!(!content.contains("[link](http://"));
                    assert!(!content.contains("![img](http://"));
                }
            }
        }
        let events = fs::read_to_string(dir.join("events.md")).unwrap();
        let sanitised = netmon::text::sanitise(name.as_bytes());
        assert!(events.contains(&markdown::escape(&sanitised)));
        let summary = fs::read_to_string(dir.join("summary.md")).unwrap();
        assert!(summary.contains(&markdown::escape(&sanitised)));
    }
}
