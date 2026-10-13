//! Checks reviewed packet listings and field explanations.
//! Synthetic packet parsing belongs to `netmon::decode`; output belongs to `netmon::render`.
//! Start with `reviewed_listings_and_packet_details`.

use netmon::{
    capture::Reader,
    render::{Mode, Renderer},
};
use std::{fs, path::Path};

#[test]
fn reviewed_listings_and_packet_details() {
    let mut cases = vec![
        (
            "loopback-mixed.pcapng",
            Mode::Default,
            "loopback-list.txt".into(),
        ),
        ("cooked-any.pcapng", Mode::Default, "cooked-list.txt".into()),
    ];
    for n in [10, 14, 17, 20, 57, 73, 75] {
        cases.push((
            "loopback-mixed.pcapng",
            Mode::Packet(n),
            format!("packet-{n}.txt"),
        ));
    }
    for (file, mode, golden) in cases {
        let reader = Reader::open(&Path::new("tests/fixtures").join(file)).unwrap();
        let mut renderer = Renderer::new(Vec::new(), mode).unwrap();
        for raw in reader {
            renderer.write_packet(&raw.unwrap()).unwrap();
        }
        let output = String::from_utf8(renderer.into_inner()).unwrap();
        let path = Path::new("tests/golden").join(golden);
        // Packet wording can be blessed independently while listings continue to detect sentence changes.
        if matches!(mode, Mode::Packet(_))
            && std::env::var_os("NETMON_BLESS").as_deref() == Some(std::ffi::OsStr::new("1"))
        {
            fs::create_dir_all("tests/golden").unwrap();
            fs::write(&path, &output).unwrap();
        }
        let expected = fs::read_to_string(&path)
            .unwrap_or_else(|e| panic!("{}: {e}; set NETMON_BLESS=1 to generate", path.display()));
        assert_eq!(output, expected, "{}", path.display());
    }
}
