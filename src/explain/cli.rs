//! Holds command-line help and validation messages.
//! Packet explanations belong to `super::sentence`; rendering belongs to `crate::render`.
//! Start with `HELP`.

/// Message shown when live viewing is requested before screen integration.
pub const LIVE_NOT_BUILT: &str = "the live view is not built yet; try: netmon explain <file>";
/// Command-line usage text, including its final newline.
pub const HELP: &str = "netmon explain <FILE|-> [--tsv | --fields | --packet N]\nnetmon glossary [TERM]\nnetmon --help | --version\n";
/// Validation message for a packet number below one.
pub const PACKET_NUMBER_ERROR: &str = "packet number must be at least 1";
/// Validation message for conflicting explain output modes.
pub const MODE_ERROR: &str = "choose only one of --tsv, --fields and --packet";
/// Validation message when explain has no capture input.
pub const FILE_ERROR: &str = "explain requires a capture file or - for standard input";
/// Validation message for an unrecognised subcommand.
pub const COMMAND_ERROR: &str = "unknown command";
