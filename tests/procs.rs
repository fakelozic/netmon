//! Entry point for socket ownership integration tests.
//! Focused cases live under procs_support; this file only registers them.
//! Read procs_support/mod.rs first for the fake procfs layout.
//! Kernel fd links tie process identifiers to socket inodes.

mod procs_support;
