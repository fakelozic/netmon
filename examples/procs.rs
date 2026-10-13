//! Diagnostic listing of the socket-owner snapshot.
//! Ownership rules stay in netmon::procs; this file only formats the result.
//! Read run first for the output format.
//! The endpoint pair names the local socket beside its peer, when connected.

use netmon::procs::{ProcTable, Transport, default_gateway, local_addresses};
use std::io::{self, Write};
use std::path::PathBuf;

fn run() -> io::Result<()> {
    let root = std::env::args_os()
        .nth(1)
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("/proc"));
    let table = ProcTable::scan(&root);
    let mut sockets: Vec<_> = table.iter().collect();
    sockets.sort_by_key(|&(transport, local, remote, owner)| (transport, local, remote, owner.pid));
    let mut out = io::BufWriter::new(io::stdout().lock());
    for (transport, local, remote, owner) in sockets {
        let transport = match transport {
            Transport::Tcp => "tcp",
            Transport::Udp => "udp",
        };
        writeln!(
            out,
            "{transport}\t{local}\t{remote}\t{}\t{}",
            owner.pid, owner.name
        )?;
    }
    writeln!(out, "addresses: {:?}", local_addresses(&root))?;
    writeln!(out, "gateway: {:?}", default_gateway(&root))?;
    out.flush()
}

fn main() -> io::Result<()> {
    // A consumer such as head can close stdout after a few rows; that is a
    // successful diagnostic read, not a reason to print an error to the terminal.
    match run() {
        Err(error) if error.kind() == io::ErrorKind::BrokenPipe => Ok(()),
        result => result,
    }
}
