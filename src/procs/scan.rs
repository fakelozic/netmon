//! Joins between socket inodes and process fd links.
//! Byte-order interpretation stays in sockets.rs; bounded reads stay in reader.rs.
//! Read scan first to follow the two-stage ownership join.
//! Several processes can hold descriptors for the same kernel socket.

use super::reader::{read_lines, read_small_file};
use super::sockets::parse_socket;
use super::{ProcInfo, ProcTable, SocketKey, Transport};
use crate::text::sanitise;
use std::collections::{BTreeSet, HashMap};
use std::fs::{self, DirEntry};
use std::io;
use std::path::Path;
use std::sync::Arc;

// The brief's table-row ceiling bounds both temporary rows and final endpoints.
const MAX_SOCKET_LINES: usize = 200_000;
// One global fd budget stops a process with many sockets from dominating a scan.
const MAX_FD_LINKS: usize = 100_000;
// Even processes with no fds must not allow an unbounded directory walk.
const MAX_PROCESS_ENTRIES: usize = 100_000;

type SocketRows = HashMap<u64, Vec<SocketKey>>;
type InodeOwners = HashMap<u64, Arc<ProcInfo>>;

/// Assemble only rows with visible owners; limits and access failures yield a partial table.
pub(super) fn scan(proc_root: &Path) -> ProcTable {
    let sockets = read_socket_tables(proc_root);
    let (inode_owners, unreadable) = read_owners(proc_root, &sockets);
    let mut table = ProcTable {
        owners: HashMap::new(),
        unreadable,
    };
    // Joining once per row avoids multiplying the work by duplicate fd links.
    for (inode, keys) in sockets {
        if let Some(owner) = inode_owners.get(&inode) {
            for key in keys {
                retain_preferred(&mut table.owners, key, owner);
            }
        }
    }
    table
}

fn read_socket_tables(proc_root: &Path) -> SocketRows {
    let mut sockets = HashMap::new();
    let mut remaining = MAX_SOCKET_LINES;
    for (file, transport, ipv6) in [
        ("tcp", Transport::Tcp, false),
        ("tcp6", Transport::Tcp, true),
        ("udp", Transport::Udp, false),
        ("udp6", Transport::Udp, true),
    ] {
        read_lines(&proc_root.join("net").join(file), &mut remaining, |line| {
            if let Some((inode, socket)) = parse_socket(line, transport, ipv6) {
                sockets.entry(inode).or_insert_with(Vec::new).push(socket);
            }
        });
    }
    sockets
}

fn read_owners(proc_root: &Path, sockets: &SocketRows) -> (InodeOwners, usize) {
    let mut owners = HashMap::new();
    let mut unreadable = 0;
    let Ok(processes) = fs::read_dir(proc_root) else {
        return (owners, unreadable);
    };
    let mut remaining = MAX_FD_LINKS;
    for process in processes.take(MAX_PROCESS_ENTRIES).flatten() {
        if remaining == 0 {
            break;
        }
        let name = process.file_name();
        let Some(pid) = name.to_str().and_then(parse_pid) else {
            continue;
        };
        let (held, mut inaccessible) = read_descriptors(&process, sockets, &mut remaining);
        if !held.is_empty() {
            match read_owner(&process, pid) {
                Ok(owner) => {
                    for inode in held {
                        retain_preferred(&mut owners, inode, &owner);
                    }
                }
                Err(error) => inaccessible |= count_unreadable(&error),
            }
        }
        unreadable += usize::from(inaccessible);
    }
    (owners, unreadable)
}

fn read_descriptors(
    process: &DirEntry,
    sockets: &SocketRows,
    remaining: &mut usize,
) -> (BTreeSet<u64>, bool) {
    let mut held = BTreeSet::new();
    let descriptors = match fs::read_dir(process.path().join("fd")) {
        Ok(entries) => entries,
        Err(error) => return (held, count_unreadable(&error)),
    };
    let mut inaccessible = false;
    for entry in descriptors.take(*remaining) {
        *remaining -= 1;
        let target = match entry.and_then(|entry| fs::read_link(entry.path())) {
            Ok(target) => target,
            Err(error) => {
                inaccessible |= count_unreadable(&error);
                continue;
            }
        };
        if let Some(inode) = target.to_str().and_then(parse_socket_link)
            && sockets.contains_key(&inode)
        {
            held.insert(inode);
        }
    }
    (held, inaccessible)
}

fn read_owner(process: &DirEntry, pid: u32) -> io::Result<Arc<ProcInfo>> {
    let mut bytes = read_small_file(&process.path().join("comm"))?;
    // Remove only the newline procfs appends; embedded controls must be escaped.
    if bytes.last() == Some(&b'\n') {
        bytes.pop();
    }
    Ok(Arc::new(ProcInfo {
        pid,
        name: sanitise(&bytes),
    }))
}

fn retain_preferred<K: Eq + std::hash::Hash>(
    owners: &mut HashMap<K, Arc<ProcInfo>>,
    key: K,
    owner: &Arc<ProcInfo>,
) {
    // PID 1 is a fallback holder. Let ordinary holders identify shared sockets,
    // then use the smallest PID so directory traversal order cannot choose it.
    match owners.get_mut(&key) {
        Some(previous) if (owner.pid == 1, owner.pid) < (previous.pid == 1, previous.pid) => {
            *previous = Arc::clone(owner);
        }
        None => {
            owners.insert(key, Arc::clone(owner));
        }
        _ => {}
    }
}

fn parse_pid(text: &str) -> Option<u32> {
    if text.is_empty() || !text.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    text.parse().ok().filter(|pid| *pid != 0)
}

fn parse_socket_link(text: &str) -> Option<u64> {
    let inode = text.strip_prefix("socket:[")?.strip_suffix(']')?;
    if inode.is_empty() || !inode.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    inode.parse().ok()
}

fn count_unreadable(error: &io::Error) -> bool {
    // Disappearance is normal in procfs; a regular fake fd file is malformed,
    // rather than an access failure. Other failures count once per process.
    !matches!(
        error.kind(),
        io::ErrorKind::NotFound | io::ErrorKind::InvalidInput
    )
}
