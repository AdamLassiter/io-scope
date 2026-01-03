use std::{
    collections::HashMap,
    io::{BufRead, BufReader},
};

use crate::model::syscall::ResourceKind;

#[derive(Debug, Clone)]
pub struct SocketEndpoint {
    proto: String,  // "tcp" or "udp"
    local: String,  // "ip:port"
    remote: String, // "ip:port"
}

pub type SocketTable = HashMap<u64, SocketEndpoint>;

fn classify_fd_path(path: &str) -> ResourceKind {
    if path.starts_with("socket:[") {
        ResourceKind::Socket
    } else if path.starts_with("pipe:[") {
        ResourceKind::Pipe
    } else if path.starts_with("/dev/pts/") || path.starts_with("/dev/tty") {
        ResourceKind::Tty
    } else {
        ResourceKind::File
    }
}

pub fn resolve_fd_info(
    pid: libc::pid_t,
    fd: i32,
    socket_table: &mut SocketTable,
) -> Option<(String, ResourceKind)> {
    let path_str = format!("/proc/{}/fd/{}", pid, fd);
    let link = std::fs::read_link(&path_str).ok()?;
    let target = link.to_string_lossy().to_string();

    let kind = classify_fd_path(&target);

    if kind == ResourceKind::Socket
        && let Some(peer) = map_socket_to_peer(&target, socket_table)
    {
        // peer already includes proto
        return Some((peer, ResourceKind::Socket));
    }

    Some((target, kind))
}

fn map_socket_to_peer(target: &str, socket_table: &mut SocketTable) -> Option<String> {
    // target is like "socket:[12345]"
    let inode = extract_socket_inode(target)?;
    if socket_table.is_empty() {
        *socket_table = load_socket_table();
    }
    if let Some(ep) = socket_table.get(&inode) {
        // We aggregate by remote endpoint; include proto.
        return Some(format!("{} {}", ep.proto, ep.remote));
    }
    None
}

fn extract_socket_inode(target: &str) -> Option<u64> {
    let start = target.find('[')? + 1;
    let end = target.find(']')?;
    target[start..end].parse::<u64>().ok()
}
fn load_socket_table() -> SocketTable {
    let mut table = SocketTable::new();
    load_proc_net("tcp", &mut table);
    load_proc_net("udp", &mut table);
    table
}

fn load_proc_net(proto: &str, table: &mut SocketTable) {
    let path = format!("/proc/net/{}", proto);
    let f = match std::fs::File::open(&path) {
        Ok(f) => f,
        Err(_) => return,
    };
    let reader = BufReader::new(f);

    for (i, line) in reader.lines().enumerate() {
        let line = match line {
            Ok(l) => l,
            Err(_) => continue,
        };
        if i == 0 {
            // header
            continue;
        }
        if let Some((local, remote, inode)) = parse_proc_net_line(&line) {
            let ep = SocketEndpoint {
                proto: proto.to_string(),
                local,
                remote,
            };
            table.insert(inode, ep);
        }
    }
}

// Very minimal parser for /proc/net/{tcp,udp} IPv4 lines.
fn parse_proc_net_line(line: &str) -> Option<(String, String, u64)> {
    // Fields are space-separated; we care about:
    // local_address (1), rem_address (2), inode (9) in typical layouts.
    let parts: Vec<&str> = line.split_whitespace().collect();
    if parts.len() < 10 {
        return None;
    }
    let local_hex = parts[1];
    let remote_hex = parts[2];
    let inode_str = parts[9];

    let local = hex_ip_port_to_string(local_hex)?;
    let remote = hex_ip_port_to_string(remote_hex)?;
    let inode = inode_str.parse::<u64>().ok()?;

    Some((local, remote, inode))
}

fn hex_ip_port_to_string(s: &str) -> Option<String> {
    // s like "0100007F:0035" (IP in little-endian hex, port hex)
    let mut parts = s.split(':');
    let ip_hex = parts.next()?;
    let port_hex = parts.next()?;

    if ip_hex.len() != 8 {
        return None;
    }
    let b0 = u8::from_str_radix(&ip_hex[6..8], 16).ok()?;
    let b1 = u8::from_str_radix(&ip_hex[4..6], 16).ok()?;
    let b2 = u8::from_str_radix(&ip_hex[2..4], 16).ok()?;
    let b3 = u8::from_str_radix(&ip_hex[0..2], 16).ok()?;
    let ip = format!("{}.{}.{}.{}", b0, b1, b2, b3);
    let port = u16::from_str_radix(port_hex, 16).ok()?;
    Some(format!("{}:{}", ip, port))
}
