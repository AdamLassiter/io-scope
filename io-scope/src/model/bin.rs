use std::collections::HashMap;

use crate::model::{
    path::PathStats,
    socket::SocketStats,
    syscall::{ResourceKind, SyscallKind, SyscallStats},
};

/// Stats broken down by resource kind (disk, network, etc.)
#[derive(Debug, Clone, Default)]
pub struct IoByKind {
    pub calls: u64,
    pub bytes: u64,
}

/// A single time bucket capturing all stats for that interval.
#[derive(Debug, Clone, Default)]
pub struct TimeBin {
    pub syscalls: u64,
    pub bytes: u64,
    pub by_kind: HashMap<SyscallKind, SyscallStats>,
    pub by_path: HashMap<String, PathStats>,
    pub by_socket: HashMap<String, SocketStats>,
    pub by_resource: HashMap<ResourceKind, IoByKind>,
}

impl TimeBin {
    pub fn merge(&mut self, other: &TimeBin) {
        self.syscalls += other.syscalls;
        self.bytes += other.bytes;

        for (kind, stats) in &other.by_kind {
            let entry = self.by_kind.entry(*kind).or_default();
            entry.count += stats.count;
            entry.total_bytes += stats.total_bytes;
        }

        for (path, stats) in &other.by_path {
            let entry = self.by_path.entry(path.clone()).or_default();
            entry.bytes += stats.bytes;
            entry.reads += stats.reads;
            entry.writes += stats.writes;
            entry.opens += stats.opens;
            entry.closes += stats.closes;
        }

        for (peer, stats) in &other.by_socket {
            let entry = self.by_socket.entry(peer.clone()).or_default();
            entry.read_calls += stats.read_calls;
            entry.read_bytes += stats.read_bytes;
            entry.write_calls += stats.write_calls;
            entry.write_bytes += stats.write_bytes;
        }

        for (res_kind, io) in &other.by_resource {
            let entry = self.by_resource.entry(*res_kind).or_default();
            entry.calls += io.calls;
            entry.bytes += io.bytes;
        }
    }

    /// Average bytes per syscall in this bin (0 if no syscalls).
    pub fn avg_bytes_per_call(&self) -> f64 {
        if self.syscalls == 0 {
            0.0
        } else {
            self.bytes as f64 / self.syscalls as f64
        }
    }
}

/// Aggregated totals derived from bins.
#[derive(Debug, Clone, Default)]
pub struct AggregatedTotals {
    pub total_syscalls: u64,
    pub total_bytes: u64,
    pub by_kind: HashMap<SyscallKind, SyscallStats>,
    pub by_path: HashMap<String, PathStats>,
    pub by_socket: HashMap<String, SocketStats>,
    pub by_resource: HashMap<ResourceKind, IoByKind>,
}

impl AggregatedTotals {
    pub fn from_bins(bins: &[TimeBin]) -> Self {
        let mut result = TimeBin::default();
        for bin in bins {
            result.merge(bin);
        }
        AggregatedTotals {
            total_syscalls: result.syscalls,
            total_bytes: result.bytes,
            by_kind: result.by_kind,
            by_path: result.by_path,
            by_socket: result.by_socket,
            by_resource: result.by_resource,
        }
    }
}