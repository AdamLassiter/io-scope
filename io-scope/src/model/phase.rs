use time::OffsetDateTime;

use crate::model::syscall::ResourceKind;

/// What type of IO dominates this phase.
#[derive(Debug, Clone, Copy, Eq, PartialEq, Hash)]
pub enum IoCategory {
    Disk,
    Network,
    Pipe,
    Tty,
    Mixed,
}

impl IoCategory {
    pub fn from_resource(kind: ResourceKind) -> Self {
        match kind {
            ResourceKind::File => IoCategory::Disk,
            ResourceKind::Socket => IoCategory::Network,
            ResourceKind::Pipe => IoCategory::Pipe,
            ResourceKind::Tty => IoCategory::Tty,
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            IoCategory::Disk => "Disk",
            IoCategory::Network => "Network",
            IoCategory::Pipe => "Pipe",
            IoCategory::Tty => "TTY",
            IoCategory::Mixed => "Mixed",
        }
    }
}

/// Pattern of IO activity.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum IoPattern {
    /// Many small operations (high call count, low bytes per call).
    Bursty,
    /// Fewer large operations (lower call count, high bytes per call).
    Streaming,
    /// Moderate mix.
    Balanced,
}

impl IoPattern {
    pub fn label(self) -> &'static str {
        match self {
            IoPattern::Bursty => "Bursty",
            IoPattern::Streaming => "Streaming",
            IoPattern::Balanced => "Balanced",
        }
    }
}

/// High-level phase classification.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum PhaseKind {
    /// Significant IO activity.
    Io {
        category: IoCategory,
        pattern: IoPattern,
    },
    /// Syscalls but minimal IO bytes (computation, metadata ops, etc.).
    Compute,
    /// Very low activity.
    Idle,
}

impl PhaseKind {
    pub fn label(&self) -> String {
        match self {
            PhaseKind::Io { category, pattern } => {
                format!("{} ({})", category.label(), pattern.label())
            }
            PhaseKind::Compute => "Compute".to_string(),
            PhaseKind::Idle => "Idle".to_string(),
        }
    }

    pub fn short_label(&self) -> &'static str {
        match self {
            PhaseKind::Io { category, .. } => category.label(),
            PhaseKind::Compute => "CPU",
            PhaseKind::Idle => "Idle",
        }
    }
}

#[derive(Debug, Clone)]
pub struct Phase {
    pub kind: PhaseKind,
    pub start: OffsetDateTime,
    pub end: OffsetDateTime,
    pub syscalls: u64,
    pub bytes: u64,
    pub avg_bytes_per_call: f64,
}