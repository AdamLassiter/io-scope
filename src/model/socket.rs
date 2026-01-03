#[derive(Debug, Clone, Default)]
pub struct SocketStats {
    pub read_calls: u64,
    pub write_calls: u64,
    pub read_bytes: u64,
    pub write_bytes: u64,
}
