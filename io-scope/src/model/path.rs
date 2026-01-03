#[derive(Debug, Clone, Default)]
pub struct PathStats {
    pub bytes: u64,
    pub reads: u64,
    pub writes: u64,
    pub opens: u64,
    pub closes: u64,
}
