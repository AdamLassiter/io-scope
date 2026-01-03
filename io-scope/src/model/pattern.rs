#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum HintLevel {
    Info,
    Warn,
}

#[derive(Debug, Clone)]
pub struct PatternHint {
    pub level: HintLevel,
    pub title: String,
    pub detail: String,
}
