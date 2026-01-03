use clap::ValueEnum;

#[derive(Debug, Clone, Copy, ValueEnum)]
pub enum Backend {
    Ptrace,
    Ebpf,
}

#[derive(Debug, Clone, Copy)]
pub enum RunMode {
    Summary,
    Live,
}

#[derive(Debug, Clone)]
pub struct RunConfig {
    pub cmd: String,
    pub args: Vec<String>,
    pub backend: Backend,
    pub mode: RunMode,
}
