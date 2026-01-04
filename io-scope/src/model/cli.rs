use clap::{Parser, ValueEnum};

#[derive(Parser, Debug)]
#[command(
    name = "io-scope",
    about = "Syscall / I/O profiler (ptrace MVP)",
    long_about = None,
    trailing_var_arg = true
)]
pub struct Cli {
    /// Use live TUI view (currently falls back to summary)
    #[arg(long)]
    pub live: bool,

    /// Select tracing backend (only ptrace is implemented for now)
    #[arg(long, value_enum, default_value_t = Backend::Ptrace)]
    pub backend: Backend,

    /// Command (and its arguments) to run and trace.
    #[arg(required = true)]
    pub command: Vec<String>,
}


#[derive(Debug, Clone, Copy, ValueEnum)]
pub enum Backend {
    Ptrace,
    #[cfg(feature = "ebpf")]
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
