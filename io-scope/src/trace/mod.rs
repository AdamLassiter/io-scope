// mod.rs
#[cfg(feature = "ebpf")]
pub mod ebpf;
pub mod ptrace;
pub mod socket;

use std::{
    fs::File,
    io::{BufRead, BufReader},
    os::fd::OwnedFd,
    sync::{Arc, Mutex},
    thread,
};

use anyhow::Result;

use crate::{
    agg::Aggregator,
    model::{
        agg::LiveState,
        cli::{Backend, RunConfig},
    },
};

pub trait TraceProvider<A: Aggregator> {
    fn run(
        &mut self,
        cfg: &RunConfig,
        agg: &mut A,
        live_state: Option<Arc<Mutex<LiveState>>>,
    ) -> Result<()>;
}

pub fn build_tracer<A: Aggregator>(
    backend: Backend,
) -> Result<Box<dyn TraceProvider<A> + Send + Sync>> {
    match backend {
        Backend::Ptrace => Ok(Box::new(ptrace::PtraceTracer::new())),
        #[cfg(feature = "ebpf")]
        Backend::Ebpf => Ok(Box::new(ebpf::EbpfTracer::new()?)),
    }
}

fn spawn_log_reader(fd: OwnedFd, state: Arc<Mutex<LiveState>>, is_stderr: bool) {
    thread::spawn(move || {
        let reader = BufReader::new(File::from(fd));

        for line in reader.lines() {
            let Ok(mut line) = line else { break };

            if is_stderr {
                line = format!("[stderr] {}", line);
            } else {
                line = format!("[stdout] {}", line);
            }

            let mut s = state.lock().unwrap();
            const MAX_LOG_LINES: usize = 200;
            if s.log_lines.len() >= MAX_LOG_LINES {
                s.log_lines.pop_front();
            }
            s.log_lines.push_back(line);
        }
    });
}
