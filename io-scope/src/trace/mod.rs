#![cfg(feature = "ebpf")]
pub mod ebpf;
pub mod ptrace;
pub mod socket;

use std::sync::{Arc, Mutex};

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

pub fn build_tracer<A: Aggregator>(backend: Backend) -> Result<Box<dyn TraceProvider<A> + Send + Sync>> {
    match backend {
        Backend::Ptrace => Ok(Box::new(ptrace::PtraceTracer::new())),
        #[cfg(feature = "ebpf")]
        Backend::Ebpf => Ok(Box::new(ebpf::EbpfTracer::new()?)),
    }
}
