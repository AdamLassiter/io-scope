pub mod ptrace;
pub mod socket;

use std::sync::{Arc, Mutex};

use anyhow::{Result, bail};

use crate::{
    agg::Aggregator,
    model::{
        agg::LiveState,
        cli::{Backend, RunConfig},
    },
};

pub trait TraceProvider {
    fn run<A: Aggregator>(
        &mut self,
        cfg: &RunConfig,
        agg: &mut A,
        live_state: Option<Arc<Mutex<LiveState>>>,
    ) -> Result<()>;
}

pub fn build_tracer(backend: Backend) -> Result<Box<impl TraceProvider>> {
    match backend {
        Backend::Ptrace => Ok(Box::new(ptrace::PtraceTracer::new())),
        _ => {
            bail!("Selected backend is not implemented yet");
        }
    }
}
