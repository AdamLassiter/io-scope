use std::sync::{Arc, Mutex};

use time::{Duration, OffsetDateTime};

use crate::{
    agg::{Aggregator, summary::SummaryAggregator},
    model::{agg::LiveState, syscall::SyscallEvent},
};

pub struct LiveAggregator {
    inner: SummaryAggregator,
    state: Arc<Mutex<LiveState>>,
    last_sample_time: Option<OffsetDateTime>,
    last_sample_syscalls: u64,
    sample_interval: Duration,
    max_samples: usize,
}

impl LiveAggregator {
    pub fn new(state: Arc<Mutex<LiveState>>) -> Self {
        Self {
            inner: SummaryAggregator::new(),
            state,
            last_sample_time: None,
            last_sample_syscalls: 0,
            sample_interval: Duration::milliseconds(500),
            max_samples: 40,
        }
    }

    fn update_summary_snapshot(&self) {
        let snapshot = self.inner.snapshot();
        let mut s = self.state.lock().unwrap();
        s.summary = Some(snapshot);
    }

    fn update_rate_history(&mut self, event_ts: OffsetDateTime) {
        let summary = self.inner.snapshot(); // cheap enough at 500ms cadence
        let total_syscalls = summary.total_syscalls;

        let mut s = self.state.lock().unwrap();

        if let Some(last_t) = self.last_sample_time {
            let dt = event_ts - last_t;
            if dt >= self.sample_interval {
                let dt_secs = dt.whole_microseconds() as f64 / 1_000_000.0;
                if dt_secs > 0.0 {
                    let delta = (total_syscalls - self.last_sample_syscalls) as f64;
                    let rate = delta / dt_secs;
                    s.last_rate = rate;

                    if s.rate_history.len() >= self.max_samples {
                        s.rate_history.pop_front();
                    }
                    s.rate_history.push_back(rate);
                }

                self.last_sample_time = Some(event_ts);
                self.last_sample_syscalls = total_syscalls;
            }
        } else {
            // first sample anchor
            self.last_sample_time = Some(event_ts);
            self.last_sample_syscalls = total_syscalls;
        }

        // Store snapshot too (we just computed it)
        s.summary = Some(summary);
    }
}

impl Aggregator for LiveAggregator {
    type Output = Arc<Mutex<LiveState>>;

    fn on_start(&mut self) {
        self.inner.on_start();

        let mut s = self.state.lock().unwrap();
        s.summary = Some(self.inner.snapshot());
        s.rate_history.clear();
        s.last_rate = 0.0;
        s.log_lines.clear();

        self.last_sample_time = None;
        self.last_sample_syscalls = 0;
    }

    fn on_event(&mut self, event: &SyscallEvent) {
        self.inner.on_event(event);
        // Update rate history and summary at a low-ish cadence
        self.update_rate_history(event.ts);
    }

    fn on_end(&mut self) {
        self.inner.on_end();
        self.update_summary_snapshot();
    }

    fn finalize(self) -> Self::Output {
        self.state
    }
}
