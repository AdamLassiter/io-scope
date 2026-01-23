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
    is_running: bool,
}

impl LiveAggregator {
    pub fn new(state: Arc<Mutex<LiveState>>) -> Self {
        Self {
            inner: SummaryAggregator::new(),
            state,
            last_sample_time: None,
            last_sample_syscalls: 0,
            sample_interval: Duration::milliseconds(100),
            max_samples: 40,
            is_running: false,
        }
    }

    fn update_state(&mut self, now: OffsetDateTime) {
        // Extend bins to current time (fills gaps with empty bins)
        self.inner.extend_bins_to(now);

        let snapshot = self.inner.snapshot();
        let total_syscalls = snapshot.total_syscalls;

        let mut s = self.state.lock().unwrap();

        // Rate sampling
        if let Some(last_t) = self.last_sample_time {
            let dt = now - last_t;
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
                self.last_sample_time = Some(now);
                self.last_sample_syscalls = total_syscalls;
            }
        } else {
            self.last_sample_time = Some(now);
            self.last_sample_syscalls = total_syscalls;
        }

        s.summary = Some(snapshot);
    }
}

impl Aggregator for LiveAggregator {
    type Output = Arc<Mutex<LiveState>>;

    fn on_start(&mut self) {
        self.is_running = true;
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
        self.update_state(event.ts);
    }

    fn on_dropped(&mut self, count: u64) {
        self.inner.on_dropped(count);
    }

    fn on_end(&mut self) {
        self.is_running = false;
        self.inner.on_end();

        let mut s = self.state.lock().unwrap();
        s.summary = Some(self.inner.snapshot());
    }

    fn tick(&mut self) {
        if !self.is_running {
            return;
        }

        let now = OffsetDateTime::now_utc();
        self.update_state(now);
    }

    fn finalize(self) -> Self::Output {
        self.state
    }
}