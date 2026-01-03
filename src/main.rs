mod agg;
mod cli;
mod model;
mod trace;
mod ui;

use std::{
    sync::{Arc, Mutex},
    thread,
};

use anyhow::Result;
use clap::Parser;
use cli::Cli;
use trace::build_tracer;

use crate::{
    agg::{Aggregator, live::LiveAggregator},
    model::{
        agg::LiveState,
        cli::{RunConfig, RunMode},
    },
    trace::TraceProvider,
    ui::report,
};

fn main() -> Result<()> {
    let cli = Cli::parse();

    let (cmd, args) = split_command(cli.command);

    let config = RunConfig {
        cmd,
        args,
        backend: cli.backend,
        mode: if cli.live {
            RunMode::Live
        } else {
            RunMode::Summary
        },
    };

    match config.mode {
        RunMode::Summary => run_summary(config),
        RunMode::Live => run_live(config),
    }
}

fn split_command(mut command: Vec<String>) -> (String, Vec<String>) {
    let cmd = command.remove(0);
    (cmd, command)
}

fn run_summary(config: RunConfig) -> Result<()> {
    let mut tracer = build_tracer(config.backend)?;
    let mut agg = agg::summary::SummaryAggregator::new();

    tracer.run(&config, &mut agg, None)?;
    let mut summary = agg.finalize();

    summary.cmdline = std::iter::once(config.cmd.clone())
        .chain(config.args.clone())
        .collect::<Vec<_>>()
        .join(" ");

    report::print_summary(&summary);

    Ok(())
}

fn run_live(config: RunConfig) -> Result<()> {
    let state = Arc::new(Mutex::new(LiveState::default()));

    let state_for_agg = Arc::clone(&state);
    let mut tracer = build_tracer(config.backend)?;
    let cfg_clone = config.clone();

    let handle = thread::spawn(move || {
        let mut agg = LiveAggregator::new(state_for_agg.clone());
        if let Err(e) = tracer.run(&cfg_clone, &mut agg, Some(state_for_agg)) {
            eprintln!("tracer error: {e}");
        }
    });

    ui::live::run_live_tui(state)?;

    handle.join().ok();
    Ok(())
}
