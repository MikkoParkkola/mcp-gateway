// SPDX-FileCopyrightText: 2026 Mikko Parkkola
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
//! Watch-mode implementation for `mcp-gateway setup export`.
//!
//! Monitors `config_path` for file-system changes and re-exports client
//! configs whenever the file is modified, using a 500 ms debounce.

use std::path::Path;

use mcp_gateway::{cli::ConnectionMode, config::Config};

use super::{ExportTarget, build_gateway_entry, client_specs, export_one};

/// Watch `config_path` for changes and re-export whenever it is modified.
///
/// Uses the `notify` crate (already required for hot-reload) with a 500 ms
/// debounce to suppress event storms.
pub(super) async fn run_watch_loop(
    target: ExportTarget,
    mode: ConnectionMode,
    name: &str,
    config_path: &Path,
) {
    use notify::{Event, RecursiveMode, Watcher, recommended_watcher};
    use std::sync::mpsc;
    use std::time::{Duration, Instant};

    println!();
    println!(
        "Watching {} for changes (Ctrl+C to stop)...",
        config_path.display()
    );

    let (tx, rx) = mpsc::channel::<notify::Result<Event>>();
    let mut watcher = match recommended_watcher(tx) {
        Ok(w) => w,
        Err(e) => {
            eprintln!("Warning: Cannot start file watcher: {e}");
            return;
        }
    };

    let watch_path = if config_path.is_absolute() {
        config_path.to_path_buf()
    } else {
        std::env::current_dir()
            .unwrap_or_default()
            .join(config_path)
    };

    if let Err(e) = watcher.watch(&watch_path, RecursiveMode::NonRecursive) {
        eprintln!("Warning: Cannot watch {}: {e}", watch_path.display());
        return;
    }

    let debounce = Duration::from_millis(500);
    let mut last_event: Option<Instant> = None;

    loop {
        match rx.recv_timeout(Duration::from_millis(100)) {
            Ok(Ok(_event)) => {
                last_event = Some(Instant::now());
            }
            Ok(Err(e)) => {
                eprintln!("Watch error: {e}");
            }
            Err(mpsc::RecvTimeoutError::Timeout) => {}
            Err(mpsc::RecvTimeoutError::Disconnected) => break,
        }

        if let Some(t) = last_event
            && t.elapsed() >= debounce
        {
            last_event = None;
            let now = chrono::Local::now().format("%H:%M:%S");
            println!(
                "[{now}] {} changed — regenerating...",
                config_path.display()
            );

            match Config::load(Some(config_path)) {
                Ok(config) => {
                    let entry = build_gateway_entry(&config, Some(config_path), mode);
                    let specs = client_specs(target);
                    let mut updated = 0usize;
                    for spec in specs {
                        match export_one(&spec, name, &entry, false) {
                            super::ExportAction::Created | super::ExportAction::Updated => {
                                println!("  {}: Updated", spec.label);
                                updated += 1;
                            }
                            super::ExportAction::Skipped(_) => {}
                            super::ExportAction::Failed(e) => {
                                eprintln!("  {}: FAILED — {e}", spec.label);
                            }
                        }
                    }
                    println!("[{now}] Done ({updated} client(s) updated).");
                }
                Err(e) => eprintln!("  Cannot reload config: {e}"),
            }
        }
    }
}
