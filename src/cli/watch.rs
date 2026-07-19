//! CLI handler for the `watch` subcommand.

use crate::config::WatchConfig;
use crate::pipeline::exit_codes;
use crate::watch::WatchError;
use anyhow::Result;

/// Run the watch command with the given configuration.
///
/// Exits the process with [`exit_codes::CHANGES_DETECTED`] (1) when the loop
/// stops because `--exit-on-change` observed a change; returns `Ok(())` (exit
/// 0) on a clean shutdown. Operational errors propagate as `Err` for `main()`
/// to map to exit 3. The gate exit mirrors how `main()` handles the other
/// verdict gates (`process::exit` on a non-zero code from the handler).
pub fn run_watch(config: WatchConfig) -> Result<()> {
    // Validate that all watch directories exist
    for dir in &config.watch_dirs {
        if !dir.is_dir() {
            return Err(WatchError::DirNotFound(dir.clone()).into());
        }
    }

    let exit_code = crate::watch::run_watch_loop(&config)?;
    if exit_code != exit_codes::SUCCESS {
        std::process::exit(exit_code);
    }
    Ok(())
}
