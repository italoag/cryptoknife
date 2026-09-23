use crate::algorithms::{validate_buffer_size, Algorithm, DEFAULT_BUFFER_SIZE};
use anyhow::{bail, Result};
use std::path::PathBuf;
use std::sync::atomic::AtomicBool;
use std::sync::Arc;

pub const MAX_JOBS: usize = 64;
pub const MAX_AGGREGATE_MEMORY: usize = 256 * 1024 * 1024;

#[derive(Clone, Debug)]
pub struct RunOptions {
  pub algorithm: Algorithm,
  pub buffer_size: usize,
  pub jobs: usize,
  pub force: bool,
  pub excluded_paths: Vec<PathBuf>,
  pub cancelled: Arc<AtomicBool>,
}

impl Default for RunOptions {
  fn default() -> Self {
    RunOptions {
      algorithm: Algorithm::BLAKE3,
      buffer_size: DEFAULT_BUFFER_SIZE,
      jobs: std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(1)
        .clamp(1, 4),
      force: false,
      excluded_paths: Vec::new(),
      cancelled: Arc::new(AtomicBool::new(false)),
    }
  }
}

impl RunOptions {
  pub fn validate(&self) -> Result<()> {
    validate_buffer_size(self.buffer_size)?;
    if self.jobs == 0 || self.jobs > MAX_JOBS {
      bail!(
        "Número de jobs inválido: {} (permitido: 1..={})",
        self.jobs,
        MAX_JOBS
      );
    }
    let aggregate = self
      .jobs
      .checked_mul(self.buffer_size)
      .ok_or_else(|| anyhow::anyhow!("Uso agregado de memória excede o limite"))?;
    if aggregate > MAX_AGGREGATE_MEMORY {
      bail!(
        "Uso agregado de memória {} bytes excede o limite de {} bytes",
        aggregate,
        MAX_AGGREGATE_MEMORY
      );
    }
    Ok(())
  }
}
