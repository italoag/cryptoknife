use crate::file_ops::{Discovery, FileDiscovery};
use crate::options::RunOptions;
use crate::report::{FileResult, FileStatus, RunSummary};
use anyhow::{anyhow, Result};
use futures::stream::{FuturesUnordered, StreamExt};
use std::path::PathBuf;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Duration;

/// Executa `worker` sobre os itens de `jobs` com concorrência limitada a
/// `options.jobs`, emitindo cada resultado na ordem de conclusão.
/// Um produtor dedicado em `std::thread` alimenta um canal com capacidade
/// igual a `jobs` e verifica o cancelamento antes de cada `next()`; erros do
/// callback sinalizam cancelamento, encerram o agendamento e aguardam apenas
/// as tarefas ativas antes de propagar. O produtor não é unido quando o
/// cancelamento pode tê-lo deixado bloqueado em E/S; caso contrário é unido
/// para propagar panics.
pub(crate) async fn run_jobs<I, T, W, F>(
  jobs: I,
  options: &RunOptions,
  worker: W,
  mut on_result: F,
) -> Result<RunSummary>
where
  I: Iterator<Item = (PathBuf, T)> + Send + 'static,
  T: Send + 'static,
  W: Fn(T, &RunOptions) -> FileResult + Send + Sync + 'static,
  F: FnMut(&FileResult) -> Result<()>,
{
  options.validate()?;
  let cancelled = options.cancelled.clone();
  let algorithm = options.algorithm;
  let worker = Arc::new(worker);

  let (tx, mut rx) = tokio::sync::mpsc::channel::<(PathBuf, T)>(options.jobs.max(1));
  let producer_flag = cancelled.clone();
  let producer = std::thread::spawn(move || {
    let mut jobs = jobs;
    loop {
      if producer_flag.load(Ordering::Relaxed) {
        break;
      }
      match jobs.next() {
        Some(item) => {
          if tx.blocking_send(item).is_err() {
            break;
          }
        }
        None => break,
      }
    }
  });

  let mut active = FuturesUnordered::new();
  let mut summary = RunSummary::default();
  let mut callback_error: Option<anyhow::Error> = None;
  let mut producer_open = true;
  let mut tick = tokio::time::interval(Duration::from_millis(10));
  tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

  loop {
    if !producer_open && active.is_empty() {
      break;
    }
    if cancelled.load(Ordering::Relaxed) {
      rx.close();
      producer_open = false;
    }
    tokio::select! {
      _ = tick.tick() => {}
      item = rx.recv(), if producer_open && active.len() < options.jobs && !cancelled.load(Ordering::Relaxed) => match item {
        Some((path, job)) => {
          let worker = worker.clone();
          let opts = options.clone();
          active.push(async move {
            let joined = tokio::task::spawn_blocking(move || worker(job, &opts)).await;
            (path, joined)
          });
        }
        None => producer_open = false,
      },
      completed = active.next(), if !active.is_empty() => {
        if let Some((path, joined)) = completed {
          let result = match joined {
            Ok(r) => r,
            Err(e) => FileResult::new(path, algorithm, FileStatus::ReadError)
              .with_message(format!("Tarefa falhou: {}", e)),
          };
          summary.record(&result);
          if callback_error.is_none() {
            if let Err(e) = on_result(&result) {
              cancelled.store(true, Ordering::Relaxed);
              rx.close();
              producer_open = false;
              callback_error = Some(e);
            }
          }
        }
      }
    }
  }

  if !cancelled.load(Ordering::Relaxed) && producer.join().is_err() {
    return Err(anyhow!("Produtor de trabalhos falhou"));
  }
  if cancelled.load(Ordering::Relaxed) {
    summary.cancelled = true;
  }
  if let Some(e) = callback_error {
    return Err(e);
  }
  Ok(summary)
}

/// Executa `worker` sobre os arquivos descobertos em `paths` respeitando
/// `options.excluded_paths`, convertendo eventos de descoberta em resultados.
pub(crate) async fn run<W, F>(
  paths: &[PathBuf],
  options: &RunOptions,
  worker: W,
  on_result: F,
) -> Result<RunSummary>
where
  W: Fn(PathBuf, &RunOptions) -> FileResult + Send + Sync + 'static,
  F: FnMut(&FileResult) -> Result<()>,
{
  let jobs = FileDiscovery::new(paths, &options.excluded_paths).map(|item| {
    let path = match &item {
      Discovery::File(p) | Discovery::Skipped(p) | Discovery::Failed(p, _) => p.clone(),
    };
    (path, item)
  });
  run_jobs(
    jobs,
    options,
    move |item, options| match item {
      Discovery::File(path) => worker(path, options),
      Discovery::Skipped(path) => {
        FileResult::new(path, options.algorithm, FileStatus::Skipped).with_message("Item ignorado")
      }
      Discovery::Failed(path, e) => FileResult::new(path, options.algorithm, FileStatus::ReadError)
        .with_message(format!("{:#}", e)),
    },
    on_result,
  )
  .await
}

#[cfg(test)]
mod tests {
  use super::*;
  use crate::algorithms::compute_file_hash;
  use std::sync::atomic::{AtomicBool, AtomicUsize};
  use std::sync::Arc;

  #[tokio::test]
  async fn test_jobs_parity() {
    let dir = tempfile::tempdir().unwrap();
    for i in 0..8 {
      std::fs::write(dir.path().join(format!("f{}.txt", i)), format!("data{}", i)).unwrap();
    }
    let mut runs: Vec<Vec<(String, String)>> = Vec::new();
    for jobs in [1usize, 4] {
      let options = RunOptions {
        jobs,
        ..RunOptions::default()
      };
      let mut results = Vec::new();
      run(
        &[dir.path().to_path_buf()],
        &options,
        |path, opts| match compute_file_hash(
          &path,
          opts.algorithm,
          opts.buffer_size,
          &opts.cancelled,
        ) {
          Ok(digest) => {
            FileResult::new(path, opts.algorithm, FileStatus::Generated).with_digest(digest)
          }
          Err(e) => FileResult::new(path, opts.algorithm, FileStatus::ReadError)
            .with_message(format!("{:#}", e)),
        },
        |r| {
          results.push((
            r.path
              .file_name()
              .map(|n| n.to_string_lossy().to_string())
              .unwrap_or_default(),
            r.digest.clone().unwrap_or_default(),
          ));
          Ok(())
        },
      )
      .await
      .unwrap();
      results.sort();
      runs.push(results);
    }
    assert_eq!(runs[0].len(), 8);
    assert_eq!(runs[0], runs[1]);
  }

  #[tokio::test]
  async fn test_preset_cancel_stops_iterator_pulls() {
    let pulls = Arc::new(AtomicUsize::new(0));
    let counted = {
      let pulls = pulls.clone();
      (0..10).map(move |i| {
        pulls.fetch_add(1, Ordering::Relaxed);
        (PathBuf::from(format!("f{}", i)), i)
      })
    };
    let options = RunOptions {
      cancelled: Arc::new(AtomicBool::new(true)),
      ..RunOptions::default()
    };
    let summary = run_jobs(
      counted,
      &options,
      |i, opts| {
        FileResult::new(
          PathBuf::from(format!("f{}", i)),
          opts.algorithm,
          FileStatus::Generated,
        )
      },
      |_| Ok(()),
    )
    .await
    .unwrap();
    assert!(summary.cancelled);
    assert_eq!(pulls.load(Ordering::Relaxed), 0);
  }

  #[tokio::test]
  async fn test_active_workers_bounded_by_jobs() {
    let running = Arc::new(AtomicUsize::new(0));
    let max_seen = Arc::new(AtomicUsize::new(0));
    let running_w = running.clone();
    let max_w = max_seen.clone();
    let options = RunOptions {
      jobs: 2,
      ..RunOptions::default()
    };
    let summary = run_jobs(
      (0..40).map(|i| (PathBuf::from(format!("f{}", i)), i)),
      &options,
      move |i, opts| {
        let now = running_w.fetch_add(1, Ordering::Relaxed) + 1;
        max_w.fetch_max(now, Ordering::Relaxed);
        std::thread::sleep(Duration::from_millis(5));
        running_w.fetch_sub(1, Ordering::Relaxed);
        FileResult::new(
          PathBuf::from(format!("f{}", i)),
          opts.algorithm,
          FileStatus::Generated,
        )
      },
      |_| Ok(()),
    )
    .await
    .unwrap();
    assert_eq!(summary.succeeded, 40);
    assert!(max_seen.load(Ordering::Relaxed) <= 2);
  }

  #[tokio::test]
  async fn test_callback_failure_bounds_pulls() {
    let pulls = Arc::new(AtomicUsize::new(0));
    let counted = {
      let pulls = pulls.clone();
      (0..64).map(move |i| {
        pulls.fetch_add(1, Ordering::Relaxed);
        (PathBuf::from(format!("f{}", i)), i)
      })
    };
    let options = RunOptions {
      jobs: 2,
      ..RunOptions::default()
    };
    let result = run_jobs(
      counted,
      &options,
      |i, opts| {
        FileResult::new(
          PathBuf::from(format!("f{}", i)),
          opts.algorithm,
          FileStatus::Generated,
        )
      },
      |_| anyhow::bail!("stop"),
    )
    .await;
    assert!(result.is_err());
    assert!(pulls.load(Ordering::Relaxed) <= 2 * 2 + 2);
  }
}
