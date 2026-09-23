use crate::cli::{Cli, ColorArg};
use cryptoknife_lib::{FileResult, FileStatus, RunSummary};
use indicatif::{ProgressBar, ProgressDrawTarget};
use std::io::{IsTerminal, Write};

fn status_label(status: FileStatus) -> &'static str {
  match status {
    FileStatus::Generated => "GENERATED",
    FileStatus::Matched => "OK",
    FileStatus::Mismatched => "FAILED",
    FileStatus::MissingData => "MISSING-DATA",
    FileStatus::MissingChecksum => "MISSING-CHECKSUM",
    FileStatus::InvalidChecksum => "INVALID-CHECKSUM",
    FileStatus::ReadError => "READ-ERROR",
    FileStatus::WriteError => "WRITE-ERROR",
    FileStatus::Skipped => "SKIPPED",
    FileStatus::Cancelled => "CANCELLED",
  }
}

fn status_json(status: FileStatus) -> &'static str {
  match status {
    FileStatus::Generated => "generated",
    FileStatus::Matched => "matched",
    FileStatus::Mismatched => "mismatched",
    FileStatus::MissingData => "missing_data",
    FileStatus::MissingChecksum => "missing_checksum",
    FileStatus::InvalidChecksum => "invalid_checksum",
    FileStatus::ReadError => "read_error",
    FileStatus::WriteError => "write_error",
    FileStatus::Skipped => "skipped",
    FileStatus::Cancelled => "cancelled",
  }
}

pub fn escape_display(text: &str) -> String {
  let mut out = String::with_capacity(text.len());
  for c in text.chars() {
    if c.is_control() {
      out.push_str(&format!("\\u{:04x}", c as u32));
    } else {
      out.push(c);
    }
  }
  out
}

fn status_color(status: FileStatus) -> &'static str {
  match status {
    FileStatus::Generated | FileStatus::Matched => "32",
    FileStatus::Skipped | FileStatus::Cancelled => "33",
    _ => "31",
  }
}

fn colored_label(status: FileStatus, use_color: bool) -> String {
  if use_color {
    format!(
      "\x1b[{}m{}\x1b[0m",
      status_color(status),
      status_label(status)
    )
  } else {
    status_label(status).to_string()
  }
}

fn color_enabled(arg: ColorArg, is_tty: bool) -> bool {
  match arg {
    ColorArg::Always => true,
    ColorArg::Never => false,
    ColorArg::Auto => is_tty && std::env::var_os("NO_COLOR").is_none(),
  }
}

pub struct Emitter {
  json: bool,
  quiet: bool,
  verbose: bool,
  payload_stdout: bool,
  use_color_stdout: bool,
  use_color_stderr: bool,
  progress: Option<ProgressBar>,
  pub log: Option<std::fs::File>,
}

impl Emitter {
  fn log_line(&mut self, line: &str) -> anyhow::Result<()> {
    if let Some(log) = &mut self.log {
      writeln!(log, "{}", line)?;
      log.flush()?;
    }
    Ok(())
  }

  pub fn result(&mut self, result: &FileResult) -> anyhow::Result<()> {
    if let Some(pb) = &self.progress {
      pb.inc(1);
    }
    if self.json {
      let mut event = serde_json::json!({
        "schema_version": 1,
        "type": "file",
        "path": result.path.to_string_lossy(),
        "algorithm": result.algorithm.name(),
        "status": status_json(result.status),
        "digest": result.digest,
        "message": result.message,
      });
      #[cfg(unix)]
      {
        use std::os::unix::ffi::OsStrExt;
        if result.path.as_os_str().to_str().is_none() {
          event["path_bytes_hex"] =
            serde_json::json!(hex::encode(result.path.as_os_str().as_bytes()));
        }
      }
      #[cfg(windows)]
      {
        use std::os::windows::ffi::OsStrExt;
        if result.path.as_os_str().to_str().is_none() {
          let wide: Vec<u16> = result.path.as_os_str().encode_wide().collect();
          event["path_wide"] = serde_json::json!(wide);
        }
      }
      let line = serde_json::to_string(&event)?;
      let stdout = std::io::stdout();
      let mut lock = stdout.lock();
      self.log_line(&line)?;
      writeln!(lock, "{}", line)?;
      return Ok(());
    }
    if self.quiet
      && matches!(
        result.status,
        FileStatus::Generated | FileStatus::Matched | FileStatus::Skipped
      )
    {
      return Ok(());
    }
    let success = matches!(result.status, FileStatus::Generated | FileStatus::Matched);
    let show = match result.status {
      FileStatus::Skipped => self.verbose && !self.quiet,
      _ if success => self.verbose && !self.quiet,
      _ => true,
    };
    if !show {
      return Ok(());
    }
    let tail = format!(
      " {}{}",
      escape_display(&result.path.display().to_string()),
      result
        .message
        .as_ref()
        .map(|m| format!(": {}", escape_display(m)))
        .unwrap_or_default()
    );
    let line = format!("[{}]{}", status_label(result.status), tail);
    self.log_line(&line)?;
    let to_stderr = !(success || result.status == FileStatus::Skipped) || self.payload_stdout;
    let use_color = if to_stderr {
      self.use_color_stderr
    } else {
      self.use_color_stdout
    };
    let display = format!("[{}]{}", colored_label(result.status, use_color), tail);
    if to_stderr {
      let stderr = std::io::stderr();
      let mut lock = stderr.lock();
      writeln!(lock, "{}", display)?;
    } else {
      let stdout = std::io::stdout();
      let mut lock = stdout.lock();
      writeln!(lock, "{}", display)?;
    }
    Ok(())
  }

  pub fn summary(&mut self, summary: &RunSummary) -> anyhow::Result<()> {
    if let Some(pb) = &self.progress {
      pb.finish_and_clear();
    }
    if self.json {
      let event = serde_json::json!({
        "schema_version": 1,
        "type": "summary",
        "selected": summary.selected,
        "succeeded": summary.succeeded,
        "mismatched": summary.mismatched,
        "missing": summary.missing,
        "errors": summary.errors,
        "skipped": summary.skipped,
        "cancelled": summary.cancelled,
        "exit_code": summary.exit_code(),
      });
      let line = serde_json::to_string(&event)?;
      let stdout = std::io::stdout();
      let mut lock = stdout.lock();
      self.log_line(&line)?;
      writeln!(lock, "{}", line)?;
      return Ok(());
    }
    if self.quiet {
      return Ok(());
    }
    let line = format!(
      "Resumo: {} selecionado(s), {} sucesso(s), {} divergente(s), {} ausente(s), {} erro(s), {} ignorado(s){}",
      summary.selected,
      summary.succeeded,
      summary.mismatched,
      summary.missing,
      summary.errors,
      summary.skipped,
      if summary.cancelled { ", cancelado" } else { "" }
    );
    self.log_line(&line)?;
    if self.payload_stdout {
      let stderr = std::io::stderr();
      let mut lock = stderr.lock();
      writeln!(lock, "{}", line)?;
    } else {
      let stdout = std::io::stdout();
      let mut lock = stdout.lock();
      writeln!(lock, "{}", line)?;
    }
    Ok(())
  }

  pub fn diagnostic(&mut self, message: &str) {
    let line = format!("Erro: {}", escape_display(message));
    let _ = writeln!(std::io::stderr().lock(), "{}", line);
    if let Err(e) = self.log_line(&line) {
      let _ = writeln!(
        std::io::stderr().lock(),
        "Erro: falha ao escrever arquivo de log: {}",
        e
      );
    }
  }
}

pub fn build_emitter(cli: &Cli, payload_stdout: bool) -> Emitter {
  let progress = if !cli.no_progress && !cli.quiet && !cli.json && std::io::stderr().is_terminal() {
    let pb = ProgressBar::new_spinner();
    pb.set_draw_target(ProgressDrawTarget::stderr());
    Some(pb)
  } else {
    None
  };
  Emitter {
    json: cli.json,
    quiet: cli.quiet,
    verbose: cli.verbose,
    payload_stdout,
    use_color_stdout: color_enabled(cli.color, std::io::stdout().is_terminal()),
    use_color_stderr: color_enabled(cli.color, std::io::stderr().is_terminal()),
    progress,
    log: None,
  }
}

#[cfg(test)]
mod tests {
  use super::*;
  use clap::Parser;

  #[test]
  fn json_summary_propagates_log_write_failure() {
    let cli = Cli::parse_from(["cryptoknife", "--json", "generate", "data.txt"]);
    let log = tempfile::NamedTempFile::new().unwrap();
    let mut emitter = build_emitter(&cli, false);
    emitter.log = Some(std::fs::File::open(log.path()).unwrap());
    let summary = RunSummary {
      selected: 1,
      succeeded: 1,
      ..RunSummary::default()
    };
    assert!(emitter.summary(&summary).is_err());
  }
}
