mod cli;
mod output;

use clap::{CommandFactory, FromArgMatches};
use cli::{
  clap_color, same_path, validate_log_file, Cli, Commands, GenFormat, GenerateArgs, VerifyArgs,
  VerifyFormat,
};
use cryptoknife_lib::{
  atomic_write, compute_file_hash, compute_hash_stdin, generate_document, generate_with_options,
  normalize_lexical, verify_request, Algorithm, AtomicOutput, ChecksumFormat, FileResult,
  FileStatus, RunOptions, RunSummary, VerifyRequest,
};
use output::{build_emitter, escape_display, Emitter};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::atomic::Ordering;
use std::sync::Arc;

fn usage_error(message: &str) -> ExitCode {
  eprintln!("Erro: {}", escape_display(message));
  ExitCode::from(2)
}

fn path_is_dash(path: &Path) -> bool {
  path.as_os_str() == "-"
}

#[tokio::main]
async fn main() -> ExitCode {
  let matches = match Cli::command().color(clap_color()).try_get_matches() {
    Ok(m) => m,
    Err(e) => {
      let code = if e.use_stderr() { 2 } else { 0 };
      let _ = e.print();
      return ExitCode::from(code);
    }
  };
  let cli = match Cli::from_arg_matches(&matches) {
    Ok(cli) => cli,
    Err(e) => {
      e.exit();
    }
  };

  let cancelled = Arc::new(std::sync::atomic::AtomicBool::new(false));
  let options = RunOptions {
    algorithm: cli.algorithm.unwrap_or(Algorithm::BLAKE3),
    buffer_size: cli.buffer_size,
    jobs: cli.jobs,
    cancelled: cancelled.clone(),
    ..RunOptions::default()
  };
  if let Err(e) = options.validate() {
    return usage_error(&format!("{:#}", e));
  }

  let flag = cancelled.clone();
  tokio::spawn(async move {
    if tokio::signal::ctrl_c().await.is_ok() {
      flag.store(true, Ordering::Relaxed);
    }
  });

  match cli.command {
    Commands::Generate(ref args) => run_generate(&cli, args, options).await,
    Commands::Verify(ref args) => run_verify(&cli, args, options).await,
  }
}

fn open_log(cli: &Cli, emitter: &mut Emitter) -> Result<(), ExitCode> {
  if let Some(path) = &cli.log_file {
    match std::fs::OpenOptions::new()
      .create(true)
      .append(true)
      .open(path)
    {
      Ok(file) => {
        let file_handle = file
          .try_clone()
          .ok()
          .and_then(|f| same_file::Handle::from_file(f).ok());
        let identity_ok = match (same_file::Handle::from_path(path), file_handle) {
          (Ok(from_path), Some(from_file)) => from_path == from_file,
          (Err(_), Some(_)) => true,
          (_, None) => false,
        };
        let metadata_ok = std::fs::symlink_metadata(path)
          .map(|m| m.file_type().is_file() && !m.file_type().is_symlink())
          .unwrap_or(false);
        if !identity_ok || !metadata_ok {
          emitter.diagnostic(&format!(
            "Identidade do arquivo de log inválida: {}",
            path.display()
          ));
          return Err(ExitCode::from(3));
        }
        emitter.log = Some(file);
        Ok(())
      }
      Err(e) => {
        emitter.diagnostic(&format!(
          "Não foi possível abrir log {}: {}",
          path.display(),
          e
        ));
        Err(ExitCode::from(3))
      }
    }
  } else {
    Ok(())
  }
}

async fn run_generate(cli: &Cli, args: &GenerateArgs, mut options: RunOptions) -> ExitCode {
  let dashes = args.paths.iter().filter(|p| path_is_dash(p)).count();
  if dashes > 0 && args.paths.len() > 1 {
    return usage_error("'-' não pode ser combinado com outros caminhos");
  }
  let stdin_mode = dashes == 1;
  let format = args.format.unwrap_or(if stdin_mode {
    GenFormat::Raw
  } else {
    GenFormat::Sidecar
  });

  if let Some(log) = &cli.log_file {
    let mut protected = args.paths.clone();
    if let Some(out) = &args.output {
      if !path_is_dash(out) {
        protected.push(out.clone());
      }
    }
    for p in &args.paths {
      if path_is_dash(p) {
        continue;
      }
      if let Ok(sidecar) = cryptoknife_lib::checksum_path(p, options.algorithm) {
        protected.push(sidecar);
      }
    }
    let input_dirs: Vec<PathBuf> = args
      .paths
      .iter()
      .filter(|p| {
        std::fs::symlink_metadata(p)
          .map(|m| m.is_dir())
          .unwrap_or(false)
      })
      .cloned()
      .collect();
    if let Err(msg) = validate_log_file(log, &protected, &input_dirs) {
      eprintln!("Erro: {}", escape_display(&msg));
      return ExitCode::from(3);
    }
    options.excluded_paths.push(log.clone());
  }

  if stdin_mode {
    return run_generate_stdin(cli, args, format, options).await;
  }

  match format {
    GenFormat::Sidecar => {
      if args.output.is_some() {
        return usage_error("--output não é válido com formato sidecar");
      }
      if args.root.is_some() {
        return usage_error("--root não é válido com formato sidecar");
      }
      options.force = args.force;
      let mut emitter = build_emitter(cli, false);
      if let Err(code) = open_log(cli, &mut emitter) {
        return code;
      }
      let result = generate_with_options(&args.paths, &options, |r| emitter.result(r)).await;
      finish_run(emitter, result).await
    }
    GenFormat::Raw => run_generate_raw_file(cli, args, options).await,
    GenFormat::Manifest | GenFormat::Sfv => run_generate_document(cli, args, format, options).await,
  }
}

async fn run_generate_stdin(
  cli: &Cli,
  args: &GenerateArgs,
  format: GenFormat,
  options: RunOptions,
) -> ExitCode {
  if format != GenFormat::Raw {
    return usage_error("stdin só é suportado com formato raw");
  }
  if args.root.is_some() {
    return usage_error("--root não é válido com entrada stdin");
  }
  let cancelled = options.cancelled.clone();
  let buffer_size = options.buffer_size;
  let algorithm = options.algorithm;
  let payload_stdout = args
    .output
    .as_ref()
    .map(|o| path_is_dash(o))
    .unwrap_or(true);
  if cli.json && payload_stdout {
    return usage_error("--json não pode ser combinado com saída raw em stdout");
  }
  let mut emitter = build_emitter(cli, payload_stdout);
  if let Err(code) = open_log(cli, &mut emitter) {
    return code;
  }
  let hash_cancelled = cancelled.clone();
  let hash = tokio::task::spawn_blocking(move || {
    compute_hash_stdin(algorithm, buffer_size, &hash_cancelled)
  });
  let digest = tokio::select! {
    joined = hash => match joined {
      Ok(Ok(digest)) => digest,
      Ok(Err(e)) => {
        if cancelled.load(Ordering::Relaxed) {
          return ExitCode::from(130);
        }
        emitter.diagnostic(&format!("{:#}", e));
        return ExitCode::from(3);
      }
      Err(e) => {
        emitter.diagnostic(&format!("Tarefa falhou: {}", e));
        return ExitCode::from(3);
      }
    },
    _ = tokio::signal::ctrl_c() => {
      cancelled.store(true, Ordering::Relaxed);
      std::process::exit(130);
    }
  };
  if cancelled.load(Ordering::Relaxed) {
    return ExitCode::from(130);
  }
  match &args.output {
    Some(out) if !path_is_dash(out) => {
      if let Err(e) = atomic_write(
        out,
        format!("{}\n", digest).as_bytes(),
        args.force,
        &cancelled,
      ) {
        emitter.diagnostic(&format!("{:#}", e));
        return ExitCode::from(3);
      }
      let result =
        FileResult::new(out.clone(), algorithm, FileStatus::Generated).with_digest(digest);
      let mut summary = RunSummary::default();
      summary.record(&result);
      if let Err(e) = emitter
        .result(&result)
        .and_then(|_| emitter.summary(&summary))
      {
        emitter.diagnostic(&format!("{:#}", e));
        return ExitCode::from(3);
      }
      ExitCode::from(summary.exit_code())
    }
    _ => {
      let stdout = std::io::stdout();
      let mut lock = stdout.lock();
      if let Err(e) = writeln!(lock, "{}", digest).and_then(|_| lock.flush()) {
        emitter.diagnostic(&format!("{:#}", e));
        return ExitCode::from(3);
      }
      let mut summary = RunSummary::default();
      let result = FileResult::new(PathBuf::from("<stdin>"), algorithm, FileStatus::Generated)
        .with_digest(digest.clone());
      summary.record(&result);
      if let Err(e) = emitter.summary(&summary) {
        emitter.diagnostic(&format!("{:#}", e));
        return ExitCode::from(3);
      }
      ExitCode::from(summary.exit_code())
    }
  }
}

async fn run_generate_raw_file(cli: &Cli, args: &GenerateArgs, options: RunOptions) -> ExitCode {
  if args.paths.len() != 1 {
    return usage_error("formato raw requer exatamente um arquivo de entrada");
  }
  if args.root.is_some() {
    return usage_error("--root não é válido com formato raw");
  }
  let input = &args.paths[0];
  let metadata = match std::fs::symlink_metadata(input) {
    Ok(m) => m,
    Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
      eprintln!(
        "Erro: entrada inexistente {}",
        escape_display(&input.display().to_string())
      );
      return ExitCode::from(3);
    }
    Err(e) => return usage_error(&format!("Entrada inválida {}: {}", input.display(), e)),
  };
  if metadata.file_type().is_dir() {
    return usage_error("formato raw não aceita diretório como entrada");
  }
  if !metadata.file_type().is_file() {
    return usage_error("formato raw requer um arquivo regular");
  }
  let output = match &args.output {
    Some(o) => o.clone(),
    None => return usage_error("formato raw requer --output (ou '-' para stdout)"),
  };
  if !path_is_dash(&output) && same_path(&output, input) {
    return usage_error("Saída não pode coincidir com a entrada");
  }
  let to_stdout = path_is_dash(&output);
  if cli.json && to_stdout {
    return usage_error("--json não pode ser combinado com saída raw em stdout");
  }
  let mut emitter = build_emitter(cli, to_stdout);
  if let Err(code) = open_log(cli, &mut emitter) {
    return code;
  }
  let cancelled = options.cancelled.clone();
  let path = input.clone();
  let algorithm = options.algorithm;
  let buffer_size = options.buffer_size;
  let hash_cancelled = cancelled.clone();
  let hash = tokio::task::spawn_blocking(move || {
    compute_file_hash(&path, algorithm, buffer_size, &hash_cancelled)
  });
  let digest = tokio::select! {
    joined = hash => match joined {
      Ok(Ok(digest)) => digest,
      Ok(Err(e)) => {
        if cancelled.load(Ordering::Relaxed) {
          return ExitCode::from(130);
        }
        let result = FileResult::new(input.clone(), algorithm, FileStatus::ReadError)
          .with_message(format!("{:#}", e));
        let mut summary = RunSummary::default();
        summary.record(&result);
        let _ = emitter.result(&result);
        let _ = emitter.summary(&summary);
        return ExitCode::from(summary.exit_code());
      }
      Err(e) => {
        emitter.diagnostic(&format!("Tarefa falhou: {}", e));
        return ExitCode::from(3);
      }
    },
    _ = tokio::signal::ctrl_c() => {
      cancelled.store(true, Ordering::Relaxed);
      std::process::exit(130);
    }
  };
  if cancelled.load(Ordering::Relaxed) {
    return ExitCode::from(130);
  }
  let mut summary = RunSummary::default();
  if to_stdout {
    let stdout = std::io::stdout();
    let mut lock = stdout.lock();
    if let Err(e) = writeln!(lock, "{}", digest).and_then(|_| lock.flush()) {
      emitter.diagnostic(&format!("{:#}", e));
      return ExitCode::from(3);
    }
    let result =
      FileResult::new(input.clone(), algorithm, FileStatus::Generated).with_digest(digest);
    summary.record(&result);
  } else {
    match atomic_write(
      &output,
      format!("{}\n", digest).as_bytes(),
      args.force,
      &cancelled,
    ) {
      Ok(()) => {
        let result =
          FileResult::new(input.clone(), algorithm, FileStatus::Generated).with_digest(digest);
        summary.record(&result);
        if let Err(e) = emitter.result(&result) {
          emitter.diagnostic(&format!("{:#}", e));
          return ExitCode::from(3);
        }
      }
      Err(e) => {
        let result = FileResult::new(input.clone(), algorithm, FileStatus::WriteError)
          .with_message(format!("{:#}", e));
        summary.record(&result);
        let _ = emitter.result(&result);
      }
    }
  }
  if let Err(e) = emitter.summary(&summary) {
    emitter.diagnostic(&format!("{:#}", e));
    return ExitCode::from(3);
  }
  ExitCode::from(summary.exit_code())
}

async fn run_generate_document(
  cli: &Cli,
  args: &GenerateArgs,
  format: GenFormat,
  mut options: RunOptions,
) -> ExitCode {
  let doc_format = match format {
    GenFormat::Manifest => ChecksumFormat::Manifest,
    GenFormat::Sfv => ChecksumFormat::Sfv,
    _ => unreachable!(),
  };
  if doc_format == ChecksumFormat::Sfv && options.algorithm != Algorithm::CRC32 {
    return usage_error("formato sfv requer algoritmo crc32 (-a crc32)");
  }
  let output = match &args.output {
    Some(o) => o.clone(),
    None => return usage_error("formatos agregados requerem --output (ou '-' para stdout)"),
  };
  let to_stdout = path_is_dash(&output);
  if to_stdout && cli.json {
    return usage_error("--output - não pode ser combinado com --json");
  }
  let root = match &args.root {
    Some(r) => {
      let meta = std::fs::symlink_metadata(r);
      match meta {
        Ok(m) if m.is_dir() => r.clone(),
        _ => return usage_error(&format!("Raiz inválida: {}", r.display())),
      }
    }
    None => {
      if to_stdout {
        std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."))
      } else {
        output
          .parent()
          .map(|p| {
            if p.as_os_str().is_empty() {
              PathBuf::from(".")
            } else {
              p.to_path_buf()
            }
          })
          .unwrap_or_else(|| PathBuf::from("."))
      }
    }
  };
  for input in &args.paths {
    if !to_stdout && same_path(input, &output) {
      return usage_error("Saída não pode ser uma das entradas");
    }
    let normalized = normalize_lexical(input);
    if !normalized.starts_with(normalize_lexical(&root)) {
      return usage_error(&format!(
        "Entrada fora da raiz {}: {}",
        root.display(),
        input.display()
      ));
    }
  }
  options.force = args.force;
  if !to_stdout {
    options.excluded_paths.push(output.clone());
  }
  let mut emitter = build_emitter(cli, to_stdout);
  if let Err(code) = open_log(cli, &mut emitter) {
    return code;
  }
  let cancelled = options.cancelled.clone();
  let summary = if to_stdout {
    let stdout = std::io::stdout();
    let mut lock = stdout.lock();
    match generate_document(&args.paths, &options, doc_format, &root, &mut lock, |r| {
      emitter.result(r)
    })
    .await
    {
      Ok(summary) => summary,
      Err(e) => {
        emitter.diagnostic(&format!("{:#}", e));
        return ExitCode::from(3);
      }
    }
  } else {
    let mut out = match AtomicOutput::new(&output, args.force) {
      Ok(out) => out,
      Err(e) => {
        let result = FileResult::new(output.clone(), options.algorithm, FileStatus::WriteError)
          .with_message(format!("{:#}", e));
        let _ = emitter.result(&result);
        let mut summary = RunSummary::default();
        summary.record(&result);
        if let Err(e) = emitter.summary(&summary) {
          emitter.diagnostic(&format!("{:#}", e));
        }
        return ExitCode::from(3);
      }
    };
    let mut summary =
      match generate_document(&args.paths, &options, doc_format, &root, &mut out, |r| {
        emitter.result(r)
      })
      .await
      {
        Ok(summary) => summary,
        Err(e) => {
          emitter.diagnostic(&format!("{:#}", e));
          return ExitCode::from(3);
        }
      };
    if summary.exit_code() == 0 && !summary.cancelled {
      if let Err(e) = out.commit(&cancelled) {
        let result = FileResult::new(output.clone(), options.algorithm, FileStatus::WriteError)
          .with_message(format!("Erro ao publicar documento: {:#}", e));
        summary.record(&result);
        let _ = emitter.result(&result);
      }
    }
    summary
  };
  if let Err(e) = emitter.summary(&summary) {
    emitter.diagnostic(&format!("{:#}", e));
    return ExitCode::from(3);
  }
  ExitCode::from(summary.exit_code())
}

async fn run_verify(cli: &Cli, args: &VerifyArgs, mut options: RunOptions) -> ExitCode {
  let dashes = args.paths.iter().filter(|p| path_is_dash(p)).count();
  if dashes > 0 && args.paths.len() > 1 {
    return usage_error("'-' não pode ser combinado com outros caminhos");
  }
  let stdin_mode = dashes == 1;
  let stdin_format = if stdin_mode {
    match args.format {
      Some(VerifyFormat::Manifest) => Some(ChecksumFormat::Manifest),
      Some(VerifyFormat::Sfv) => Some(ChecksumFormat::Sfv),
      _ => return usage_error("verify '-' requer --format manifest ou sfv"),
    }
  } else {
    None
  };
  let forced_format = match args.format {
    Some(VerifyFormat::Manifest) => Some(ChecksumFormat::Manifest),
    Some(VerifyFormat::Sfv) => Some(ChecksumFormat::Sfv),
    _ => None,
  };

  if let Some(explicit) = cli.algorithm {
    for path in &args.paths {
      if path_is_dash(path) {
        continue;
      }
      if let Some(ext) = path.extension() {
        if ext == "ckmanifest" {
          continue;
        }
        if let Some(inferred) = Algorithm::from_extension(ext) {
          if inferred != explicit {
            return usage_error(&format!(
              "Algoritmo explícito {} conflita com a extensão de {}",
              explicit.name(),
              path.display()
            ));
          }
        }
      }
    }
  }

  let root = match &args.root {
    Some(r) => match std::fs::symlink_metadata(r) {
      Ok(m) if m.is_dir() => Some(r.clone()),
      _ => return usage_error(&format!("Raiz inválida: {}", r.display())),
    },
    None => None,
  };

  if let Some(log) = &cli.log_file {
    let mut protected = args.paths.clone();
    protected.retain(|p| !path_is_dash(p));
    let mut input_dirs: Vec<PathBuf> = protected
      .iter()
      .filter(|p| {
        std::fs::symlink_metadata(p)
          .map(|m| m.is_dir())
          .unwrap_or(false)
      })
      .cloned()
      .collect();
    for p in &args.paths {
      if path_is_dash(p) {
        continue;
      }
      let is_sidecar = p.extension().and_then(Algorithm::from_extension).is_some();
      if is_sidecar {
        if let Some(stem) = p.file_stem() {
          protected.push(p.with_file_name(stem));
        }
      } else if let Ok(sidecar) = cryptoknife_lib::checksum_path(p, options.algorithm) {
        protected.push(sidecar);
      }
      let is_doc = forced_format.is_some()
        || p
          .extension()
          .map(|e| e == "ckmanifest" || e == "sfv")
          .unwrap_or(false);
      if is_doc {
        let doc_root = root.clone().unwrap_or_else(|| {
          p.parent()
            .map(|d| {
              if d.as_os_str().is_empty() {
                PathBuf::from(".")
              } else {
                d.to_path_buf()
              }
            })
            .unwrap_or_else(|| PathBuf::from("."))
        });
        input_dirs.push(doc_root);
      }
    }
    if stdin_mode {
      input_dirs.push(
        root
          .clone()
          .or_else(|| std::env::current_dir().ok())
          .unwrap_or_else(|| PathBuf::from(".")),
      );
    }
    if let Err(msg) = validate_log_file(log, &protected, &input_dirs) {
      eprintln!("Erro: {}", escape_display(&msg));
      return ExitCode::from(3);
    }
    options.excluded_paths.push(log.clone());
  }

  let mut emitter = build_emitter(cli, false);
  if let Err(code) = open_log(cli, &mut emitter) {
    return code;
  }
  let paths: Vec<PathBuf> = args
    .paths
    .iter()
    .filter(|p| !path_is_dash(p))
    .cloned()
    .collect();
  let request = VerifyRequest {
    paths,
    stdin_format,
    forced_format,
    root,
  };
  match verify_request(&request, &options, |r| emitter.result(r)).await {
    Ok(summary) => {
      if let Err(e) = emitter.summary(&summary) {
        emitter.diagnostic(&format!("{:#}", e));
        return ExitCode::from(3);
      }
      ExitCode::from(summary.exit_code())
    }
    Err(e) => {
      emitter.diagnostic(&format!("{:#}", e));
      ExitCode::from(3)
    }
  }
}

async fn finish_run(mut emitter: Emitter, result: anyhow::Result<RunSummary>) -> ExitCode {
  match result {
    Ok(summary) => {
      if let Err(e) = emitter.summary(&summary) {
        emitter.diagnostic(&format!("{:#}", e));
        return ExitCode::from(3);
      }
      ExitCode::from(summary.exit_code())
    }
    Err(e) => {
      emitter.diagnostic(&format!("{:#}", e));
      ExitCode::from(3)
    }
  }
}
