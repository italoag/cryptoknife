use crate::algorithms::{compute_file_hash, Algorithm};
use crate::execute;
use crate::file_ops::{atomic_write, checksum_path, normalize_lexical};
use crate::formats::{
  manifest_checksum_line, manifest_end_line, manifest_header_line, portable_rel_path, sfv_line,
  ChecksumFormat,
};
use crate::options::RunOptions;
use crate::report::{FileResult, FileStatus, RunSummary};
use anyhow::{bail, Context, Result};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::atomic::Ordering;

fn is_checksum_like(path: &Path) -> bool {
  path
    .extension()
    .map(|ext| {
      Algorithm::from_extension(ext).is_some() || ext == crate::formats::MANIFEST_EXTENSION
    })
    .unwrap_or(false)
}

fn generate_file(path: PathBuf, options: &RunOptions) -> FileResult {
  let algorithm = options.algorithm;
  if options.cancelled.load(Ordering::Relaxed) {
    return FileResult::new(path, algorithm, FileStatus::Cancelled)
      .with_message("Operação cancelada");
  }
  if is_checksum_like(&path) {
    return FileResult::new(path, algorithm, FileStatus::Skipped)
      .with_message("Arquivo de checksum ignorado");
  }
  generate_data_file(path, options)
}

fn generate_data_file(path: PathBuf, options: &RunOptions) -> FileResult {
  let algorithm = options.algorithm;
  let digest = match compute_file_hash(&path, algorithm, options.buffer_size, &options.cancelled) {
    Ok(digest) => digest,
    Err(e) => {
      let status = if options.cancelled.load(Ordering::Relaxed) {
        FileStatus::Cancelled
      } else {
        FileStatus::ReadError
      };
      return FileResult::new(path, algorithm, status).with_message(format!("{:#}", e));
    }
  };
  // Nome do arquivo de checksum: <nome_original>.<extensão>
  let output_file = match checksum_path(&path, algorithm) {
    Ok(p) => p,
    Err(e) => {
      return FileResult::new(path, algorithm, FileStatus::WriteError)
        .with_message(format!("{:#}", e))
    }
  };
  if output_file == path {
    return FileResult::new(path, algorithm, FileStatus::WriteError)
      .with_message("Destino colide com a origem");
  }
  // Para CRC32, grava o sidecar convencional "nome CRC32"; quando o nome não
  // é representável em SFV, recai para o digest isolado.
  let content = if algorithm == Algorithm::CRC32 {
    match path.file_name().and_then(|n| n.to_str()) {
      Some(name) if crate::formats::validate_sfv_name(name).is_ok() => {
        format!("{} {}\n", name, digest.to_uppercase())
      }
      _ => format!("{}\n", digest),
    }
  } else {
    format!("{}\n", digest)
  };
  match atomic_write(
    &output_file,
    content.as_bytes(),
    options.force,
    &options.cancelled,
  ) {
    Ok(()) => FileResult::new(path, algorithm, FileStatus::Generated).with_digest(digest),
    Err(e) => {
      let status = if options.cancelled.load(Ordering::Relaxed) {
        FileStatus::Cancelled
      } else {
        FileStatus::WriteError
      };
      FileResult::new(path, algorithm, status).with_message(format!("{:#}", e))
    }
  }
}

/// Gera arquivos de checksum para cada arquivo de dados encontrado.
/// Para cada arquivo (seja individual ou em diretório), é criado um arquivo com o mesmo nome acrescido da extensão do algoritmo.
/// O tamanho do buffer usado nas leituras vem de `options.buffer_size`.
pub async fn generate_with_options<F>(
  paths: &[PathBuf],
  options: &RunOptions,
  on_result: F,
) -> Result<RunSummary>
where
  F: FnMut(&FileResult) -> Result<()>,
{
  execute::run(paths, options, generate_file, on_result).await
}

fn document_rel(path: &Path, root: &Path, canonical_root: &Path) -> Result<String> {
  let canonical = path
    .canonicalize()
    .with_context(|| format!("Não foi possível resolver {}", path.display()))?;
  if !canonical.starts_with(canonical_root) {
    bail!(
      "Entrada fora da raiz do documento {}: {}",
      canonical_root.display(),
      path.display()
    );
  }
  let normalized_root = normalize_lexical(root);
  let rel = normalize_lexical(path)
    .strip_prefix(&normalized_root)
    .map_err(|_| anyhow::anyhow!("Entrada fora da raiz lexical {}", root.display()))?
    .to_path_buf();
  if rel.as_os_str().is_empty() {
    bail!("Entrada coincide com a raiz do documento");
  }
  let mut current = normalized_root;
  for component in rel.components() {
    current.push(component.as_os_str());
    if let Ok(metadata) = std::fs::symlink_metadata(&current) {
      if metadata.file_type().is_symlink() {
        bail!(
          "Componente symlink não permitido em documento: {}",
          current.display()
        );
      }
    }
  }
  portable_rel_path(&rel)
}

fn hash_document_file(
  path: PathBuf,
  options: &RunOptions,
  root: &Path,
  canonical_root: &Path,
) -> FileResult {
  let algorithm = options.algorithm;
  if options.cancelled.load(Ordering::Relaxed) {
    return FileResult::new(path, algorithm, FileStatus::Cancelled)
      .with_message("Operação cancelada");
  }
  if is_checksum_like(&path) {
    return FileResult::new(path, algorithm, FileStatus::Skipped)
      .with_message("Arquivo de checksum ignorado");
  }
  if let Err(e) = document_rel(&path, root, canonical_root) {
    return FileResult::new(path, algorithm, FileStatus::WriteError)
      .with_message(format!("{:#}", e));
  }
  match compute_file_hash(&path, algorithm, options.buffer_size, &options.cancelled) {
    Ok(digest) => FileResult::new(path, algorithm, FileStatus::Generated).with_digest(digest),
    Err(e) => {
      let status = if options.cancelled.load(Ordering::Relaxed) {
        FileStatus::Cancelled
      } else {
        FileStatus::ReadError
      };
      FileResult::new(path, algorithm, status).with_message(format!("{:#}", e))
    }
  }
}

/// Processa os arquivos sob `paths` e emite um documento agregado
/// (manifesto JSONL ou SFV) com digests relativos a `root` diretamente em
/// `writer`. O footer só é escrito quando o resumo é integralmente bem
/// sucedido; falhas de escrita cancelam o trabalho restante.
pub async fn generate_document<W: Write, F>(
  paths: &[PathBuf],
  options: &RunOptions,
  format: ChecksumFormat,
  root: &Path,
  writer: &mut W,
  mut on_result: F,
) -> Result<RunSummary>
where
  F: FnMut(&FileResult) -> Result<()>,
{
  options.validate()?;
  if format == ChecksumFormat::Raw {
    bail!("Formato raw não agrega múltiplos arquivos");
  }
  if format == ChecksumFormat::Sfv && options.algorithm != Algorithm::CRC32 {
    bail!("Formato SFV requer algoritmo CRC32");
  }
  let canonical_root = root
    .canonicalize()
    .with_context(|| format!("Raiz do documento inválida: {}", root.display()))?;
  if !canonical_root.is_dir() {
    bail!("Raiz do documento não é um diretório: {}", root.display());
  }
  let root = root.to_path_buf();

  if format == ChecksumFormat::Manifest && !options.cancelled.load(Ordering::Relaxed) {
    writer
      .write_all(manifest_header_line()?.as_bytes())
      .context("Erro ao escrever header do documento")?;
  }

  let mut count: u64 = 0;
  let mut convert_errors: u64 = 0;
  let mut write_failed = false;
  let writer_ref = &mut *writer;
  let emit = |result: &FileResult,
              writer: &mut W,
              convert_errors: &mut u64,
              count: &mut u64,
              write_failed: &mut bool|
   -> FileResult {
    if result.status != FileStatus::Generated {
      return result.clone();
    }
    let digest = result.digest.clone().unwrap_or_default();
    let rel = match document_rel(&result.path, &root, &canonical_root) {
      Ok(rel) => rel,
      Err(e) => {
        *convert_errors += 1;
        return FileResult::new(
          result.path.clone(),
          result.algorithm,
          FileStatus::WriteError,
        )
        .with_message(format!("{:#}", e));
      }
    };
    let line = match format {
      ChecksumFormat::Manifest => manifest_checksum_line(&rel, result.algorithm, &digest),
      ChecksumFormat::Sfv => sfv_line(&rel, &digest),
      ChecksumFormat::Raw => unreachable!(),
    };
    match line {
      Ok(line) => match writer.write_all(line.as_bytes()) {
        Ok(()) => {
          *count += 1;
          result.clone()
        }
        Err(e) => {
          *write_failed = true;
          *convert_errors += 1;
          FileResult::new(
            result.path.clone(),
            result.algorithm,
            FileStatus::WriteError,
          )
          .with_message(format!("Erro ao escrever documento: {}", e))
        }
      },
      Err(e) => {
        *convert_errors += 1;
        FileResult::new(
          result.path.clone(),
          result.algorithm,
          FileStatus::WriteError,
        )
        .with_message(format!("{:#}", e))
      }
    }
  };

  let mut emit_wrapper = |result: &FileResult| -> Result<()> {
    if options.cancelled.load(Ordering::Relaxed) {
      return on_result(result);
    }
    let final_result = emit(
      result,
      writer_ref,
      &mut convert_errors,
      &mut count,
      &mut write_failed,
    );
    on_result(&final_result)?;
    if write_failed {
      bail!("Erro ao escrever documento");
    }
    Ok(())
  };

  let worker_root = root.clone();
  let worker_canonical = canonical_root.clone();
  let mut summary = execute::run(
    paths,
    options,
    move |path, options| hash_document_file(path, options, &worker_root, &worker_canonical),
    &mut emit_wrapper,
  )
  .await?;

  summary.succeeded = summary.succeeded.saturating_sub(convert_errors);
  summary.errors += convert_errors;
  if format == ChecksumFormat::Manifest && !summary.cancelled && summary.exit_code() == 0 {
    match manifest_end_line(count)
      .and_then(|line| writer.write_all(line.as_bytes()).map_err(|e| e.into()))
    {
      Ok(()) => {}
      Err(e) => {
        let result = FileResult::new(
          PathBuf::from("<documento>"),
          options.algorithm,
          FileStatus::WriteError,
        )
        .with_message(format!("Erro ao escrever footer: {:#}", e));
        summary.record(&result);
        on_result(&result)?;
      }
    }
  }
  writer.flush()?;
  Ok(summary)
}

/// Gera arquivos de checksum para cada arquivo de dados encontrado.
/// Para cada arquivo (seja individual ou em diretório), é criado um arquivo com o mesmo nome acrescido da extensão do algoritmo.
/// O parâmetro `buffer_size` define o tamanho do buffer usado para leituras.
pub async fn generate_checksums(
  paths: &[PathBuf],
  algorithm: Algorithm,
  _verbose: bool,
  buffer_size: usize,
) -> Result<()> {
  let options = RunOptions {
    algorithm,
    buffer_size,
    ..RunOptions::default()
  };
  let summary = generate_with_options(paths, &options, |_| Ok(())).await?;
  if summary.exit_code() != 0 {
    bail!(
      "Geração concluída com falhas: {} erro(s), {} ignorado(s)",
      summary.errors,
      summary.skipped
    );
  }
  Ok(())
}

#[cfg(test)]
mod tests {
  use super::*;
  use crate::formats::ChecksumFormat;
  use crate::options::RunOptions;
  use std::io;
  use std::sync::atomic::AtomicBool;
  use std::sync::Arc;

  fn opts(algorithm: Algorithm) -> RunOptions {
    RunOptions {
      algorithm,
      ..RunOptions::default()
    }
  }

  #[tokio::test]
  async fn document_rejects_sfv_non_crc32_without_output() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("a.txt"), "x").unwrap();
    let mut out: Vec<u8> = Vec::new();
    let result = generate_document(
      &[dir.path().to_path_buf()],
      &opts(Algorithm::BLAKE3),
      ChecksumFormat::Sfv,
      dir.path(),
      &mut out,
      |_| Ok(()),
    )
    .await;
    assert!(result.is_err());
    assert!(out.is_empty());
  }

  #[tokio::test]
  async fn document_rejects_non_dir_root_without_output() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("a.txt"), "x").unwrap();
    let file_root = dir.path().join("a.txt");
    let mut out: Vec<u8> = Vec::new();
    let result = generate_document(
      std::slice::from_ref(&file_root),
      &opts(Algorithm::BLAKE3),
      ChecksumFormat::Manifest,
      &file_root,
      &mut out,
      |_| Ok(()),
    )
    .await;
    assert!(result.is_err());
    assert!(out.is_empty());
  }

  struct FailingWriter;

  impl Write for FailingWriter {
    fn write(&mut self, _buf: &[u8]) -> io::Result<usize> {
      Err(io::Error::new(io::ErrorKind::BrokenPipe, "falha forçada"))
    }
    fn flush(&mut self) -> io::Result<()> {
      Ok(())
    }
  }

  #[tokio::test]
  async fn document_writer_failure_returns_err() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("a.txt"), "x").unwrap();
    let mut writer = FailingWriter;
    let mut events = Vec::new();
    let result = generate_document(
      &[dir.path().to_path_buf()],
      &opts(Algorithm::CRC32),
      ChecksumFormat::Sfv,
      dir.path(),
      &mut writer,
      |event| {
        events.push(event.status);
        Ok(())
      },
    )
    .await;
    assert!(result.is_err());
    assert_eq!(events, vec![FileStatus::WriteError]);
  }

  struct FailAfterHeader(Vec<u8>);

  impl Write for FailAfterHeader {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
      if self.0.contains(&b'\n') {
        return Err(io::Error::new(io::ErrorKind::BrokenPipe, "record rejected"));
      }
      self.0.extend_from_slice(buf);
      Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
      Ok(())
    }
  }

  #[tokio::test]
  async fn document_record_write_failure_has_no_footer() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("a.txt"), "hello world").unwrap();
    let mut writer = FailAfterHeader(Vec::new());
    let mut events = Vec::new();
    let result = generate_document(
      &[dir.path().to_path_buf()],
      &opts(Algorithm::BLAKE3),
      ChecksumFormat::Manifest,
      dir.path(),
      &mut writer,
      |event| {
        events.push(event.status);
        Ok(())
      },
    )
    .await;
    assert!(result.is_err());
    assert_eq!(events, vec![FileStatus::WriteError]);
    assert_eq!(writer.0, manifest_header_line().unwrap().as_bytes());
  }

  #[tokio::test]
  async fn document_cancel_from_callback_stops_payload_and_footer() {
    let dir = tempfile::tempdir().unwrap();
    for name in ["a", "b", "c", "d"] {
      std::fs::write(dir.path().join(name), "hello world").unwrap();
    }
    let options = opts(Algorithm::BLAKE3);
    let mut output = Vec::new();
    let mut events = Vec::new();
    let summary = generate_document(
      &[dir.path().to_path_buf()],
      &options,
      ChecksumFormat::Manifest,
      dir.path(),
      &mut output,
      |event| {
        events.push(event.status);
        options.cancelled.store(true, Ordering::Relaxed);
        Ok(())
      },
    )
    .await
    .unwrap();
    let lines: Vec<serde_json::Value> = String::from_utf8(output)
      .unwrap()
      .lines()
      .map(|line| serde_json::from_str(line).unwrap())
      .collect();
    assert_eq!(summary.exit_code(), 130);
    assert_eq!(summary.selected as usize, events.len());
    assert_eq!(lines.len(), 2);
    assert_eq!(lines[1]["type"], "checksum");
  }

  #[tokio::test]
  async fn document_preset_cancel_writes_nothing() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("a.txt"), "x").unwrap();
    let cancelled = Arc::new(AtomicBool::new(true));
    let options = RunOptions {
      algorithm: Algorithm::BLAKE3,
      cancelled,
      ..RunOptions::default()
    };
    let mut out: Vec<u8> = Vec::new();
    let summary = generate_document(
      &[dir.path().to_path_buf()],
      &options,
      ChecksumFormat::Manifest,
      dir.path(),
      &mut out,
      |_| Ok(()),
    )
    .await
    .unwrap();
    assert!(summary.cancelled);
    assert!(out.is_empty());
  }
}
