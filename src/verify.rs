use crate::algorithms::{compute_file_hash, compute_hash_from_handle, Algorithm};
use crate::execute;
use crate::file_ops::{checksum_path, normalize_lexical, Discovery, FileDiscovery};
use crate::formats::{
  parse_sidecar, ChecksumFormat, ManifestIter, SfvIter, MANIFEST_EXTENSION, MAX_SIDECAR_SIZE,
};
use crate::options::RunOptions;
use crate::report::{FileResult, FileStatus, RunSummary};
use anyhow::{bail, Result};
use cap_std::fs::Dir;
use std::collections::{HashMap, VecDeque};
use std::ffi::OsStr;
use std::io::{BufReader, Read};
use std::path::{Path, PathBuf};
use std::sync::atomic::Ordering;
use std::sync::Arc;

enum DocKind {
  Manifest(ManifestIter<BufReader<Box<dyn Read + Send>>>),
  Sfv(SfvIter<BufReader<Box<dyn Read + Send>>>),
}

impl Iterator for DocKind {
  type Item = Result<crate::formats::ChecksumEntry>;
  fn next(&mut self) -> Option<Self::Item> {
    match self {
      DocKind::Manifest(it) => it.next(),
      DocKind::Sfv(it) => it.next(),
    }
  }
}

struct ActiveDoc {
  iter: DocKind,
  root: Arc<Dir>,
  root_path: PathBuf,
  origin: PathBuf,
}

enum VerifyJob {
  Task(VerifyTask),
  Done(FileResult),
}

enum VerifyTask {
  Sidecar {
    data: PathBuf,
    algorithm: Algorithm,
    expected: Vec<u8>,
  },
  ManifestEntry {
    rel: PathBuf,
    display: PathBuf,
    algorithm: Algorithm,
    expected: Vec<u8>,
    root: Arc<Dir>,
  },
}

/// Pedido de verificação: caminhos de dados/checksums/diretórios, documento
/// agregado opcional via stdin e raiz de confinamento para entradas de
/// manifesto/SFV.
#[derive(Default)]
pub struct VerifyRequest {
  pub paths: Vec<PathBuf>,
  pub stdin_format: Option<ChecksumFormat>,
  pub forced_format: Option<ChecksumFormat>,
  pub root: Option<PathBuf>,
}

fn immediate(
  path: PathBuf,
  algorithm: Algorithm,
  status: FileStatus,
  message: String,
) -> VerifyJob {
  VerifyJob::Done(FileResult::new(path, algorithm, status).with_message(message))
}

struct VerifyJobs {
  pending: VecDeque<PathBuf>,
  discoveries: VecDeque<FileDiscovery>,
  active_doc: Option<ActiveDoc>,
  stdin_format: Option<ChecksumFormat>,
  forced_format: Option<ChecksumFormat>,
  default_algorithm: Algorithm,
  verify_root: Option<PathBuf>,
  excluded: Vec<PathBuf>,
  deferred: VecDeque<VerifyJob>,
  seen: HashMap<(PathBuf, Algorithm), Vec<u8>>,
  pending_missing: HashMap<(PathBuf, Algorithm), (PathBuf, Algorithm, String)>,
}

impl VerifyJobs {
  fn dedup_key(data: &Path, algorithm: Algorithm) -> (PathBuf, Algorithm) {
    let key_path = match data.canonicalize() {
      Ok(canonical) => canonical,
      Err(_) => {
        let normalized = normalize_lexical(data);
        let parent = normalized
          .parent()
          .map(|p| p.canonicalize().unwrap_or_else(|_| p.to_path_buf()));
        match (parent, normalized.file_name()) {
          (Some(parent), Some(name)) => parent.join(name),
          _ => normalized,
        }
      }
    };
    (key_path, algorithm)
  }

  fn dedup(&mut self, data: &Path, algorithm: Algorithm, expected: Option<&[u8]>) -> Dedup {
    let key = Self::dedup_key(data, algorithm);
    match self.seen.get(&key) {
      None => {
        self
          .seen
          .insert(key, expected.map(|e| e.to_vec()).unwrap_or_default());
        Dedup::New
      }
      Some(existing) => {
        let new = expected.map(|e| e.to_vec()).unwrap_or_default();
        if *existing == new {
          Dedup::Duplicate
        } else {
          Dedup::Conflict
        }
      }
    }
  }

  fn classify_sidecar(path: &Path) -> Option<(PathBuf, Algorithm)> {
    let ext = path.extension()?;
    let algorithm = Algorithm::from_extension(ext)?;
    let stem = path.file_stem()?;
    if stem.is_empty() {
      return None;
    }
    Some((path.with_file_name(stem), algorithm))
  }

  fn read_expected(
    checksum: &PathBuf,
    algorithm: Algorithm,
    data: &Path,
  ) -> std::result::Result<Vec<u8>, (FileStatus, String)> {
    crate::file_ops::validate_input_path(checksum).map_err(|e| {
      (
        FileStatus::ReadError,
        format!("Erro ao validar {}: {:#}", checksum.display(), e),
      )
    })?;
    let metadata = std::fs::symlink_metadata(checksum).map_err(|e| {
      if e.kind() == std::io::ErrorKind::NotFound {
        (
          FileStatus::MissingChecksum,
          format!("Arquivo de checksum {} não encontrado", checksum.display()),
        )
      } else {
        (
          FileStatus::ReadError,
          format!("Erro ao acessar {}: {}", checksum.display(), e),
        )
      }
    })?;
    if !metadata.file_type().is_file() {
      return Err((
        FileStatus::InvalidChecksum,
        format!("Arquivo de checksum não é regular: {}", checksum.display()),
      ));
    }
    let file = std::fs::File::open(checksum).map_err(|e| {
      (
        FileStatus::ReadError,
        format!("Erro ao abrir {}: {}", checksum.display(), e),
      )
    })?;
    let mut content = Vec::new();
    file
      .take(MAX_SIDECAR_SIZE + 1)
      .read_to_end(&mut content)
      .map_err(|e| {
        (
          FileStatus::ReadError,
          format!("Erro ao ler {}: {}", checksum.display(), e),
        )
      })?;
    if content.len() as u64 > MAX_SIDECAR_SIZE {
      return Err((
        FileStatus::InvalidChecksum,
        format!(
          "Arquivo de checksum excede {} bytes: {}",
          MAX_SIDECAR_SIZE,
          checksum.display()
        ),
      ));
    }
    let text = String::from_utf8(content).map_err(|_| {
      (
        FileStatus::InvalidChecksum,
        format!("Checksum não é UTF-8: {}", checksum.display()),
      )
    })?;
    parse_sidecar(&text, algorithm, data.file_name()).map_err(|e| {
      (
        FileStatus::InvalidChecksum,
        format!("Checksum inválido em {}: {:#}", checksum.display(), e),
      )
    })
  }

  fn data_job(&mut self, data: PathBuf, algorithm: Algorithm) -> Option<VerifyJob> {
    let checksum = match checksum_path(&data, algorithm) {
      Ok(p) => p,
      Err(e) => {
        return Some(immediate(
          data,
          algorithm,
          FileStatus::ReadError,
          format!("{:#}", e),
        ))
      }
    };
    match Self::read_expected(&checksum, algorithm, &data) {
      Ok(expected) => match self.dedup(&data, algorithm, Some(&expected)) {
        Dedup::New => Some(VerifyJob::Task(VerifyTask::Sidecar {
          data,
          algorithm,
          expected,
        })),
        Dedup::Duplicate => None,
        Dedup::Conflict => Some(immediate(
          data,
          algorithm,
          FileStatus::InvalidChecksum,
          "Checksums esperados divergentes para o mesmo arquivo".to_string(),
        )),
      },
      Err((FileStatus::MissingChecksum, message)) => {
        let key = Self::dedup_key(&data, algorithm);
        if self.seen.contains_key(&key) || self.pending_missing.contains_key(&key) {
          None
        } else {
          self.pending_missing.insert(key, (data, algorithm, message));
          None
        }
      }
      Err((status, message)) => Some(immediate(data, algorithm, status, message)),
    }
  }

  fn sidecar_input_job(
    &mut self,
    checksum: PathBuf,
    data: PathBuf,
    algorithm: Algorithm,
  ) -> Option<VerifyJob> {
    let data_meta = match std::fs::symlink_metadata(&data) {
      Ok(m) => m,
      Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
        return match self.dedup(&data, algorithm, None) {
          Dedup::New => Some(immediate(
            data.clone(),
            algorithm,
            FileStatus::MissingData,
            format!(
              "Checksum {} sem dados correspondentes {}",
              checksum.display(),
              data.display()
            ),
          )),
          Dedup::Duplicate => None,
          Dedup::Conflict => Some(immediate(
            data,
            algorithm,
            FileStatus::InvalidChecksum,
            "Checksums esperados divergentes para o mesmo arquivo".to_string(),
          )),
        };
      }
      Err(e) => {
        return Some(immediate(
          data.clone(),
          algorithm,
          FileStatus::ReadError,
          format!("Erro ao acessar dados {}: {}", data.display(), e),
        ))
      }
    };
    if !data_meta.file_type().is_file() {
      return Some(immediate(
        data.clone(),
        algorithm,
        FileStatus::InvalidChecksum,
        format!(
          "Dados associados não são arquivo regular: {}",
          data.display()
        ),
      ));
    }
    match Self::read_expected(&checksum, algorithm, &data) {
      Ok(expected) => match self.dedup(&data, algorithm, Some(&expected)) {
        Dedup::New => Some(VerifyJob::Task(VerifyTask::Sidecar {
          data,
          algorithm,
          expected,
        })),
        Dedup::Duplicate => None,
        Dedup::Conflict => Some(immediate(
          data,
          algorithm,
          FileStatus::InvalidChecksum,
          "Checksums esperados divergentes para o mesmo arquivo".to_string(),
        )),
      },
      Err((status, message)) => Some(immediate(data, algorithm, status, message)),
    }
  }

  fn looks_like_bare_sidecar(path: &Path) -> bool {
    if crate::file_ops::validate_input_path(path).is_err() {
      return false;
    }
    let file = match std::fs::File::open(path) {
      Ok(f) => f,
      Err(_) => return false,
    };
    let mut content = Vec::new();
    if file
      .take(MAX_SIDECAR_SIZE + 1)
      .read_to_end(&mut content)
      .is_err()
    {
      return false;
    }
    let text = match String::from_utf8(content) {
      Ok(t) => t,
      Err(_) => return false,
    };
    let trimmed = text.trim();
    trimmed.len() == Algorithm::CRC32.digest_bytes() * 2
      && trimmed.chars().all(|c| c.is_ascii_hexdigit())
  }

  fn open_doc(&mut self, origin: PathBuf, format: ChecksumFormat) {
    let algorithm = self.default_algorithm;
    if let Err(e) = crate::file_ops::validate_input_path(&origin) {
      self.deferred.push_back(immediate(
        origin,
        algorithm,
        FileStatus::ReadError,
        format!("Erro ao validar documento: {:#}", e),
      ));
      return;
    }
    let file = match std::fs::File::open(&origin) {
      Ok(f) => f,
      Err(e) => {
        self.deferred.push_back(immediate(
          origin,
          algorithm,
          FileStatus::ReadError,
          format!("Erro ao abrir documento: {}", e),
        ));
        return;
      }
    };
    let root_path = self
      .verify_root
      .clone()
      .or_else(|| {
        origin.parent().map(|p| {
          if p.as_os_str().is_empty() {
            PathBuf::from(".")
          } else {
            p.to_path_buf()
          }
        })
      })
      .unwrap_or_else(|| PathBuf::from("."));
    match Dir::open_ambient_dir(&root_path, cap_std::ambient_authority()) {
      Ok(dir) => {
        let reader: BufReader<Box<dyn Read + Send>> = BufReader::new(Box::new(file));
        let iter = match format {
          ChecksumFormat::Manifest => DocKind::Manifest(ManifestIter::new(reader)),
          _ => DocKind::Sfv(SfvIter::new(reader)),
        };
        self.active_doc = Some(ActiveDoc {
          iter,
          root: Arc::new(dir),
          root_path,
          origin,
        });
      }
      Err(e) => {
        self.deferred.push_back(immediate(
          origin,
          algorithm,
          FileStatus::ReadError,
          format!("Erro ao abrir raiz {}: {}", root_path.display(), e),
        ));
      }
    }
  }

  fn open_stdin_doc(&mut self, format: ChecksumFormat) {
    let reader: BufReader<Box<dyn Read + Send>> = BufReader::new(Box::new(std::io::stdin()));
    let root_path = self
      .verify_root
      .clone()
      .unwrap_or_else(|| PathBuf::from("."));
    match Dir::open_ambient_dir(&root_path, cap_std::ambient_authority()) {
      Ok(dir) => {
        let iter = match format {
          ChecksumFormat::Manifest => DocKind::Manifest(ManifestIter::new(reader)),
          _ => DocKind::Sfv(SfvIter::new(reader)),
        };
        self.active_doc = Some(ActiveDoc {
          iter,
          root: Arc::new(dir),
          root_path,
          origin: PathBuf::from("<stdin>"),
        });
      }
      Err(e) => {
        self.deferred.push_back(immediate(
          PathBuf::from("<stdin>"),
          self.default_algorithm,
          FileStatus::ReadError,
          format!("Erro ao abrir raiz: {}", e),
        ));
      }
    }
  }
}

enum Dedup {
  New,
  Duplicate,
  Conflict,
}

enum DocStep {
  Entry(crate::formats::ChecksumEntry, Arc<Dir>, PathBuf),
  Failed(PathBuf, anyhow::Error),
  Finished,
}

impl Iterator for VerifyJobs {
  type Item = (PathBuf, VerifyJob);

  fn next(&mut self) -> Option<Self::Item> {
    loop {
      if let Some(job) = self.deferred.pop_front() {
        let path = match &job {
          VerifyJob::Done(r) => r.path.clone(),
          _ => PathBuf::new(),
        };
        return Some((path, job));
      }
      if self.active_doc.is_some() {
        let step = {
          let doc = self.active_doc.as_mut().expect("active doc");
          match doc.iter.next() {
            Some(Ok(entry)) => DocStep::Entry(entry, doc.root.clone(), doc.root_path.clone()),
            Some(Err(e)) => DocStep::Failed(doc.origin.clone(), e),
            None => DocStep::Finished,
          }
        };
        match step {
          DocStep::Finished => {
            self.active_doc = None;
            continue;
          }
          DocStep::Failed(origin, e) => {
            self.active_doc = None;
            let algorithm = self.default_algorithm;
            return Some((
              origin.clone(),
              immediate(
                origin,
                algorithm,
                FileStatus::InvalidChecksum,
                format!("Documento inválido: {:#}", e),
              ),
            ));
          }
          DocStep::Entry(entry, root, root_path) => {
            let display = root_path.join(&entry.path);
            let expected = hex::decode(&entry.digest).unwrap_or_default();
            match self.dedup(&display, entry.algorithm, Some(&expected)) {
              Dedup::New => {
                return Some((
                  display.clone(),
                  VerifyJob::Task(VerifyTask::ManifestEntry {
                    rel: entry.path,
                    display,
                    algorithm: entry.algorithm,
                    expected,
                    root,
                  }),
                ));
              }
              Dedup::Duplicate => continue,
              Dedup::Conflict => {
                return Some((
                  display.clone(),
                  immediate(
                    display,
                    entry.algorithm,
                    FileStatus::InvalidChecksum,
                    "Checksums esperados divergentes para o mesmo arquivo".to_string(),
                  ),
                ));
              }
            }
          }
        }
      }
      if !self.discoveries.is_empty() {
        let discovered = self
          .discoveries
          .front_mut()
          .and_then(|discovery| discovery.next());
        match discovered {
          Some(Discovery::File(path)) => {
            let is_sfv = path.extension() == Some(OsStr::new("sfv"));
            if is_sfv
              && self.default_algorithm == Algorithm::CRC32
              && !Self::looks_like_bare_sidecar(&path)
            {
              self.open_doc(path, ChecksumFormat::Sfv);
              continue;
            }
            if let Some((data, algorithm)) = Self::classify_sidecar(&path) {
              if algorithm == self.default_algorithm {
                match std::fs::symlink_metadata(&data) {
                  Ok(m) if m.file_type().is_file() => continue,
                  Ok(_) => {
                    return Some((
                      data.clone(),
                      immediate(
                        data,
                        algorithm,
                        FileStatus::InvalidChecksum,
                        format!(
                          "Dados associados a {} não são arquivo regular",
                          path.display()
                        ),
                      ),
                    ));
                  }
                  Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                    match self.dedup(&data, algorithm, None) {
                      Dedup::New => {
                        return Some((
                          data.clone(),
                          immediate(
                            data,
                            algorithm,
                            FileStatus::MissingData,
                            format!(
                              "Checksum órfão {} sem dados correspondentes",
                              path.display()
                            ),
                          ),
                        ));
                      }
                      Dedup::Duplicate => continue,
                      Dedup::Conflict => {
                        return Some((
                          data.clone(),
                          immediate(
                            data,
                            algorithm,
                            FileStatus::InvalidChecksum,
                            "Checksums esperados divergentes para o mesmo arquivo".to_string(),
                          ),
                        ));
                      }
                    }
                  }
                  Err(e) => {
                    return Some((
                      data.clone(),
                      immediate(
                        data.clone(),
                        algorithm,
                        FileStatus::ReadError,
                        format!("Erro ao acessar dados {}: {}", data.display(), e),
                      ),
                    ));
                  }
                }
              }
              continue;
            }
            if path.extension() == Some(OsStr::new(MANIFEST_EXTENSION)) {
              continue;
            }
            let algorithm = self.default_algorithm;
            match self.data_job(path.clone(), algorithm) {
              Some(job) => return Some((path, job)),
              None => continue,
            }
          }
          Some(Discovery::Skipped(path)) => {
            return Some((
              path.clone(),
              immediate(
                path,
                self.default_algorithm,
                FileStatus::Skipped,
                "Item ignorado".into(),
              ),
            ));
          }
          Some(Discovery::Failed(path, e)) => {
            return Some((
              path.clone(),
              immediate(
                path,
                self.default_algorithm,
                FileStatus::ReadError,
                format!("{:#}", e),
              ),
            ));
          }
          None => {
            self.discoveries.pop_front();
            continue;
          }
        }
      }
      if let Some(path) = self.pending.pop_front() {
        if let Err(e) = crate::file_ops::validate_input_path(&path) {
          return Some((
            path.clone(),
            immediate(
              path,
              self.default_algorithm,
              FileStatus::ReadError,
              format!("{:#}", e),
            ),
          ));
        }
        let metadata = match std::fs::symlink_metadata(&path) {
          Ok(m) => m,
          Err(e) => {
            return Some((
              path.clone(),
              immediate(
                path,
                self.default_algorithm,
                FileStatus::ReadError,
                format!("Caminho inválido: {}", e),
              ),
            ));
          }
        };
        if metadata.file_type().is_symlink() {
          return Some((
            path.clone(),
            immediate(
              path,
              self.default_algorithm,
              FileStatus::ReadError,
              "Symlink não permitido como entrada".into(),
            ),
          ));
        }
        if metadata.file_type().is_dir() {
          self
            .discoveries
            .push_back(FileDiscovery::new(&[path], &self.excluded));
          continue;
        }
        if !metadata.file_type().is_file() {
          return Some((
            path.clone(),
            immediate(
              path,
              self.default_algorithm,
              FileStatus::Skipped,
              "Item ignorado".into(),
            ),
          ));
        }
        if let Some(format) = self.forced_format {
          if format != ChecksumFormat::Raw {
            self.open_doc(path, format);
            continue;
          }
        }
        let is_manifest = path.extension() == Some(OsStr::new(MANIFEST_EXTENSION));
        let is_sfv = path.extension() == Some(OsStr::new("sfv"));
        if is_manifest {
          self.open_doc(path, ChecksumFormat::Manifest);
          continue;
        }
        if is_sfv && !Self::looks_like_bare_sidecar(&path) {
          self.open_doc(path, ChecksumFormat::Sfv);
          continue;
        }
        if let Some((data, algorithm)) = Self::classify_sidecar(&path) {
          match self.sidecar_input_job(path.clone(), data.clone(), algorithm) {
            Some(job) => {
              let p = match &job {
                VerifyJob::Done(r) => r.path.clone(),
                _ => data,
              };
              return Some((p, job));
            }
            None => continue,
          }
        }
        let algorithm = self.default_algorithm;
        match self.data_job(path.clone(), algorithm) {
          Some(job) => return Some((path, job)),
          None => continue,
        }
      }
      if let Some(format) = self.stdin_format.take() {
        self.open_stdin_doc(format);
        continue;
      }
      while let Some((key, (data, algorithm, message))) = self
        .pending_missing
        .iter()
        .next()
        .map(|(k, v)| (k.clone(), v.clone()))
      {
        self.pending_missing.remove(&key);
        if self.seen.contains_key(&key) {
          continue;
        }
        return Some((
          data.clone(),
          immediate(data, algorithm, FileStatus::MissingChecksum, message),
        ));
      }
      return None;
    }
  }
}

fn verify_task(task: VerifyTask, options: &RunOptions) -> FileResult {
  match task {
    VerifyTask::Sidecar {
      data,
      algorithm,
      expected,
    } => {
      if options.cancelled.load(Ordering::Relaxed) {
        return FileResult::new(data, algorithm, FileStatus::Cancelled)
          .with_message("Operação cancelada");
      }
      match compute_file_hash(&data, algorithm, options.buffer_size, &options.cancelled) {
        Ok(actual) => {
          let actual_bytes = hex::decode(&actual).unwrap_or_default();
          if actual_bytes == expected {
            FileResult::new(data, algorithm, FileStatus::Matched).with_digest(actual)
          } else {
            FileResult::new(data, algorithm, FileStatus::Mismatched)
              .with_digest(actual.clone())
              .with_message(format!(
                "Esperado {}, obtido {}",
                hex::encode(&expected),
                actual
              ))
          }
        }
        Err(e) => {
          let status = if options.cancelled.load(Ordering::Relaxed) {
            FileStatus::Cancelled
          } else {
            FileStatus::ReadError
          };
          FileResult::new(data, algorithm, status).with_message(format!("{:#}", e))
        }
      }
    }
    VerifyTask::ManifestEntry {
      rel,
      display,
      algorithm,
      expected,
      root,
    } => {
      if options.cancelled.load(Ordering::Relaxed) {
        return FileResult::new(display, algorithm, FileStatus::Cancelled)
          .with_message("Operação cancelada");
      }
      let mut prefix = PathBuf::new();
      for component in rel.components() {
        prefix.push(component.as_os_str());
        match root.symlink_metadata(&prefix) {
          Ok(m) if m.file_type().is_symlink() => {
            return FileResult::new(display, algorithm, FileStatus::InvalidChecksum).with_message(
              format!("Componente symlink não permitido: {}", rel.display()),
            );
          }
          _ => {}
        }
      }
      match root.symlink_metadata(&rel) {
        Ok(m) if !m.file_type().is_file() => {
          return FileResult::new(display, algorithm, FileStatus::InvalidChecksum)
            .with_message(format!("Entrada não é arquivo regular: {}", rel.display()));
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
          return FileResult::new(display, algorithm, FileStatus::MissingData)
            .with_message(format!("Arquivo ausente no manifesto: {}", rel.display()));
        }
        Err(e) => {
          return FileResult::new(display, algorithm, FileStatus::ReadError).with_message(format!(
            "Erro ao acessar {}: {}",
            rel.display(),
            e
          ));
        }
        _ => {}
      }
      let opened =
        match root.open(&rel) {
          Ok(f) => f,
          Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return FileResult::new(display, algorithm, FileStatus::MissingData)
              .with_message(format!("Arquivo ausente no manifesto: {}", rel.display()));
          }
          Err(e) => {
            return FileResult::new(display, algorithm, FileStatus::ReadError)
              .with_message(format!("Erro ao abrir {}: {}", rel.display(), e));
          }
        };
      let mut std_file = opened.into_std();
      let context = display.display().to_string();
      match compute_hash_from_handle(
        &mut std_file,
        algorithm,
        options.buffer_size,
        &options.cancelled,
        &context,
      ) {
        Ok(actual) => {
          let actual_bytes = hex::decode(&actual).unwrap_or_default();
          if actual_bytes == expected {
            FileResult::new(display, algorithm, FileStatus::Matched).with_digest(actual)
          } else {
            FileResult::new(display, algorithm, FileStatus::Mismatched)
              .with_digest(actual.clone())
              .with_message(format!(
                "Esperado {}, obtido {}",
                hex::encode(&expected),
                actual
              ))
          }
        }
        Err(e) => {
          let status = if options.cancelled.load(Ordering::Relaxed) {
            FileStatus::Cancelled
          } else {
            FileStatus::ReadError
          };
          FileResult::new(display, algorithm, status).with_message(format!("{:#}", e))
        }
      }
    }
  }
}

/// Verifica os arquivos de dados comparando com seus respectivos arquivos de checksum.
/// Para cada arquivo, procura um arquivo de checksum com o mesmo nome acrescido da extensão do algoritmo.
/// Arquivos de checksum órfãos e entradas de manifesto também produzem resultados.
pub async fn verify_with_options<F>(
  paths: &[PathBuf],
  options: &RunOptions,
  on_result: F,
) -> Result<RunSummary>
where
  F: FnMut(&FileResult) -> Result<()>,
{
  verify_request(
    &VerifyRequest {
      paths: paths.to_vec(),
      ..VerifyRequest::default()
    },
    options,
    on_result,
  )
  .await
}

/// Executa verificação completa conforme `request`, incluindo documentos
/// agregados e detecção de checksums órfãos em diretórios.
pub async fn verify_request<F>(
  request: &VerifyRequest,
  options: &RunOptions,
  on_result: F,
) -> Result<RunSummary>
where
  F: FnMut(&FileResult) -> Result<()>,
{
  options.validate()?;
  let jobs = VerifyJobs {
    pending: request.paths.iter().cloned().collect(),
    discoveries: VecDeque::new(),
    active_doc: None,
    stdin_format: request.stdin_format,
    forced_format: request.forced_format,
    default_algorithm: options.algorithm,
    verify_root: request.root.clone(),
    excluded: options.excluded_paths.clone(),
    seen: HashMap::new(),
    pending_missing: HashMap::new(),
    deferred: VecDeque::new(),
  };
  execute::run_jobs(
    jobs,
    options,
    |job, options| match job {
      VerifyJob::Task(task) => verify_task(task, options),
      VerifyJob::Done(result) => result,
    },
    on_result,
  )
  .await
}

/// Verifica os arquivos de dados comparando com seus respectivos arquivos de checksum.
/// Para cada arquivo, procura um arquivo de checksum com o mesmo nome acrescido da extensão do algoritmo.
/// Retorna erro quando a verificação não foi integralmente bem-sucedida.
pub async fn verify_checksums(
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
  let summary = verify_with_options(paths, &options, |_| Ok(())).await?;
  if summary.exit_code() != 0 {
    bail!(
      "Verificação concluída com falhas: {} divergente(s), {} ausente(s), {} erro(s)",
      summary.mismatched,
      summary.missing,
      summary.errors
    );
  }
  Ok(())
}
