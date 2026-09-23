use crate::algorithms::Algorithm;
use anyhow::{anyhow, bail, Context, Result};
use std::collections::{HashSet, VecDeque};
use std::io::Write;
use std::path::{Component, Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use walkdir::WalkDir;

pub const TEMP_PREFIX: &str = ".cryptoknife-tmp-";

/// Normaliza `path` para forma absoluta lexical resolvendo `.` e `..`
/// sem consultar o sistema de arquivos nem converter por lossy.
pub fn normalize_lexical(path: &Path) -> PathBuf {
  let absolute = if path.is_absolute() {
    path.to_path_buf()
  } else {
    match std::env::current_dir() {
      Ok(cwd) => cwd.join(path),
      Err(_) => path.to_path_buf(),
    }
  };
  let mut normalized = PathBuf::new();
  for component in absolute.components() {
    match component {
      Component::CurDir => {}
      Component::ParentDir => {
        normalized.pop();
      }
      other => normalized.push(other.as_os_str()),
    }
  }
  normalized
}

pub enum Discovery {
  File(PathBuf),
  Skipped(PathBuf),
  Failed(PathBuf, anyhow::Error),
}

/// Iterador preguiçoso de descoberta de arquivos sobre os caminhos raiz.
/// Não segue symlinks de diretório, deduplica por identidade canônica e
/// exclui caminhos normalizados ou canônicos listados em `excluded_paths`.
pub struct FileDiscovery {
  roots: VecDeque<PathBuf>,
  walkers: Vec<walkdir::IntoIter>,
  excluded_lexical: Vec<PathBuf>,
  excluded_canonical: HashSet<PathBuf>,
  excluded_inodes: HashSet<(u64, u64)>,
  seen: HashSet<PathBuf>,
}

impl FileDiscovery {
  pub fn new(paths: &[PathBuf], excluded_paths: &[PathBuf]) -> Self {
    let excluded_lexical: Vec<PathBuf> = excluded_paths
      .iter()
      .map(|p| normalize_lexical(p))
      .collect();
    let excluded_canonical: HashSet<PathBuf> = excluded_paths
      .iter()
      .filter_map(|p| p.canonicalize().ok())
      .collect();
    let excluded_inodes: HashSet<(u64, u64)> = excluded_paths
      .iter()
      .filter_map(|p| file_identity(p))
      .collect();
    FileDiscovery {
      roots: paths.iter().cloned().collect(),
      walkers: Vec::new(),
      excluded_lexical,
      excluded_canonical,
      excluded_inodes,
      seen: HashSet::new(),
    }
  }
}

fn is_temp_file(path: &Path) -> bool {
  path
    .file_name()
    .map(|name| name.to_string_lossy().starts_with(TEMP_PREFIX))
    .unwrap_or(false)
}

fn dedup(seen: &mut HashSet<PathBuf>, path: &Path) -> bool {
  let key = path.canonicalize().unwrap_or_else(|_| path.to_path_buf());
  seen.insert(key)
}

fn file_identity(path: &Path) -> Option<(u64, u64)> {
  #[cfg(unix)]
  {
    use std::os::unix::fs::MetadataExt;
    std::fs::metadata(path).ok().map(|m| (m.dev(), m.ino()))
  }
  #[cfg(not(unix))]
  {
    let _ = path;
    None
  }
}

fn is_excluded(
  lexical: &[PathBuf],
  canonical: &HashSet<PathBuf>,
  inodes: &HashSet<(u64, u64)>,
  path: &Path,
) -> bool {
  let normalized = normalize_lexical(path);
  if lexical
    .iter()
    .any(|excl| normalized == *excl || normalized.starts_with(excl))
  {
    return true;
  }
  if let Ok(resolved) = path.canonicalize() {
    if canonical
      .iter()
      .any(|excl| resolved == *excl || resolved.starts_with(excl))
    {
      return true;
    }
  }
  if let Some(identity) = file_identity(path) {
    if inodes.contains(&identity) {
      return true;
    }
  }
  false
}

impl Iterator for FileDiscovery {
  type Item = Discovery;

  fn next(&mut self) -> Option<Discovery> {
    loop {
      while let Some(walker) = self.walkers.last_mut() {
        match walker.next() {
          None => {
            self.walkers.pop();
            continue;
          }
          Some(Err(e)) => {
            let path = e.path().map(|p| p.to_path_buf()).unwrap_or_default();
            return Some(Discovery::Failed(path, e.into()));
          }
          Some(Ok(entry)) => {
            let path = entry.path().to_path_buf();
            let file_type = entry.file_type();
            if file_type.is_symlink() {
              if is_excluded(
                &self.excluded_lexical,
                &self.excluded_canonical,
                &self.excluded_inodes,
                &path,
              ) {
                continue;
              }
              return Some(Discovery::Skipped(path));
            }
            if file_type.is_dir() {
              if is_excluded(
                &self.excluded_lexical,
                &self.excluded_canonical,
                &self.excluded_inodes,
                &path,
              ) {
                // Impede descida em diretório excluído
                walker.skip_current_dir();
              }
              continue;
            }
            if !file_type.is_file() {
              return Some(Discovery::Skipped(path));
            }
            if is_temp_file(&path)
              || is_excluded(
                &self.excluded_lexical,
                &self.excluded_canonical,
                &self.excluded_inodes,
                &path,
              )
              || !dedup(&mut self.seen, &path)
            {
              continue;
            }
            return Some(Discovery::File(path));
          }
        }
      }
      let root = self.roots.pop_front()?;
      let metadata = match std::fs::symlink_metadata(&root) {
        Ok(m) => m,
        Err(e) => {
          return Some(Discovery::Failed(
            root.clone(),
            anyhow::Error::new(e).context(format!("Caminho inválido: {}", root.display())),
          ));
        }
      };
      let file_type = metadata.file_type();
      if file_type.is_symlink() {
        return Some(Discovery::Failed(
          root.clone(),
          anyhow!("Symlink não permitido como entrada: {}", root.display()),
        ));
      }
      if file_type.is_dir() {
        self
          .walkers
          .push(WalkDir::new(&root).follow_links(false).into_iter());
        continue;
      }
      if !file_type.is_file() {
        return Some(Discovery::Skipped(root));
      }
      if is_temp_file(&root)
        || is_excluded(
          &self.excluded_lexical,
          &self.excluded_canonical,
          &self.excluded_inodes,
          &root,
        )
        || !dedup(&mut self.seen, &root)
      {
        continue;
      }
      return Some(Discovery::File(root));
    }
  }
}

/// Obtém uma lista de arquivos a partir de caminhos (arquivos ou diretórios).
pub fn gather_files(paths: &[PathBuf]) -> Result<Vec<PathBuf>> {
  let mut files = Vec::new();
  for item in FileDiscovery::new(paths, &[]) {
    match item {
      Discovery::File(p) => files.push(p),
      Discovery::Skipped(_) => {}
      Discovery::Failed(_, e) => return Err(e),
    }
  }
  Ok(files)
}

/// Retorna o caminho do arquivo de checksum para `path`, preservando o nome nativo.
pub fn checksum_path(path: &Path, algorithm: Algorithm) -> Result<PathBuf> {
  let name = path
    .file_name()
    .ok_or_else(|| anyhow!("Caminho sem nome de arquivo: {}", path.display()))?;
  let mut new_name = name.to_os_string();
  new_name.push(".");
  new_name.push(algorithm.extension());
  Ok(path.with_file_name(new_name))
}

/// Destino de escrita atômica: conteúdo vai para um temporário no mesmo
/// diretório e só é publicado em `commit`, que exige flag de cancelamento
/// inativa. Sem `force` o destino pré-existente é rejeitado já em `new` e a
/// publicação usa `persist_noclobber`; nunca segue symlink nem substitui
/// diretório. Falhas e cancelamento removem o temporário via RAII.
pub struct AtomicOutput {
  target: PathBuf,
  force: bool,
  tmp: tempfile::NamedTempFile,
}

impl AtomicOutput {
  pub fn new(path: &Path, force: bool) -> Result<Self> {
    let parent = path
      .parent()
      .ok_or_else(|| anyhow!("Caminho sem diretório pai: {}", path.display()))?;
    let parent = if parent.as_os_str().is_empty() {
      Path::new(".")
    } else {
      parent
    };
    if let Ok(metadata) = std::fs::symlink_metadata(path) {
      let file_type = metadata.file_type();
      if file_type.is_symlink() {
        bail!("Destino é um symlink: {}", path.display());
      }
      if !file_type.is_file() {
        bail!("Destino não é arquivo regular: {}", path.display());
      }
      if !force {
        bail!("Destino já existe: {}", path.display());
      }
    }
    let tmp = tempfile::Builder::new()
      .prefix(TEMP_PREFIX)
      .tempfile_in(parent)
      .with_context(|| format!("Não foi possível criar temporário em {}", parent.display()))?;
    Ok(AtomicOutput {
      target: path.to_path_buf(),
      force,
      tmp,
    })
  }

  pub fn commit(self, cancelled: &AtomicBool) -> Result<()> {
    self
      .tmp
      .as_file()
      .sync_all()
      .with_context(|| format!("Não foi possível sincronizar {}", self.target.display()))?;
    if cancelled.load(Ordering::Relaxed) {
      bail!(
        "Operação cancelada antes de publicar {}",
        self.target.display()
      );
    }
    let result = if self.force {
      self.tmp.persist(&self.target)
    } else {
      self.tmp.persist_noclobber(&self.target)
    };
    result.map(|_| ()).map_err(|e| {
      anyhow!(
        "Não foi possível publicar {}: {}",
        self.target.display(),
        e.error
      )
    })
  }
}

impl Write for AtomicOutput {
  fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
    self.tmp.write(buf)
  }
  fn flush(&mut self) -> std::io::Result<()> {
    self.tmp.flush()
  }
}

/// Escreve `bytes` em `path` de forma atômica via arquivo temporário no mesmo diretório.
/// Sem `force`, não sobrescreve destino existente; nunca segue symlink nem
/// substitui diretório no destino.
pub fn atomic_write(path: &Path, bytes: &[u8], force: bool, cancelled: &AtomicBool) -> Result<()> {
  let mut out = AtomicOutput::new(path, force)?;
  out.write_all(bytes).with_context(|| {
    format!(
      "Não foi possível escrever temporário para {}",
      path.display()
    )
  })?;
  out.commit(cancelled)
}

#[cfg(test)]
mod tests {
  use super::*;
  use std::fs::{create_dir_all, File};
  use std::io::Write;
  use tempfile::tempdir;

  #[test]
  fn test_gather_files_with_file() {
    let dir = tempdir().unwrap();
    let file_path = dir.path().join("test.txt");
    let mut file = File::create(&file_path).unwrap();
    writeln!(file, "conteúdo").unwrap();

    let paths = vec![file_path.clone()];
    let files = gather_files(&paths).unwrap();
    assert_eq!(files, vec![file_path]);
  }

  #[test]
  fn test_gather_files_with_directory() {
    let dir = tempdir().unwrap();
    let sub_dir = dir.path().join("sub");
    create_dir_all(&sub_dir).unwrap();
    let file_path = sub_dir.join("test.txt");
    let mut file = File::create(&file_path).unwrap();
    writeln!(file, "conteúdo").unwrap();

    let paths = vec![dir.path().to_path_buf()];
    let files = gather_files(&paths).unwrap();
    assert!(files.contains(&file_path));
  }

  #[test]
  fn test_gather_files_missing_path_errors() {
    let dir = tempdir().unwrap();
    let missing = dir.path().join("absent.txt");
    assert!(gather_files(&[missing]).is_err());
  }

  #[test]
  fn test_checksum_path_preserves_name() {
    let path = PathBuf::from("/tmp/x/data.txt");
    let checksum = checksum_path(&path, Algorithm::BLAKE3).unwrap();
    assert_eq!(checksum, PathBuf::from("/tmp/x/data.txt.blake3"));
  }

  #[cfg(unix)]
  #[test]
  fn test_checksum_path_non_utf8_osstring() {
    use std::os::unix::ffi::OsStrExt;
    let name = std::ffi::OsStr::from_bytes(b"data\xff.bin");
    let path = PathBuf::from(name);
    let checksum = checksum_path(&path, Algorithm::BLAKE3).unwrap();
    assert!(checksum.as_os_str().as_bytes().ends_with(b".blake3"));
    assert!(checksum.as_os_str().as_bytes().contains(&0xff));
  }

  #[test]
  fn test_atomic_write_no_overwrite() {
    let dir = tempdir().unwrap();
    let dest = dir.path().join("out.txt");
    std::fs::write(&dest, "SENTINEL").unwrap();
    let cancelled = AtomicBool::new(false);
    let result = atomic_write(&dest, b"new", false, &cancelled);
    assert!(result.is_err());
    assert_eq!(std::fs::read_to_string(&dest).unwrap(), "SENTINEL");
  }

  #[test]
  fn test_atomic_write_force() {
    let dir = tempdir().unwrap();
    let dest = dir.path().join("out.txt");
    std::fs::write(&dest, "old").unwrap();
    let cancelled = AtomicBool::new(false);
    atomic_write(&dest, b"new", true, &cancelled).unwrap();
    assert_eq!(std::fs::read_to_string(&dest).unwrap(), "new");
  }

  #[cfg(unix)]
  #[test]
  fn test_atomic_write_rejects_symlink_dest() {
    let dir = tempdir().unwrap();
    let target = dir.path().join("target.txt");
    std::fs::write(&target, "target").unwrap();
    let dest = dir.path().join("link.txt");
    std::os::unix::fs::symlink(&target, &dest).unwrap();
    let cancelled = AtomicBool::new(false);
    assert!(atomic_write(&dest, b"x", false, &cancelled).is_err());
    assert!(atomic_write(&dest, b"x", true, &cancelled).is_err());
    assert_eq!(std::fs::read_to_string(&target).unwrap(), "target");
  }
}
