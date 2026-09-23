use clap::{Args, ColorChoice, Parser, Subcommand, ValueEnum};
use cryptoknife_lib::{normalize_lexical, Algorithm, RunOptions, DEFAULT_BUFFER_SIZE};
use std::path::{Path, PathBuf};
use std::str::FromStr;

/// Aplicação CLI para geração e verificação de checksums.
#[derive(Parser, Debug)]
#[command(
  author = "Italo A. G.",
  version,
  about = "Cryptographic Tools CLI",
  long_about = None
)]
pub struct Cli {
  #[command(subcommand)]
  pub command: Commands,

  /// Algoritmo a ser utilizado.
  /// Exemplos válidos:
  ///   sha3-256, sha3-512, keccak-256, keccak-512, blake3, crc32, k12-256, k12-512, whirlpool
  #[arg(long, short = 'a', global = true, value_name = "ALGORITMO", value_parser = parse_algorithm)]
  pub algorithm: Option<Algorithm>,

  /// Tamanho do buffer para leituras (em bytes). Valor padrão: 8192.
  #[arg(long, short = 'b', global = true, default_value_t = DEFAULT_BUFFER_SIZE)]
  pub buffer_size: usize,

  /// Número máximo de operações simultâneas (1-64)
  #[arg(long, global = true, default_value_t = default_jobs())]
  pub jobs: usize,

  /// Exibe resultados detalhados por arquivo
  #[arg(long, short = 'v', global = true, conflicts_with = "quiet")]
  pub verbose: bool,

  /// Suprime saída de sucesso e resumo
  #[arg(long, short = 'q', global = true, conflicts_with = "json")]
  pub quiet: bool,

  /// Emite resultados em JSON Lines na saída padrão
  #[arg(long, global = true)]
  pub json: bool,

  /// Desativa o indicador de progresso
  #[arg(long, global = true)]
  pub no_progress: bool,

  /// Controle de cor: auto, always ou never
  #[arg(long, global = true, value_enum, default_value_t = ColorArg::Auto)]
  pub color: ColorArg,

  /// Anexa diagnósticos ao arquivo de log indicado
  #[arg(long, global = true, value_name = "CAMINHO")]
  pub log_file: Option<PathBuf>,
}

#[derive(Subcommand, Debug)]
pub enum Commands {
  /// Gera checksums dos arquivos indicados.
  /// Exemplos:
  ///   cryptoknife generate arquivo.txt
  ///   cryptoknife -a crc32 generate pasta/ --format sfv -o lista.sfv
  ///   cat dados | cryptoknife generate -
  Generate(GenerateArgs),

  /// Verifica arquivos contra seus checksums.
  /// Exemplos:
  ///   cryptoknife verify arquivo.txt
  ///   cryptoknife verify manifesto.ckmanifest
  ///   cryptoknife verify - --format manifest < manifesto.ckmanifest
  Verify(VerifyArgs),
}

#[derive(Args, Debug)]
pub struct GenerateArgs {
  /// Caminho(s) para arquivo(s) e/ou diretório(s) a serem processados, ou "-" para stdin
  #[arg(required = true, value_name = "CAMINHO")]
  pub paths: Vec<PathBuf>,

  /// Sobrescreve arquivos de checksum existentes
  #[arg(long)]
  pub force: bool,

  /// Formato de saída: sidecar, raw, sfv ou manifest
  #[arg(long, value_enum)]
  pub format: Option<GenFormat>,

  /// Destino do documento agregado (ou "-" para saída padrão)
  #[arg(long, short = 'o', value_name = "CAMINHO")]
  pub output: Option<PathBuf>,

  /// Diretório raiz para caminhos relativos do documento
  #[arg(long, value_name = "DIR")]
  pub root: Option<PathBuf>,
}

#[derive(Args, Debug)]
pub struct VerifyArgs {
  /// Caminho(s) de dados, checksums, manifestos ou "-" para documento via stdin
  #[arg(required = true, value_name = "CAMINHO")]
  pub paths: Vec<PathBuf>,

  /// Formato do documento: auto, manifest ou sfv
  #[arg(long, value_enum)]
  pub format: Option<VerifyFormat>,

  /// Diretório raiz para entradas de documentos agregados
  #[arg(long, value_name = "DIR")]
  pub root: Option<PathBuf>,
}

#[derive(Copy, Clone, PartialEq, Eq, ValueEnum, Debug)]
pub enum GenFormat {
  Sidecar,
  Raw,
  Sfv,
  Manifest,
}

#[derive(Copy, Clone, PartialEq, Eq, ValueEnum, Debug)]
pub enum VerifyFormat {
  Auto,
  Manifest,
  Sfv,
}

#[derive(Copy, Clone, PartialEq, Eq, ValueEnum, Debug)]
pub enum ColorArg {
  Auto,
  Always,
  Never,
}

fn default_jobs() -> usize {
  RunOptions::default().jobs
}

/// Converte a string de algoritmo para o enum correspondente.
/// Exemplos:
/// - "sha3-256"    → Algorithm::Sha3_256
/// - "sha3-512"    → Algorithm::Sha3_512
/// - "keccak-256"  → Algorithm::Keccak256
/// - "keccak-512"  → Algorithm::Keccak512
/// - "blake3"      → Algorithm::BLAKE3
/// - "crc32" ou "sfv" → Algorithm::CRC32
/// - "k12-256"     → Algorithm::K12_256
/// - "k12-512"     → Algorithm::K12_512
/// - "whirlpool"   → Algorithm::Whirlpool
fn parse_algorithm(s: &str) -> Result<Algorithm, String> {
  Algorithm::from_str(s).map_err(|e| e.to_string())
}

pub fn clap_color() -> ColorChoice {
  use std::ffi::OsStr;
  let mut choice = ColorChoice::Auto;
  let mut args = std::env::args_os().skip(1);
  while let Some(arg) = args.next() {
    if arg == OsStr::new("--") {
      break;
    }
    let value = if arg == OsStr::new("--color") {
      args.next()
    } else {
      arg
        .to_str()
        .and_then(|s| s.strip_prefix("--color="))
        .map(std::ffi::OsString::from)
    };
    if let Some(value) = value {
      choice = match value.to_str() {
        Some("always") => ColorChoice::Always,
        Some("never") => ColorChoice::Never,
        _ => ColorChoice::Auto,
      };
      break;
    }
  }
  if choice == ColorChoice::Auto && std::env::var_os("NO_COLOR").is_some() {
    choice = ColorChoice::Never;
  }
  choice
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

pub fn same_path(a: &Path, b: &Path) -> bool {
  if normalize_lexical(a) == normalize_lexical(b) {
    return true;
  }
  match (a.canonicalize(), b.canonicalize()) {
    (Ok(ca), Ok(cb)) if ca == cb => return true,
    _ => {}
  }
  if let (Ok(a_handle), Ok(b_handle)) = (
    same_file::Handle::from_path(a),
    same_file::Handle::from_path(b),
  ) {
    if a_handle == b_handle {
      return true;
    }
  }
  match (file_identity(a), file_identity(b)) {
    (Some(ia), Some(ib)) => ia == ib,
    _ => false,
  }
}

/// Valida o destino de log: rejeita symlink/diretório, igualdade ou alias de
/// entradas e saídas, e localização dentro de diretórios de entrada.
pub fn validate_log_file(
  log: &Path,
  protected: &[PathBuf],
  input_dirs: &[PathBuf],
) -> Result<(), String> {
  let mut log_alias: Option<PathBuf> = None;
  let mut log_exists = false;
  match std::fs::symlink_metadata(log) {
    Ok(metadata) => {
      if metadata.file_type().is_symlink() {
        return Err(format!("Arquivo de log é um symlink: {}", log.display()));
      }
      if !metadata.file_type().is_file() {
        return Err(format!(
          "Arquivo de log não é arquivo regular: {}",
          log.display()
        ));
      }
      log_exists = true;
    }
    Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
      let parent = log.parent().filter(|p| !p.as_os_str().is_empty());
      let parent = parent
        .map(|p| p.to_path_buf())
        .unwrap_or_else(|| PathBuf::from("."));
      if !parent.exists() {
        return Err(format!(
          "Diretório do arquivo de log não existe: {}",
          parent.display()
        ));
      }
      if let (Ok(canonical_parent), Some(leaf)) = (parent.canonicalize(), log.file_name()) {
        log_alias = Some(canonical_parent.join(leaf));
      }
    }
    Err(e) => return Err(format!("Erro ao acessar log {}: {}", log.display(), e)),
  }
  for item in protected {
    if same_path(log, item) {
      return Err(format!(
        "Arquivo de log coincide com entrada ou saída: {}",
        log.display()
      ));
    }
  }
  let normalized_log = normalize_lexical(log);
  for dir in input_dirs {
    let normalized_dir = normalize_lexical(dir);
    if normalized_log.starts_with(&normalized_dir) {
      return Err(format!(
        "Arquivo de log dentro de diretório de entrada: {}",
        log.display()
      ));
    }
    if let Ok(canonical_dir) = dir.canonicalize() {
      if let Ok(canonical_log) = log.canonicalize() {
        if canonical_log.starts_with(&canonical_dir) {
          return Err(format!(
            "Arquivo de log dentro de diretório de entrada: {}",
            log.display()
          ));
        }
      }
      if let Some(alias) = &log_alias {
        if alias.starts_with(&canonical_dir) {
          return Err(format!(
            "Arquivo de log dentro de diretório de entrada: {}",
            log.display()
          ));
        }
      }
    }
    if log_exists {
      match log_hardlink_in_tree(log, dir) {
        Ok(true) => {
          return Err(format!(
            "Arquivo de log é hardlink de arquivo de entrada: {}",
            log.display()
          ))
        }
        Err(e) => {
          return Err(format!(
            "Falha ao verificar aliases de log em {}: {}",
            dir.display(),
            e
          ))
        }
        Ok(false) => {}
      }
    }
  }
  Ok(())
}

fn log_hardlink_in_tree(log: &Path, dir: &Path) -> std::io::Result<bool> {
  for entry in walkdir::WalkDir::new(dir).follow_links(false) {
    let entry = entry?;
    let path = entry.path();
    let metadata = std::fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink() {
      continue;
    }
    if metadata.is_file() && same_path(log, path) {
      return Ok(true);
    }
  }
  Ok(false)
}
