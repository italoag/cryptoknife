use crate::algorithms::Algorithm;
use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use std::ffi::OsStr;
use std::io::{BufRead, Read, Write};
use std::path::{Component, Path, PathBuf};

pub const MAX_LINE_SIZE: u64 = 64 * 1024;
pub const MAX_SIDECAR_SIZE: u64 = 4096;
pub const MANIFEST_EXTENSION: &str = "ckmanifest";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ChecksumFormat {
  Raw,
  Sfv,
  Manifest,
}

#[derive(Clone, Debug)]
pub struct ChecksumEntry {
  pub path: PathBuf,
  pub algorithm: Algorithm,
  pub digest: String,
}

pub fn parse_digest(text: &str, algorithm: Algorithm) -> Result<Vec<u8>> {
  let trimmed = text.trim();
  let bytes = hex::decode(trimmed).context("Digest não é hexadecimal válido")?;
  if bytes.len() != algorithm.digest_bytes() {
    bail!(
      "Comprimento de digest inválido: {} bytes (esperado {})",
      bytes.len(),
      algorithm.digest_bytes()
    );
  }
  Ok(bytes)
}

/// Interpreta o conteúdo de um sidecar: digest isolado para todos os
/// algoritmos; para CRC32 também aceita a linha convencional `nome HEX`,
/// exigindo que `nome` seja igual a `expected_name` quando informado.
pub fn parse_sidecar(
  text: &str,
  algorithm: Algorithm,
  expected_name: Option<&OsStr>,
) -> Result<Vec<u8>> {
  if let Ok(bytes) = parse_digest(text, algorithm) {
    return Ok(bytes);
  }
  if algorithm != Algorithm::CRC32 {
    bail!("Conteúdo de sidecar inválido");
  }
  let trimmed = text.trim();
  if trimmed.lines().count() == 1 {
    if let Some(token) = trimmed.split_whitespace().next_back() {
      if token != trimmed {
        let name = trimmed[..trimmed.len() - token.len()].trim_end();
        if let Some(expected) = expected_name {
          if OsStr::new(name) != expected {
            bail!(
              "Nome em sidecar {:?} não corresponde ao arquivo de dados",
              name
            );
          }
        }
        return parse_digest(token, algorithm)
          .context("Token final do sidecar não é digest válido");
      }
    }
  }
  bail!("Conteúdo de sidecar inválido")
}

/// Converte um caminho relativo para a forma portátil com separador '/'.
/// Rejeita componentes `.`, `..`, prefixos, raízes, separadores '\\',
/// dois-pontos, controles e componentes não UTF-8.
pub fn portable_rel_path(path: &Path) -> Result<String> {
  let mut parts: Vec<String> = Vec::new();
  for component in path.components() {
    match component {
      Component::Normal(part) => {
        let text = part
          .to_str()
          .ok_or_else(|| anyhow::anyhow!("Nome não UTF-8 em caminho: {}", path.display()))?;
        if text.is_empty()
          || text.contains('\\')
          || text.contains(':')
          || text.chars().any(|c| c.is_control())
        {
          bail!(
            "Componente inválido para formato portátil: {}",
            path.display()
          );
        }
        parts.push(text.to_string());
      }
      _ => bail!("Caminho não relativo portátil: {}", path.display()),
    }
  }
  if parts.is_empty() {
    bail!("Caminho relativo vazio");
  }
  Ok(parts.join("/"))
}

/// Valida um caminho relativo vindo de documento externo.
pub fn validate_rel_path(text: &str) -> Result<PathBuf> {
  if text.is_empty() {
    bail!("Caminho vazio em documento");
  }
  if text.contains('\\') || text.contains(':') {
    bail!("Separador ou drive inválido em caminho: {}", text);
  }
  if text.chars().any(|c| c.is_control() || c == '\0') {
    bail!("Caractere de controle em caminho: {}", text);
  }
  if text.starts_with('/') || text.starts_with("//") {
    bail!("Caminho absoluto não permitido: {}", text);
  }
  for segment in text.split('/') {
    if segment.is_empty() || segment == "." || segment == ".." {
      bail!("Componente inválido em caminho: {}", text);
    }
  }
  let path = PathBuf::from(text);
  if path.is_absolute() {
    bail!("Caminho absoluto não permitido: {}", text);
  }
  Ok(path)
}

/// Lê uma linha de `reader` com limite de tamanho, retornando None em EOF.
fn read_bounded_line<R: BufRead>(reader: &mut R, max: u64) -> Result<Option<String>> {
  let mut buf = Vec::new();
  let n = reader
    .by_ref()
    .take(max + 1)
    .read_until(b'\n', &mut buf)
    .context("Erro de leitura em documento")?;
  if n == 0 {
    return Ok(None);
  }
  if n as u64 > max {
    bail!("Linha excede {} bytes", max);
  }
  let text = String::from_utf8(buf).context("Documento não é UTF-8")?;
  Ok(Some(text))
}

#[derive(Serialize)]
struct ManifestHeader {
  schema_version: u32,
  #[serde(rename = "type")]
  kind: &'static str,
  format: &'static str,
}

#[derive(Serialize)]
struct ManifestChecksum<'a> {
  #[serde(rename = "type")]
  kind: &'static str,
  algorithm: &'a str,
  path: &'a str,
  digest: &'a str,
}

#[derive(Serialize)]
struct ManifestEnd {
  #[serde(rename = "type")]
  kind: &'static str,
  entries: u64,
}

/// Linha de header de manifesto JSON Lines versionado.
pub fn manifest_header_line() -> Result<String> {
  let header = ManifestHeader {
    schema_version: 1,
    kind: "manifest",
    format: "cryptoknife",
  };
  Ok(format!("{}\n", serde_json::to_string(&header)?))
}

/// Linha de registro de checksum de manifesto; falha se exceder o limite.
pub fn manifest_checksum_line(path: &str, algorithm: Algorithm, digest: &str) -> Result<String> {
  let record = ManifestChecksum {
    kind: "checksum",
    algorithm: algorithm.name(),
    path,
    digest,
  };
  let line = format!("{}\n", serde_json::to_string(&record)?);
  if line.len() as u64 > MAX_LINE_SIZE {
    bail!("Registro de manifesto excede {} bytes", MAX_LINE_SIZE);
  }
  Ok(line)
}

/// Linha de footer de manifesto com a contagem de registros.
pub fn manifest_end_line(count: u64) -> Result<String> {
  let end = ManifestEnd {
    kind: "end",
    entries: count,
  };
  Ok(format!("{}\n", serde_json::to_string(&end)?))
}

/// Serializa um manifesto JSON Lines versionado: header, registros e footer.
pub fn write_manifest<W: Write>(
  writer: &mut W,
  entries: &[(String, Algorithm, String)],
) -> Result<()> {
  writer.write_all(manifest_header_line()?.as_bytes())?;
  for (path, algorithm, digest) in entries {
    writer.write_all(manifest_checksum_line(path, *algorithm, digest)?.as_bytes())?;
  }
  writer.write_all(manifest_end_line(entries.len() as u64)?.as_bytes())?;
  writer.flush()?;
  Ok(())
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ManifestHeaderIn {
  schema_version: u32,
  #[serde(rename = "type")]
  kind: String,
  format: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ManifestChecksumIn {
  #[serde(rename = "type")]
  kind: String,
  algorithm: String,
  path: String,
  digest: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ManifestEndIn {
  #[serde(rename = "type")]
  kind: String,
  entries: u64,
}

enum ManifestState {
  Header,
  Records,
  AfterFooter,
  Failed,
}

#[derive(Deserialize)]
struct TypeProbe {
  #[serde(rename = "type")]
  kind: String,
}

/// Iterador incremental sobre um manifesto JSON Lines com validação
/// estrita de esquema, footer obrigatório e contagem reconciliada.
pub struct ManifestIter<R: BufRead> {
  reader: R,
  state: ManifestState,
  count: u64,
  seen: std::collections::HashSet<(String, String)>,
}

impl<R: BufRead> ManifestIter<R> {
  pub fn new(reader: R) -> Self {
    ManifestIter {
      reader,
      state: ManifestState::Header,
      count: 0,
      seen: std::collections::HashSet::new(),
    }
  }
}

impl<R: BufRead> Iterator for ManifestIter<R> {
  type Item = Result<ChecksumEntry>;

  fn next(&mut self) -> Option<Self::Item> {
    if matches!(self.state, ManifestState::Failed) {
      return None;
    }
    loop {
      let line = match read_bounded_line(&mut self.reader, MAX_LINE_SIZE) {
        Ok(line) => line,
        Err(e) => {
          self.state = ManifestState::Failed;
          return Some(Err(e));
        }
      };
      match self.state {
        ManifestState::Failed => return None,
        ManifestState::Header => match line {
          None => {
            self.state = ManifestState::Failed;
            return Some(Err(anyhow::anyhow!("Manifesto vazio ou truncado")));
          }
          Some(text) => {
            let header: ManifestHeaderIn = match serde_json::from_str(text.trim()) {
              Ok(h) => h,
              Err(e) => {
                self.state = ManifestState::Failed;
                return Some(Err(anyhow::anyhow!("Header de manifesto inválido: {}", e)));
              }
            };
            if header.schema_version != 1
              || header.kind != "manifest"
              || header.format != "cryptoknife"
            {
              self.state = ManifestState::Failed;
              return Some(Err(anyhow::anyhow!(
                "Versão ou tipo de manifesto não suportado"
              )));
            }
            self.state = ManifestState::Records;
            continue;
          }
        },
        ManifestState::Records => match line {
          None => {
            self.state = ManifestState::Failed;
            return Some(Err(anyhow::anyhow!("Manifesto sem footer de encerramento")));
          }
          Some(text) => {
            let trimmed = text.trim();
            let probe: TypeProbe = match serde_json::from_str(trimmed) {
              Ok(p) => p,
              Err(e) => {
                self.state = ManifestState::Failed;
                return Some(Err(anyhow::anyhow!("Linha de manifesto malformada: {}", e)));
              }
            };
            match probe.kind.as_str() {
              "checksum" => {
                let record: ManifestChecksumIn = match serde_json::from_str(trimmed) {
                  Ok(r) => r,
                  Err(e) => {
                    self.state = ManifestState::Failed;
                    return Some(Err(anyhow::anyhow!("Registro de checksum inválido: {}", e)));
                  }
                };
                let parsed = (|| -> Result<ChecksumEntry> {
                  if record.kind != "checksum" {
                    bail!("Registro de manifesto com tipo inválido");
                  }
                  let algorithm: Algorithm = record
                    .algorithm
                    .parse()
                    .context("Algoritmo inválido em manifesto")?;
                  let digest = parse_digest(&record.digest, algorithm).map(hex::encode)?;
                  let path = validate_rel_path(&record.path)?;
                  Ok(ChecksumEntry {
                    path,
                    algorithm,
                    digest,
                  })
                })();
                match parsed {
                  Ok(entry) => {
                    let key = (
                      entry.path.to_string_lossy().to_string(),
                      entry.algorithm.name().to_string(),
                    );
                    if !self.seen.insert(key) {
                      self.state = ManifestState::Failed;
                      return Some(Err(anyhow::anyhow!(
                        "Registro duplicado em manifesto: {}",
                        entry.path.display()
                      )));
                    }
                    self.count += 1;
                    return Some(Ok(entry));
                  }
                  Err(e) => {
                    self.state = ManifestState::Failed;
                    return Some(Err(e));
                  }
                }
              }
              "end" => {
                let end: ManifestEndIn = match serde_json::from_str(trimmed) {
                  Ok(e) => e,
                  Err(e) => {
                    self.state = ManifestState::Failed;
                    return Some(Err(anyhow::anyhow!("Footer de manifesto inválido: {}", e)));
                  }
                };
                if end.kind != "end" {
                  self.state = ManifestState::Failed;
                  return Some(Err(anyhow::anyhow!("Footer de manifesto inválido")));
                }
                if end.entries != self.count {
                  self.state = ManifestState::Failed;
                  return Some(Err(anyhow::anyhow!(
                    "Contagem de registros diverge: {} declarado(s), {} lido(s)",
                    end.entries,
                    self.count
                  )));
                }
                self.state = ManifestState::AfterFooter;
                continue;
              }
              _ => {
                self.state = ManifestState::Failed;
                return Some(Err(anyhow::anyhow!(
                  "Tipo de registro desconhecido em manifesto"
                )));
              }
            }
          }
        },
        ManifestState::AfterFooter => match line {
          None => {
            self.state = ManifestState::Failed;
            return None;
          }
          Some(text) if text.trim().is_empty() => continue,
          Some(_) => {
            self.state = ManifestState::Failed;
            return Some(Err(anyhow::anyhow!("Conteúdo após footer de manifesto")));
          }
        },
      }
    }
  }
}

/// Valida um nome de arquivo para linha SFV convencional.
pub fn validate_sfv_name(name: &str) -> Result<()> {
  if name.is_empty() {
    bail!("Nome SFV vazio");
  }
  if name != name.trim() {
    bail!("Nome SFV com espaço nas extremidades: {:?}", name);
  }
  if name.starts_with(';') {
    bail!("Nome SFV iniciado por comentário: {:?}", name);
  }
  if name.contains('\\')
    || name.contains(':')
    || name.contains('\r')
    || name.contains('\n')
    || name.chars().any(|c| c.is_control())
  {
    bail!("Nome SFV contém caractere inválido: {:?}", name);
  }
  Ok(())
}

/// Linha SFV `caminho CRC32`; falha se o nome for inválido ou exceder o limite.
pub fn sfv_line(name: &str, crc: &str) -> Result<String> {
  validate_sfv_name(name)?;
  let line = format!("{} {}\n", name, crc.to_uppercase());
  if line.len() as u64 > MAX_LINE_SIZE {
    bail!("Linha SFV excede {} bytes", MAX_LINE_SIZE);
  }
  Ok(line)
}

/// Serializa entradas SFV no formato `caminho CRC32`.
pub fn write_sfv<W: Write>(writer: &mut W, entries: &[(String, String)]) -> Result<()> {
  for (name, crc) in entries {
    writer.write_all(sfv_line(name, crc)?.as_bytes())?;
  }
  writer.flush()?;
  Ok(())
}

/// Iterador incremental sobre um documento SFV: ignora linhas em branco e
/// comentários `;`, extrai o último token de 8 dígitos hex como CRC32.
pub struct SfvIter<R: BufRead> {
  reader: R,
  done: bool,
  seen: std::collections::HashSet<PathBuf>,
}

impl<R: BufRead> SfvIter<R> {
  pub fn new(reader: R) -> Self {
    SfvIter {
      reader,
      done: false,
      seen: std::collections::HashSet::new(),
    }
  }
}

impl<R: BufRead> Iterator for SfvIter<R> {
  type Item = Result<ChecksumEntry>;

  fn next(&mut self) -> Option<Self::Item> {
    if self.done {
      return None;
    }
    loop {
      let line = match read_bounded_line(&mut self.reader, MAX_LINE_SIZE) {
        Ok(line) => line,
        Err(e) => {
          self.done = true;
          return Some(Err(e));
        }
      };
      let text = match line {
        None => {
          self.done = true;
          return None;
        }
        Some(text) => text,
      };
      let trimmed = text.trim_end();
      if trimmed.trim().is_empty() || trimmed.trim_start().starts_with(';') {
        continue;
      }
      let parsed = (|| -> Result<ChecksumEntry> {
        let token = trimmed
          .split_whitespace()
          .next_back()
          .ok_or_else(|| anyhow::anyhow!("Linha SFV sem digest"))?;
        let digest = hex::encode(parse_digest(token, Algorithm::CRC32)?);
        let name = trimmed[..trimmed.len() - token.len()].trim_end();
        validate_sfv_name(name)?;
        let path = validate_rel_path(name)?;
        Ok(ChecksumEntry {
          path,
          algorithm: Algorithm::CRC32,
          digest,
        })
      })();
      match parsed {
        Ok(entry) => {
          if !self.seen.insert(entry.path.clone()) {
            self.done = true;
            return Some(Err(anyhow::anyhow!(
              "Entrada duplicada em SFV: {}",
              entry.path.display()
            )));
          }
          return Some(Ok(entry));
        }
        Err(e) => {
          self.done = true;
          return Some(Err(e));
        }
      }
    }
  }
}
