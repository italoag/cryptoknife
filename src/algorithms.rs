use anyhow::{anyhow, bail, Context, Result};
use std::ffi::OsStr;
use std::io::Read;
use std::path::Path;
use std::str::FromStr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

pub const DEFAULT_BUFFER_SIZE: usize = 8192;
pub const MAX_BUFFER_SIZE: usize = 16 * 1024 * 1024;

pub fn validate_buffer_size(buffer_size: usize) -> Result<()> {
  if buffer_size == 0 || buffer_size > MAX_BUFFER_SIZE {
    bail!(
      "Tamanho de buffer inválido: {} (permitido: 1..={})",
      buffer_size,
      MAX_BUFFER_SIZE
    );
  }
  Ok(())
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Algorithm {
  BLAKE3,
  CRC32,
  // Para SHA3, KangarooTwelve e Keccak, indicamos o tamanho (em bits)
  Sha3_256,
  Sha3_512,
  Keccak256,
  Keccak512,
  K12_256,
  K12_512,
  Whirlpool,
}

impl Algorithm {
  pub const ALL: [Self; 9] = [
    Self::BLAKE3,
    Self::CRC32,
    Self::Sha3_256,
    Self::Sha3_512,
    Self::Keccak256,
    Self::Keccak512,
    Self::K12_256,
    Self::K12_512,
    Self::Whirlpool,
  ];

  pub fn name(self) -> &'static str {
    match self {
      Algorithm::BLAKE3 => "blake3",
      Algorithm::CRC32 => "crc32",
      Algorithm::Sha3_256 => "sha3-256",
      Algorithm::Sha3_512 => "sha3-512",
      Algorithm::Keccak256 => "keccak-256",
      Algorithm::Keccak512 => "keccak-512",
      Algorithm::K12_256 => "k12-256",
      Algorithm::K12_512 => "k12-512",
      Algorithm::Whirlpool => "whirlpool",
    }
  }

  /// Retorna uma extensão usada para nomear os arquivos de checksum.
  pub fn extension(&self) -> &'static str {
    match self {
      Algorithm::BLAKE3 => "blake3",
      Algorithm::CRC32 => "sfv",
      Algorithm::Sha3_256 => "sha3-256",
      Algorithm::Sha3_512 => "sha3-512",
      Algorithm::Keccak256 => "keccak256",
      Algorithm::Keccak512 => "keccak512",
      Algorithm::K12_256 => "k12-256",
      Algorithm::K12_512 => "k12-512",
      Algorithm::Whirlpool => "whirlpool",
    }
  }

  pub fn digest_bytes(self) -> usize {
    match self {
      Algorithm::BLAKE3 => 32,
      Algorithm::CRC32 => 4,
      Algorithm::Sha3_256 => 32,
      Algorithm::Sha3_512 => 64,
      Algorithm::Keccak256 => 32,
      Algorithm::Keccak512 => 64,
      Algorithm::K12_256 => 32,
      Algorithm::K12_512 => 64,
      Algorithm::Whirlpool => 64,
    }
  }

  pub fn from_extension(extension: &OsStr) -> Option<Self> {
    Algorithm::ALL
      .iter()
      .copied()
      .find(|alg| extension == OsStr::new(alg.extension()))
  }
}

impl FromStr for Algorithm {
  type Err = anyhow::Error;

  fn from_str(s: &str) -> Result<Self> {
    let s = s.to_lowercase();
    Algorithm::ALL
      .iter()
      .copied()
      .find(|alg| s == alg.name() || s == alg.extension())
      .or(if s == "sfv" {
        Some(Algorithm::CRC32)
      } else {
        None
      })
      .ok_or_else(|| anyhow!("Algoritmo desconhecido ou formato inválido: {}", s))
  }
}

enum Hasher {
  Blake3(Box<blake3::Hasher>),
  Crc32(crc32fast::Hasher),
  Sha3_256(sha3::Sha3_256),
  Sha3_512(sha3::Sha3_512),
  Keccak256(sha3::Keccak256),
  Keccak512(sha3::Keccak512),
  K12(Box<k12::KangarooTwelve<'static>>, usize),
  Whirlpool(whirlpool::Whirlpool),
}

impl Hasher {
  fn new(algorithm: Algorithm) -> Self {
    use sha3::Digest;
    match algorithm {
      Algorithm::BLAKE3 => Hasher::Blake3(Box::new(blake3::Hasher::new())),
      Algorithm::CRC32 => Hasher::Crc32(crc32fast::Hasher::new()),
      Algorithm::Sha3_256 => Hasher::Sha3_256(sha3::Sha3_256::new()),
      Algorithm::Sha3_512 => Hasher::Sha3_512(sha3::Sha3_512::new()),
      Algorithm::Keccak256 => Hasher::Keccak256(sha3::Keccak256::new()),
      Algorithm::Keccak512 => Hasher::Keccak512(sha3::Keccak512::new()),
      Algorithm::K12_256 => Hasher::K12(Box::new(k12::KangarooTwelve::default()), 32),
      Algorithm::K12_512 => Hasher::K12(Box::new(k12::KangarooTwelve::default()), 64),
      Algorithm::Whirlpool => Hasher::Whirlpool(whirlpool::Whirlpool::new()),
    }
  }

  fn update(&mut self, data: &[u8]) {
    match self {
      Hasher::Blake3(h) => {
        h.update(data);
      }
      Hasher::Crc32(h) => {
        h.update(data);
      }
      Hasher::Sha3_256(h) => {
        sha3::Digest::update(h, data);
      }
      Hasher::Sha3_512(h) => {
        sha3::Digest::update(h, data);
      }
      Hasher::Keccak256(h) => {
        sha3::Digest::update(h, data);
      }
      Hasher::Keccak512(h) => {
        sha3::Digest::update(h, data);
      }
      Hasher::K12(h, _) => {
        k12::digest::Update::update(h.as_mut(), data);
      }
      Hasher::Whirlpool(h) => {
        sha3::Digest::update(h, data);
      }
    }
  }

  fn finalize(self) -> String {
    use k12::digest::ExtendableOutput;
    use sha3::Digest;
    match self {
      Hasher::Blake3(h) => h.finalize().to_hex().to_string(),
      Hasher::Crc32(h) => format!("{:08x}", h.finalize()),
      Hasher::Sha3_256(h) => hex::encode(h.finalize()),
      Hasher::Sha3_512(h) => hex::encode(h.finalize()),
      Hasher::Keccak256(h) => hex::encode(h.finalize()),
      Hasher::Keccak512(h) => hex::encode(h.finalize()),
      Hasher::K12(h, size) => hex::encode(h.finalize_boxed(size).as_ref()),
      Hasher::Whirlpool(h) => hex::encode(h.finalize()),
    }
  }
}

fn hash_stream<R: Read>(
  reader: &mut R,
  algorithm: Algorithm,
  buffer_size: usize,
  cancelled: &AtomicBool,
  context: &str,
) -> Result<(String, u64)> {
  validate_buffer_size(buffer_size)?;
  let mut hasher = Hasher::new(algorithm);
  let mut buffer = vec![0u8; buffer_size];
  let mut read_total: u64 = 0;
  loop {
    if cancelled.load(Ordering::Relaxed) {
      bail!("Operação cancelada: {}", context);
    }
    match reader.read(&mut buffer) {
      Ok(0) => break,
      Ok(n) => {
        read_total += n as u64;
        hasher.update(&buffer[..n]);
      }
      Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
      Err(e) => return Err(e).with_context(|| format!("Erro de leitura em {}", context)),
    }
  }
  Ok((hasher.finalize(), read_total))
}

fn metadata_changed(a: &std::fs::Metadata, b: &std::fs::Metadata) -> bool {
  a.len() != b.len() || a.modified().ok() != b.modified().ok()
}

fn same_file_identity(a: &std::fs::Metadata, b: &std::fs::Metadata) -> bool {
  #[cfg(unix)]
  {
    use std::os::unix::fs::MetadataExt;
    a.dev() == b.dev() && a.ino() == b.ino()
  }
  #[cfg(not(unix))]
  {
    let _ = (a, b);
    true
  }
}

/// Calcula o hash de um handle de arquivo já aberto, verificando tamanho e
/// metadados antes e depois da leitura.
pub(crate) fn compute_hash_from_handle(
  file: &mut std::fs::File,
  algorithm: Algorithm,
  buffer_size: usize,
  cancelled: &AtomicBool,
  context: &str,
) -> Result<String> {
  validate_buffer_size(buffer_size)?;
  let pre_metadata = file
    .metadata()
    .with_context(|| format!("Não foi possível ler metadados de {}", context))?;
  if !pre_metadata.is_file() {
    bail!("Não é um arquivo regular: {}", context);
  }
  let (digest, read_total) = hash_stream(file, algorithm, buffer_size, cancelled, context)?;
  let post_metadata = file
    .metadata()
    .with_context(|| format!("Não foi possível ler metadados de {}", context))?;
  if read_total != pre_metadata.len() || metadata_changed(&pre_metadata, &post_metadata) {
    bail!("Arquivo modificado durante a leitura: {}", context);
  }
  Ok(digest)
}

fn hash_file(
  path: &Path,
  algorithm: Algorithm,
  buffer_size: usize,
  cancelled: &AtomicBool,
) -> Result<String> {
  validate_buffer_size(buffer_size)?;
  crate::file_ops::validate_input_path(path)?;
  let context = path.display().to_string();
  let pre_metadata = std::fs::symlink_metadata(path)
    .with_context(|| format!("Não foi possível ler metadados de {}", context))?;
  if !pre_metadata.file_type().is_file() {
    bail!("Não é um arquivo regular: {}", context);
  }
  let mut file =
    std::fs::File::open(path).with_context(|| format!("Não foi possível abrir {}", context))?;
  let open_metadata = file
    .metadata()
    .with_context(|| format!("Não foi possível ler metadados de {}", context))?;
  if !open_metadata.is_file()
    || !same_file_identity(&pre_metadata, &open_metadata)
    || metadata_changed(&pre_metadata, &open_metadata)
  {
    bail!("Arquivo alterado durante a abertura: {}", context);
  }
  let (digest, read_total) = hash_stream(&mut file, algorithm, buffer_size, cancelled, &context)?;
  let post_metadata = file
    .metadata()
    .with_context(|| format!("Não foi possível ler metadados de {}", context))?;
  if read_total != open_metadata.len() || metadata_changed(&open_metadata, &post_metadata) {
    bail!("Arquivo modificado durante a leitura: {}", context);
  }
  match std::fs::symlink_metadata(path) {
    Ok(path_metadata)
      if same_file_identity(&open_metadata, &path_metadata)
        && !metadata_changed(&open_metadata, &path_metadata) => {}
    Ok(_) => bail!("Arquivo substituído durante a leitura: {}", context),
    Err(e) => {
      return Err(e).with_context(|| format!("Arquivo removido durante a leitura: {}", context))
    }
  }
  Ok(digest)
}

/// Calcula o hash de um arquivo de forma assíncrona.
/// Usa leitura em stream dentro de uma task bloqueante para todos os tamanhos.
pub async fn compute_hash_async(
  path: &Path,
  algorithm: Algorithm,
  buffer_size: usize,
) -> Result<String> {
  validate_buffer_size(buffer_size)?;
  let path = path.to_owned();
  let cancelled = Arc::new(AtomicBool::new(false));
  let join_handle =
    tokio::task::spawn_blocking(move || hash_file(&path, algorithm, buffer_size, &cancelled));
  join_handle.await?
}

/// Calcula o hash a partir de um slice de bytes (forma síncrona).
pub fn compute_hash_from_bytes(data: &[u8], algorithm: Algorithm) -> String {
  let mut hasher = Hasher::new(algorithm);
  hasher.update(data);
  hasher.finalize()
}

/// Calcula o hash a partir de um leitor que implementa o trait `Read`, utilizando um buffer configurável.
pub fn compute_hash_from_reader<R: Read>(
  reader: &mut R,
  algorithm: Algorithm,
  buffer_size: usize,
) -> Result<String> {
  hash_stream(
    reader,
    algorithm,
    buffer_size,
    &AtomicBool::new(false),
    "leitor",
  )
  .map(|r| r.0)
}

pub(crate) fn compute_hash_from_reader_cancellable<R: Read>(
  reader: &mut R,
  algorithm: Algorithm,
  buffer_size: usize,
  cancelled: &AtomicBool,
) -> Result<String> {
  hash_stream(reader, algorithm, buffer_size, cancelled, "entrada").map(|r| r.0)
}

/// Calcula o hash da entrada padrão (stdin) respeitando cancelamento.
pub fn compute_hash_stdin(
  algorithm: Algorithm,
  buffer_size: usize,
  cancelled: &AtomicBool,
) -> Result<String> {
  let mut stdin = std::io::stdin().lock();
  compute_hash_from_reader_cancellable(&mut stdin, algorithm, buffer_size, cancelled)
}

/// Calcula o hash de um arquivo respeitando cancelamento compartilhado.
pub fn compute_file_hash(
  path: &Path,
  algorithm: Algorithm,
  buffer_size: usize,
  cancelled: &AtomicBool,
) -> Result<String> {
  hash_file(path, algorithm, buffer_size, cancelled)
}

#[cfg(test)]
mod tests {
  use super::*;
  use std::io::Cursor;

  #[test]
  fn test_compute_hash_from_bytes_sha3_256() {
    let data = b"hello world";
    let hash = compute_hash_from_bytes(data, Algorithm::Sha3_256);
    let expected = "644bcc7e564373040999aac89e7622f3ca71fba1d972fd94a31c3bfbf24e3938";
    assert_eq!(hash, expected);
  }

  #[test]
  fn test_compute_hash_from_bytes_sha3_512() {
    let data = b"hello world";
    let hash = compute_hash_from_bytes(data, Algorithm::Sha3_512);
    let expected = "840006653e9ac9e95117a15c915caab81662918e925de9e004f774ff82d7079a40d4d27b1b372657c61d46d470304c88c788b3a4527ad074d1dccbee5dbaa99a";
    assert_eq!(hash, expected);
  }

  #[test]
  fn test_compute_hash_from_bytes_keccak256() {
    let data = b"hello world";
    let hash = compute_hash_from_bytes(data, Algorithm::Keccak256);
    let expected = "47173285a8d7341e5e972fc677286384f802f8ef42a5ec5f03bbfa254cb01fad";
    assert_eq!(hash, expected);
  }

  #[test]
  fn test_compute_hash_from_bytes_keccak512() {
    let data = b"hello world";
    let hash = compute_hash_from_bytes(data, Algorithm::Keccak512);
    let expected = "3ee2b40047b8060f68c67242175660f4174d0af5c01d47168ec20ed619b0b7c42181f40aa1046f39e2ef9efc6910782a998e0013d172458957957fac9405b67d";
    assert_eq!(hash, expected);
  }

  #[test]
  fn test_compute_hash_from_bytes_crc32() {
    let data = b"hello world";
    let hash = compute_hash_from_bytes(data, Algorithm::CRC32);
    let expected = "0d4a1185";
    assert_eq!(hash, expected);
  }

  #[test]
  fn test_compute_hash_from_bytes_blake3() {
    let data = b"hello world";
    let hash = compute_hash_from_bytes(data, Algorithm::BLAKE3);
    let expected = "d74981efa70a0c880b8d8c1985d075dbcbf679b99a5f9914e5aaf96b831a9e24";
    assert_eq!(hash, expected);
  }

  #[test]
  fn test_compute_hash_from_bytes_kangaroo256() {
    let hash = compute_hash_from_bytes(b"", Algorithm::K12_256);
    let expected = "1ac2d450fc3b4205d19da7bfca1b37513c0803577ac7167f06fe2ce1f0ef39e5";
    assert_eq!(hash, expected);
  }

  #[test]
  fn test_compute_hash_from_bytes_kangaroo512() {
    let hash = compute_hash_from_bytes(b"", Algorithm::K12_512);
    let expected = "1ac2d450fc3b4205d19da7bfca1b37513c0803577ac7167f06fe2ce1f0ef39e54269c056b8c82e48276038b6d292966cc07a3d4645272e31ff38508139eb0a71";
    assert_eq!(hash, expected);
  }

  #[test]
  fn test_compute_hash_from_bytes_kangaroo256_long() {
    let data: Vec<u8> = (0..17usize.pow(4)).map(|i| (i % 251) as u8).collect();
    let hash = compute_hash_from_bytes(&data, Algorithm::K12_256);
    let expected = "8701045e22205345ff4dda05555cbb5c3af1a771c2b89baef37db43d9998b9fe";
    assert_eq!(hash, expected);
  }

  #[test]
  fn test_compute_hash_from_bytes_whirlpool() {
    let hash = compute_hash_from_bytes(b"", Algorithm::Whirlpool);
    let expected = "19fa61d75522a4669b44e39c1d2e1726c530232130d407f89afee0964997f7a73e83be698b288febcf88e3e03c4f0757ea8964e59b63d93708b138cc42a66eb3";
    assert_eq!(hash, expected);
  }

  #[test]
  fn test_compute_hash_from_reader_sha3_256() {
    let data = b"hello world";
    let mut cursor = Cursor::new(data);
    let hash = compute_hash_from_reader(&mut cursor, Algorithm::Sha3_256, 4).unwrap();
    let expected = "644bcc7e564373040999aac89e7622f3ca71fba1d972fd94a31c3bfbf24e3938";
    assert_eq!(hash, expected);
  }

  #[test]
  fn test_compute_hash_from_reader_keccak256() {
    let data = b"hello world";
    let mut cursor = Cursor::new(data);
    let hash = compute_hash_from_reader(&mut cursor, Algorithm::Keccak256, 4).unwrap();
    let expected = "47173285a8d7341e5e972fc677286384f802f8ef42a5ec5f03bbfa254cb01fad";
    assert_eq!(hash, expected);
  }

  #[test]
  fn test_compute_hash_from_reader_crc32() {
    let data = b"hello world";
    let mut cursor = Cursor::new(data);
    let hash = compute_hash_from_reader(&mut cursor, Algorithm::CRC32, 4).unwrap();
    let expected = "0d4a1185";
    assert_eq!(hash, expected);
  }

  #[test]
  fn test_compute_hash_from_reader_blake3() {
    let data = b"hello world";
    let mut cursor = Cursor::new(data);
    let hash = compute_hash_from_reader(&mut cursor, Algorithm::BLAKE3, 4).unwrap();
    let expected = "d74981efa70a0c880b8d8c1985d075dbcbf679b99a5f9914e5aaf96b831a9e24";
    assert_eq!(hash, expected);
  }

  #[test]
  fn test_zero_buffer_rejected_before_read() {
    struct CountingReader {
      calls: usize,
    }
    impl Read for CountingReader {
      fn read(&mut self, _buf: &mut [u8]) -> std::io::Result<usize> {
        self.calls += 1;
        Ok(0)
      }
    }
    let mut reader = CountingReader { calls: 0 };
    let result = compute_hash_from_reader(&mut reader, Algorithm::BLAKE3, 0);
    assert!(result.is_err());
    assert_eq!(reader.calls, 0);
  }

  #[test]
  fn test_interrupted_reads_are_retried() {
    struct FlakyReader {
      inner: Cursor<Vec<u8>>,
      remaining_interrupts: usize,
    }
    impl Read for FlakyReader {
      fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        if self.remaining_interrupts > 0 {
          self.remaining_interrupts -= 1;
          return Err(std::io::Error::new(
            std::io::ErrorKind::Interrupted,
            "retry",
          ));
        }
        self.inner.read(buf)
      }
    }
    let mut reader = FlakyReader {
      inner: Cursor::new(b"hello world".to_vec()),
      remaining_interrupts: 3,
    };
    let hash = compute_hash_from_reader(&mut reader, Algorithm::BLAKE3, 4).unwrap();
    assert_eq!(
      hash,
      "d74981efa70a0c880b8d8c1985d075dbcbf679b99a5f9914e5aaf96b831a9e24"
    );
  }

  #[test]
  fn test_reader_io_error_propagates() {
    struct FailingReader;
    impl Read for FailingReader {
      fn read(&mut self, _buf: &mut [u8]) -> std::io::Result<usize> {
        Err(std::io::Error::new(
          std::io::ErrorKind::PermissionDenied,
          "denied",
        ))
      }
    }
    let mut reader = FailingReader;
    let result = compute_hash_from_reader(&mut reader, Algorithm::BLAKE3, 8192);
    assert!(result.is_err());
  }

  #[test]
  fn test_chunk_boundary_parity_all_algorithms() {
    let data: Vec<u8> = (0..100_000u32).map(|i| (i % 251) as u8).collect();
    for alg in Algorithm::ALL {
      let expected = compute_hash_from_bytes(&data, alg);
      for chunk in [1usize, 7, 8192, 65_536] {
        let mut cursor = Cursor::new(data.clone());
        let hash = compute_hash_from_reader(&mut cursor, alg, chunk).unwrap();
        assert_eq!(hash, expected, "alg {:?} chunk {}", alg, chunk);
      }
    }
  }

  #[test]
  fn test_file_reader_bytes_parity_all_algorithms() {
    let dir = tempfile::tempdir().unwrap();
    let data: Vec<u8> = (0..50_000u32).map(|i| (i % 251) as u8).collect();
    let file = dir.path().join("data.bin");
    std::fs::write(&file, &data).unwrap();
    let cancelled = AtomicBool::new(false);
    for alg in Algorithm::ALL {
      let expected = compute_hash_from_bytes(&data, alg);
      let mut cursor = Cursor::new(data.clone());
      assert_eq!(
        compute_hash_from_reader(&mut cursor, alg, 8192).unwrap(),
        expected,
        "reader parity alg {:?}",
        alg
      );
      assert_eq!(
        compute_file_hash(&file, alg, 8192, &cancelled).unwrap(),
        expected,
        "file parity alg {:?}",
        alg
      );
    }
  }

  #[test]
  fn test_blake3_large_buffer_boundaries() {
    for len in [
      10 * 1024 * 1024 - 1usize,
      10 * 1024 * 1024,
      10 * 1024 * 1024 + 1,
    ] {
      let data: Vec<u8> = (0..len).map(|i| (i % 251) as u8).collect();
      let expected = compute_hash_from_bytes(&data, Algorithm::BLAKE3);
      let mut cursor = Cursor::new(data);
      assert_eq!(
        compute_hash_from_reader(&mut cursor, Algorithm::BLAKE3, 8192).unwrap(),
        expected,
        "boundary len {}",
        len
      );
    }
  }

  #[tokio::test]
  async fn test_async_file_parity_all_algorithms() {
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("data.bin");
    std::fs::write(&file, b"hello world").unwrap();
    for alg in Algorithm::ALL {
      let expected = compute_hash_from_bytes(b"hello world", alg);
      assert_eq!(
        compute_hash_async(&file, alg, 8192).await.unwrap(),
        expected,
        "async parity alg {:?}",
        alg
      );
    }
  }

  #[test]
  fn test_empty_input_all_algorithms() {
    for alg in Algorithm::ALL {
      let hash = compute_hash_from_bytes(b"", alg);
      assert_eq!(hash.len(), alg.digest_bytes() * 2, "alg {:?}", alg);
      assert!(hash.chars().all(|c| c.is_ascii_hexdigit()));
    }
  }

  #[test]
  fn test_cancelled_reader_produces_no_output() {
    let cancelled = AtomicBool::new(true);
    let mut cursor = Cursor::new(b"hello world".to_vec());
    let result =
      compute_hash_from_reader_cancellable(&mut cursor, Algorithm::BLAKE3, 8192, &cancelled);
    assert!(result.is_err());
  }

  #[test]
  fn test_algorithm_from_str() {
    assert_eq!("blake3".parse::<Algorithm>().unwrap(), Algorithm::BLAKE3);
    assert_eq!(
      "SHA3-256".parse::<Algorithm>().unwrap(),
      Algorithm::Sha3_256
    );
    assert_eq!(
      "keccak-512".parse::<Algorithm>().unwrap(),
      Algorithm::Keccak512
    );
    assert_eq!(
      "keccak256".parse::<Algorithm>().unwrap(),
      Algorithm::Keccak256
    );
    assert_eq!("sfv".parse::<Algorithm>().unwrap(), Algorithm::CRC32);
    assert_eq!("k12-512".parse::<Algorithm>().unwrap(), Algorithm::K12_512);
    assert!("sha3-123".parse::<Algorithm>().is_err());
    assert!("md5".parse::<Algorithm>().is_err());
  }
}
