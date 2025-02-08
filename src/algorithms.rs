use anyhow::Result;
use std::io::Read;
use std::path::Path;
use tokio::io::AsyncReadExt;

// Importações para os algoritmos de SHA3 e Keccak.
use sha3::{Digest, Sha3_256, Sha3_512, Keccak256, Keccak512};

/// Limiar (em bytes) para considerar um arquivo como “grande” e usar memory mapping.
const LARGE_FILE_THRESHOLD: u64 = 10 * 1024 * 1024; // 10 MB

/// Algoritmos suportados.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Algorithm {
    BLAKE3,
    // Para SHA3 e Keccak, passamos o tamanho (em bits)
    SHA3 { bits: u16 },
    Keccak { bits: u16 },
    CRC32,
}

impl Algorithm {
    /// Retorna a extensão associada a cada algoritmo.
    pub fn extension(&self) -> &'static str {
        match self {
            Algorithm::SHA3 { bits } => match bits {
                256 => "sha3-256",
                512 => "sha3-512",
                _ => "sha3",
            },
            Algorithm::Keccak { bits } => match bits {
                256 => "keccak256",
                512 => "keccak512",
                _ => "keccak",
            },
            Algorithm::CRC32 => "sfv",
            Algorithm::BLAKE3 => "blake3",
        }
    }
}

/// Calcula o hash de um arquivo de forma assíncrona.  
/// Se o arquivo for grande (>= 10 MB), usa memory mapping em uma task bloqueante.
pub async fn compute_hash_async(path: &Path, algorithm: Algorithm, buffer_size: usize) -> Result<String> {
    let metadata = tokio::fs::metadata(path).await?;
    if metadata.len() >= LARGE_FILE_THRESHOLD {
        let path = path.to_owned();
        match algorithm {
            Algorithm::SHA3 { bits } => {
                use memmap2::Mmap;
                let join_handle = tokio::task::spawn_blocking(move || -> Result<String> {
                    let file = std::fs::File::open(&path)?;
                    let mmap = unsafe { Mmap::map(&file)? };
                    let encoded = match bits {
                        256 => {
                            let mut hasher = Sha3_256::new();
                            hasher.update(&mmap);
                            hex::encode(hasher.finalize())
                        },
                        512 => {
                            let mut hasher = Sha3_512::new();
                            hasher.update(&mmap);
                            hex::encode(hasher.finalize())
                        },
                        _ => panic!("Unsupported SHA3 bits: {}", bits),
                    };
                    Ok(encoded)
                });
                let result = join_handle.await??;
                Ok(result)
            }
            Algorithm::Keccak { bits } => {
                use memmap2::Mmap;
                let join_handle = tokio::task::spawn_blocking(move || -> Result<String> {
                    let file = std::fs::File::open(&path)?;
                    let mmap = unsafe { Mmap::map(&file)? };
                    let encoded = match bits {
                        256 => {
                            let mut hasher = Keccak256::new();
                            hasher.update(&mmap);
                            hex::encode(hasher.finalize())
                        },
                        512 => {
                            let mut hasher = Keccak512::new();
                            hasher.update(&mmap);
                            hex::encode(hasher.finalize())
                        },
                        _ => panic!("Unsupported Keccak bits: {}", bits),
                    };
                    Ok(encoded)
                });
                let result = join_handle.await??;
                Ok(result)
            }
            Algorithm::CRC32 => {
                use memmap2::Mmap;
                let join_handle = tokio::task::spawn_blocking(move || -> Result<String> {
                    let file = std::fs::File::open(&path)?;
                    let mmap = unsafe { Mmap::map(&file)? };
                    let mut hasher = crc32fast::Hasher::new();
                    hasher.update(&mmap);
                    let hash = hasher.finalize();
                    Ok(format!("{:08x}", hash))
                });
                let result = join_handle.await??;
                Ok(result)
            }
            Algorithm::BLAKE3 => {
                use memmap2::Mmap;
                let join_handle = tokio::task::spawn_blocking(move || -> Result<String> {
                    let file = std::fs::File::open(&path)?;
                    let mmap = unsafe { Mmap::map(&file)? };
                    let mut hasher = blake3::Hasher::new();
                    hasher.update(&mmap);
                    let result = hasher.finalize();
                    Ok(result.to_hex().to_string())
                });
                let result = join_handle.await??;
                Ok(result)
            }
        }
    } else {
        let mut file = tokio::fs::File::open(path).await?;
        match algorithm {
            Algorithm::SHA3 { bits } => {
                let mut buffer = vec![0u8; buffer_size];
                let encoded = match bits {
                    256 => {
                        let mut hasher = Sha3_256::new();
                        loop {
                            let n = file.read(&mut buffer).await?;
                            if n == 0 { break; }
                            hasher.update(&buffer[..n]);
                        }
                        hex::encode(hasher.finalize())
                    },
                    512 => {
                        let mut hasher = Sha3_512::new();
                        loop {
                            let n = file.read(&mut buffer).await?;
                            if n == 0 { break; }
                            hasher.update(&buffer[..n]);
                        }
                        hex::encode(hasher.finalize())
                    },
                    _ => panic!("Unsupported SHA3 bits: {}", bits),
                };
                Ok(encoded)
            }
            Algorithm::Keccak { bits } => {
                let mut buffer = vec![0u8; buffer_size];
                let encoded = match bits {
                    256 => {
                        let mut hasher = Keccak256::new();
                        loop {
                            let n = file.read(&mut buffer).await?;
                            if n == 0 { break; }
                            hasher.update(&buffer[..n]);
                        }
                        hex::encode(hasher.finalize())
                    },
                    512 => {
                        let mut hasher = Keccak512::new();
                        loop {
                            let n = file.read(&mut buffer).await?;
                            if n == 0 { break; }
                            hasher.update(&buffer[..n]);
                        }
                        hex::encode(hasher.finalize())
                    },
                    _ => panic!("Unsupported Keccak bits: {}", bits),
                };
                Ok(encoded)
            }
            Algorithm::CRC32 => {
                let mut hasher = crc32fast::Hasher::new();
                let mut buffer = vec![0u8; buffer_size];
                loop {
                    let n = file.read(&mut buffer).await?;
                    if n == 0 { break; }
                    hasher.update(&buffer[..n]);
                }
                let hash = hasher.finalize();
                Ok(format!("{:08x}", hash))
            }
            Algorithm::BLAKE3 => {
                let mut hasher = blake3::Hasher::new();
                let mut buffer = vec![0u8; buffer_size];
                loop {
                    let n = file.read(&mut buffer).await?;
                    if n == 0 { break; }
                    hasher.update(&buffer[..n]);
                }
                let result = hasher.finalize();
                Ok(result.to_hex().to_string())
            }
        }
    }
}

/// Calcula o hash a partir de um slice de bytes (opera de forma síncrona).
pub fn compute_hash_from_bytes(data: &[u8], algorithm: Algorithm) -> String {
    match algorithm {
        Algorithm::SHA3 { bits } => match bits {
            256 => {
                let mut hasher = Sha3_256::new();
                hasher.update(data);
                hex::encode(hasher.finalize())
            },
            512 => {
                let mut hasher = Sha3_512::new();
                hasher.update(data);
                hex::encode(hasher.finalize())
            },
            _ => panic!("Unsupported SHA3 bits: {}", bits),
        },
        Algorithm::Keccak { bits } => match bits {
            256 => {
                let mut hasher = Keccak256::new();
                hasher.update(data);
                hex::encode(hasher.finalize())
            },
            512 => {
                let mut hasher = Keccak512::new();
                hasher.update(data);
                hex::encode(hasher.finalize())
            },
            _ => panic!("Unsupported Keccak bits: {}", bits),
        },
        Algorithm::CRC32 => {
            let mut hasher = crc32fast::Hasher::new();
            hasher.update(data);
            format!("{:08x}", hasher.finalize())
        },
        Algorithm::BLAKE3 => {
            let mut hasher = blake3::Hasher::new();
            hasher.update(data);
            hasher.finalize().to_hex().to_string()
        },
    }
}

/// Calcula o hash a partir de um leitor que implementa o trait `Read`, utilizando um buffer configurável.
pub fn compute_hash_from_reader<R: Read>(reader: &mut R, algorithm: Algorithm, buffer_size: usize) -> Result<String> {
    let mut buffer = vec![0u8; buffer_size];
    match algorithm {
        Algorithm::SHA3 { bits } => match bits {
            256 => {
                let mut hasher = Sha3_256::new();
                loop {
                    let n = reader.read(&mut buffer)?;
                    if n == 0 { break; }
                    hasher.update(&buffer[..n]);
                }
                Ok(hex::encode(hasher.finalize()))
            },
            512 => {
                let mut hasher = Sha3_512::new();
                loop {
                    let n = reader.read(&mut buffer)?;
                    if n == 0 { break; }
                    hasher.update(&buffer[..n]);
                }
                Ok(hex::encode(hasher.finalize()))
            },
            _ => panic!("Unsupported SHA3 bits: {}", bits),
        },
        Algorithm::Keccak { bits } => match bits {
            256 => {
                let mut hasher = Keccak256::new();
                loop {
                    let n = reader.read(&mut buffer)?;
                    if n == 0 { break; }
                    hasher.update(&buffer[..n]);
                }
                Ok(hex::encode(hasher.finalize()))
            },
            512 => {
                let mut hasher = Keccak512::new();
                loop {
                    let n = reader.read(&mut buffer)?;
                    if n == 0 { break; }
                    hasher.update(&buffer[..n]);
                }
                Ok(hex::encode(hasher.finalize()))
            },
            _ => panic!("Unsupported Keccak bits: {}", bits),
        },
        Algorithm::CRC32 => {
            let mut hasher = crc32fast::Hasher::new();
            loop {
                let n = reader.read(&mut buffer)?;
                if n == 0 { break; }
                hasher.update(&buffer[..n]);
            }
            Ok(format!("{:08x}", hasher.finalize()))
        },
        Algorithm::BLAKE3 => {
            let mut hasher = blake3::Hasher::new();
            loop {
                let n = reader.read(&mut buffer)?;
                if n == 0 { break; }
                hasher.update(&buffer[..n]);
            }
            Ok(hasher.finalize().to_hex().to_string())
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn test_compute_hash_from_bytes_sha3_256() {
        let data = b"hello world";
        let hash = compute_hash_from_bytes(data, Algorithm::SHA3 { bits: 256 });
        let expected = "644bcc7e564373040999aac89e7622f3ca71fba1d972fd94a31c3bfbf24e3938";
        assert_eq!(hash, expected);
    }

    #[test]
    fn test_compute_hash_from_bytes_sha3_512() {
        let data = b"hello world";
        let hash = compute_hash_from_bytes(data, Algorithm::SHA3 { bits: 512 });
        let expected = "840006653e9ac9e95117a15c915caab81662918e925de9e004f774ff82d7079a40d4d27b1b372657c61d46d470304c88c788b3a4527ad074d1dccbee5dbaa99a";
        assert_eq!(hash, expected);
    }

    #[test]
    fn test_compute_hash_from_bytes_keccak256() {
        let data = b"hello world";
        let hash = compute_hash_from_bytes(data, Algorithm::Keccak { bits: 256 });
        let expected = "47173285a8d7341e5e972fc677286384f802f8ef42a5ec5f03bbfa254cb01fad";
        assert_eq!(hash, expected);
    }

    #[test]
    fn test_compute_hash_from_bytes_keccak512() {
        let data = b"hello world";
        let hash = compute_hash_from_bytes(data, Algorithm::Keccak { bits: 512 });
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
    fn test_compute_hash_from_reader_sha3_256() {
        let data = b"hello world";
        let mut cursor = Cursor::new(data);
        let hash = compute_hash_from_reader(&mut cursor, Algorithm::SHA3 { bits: 256 }, 4).unwrap();
        let expected = "644bcc7e564373040999aac89e7622f3ca71fba1d972fd94a31c3bfbf24e3938";
        assert_eq!(hash, expected);
    }

    #[test]
    fn test_compute_hash_from_reader_keccak256() {
        let data = b"hello world";
        let mut cursor = Cursor::new(data);
        let hash = compute_hash_from_reader(&mut cursor, Algorithm::Keccak { bits: 256 }, 4).unwrap();
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
}
