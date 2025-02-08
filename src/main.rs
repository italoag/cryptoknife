use clap::{Parser, ValueEnum};
use std::path::PathBuf;
use cryptoknife_lib::{generate_checksums, verify_checksums, Algorithm};

use simplelog::*;
use std::fs::File;

/// Aplicação CLI para geração e verificação de checksums.
#[derive(Parser, Debug)]
#[command(author = "Italo A. G.", version = "0.1.0", about = "Cryptographic Tools CLI", long_about = None)]
struct Cli {
    /// Modo de operação: generate ou verify
    #[arg(value_enum)]
    mode: OperationMode,

    /// Caminho(s) para arquivo(s) e/ou diretório(s) a serem processados
    #[arg(required = true)]
    paths: Vec<PathBuf>,

    /// Algoritmo a ser utilizado.
    /// Exemplos válidos:
    ///   sha3-256, sha3-512, keccak-256, keccak-512, blake3, crc32
    #[arg(long, short = 'a', default_value = "blake3")]
    algorithm: String,

    /// Exibe logs detalhados (nível debug)
    #[arg(long, short = 'v', action = clap::ArgAction::SetTrue)]
    verbose: bool,

    /// Tamanho do buffer para leituras (em bytes). Valor padrão: 8192.
    #[arg(long, short = 'b', default_value = "8192")]
    buffer_size: usize,
}

#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, ValueEnum, Debug)]
enum OperationMode {
    Generate,
    Verify,
}

/// Interpreta a string informada em --algorithm e retorna o algoritmo correspondente.
/// Exemplos:
/// - "sha3-256"   → Algorithm::SHA3 { bits: 256 }
/// - "sha3-512"   → Algorithm::SHA3 { bits: 512 }
/// - "keccak-256" → Algorithm::Keccak { bits: 256 }
/// - "keccak-512" → Algorithm::Keccak { bits: 512 }
/// - "blake3"     → Algorithm::BLAKE3
/// - "crc32" ou "sfv" → Algorithm::CRC32
fn parse_algorithm(s: &str) -> Option<Algorithm> {
    let s = s.to_lowercase();
    if s.starts_with("sha3-") {
        let parts: Vec<&str> = s.split('-').collect();
        if parts.len() == 2 {
            if let Ok(bits) = parts[1].parse::<u16>() {
                return Some(Algorithm::SHA3 { bits });
            }
        }
    } else if s.starts_with("keccak-") {
        let parts: Vec<&str> = s.split('-').collect();
        if parts.len() == 2 {
            if let Ok(bits) = parts[1].parse::<u16>() {
                return Some(Algorithm::Keccak { bits });
            }
        }
    } else if s == "blake3" {
        return Some(Algorithm::BLAKE3);
    } else if s == "crc32" || s == "sfv" {
        return Some(Algorithm::CRC32);
    }
    None
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Processa os argumentos.
    let cli = Cli::parse();

    // Define o nível de log padrão com base no modo de compilação.
    let default_log_level = if cfg!(debug_assertions) {
        LevelFilter::Debug
    } else {
        LevelFilter::Info
    };
    let log_level = if cli.verbose { LevelFilter::Debug } else { default_log_level };

    // Inicializa o logger combinando terminal e arquivo.
    CombinedLogger::init(vec![
        TermLogger::new(
            log_level,
            Config::default(),
            TerminalMode::Mixed,
            ColorChoice::Auto,
        ),
        WriteLogger::new(log_level, Config::default(), File::create("hashsum.log")?),
    ])?;

    // Converte a string de algoritmo para o valor do enum.
    let algorithm = match parse_algorithm(&cli.algorithm) {
        Some(alg) => alg,
        None => {
            log::error!("Algoritmo desconhecido ou formato inválido: {}", cli.algorithm);
            std::process::exit(1);
        }
    };

    // Executa o modo escolhido.
    match cli.mode {
        OperationMode::Generate => {
            generate_checksums(&cli.paths, algorithm, cli.verbose, cli.buffer_size).await?
        }
        OperationMode::Verify => {
            verify_checksums(&cli.paths, algorithm, cli.verbose, cli.buffer_size).await?
        }
    }

    Ok(())
}
