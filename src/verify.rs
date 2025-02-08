use crate::algorithms::{compute_hash_async, Algorithm};
use crate::file_ops::gather_files;
use anyhow::Result;
use futures::StreamExt;
use indicatif::{ProgressBar, ProgressStyle};
use std::path::PathBuf;
use tokio::fs;

const MAX_CONCURRENT_FILES: usize = 100; // Limita o número de operações simultâneas

const KNOWN_EXTENSIONS: &[&str] = &[
    "sha3-256", "sha3-512",
    "keccak256", "keccak512",
    "blake3",
    "sfv",
    "k12-256", "k12-512",
    "whirlpool",
];

fn is_checksum_file(fname: &str) -> bool {
    KNOWN_EXTENSIONS.iter().any(|ext| fname.ends_with(ext))
}

/// Verifica os arquivos de dados comparando com seus respectivos arquivos de checksum.
/// Para cada arquivo, procura um arquivo de checksum com o mesmo nome acrescido da extensão do algoritmo.
/// Se o arquivo de checksum não for encontrado, registra uma mensagem de aviso.
pub async fn verify_checksums(
    paths: &[PathBuf],
    algorithm: Algorithm,
    verbose: bool,
    buffer_size: usize,
) -> Result<()> {
    let all_files = gather_files(paths)?;
    // Filtra: ignora arquivos que já são checksum
    let files: Vec<PathBuf> = all_files
        .into_iter()
        .filter(|file| {
            if let Some(fname) = file.file_name().and_then(|s| s.to_str()) {
                !is_checksum_file(fname)
            } else {
                true
            }
        })
        .collect();

    if files.is_empty() {
        log::info!("Nenhum arquivo de dados encontrado para verificação.");
        return Ok(());
    }

    let pb = ProgressBar::new(files.len() as u64);
    pb.set_style(
        ProgressStyle::with_template("[{elapsed_precise}] {bar:40.green/blue} {pos}/{len} ({eta})")?
            .progress_chars("=>-"),
    );

    futures::stream::iter(files.into_iter().map(|file| {
        let pb = pb.clone();
        let alg = algorithm;
        async move {
            // Define o caminho esperado para o arquivo de checksum.
            let checksum_file = file.with_file_name(format!(
                "{}.{}",
                file.file_name().unwrap().to_string_lossy(),
                alg.extension()
            ));

            if !checksum_file.exists() {
                log::warn!(
                    "[Not Found] {} (arquivo de checksum {} não encontrado)",
                    file.display(),
                    checksum_file.display()
                );
                pb.inc(1);
                return Ok::<(), anyhow::Error>(());
            }
            let expected_hash = fs::read_to_string(&checksum_file).await?;
            let actual_hash = compute_hash_async(&file, alg, buffer_size).await?;
            if actual_hash.trim() == expected_hash.trim() {
                if verbose {
                    log::info!("[OK] {}: {}", file.display(), actual_hash);
                } else {
                    log::debug!("[OK] {}: {}", file.display(), actual_hash);
                }
            } else {
                log::error!(
                    "[FAILED] {}: esperado {}, obtido {}",
                    file.display(),
                    expected_hash.trim(),
                    actual_hash
                );
            }
            pb.inc(1);
            Ok::<(), anyhow::Error>(())
        }
    }))
    .buffer_unordered(MAX_CONCURRENT_FILES)
    .for_each(|result| async {
        if let Err(e) = result {
            log::error!("Erro ao verificar arquivo: {}", e);
        }
    })
    .await;

    pb.finish_with_message("Verificação concluída.");
    Ok(())
}
