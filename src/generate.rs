use crate::algorithms::{compute_hash_async, Algorithm};
use crate::file_ops::gather_files;
use anyhow::Result;
use futures::StreamExt;
use indicatif::{ProgressBar, ProgressStyle};
use std::path::PathBuf;
use tokio::fs;

const MAX_CONCURRENT_FILES: usize = 100; // Limita o número de operações simultâneas

// Lista de extensões geradas pelos algoritmos
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

/// Gera arquivos de checksum para cada arquivo de dados encontrado.
/// Para cada arquivo (seja individual ou em diretório), é criado um arquivo com o mesmo nome acrescido da extensão do algoritmo.
/// O parâmetro `buffer_size` define o tamanho do buffer usado para leituras assíncronas.
pub async fn generate_checksums(
    paths: &[PathBuf],
    algorithm: Algorithm,
    verbose: bool,
    buffer_size: usize,
) -> Result<()> {
    let files = gather_files(paths)?;
    if files.is_empty() {
        log::info!("Nenhum arquivo encontrado para processar.");
        return Ok(());
    }

    // Filtra: ignora arquivos que já são checksum (qualquer algoritmo)
    let files: Vec<PathBuf> = files
        .into_iter()
        .filter(|file| {
            if let Some(fname) = file.file_name().and_then(|s| s.to_str()) {
                !is_checksum_file(fname)
            } else {
                true
            }
        })
        .collect();

    let pb = ProgressBar::new(files.len() as u64);
    pb.set_style(
        ProgressStyle::with_template("[{elapsed_precise}] {bar:40.cyan/blue} {pos}/{len} ({eta})")?
            .progress_chars("#>-"),
    );

    // Processa os arquivos com um limite de concorrência
    futures::stream::iter(files.into_iter().map(|file| {
        let pb = pb.clone();
        let alg = algorithm;
        async move {
            if verbose {
                log::info!("Processando: {}", file.display());
            } else {
                log::debug!("Processando: {}", file.display());
            }
            let hash = compute_hash_async(&file, alg, buffer_size).await?;
            // Nome do arquivo de checksum: <nome_original>.<extensão>
            let output_file = file.with_file_name(format!(
                "{}.{}",
                file.file_name().unwrap().to_string_lossy(),
                alg.extension()
            ));
            fs::write(&output_file, format!("{}\n", hash)).await?;
            pb.inc(1);
            Ok::<(), anyhow::Error>(())
        }
    }))
    .buffer_unordered(MAX_CONCURRENT_FILES)
    .for_each(|result| async {
        if let Err(e) = result {
            log::error!("Erro ao processar arquivo: {}", e);
        }
    })
    .await;

    pb.finish_with_message("Geração concluída.");
    Ok(())
}
