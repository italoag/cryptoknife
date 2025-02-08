use anyhow::Result;
use std::path::PathBuf;
use walkdir::WalkDir;

/// Obtém uma lista de arquivos a partir de caminhos (arquivos ou diretórios).
pub fn gather_files(paths: &[PathBuf]) -> Result<Vec<PathBuf>> {
    let mut files = Vec::new();
    for path in paths {
        if path.is_file() {
            files.push(path.clone());
        } else if path.is_dir() {
            // Varre recursivamente o diretório
            for entry in WalkDir::new(path).into_iter().filter_map(|e| e.ok()) {
                let p = entry.path();
                if p.is_file() {
                    files.push(p.to_path_buf());
                }
            }
        } else {
            log::warn!("Caminho inválido: {}", path.display());
        }
    }
    Ok(files)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs::{File, create_dir_all};
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
}
