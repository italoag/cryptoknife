use crate::algorithms::Algorithm;
use std::path::PathBuf;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FileStatus {
  Generated,
  Matched,
  Mismatched,
  MissingData,
  MissingChecksum,
  InvalidChecksum,
  ReadError,
  WriteError,
  Skipped,
  Cancelled,
}

#[derive(Clone, Debug)]
pub struct FileResult {
  pub path: PathBuf,
  pub algorithm: Algorithm,
  pub status: FileStatus,
  pub digest: Option<String>,
  pub message: Option<String>,
}

impl FileResult {
  pub fn new(path: PathBuf, algorithm: Algorithm, status: FileStatus) -> Self {
    FileResult {
      path,
      algorithm,
      status,
      digest: None,
      message: None,
    }
  }

  pub fn with_message(mut self, message: impl Into<String>) -> Self {
    self.message = Some(message.into());
    self
  }

  pub fn with_digest(mut self, digest: impl Into<String>) -> Self {
    self.digest = Some(digest.into());
    self
  }
}

#[derive(Clone, Debug, Default)]
pub struct RunSummary {
  pub selected: u64,
  pub succeeded: u64,
  pub mismatched: u64,
  pub missing: u64,
  pub errors: u64,
  pub skipped: u64,
  pub cancelled: bool,
}

impl RunSummary {
  pub fn record(&mut self, result: &FileResult) {
    match result.status {
      FileStatus::Skipped => {
        self.skipped += 1;
      }
      FileStatus::Cancelled => {
        self.selected += 1;
        self.errors += 1;
        self.cancelled = true;
      }
      FileStatus::Generated | FileStatus::Matched => {
        self.selected += 1;
        self.succeeded += 1;
      }
      FileStatus::Mismatched => {
        self.selected += 1;
        self.mismatched += 1;
      }
      FileStatus::MissingData | FileStatus::MissingChecksum => {
        self.selected += 1;
        self.missing += 1;
      }
      FileStatus::InvalidChecksum | FileStatus::ReadError | FileStatus::WriteError => {
        self.selected += 1;
        self.errors += 1;
      }
    }
  }

  pub fn exit_code(&self) -> u8 {
    if self.cancelled {
      130
    } else if self.errors > 0 {
      3
    } else if self.mismatched > 0 || self.missing > 0 {
      1
    } else if self.selected == 0 {
      3
    } else {
      0
    }
  }
}

#[cfg(test)]
mod tests {
  use super::*;

  fn result(status: FileStatus) -> FileResult {
    FileResult::new(PathBuf::from("x"), Algorithm::BLAKE3, status)
  }

  #[test]
  fn test_summary_reconciles_counts() {
    let mut s = RunSummary::default();
    for status in [
      FileStatus::Generated,
      FileStatus::Matched,
      FileStatus::Mismatched,
      FileStatus::MissingChecksum,
      FileStatus::InvalidChecksum,
      FileStatus::Skipped,
    ] {
      s.record(&result(status));
    }
    assert_eq!(s.selected, 5);
    assert_eq!(s.succeeded, 2);
    assert_eq!(s.mismatched, 1);
    assert_eq!(s.missing, 1);
    assert_eq!(s.errors, 1);
    assert_eq!(s.skipped, 1);
    assert_eq!(
      s.selected,
      s.succeeded + s.mismatched + s.missing + s.errors
    );
  }

  #[test]
  fn test_exit_code_precedence() {
    let mut s = RunSummary::default();
    assert_eq!(s.exit_code(), 3);

    s.record(&result(FileStatus::Matched));
    assert_eq!(s.exit_code(), 0);

    s.record(&result(FileStatus::Mismatched));
    assert_eq!(s.exit_code(), 1);

    s.record(&result(FileStatus::ReadError));
    assert_eq!(s.exit_code(), 3);

    s.record(&result(FileStatus::Cancelled));
    assert_eq!(s.exit_code(), 130);
  }

  #[test]
  fn test_missing_exit_code() {
    let mut s = RunSummary::default();
    s.record(&result(FileStatus::MissingData));
    s.record(&result(FileStatus::Matched));
    assert_eq!(s.exit_code(), 1);
  }
}
