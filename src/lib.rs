pub mod algorithms;
pub mod file_ops;
pub mod formats;
pub mod generate;
pub mod options;
pub mod report;
pub mod verify;

pub(crate) mod execute;

pub use algorithms::{
  compute_file_hash, compute_hash_async, compute_hash_from_bytes, compute_hash_from_reader,
  compute_hash_stdin, validate_buffer_size, Algorithm, DEFAULT_BUFFER_SIZE, MAX_BUFFER_SIZE,
};
pub use file_ops::{
  atomic_write, checksum_path, normalize_lexical, AtomicOutput, Discovery, FileDiscovery,
};
pub use formats::{ChecksumEntry, ChecksumFormat};
pub use generate::{generate_checksums, generate_document, generate_with_options};
pub use options::RunOptions;
pub use report::{FileResult, FileStatus, RunSummary};
pub use verify::{verify_checksums, verify_request, verify_with_options, VerifyRequest};
