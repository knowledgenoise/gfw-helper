//! Parallel processing utilities for thread-safe concurrent operations.
//!
//! This module provides common patterns and helpers for parallel processing,
//! following the DRY principle by centralizing reusable parallel processing logic.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use crate::logger::Logger;

/// Counters and state for parallel operations
pub struct ParallelState {
    /// Number of items processed so far
    pub processed: Arc<AtomicUsize>,
    /// Number of successful items
    pub successful: Arc<AtomicUsize>,
    /// List of failures with descriptions
    pub failures: Arc<Mutex<Vec<(String, String)>>>,
}

impl ParallelState {
    /// Create a new parallel state for tracking progress
    pub fn new() -> Self {
        ParallelState {
            processed: Arc::new(AtomicUsize::new(0)),
            successful: Arc::new(AtomicUsize::new(0)),
            failures: Arc::new(Mutex::new(Vec::new())),
        }
    }

    /// Increment the processed counter and return the new value
    pub fn increment_processed(&self, ordering: Ordering) -> usize {
        self.processed.fetch_add(1, ordering) + 1
    }

    /// Increment the successful counter
    pub fn increment_successful(&self, ordering: Ordering) {
        self.successful.fetch_add(1, ordering);
    }

    /// Add a failure to the failures list
    pub fn add_failure(&self, name: String, error: String) {
        self.failures.lock().unwrap().push((name, error));
    }


    /// Get the current count of successful items
    pub fn get_successful(&self, ordering: Ordering) -> usize {
        self.successful.load(ordering)
    }

    /// Get all failures as a vector
    pub fn get_failures(&self) -> Vec<(String, String)> {
        self.failures.lock().unwrap().clone()
    }

    /// Get the number of failures
    pub fn get_failure_count(&self) -> usize {
        self.failures.lock().unwrap().len()
    }

    /// Report completion with standard logging
    pub fn report_completion(&self, total: usize, operation: &str) {
        let successful = self.get_successful(Ordering::SeqCst);
        let failed = self.get_failure_count();
        Logger::parallel_complete(successful, failed, total, operation);
    }

    /// Report completion and log failures
    pub fn report_completion_with_failures(&self, total: usize, operation: &str) {
        self.report_completion(total, operation);
        let failures = self.get_failures();
        if !failures.is_empty() {
            Logger::parallel_failures(&failures);
        }
    }
}

impl Default for ParallelState {
    fn default() -> Self {
        Self::new()
    }
}

/// Helper function to process PathBuf items in parallel with progress tracking.
///
/// This function encapsulates the common pattern of parallel file processing,
/// eliminating duplicate code across PDF conversion commands.
///
/// # Arguments
/// * `file_paths` - Slice of PathBuf items to process in parallel
/// * `process_fn` - Function that processes a single file path
/// * `progress_message` - Optional message to display during processing (defaults to "Converting PDFs...")
/// * `operation_name` - Optional name of the operation for completion reporting (defaults to "PDF conversion")
///
/// # Returns
/// * `ParallelState` - Final state with all processing results
pub fn process_files_parallel<F>(
    file_paths: &[std::path::PathBuf],
    process_fn: F,
    progress_message: Option<&str>,
    operation_name: Option<&str>,
) -> ParallelState
where
    F: Fn(&std::path::Path) -> Result<(), Box<dyn std::error::Error>> + Send + Sync,
{
    use rayon::prelude::*;
    
    let progress_msg = progress_message.unwrap_or("Converting PDFs...\n");
    let operation = operation_name.unwrap_or("PDF conversion");
    
    let total = file_paths.len();
    let state = ParallelState::new();

    file_paths.par_iter().for_each(|file_path| {
        let result = process_fn(file_path);
        let count = state.increment_processed(Ordering::SeqCst);

        if result.is_ok() {
            state.increment_successful(Ordering::SeqCst);
        } else if let Err(e) = result {
            let file_name = file_path
                .file_name()
                .unwrap_or_default()
                .to_string_lossy()
                .to_string();
            state.add_failure(file_name, e.to_string());
        }

        Logger::parallel_progress(count, total, progress_msg);
    });

    state.report_completion_with_failures(total, operation);
    state
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parallel_state_creation() {
        let state = ParallelState::new();
        assert_eq!(state.get_successful(Ordering::SeqCst), 0);
        assert_eq!(state.get_failure_count(), 0);
    }

    #[test]
    fn test_parallel_state_increment() {
        let state = ParallelState::new();
        assert_eq!(state.increment_processed(Ordering::SeqCst), 1);
        assert_eq!(state.increment_processed(Ordering::SeqCst), 2);
    }

    #[test]
    fn test_parallel_state_failures() {
        let state = ParallelState::new();
        state.add_failure("file1.txt".to_string(), "error occurred".to_string());
        state.add_failure("file2.txt".to_string(), "another error".to_string());
        assert_eq!(state.get_failure_count(), 2);
        let failures = state.get_failures();
        assert_eq!(failures.len(), 2);
    }
}
