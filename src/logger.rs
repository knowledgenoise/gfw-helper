//! Professional logging module for GFW Helper
//!
//! Provides consistent, colored output for CLI operations with different log levels:
//! - INFO: General information (blue)
//! - SUCCESS: Successful operations (green)
//! - WARNING: Non-critical issues (yellow)
//! - ERROR: Critical errors (red)
//! - PROGRESS: Operation progress (cyan)

use colored::*;
use std::path::Path;
use std::sync::Mutex;
use std::io::{self, Write};

// Global mutex for synchronized output in multi-threaded contexts
static OUTPUT_LOCK: Mutex<()> = Mutex::new(());

/// Main logger struct for GFW Helper
pub struct Logger;

#[allow(dead_code)]
impl Logger {
    /// Print application header
    pub fn header(version: &str) {
        println!("{}", "═".repeat(80).bright_blue());
        println!(
            "  {} {}",
            "GFW Helper".bright_white().bold(),
            format!("v{}", version).bright_blue()
        );
        println!(
            "  {}",
            "Comprehensive Documentation Processor".bright_black()
        );
        println!("{}", "═".repeat(80).bright_blue());
    }

    /// Print a general information message
    pub fn info(message: &str) {
        let _lock = OUTPUT_LOCK.lock().unwrap();
        println!("  {} {}", "●".bright_blue(), message);
    }

    /// Print a success message
    pub fn success(message: &str) {
        let _lock = OUTPUT_LOCK.lock().unwrap();
        println!("  {} {}", "✓".bright_green(), message.bright_white());
    }

    /// Print a warning message
    pub fn warning(message: &str) {
        let _lock = OUTPUT_LOCK.lock().unwrap();
        println!("  {} {}", "⚠".bright_yellow(), message.yellow());
    }

    /// Print an error message to stderr
    pub fn error(message: &str) {
        let _lock = OUTPUT_LOCK.lock().unwrap();
        eprintln!("  {} {}", "✗".bright_red(), message.red());
    }

    /// Print a progress/step message
    pub fn progress(step: &str, message: &str) {
        let _lock = OUTPUT_LOCK.lock().unwrap();
        println!("\n  {} {}", step.bright_cyan().bold(), message.bright_white());
    }

    /// Print a sub-item message (indented)
    pub fn detail(message: &str) {
        let _lock = OUTPUT_LOCK.lock().unwrap();
        println!("    · {}", message.bright_black());
    }

    /// Print a section separator
    pub fn separator() {
        let _lock = OUTPUT_LOCK.lock().unwrap();
        println!("{}", "  ─".repeat(40).bright_black());
    }

    /// Print workflow start message
    pub fn workflow_start(workflow_type: &str, path: &Path) {
        let _lock = OUTPUT_LOCK.lock().unwrap();
        println!("\n{}", "═".repeat(80).bright_blue());
        println!(
            "  {} {}",
            "Starting Workflow:".bright_white().bold(),
            workflow_type.bright_cyan()
        );
        println!(
            "  {} {}",
            "Source Directory:".bright_white(),
            path.display().to_string().bright_blue()
        );
        println!("{}", "═".repeat(80).bright_blue());
    }

    /// Print workflow completion message
    pub fn workflow_complete(summary: &str) {
        let _lock = OUTPUT_LOCK.lock().unwrap();
        println!("\n{}", "═".repeat(80).bright_green());
        println!("  {} {}", "✓".bright_green(), "Workflow Complete!".bright_white().bold());
        println!("  {}", summary.bright_black());
        println!("{}", "═".repeat(80).bright_green());
    }

    /// Print a step header (for multi-step workflows)
    pub fn step(number: u8, title: &str) {
        let _lock = OUTPUT_LOCK.lock().unwrap();
        println!(
            "\n  {} {}",
            format!("[Step {}]", number).bright_cyan().bold(),
            title.bright_white()
        );
    }

    /// Print file operation message
    pub fn file_operation(operation: &str, path: &Path) {
        Self::detail(&format!("{}: {}", operation, path.display()));
    }

    /// Print conversion message
    pub fn conversion(from: &str, to: &str) {
        Self::detail(&format!("Converting: {} → {}", from.bright_blue(), to.bright_green()));
    }

    /// Print statistics message
    pub fn stats(label: &str, value: &str) {
        let _lock = OUTPUT_LOCK.lock().unwrap();
        println!("    {} {}", label.bright_white(), value.bright_cyan());
    }

    /// Print a progress update for parallel operations (thread-safe)
    pub fn parallel_progress(current: usize, total: usize, message: &str) {
        let _lock = OUTPUT_LOCK.lock().unwrap();
        let percentage = (current as f64 / total as f64 * 100.0) as u8;
        let bar_width = 30;
        let filled = (bar_width as f64 * current as f64 / total as f64) as usize;
        let bar = format!(
            "[{}{}]",
            "█".repeat(filled).bright_green(),
            "░".repeat(bar_width - filled).bright_black()
        );
        print!("\r  {} {}/{} ({}%) {}", 
               bar,
               current.to_string().bright_cyan(),
               total.to_string().bright_white(),
               percentage.to_string().bright_yellow(),
               message.bright_black()
        );
        io::stdout().flush().unwrap();
        if current == total {
            println!(); // New line after completion
        }
    }

    /// Print parallel operation completion summary
    pub fn parallel_complete(successful: usize, failed: usize, total: usize, operation: &str) {
        let _lock = OUTPUT_LOCK.lock().unwrap();
        println!("\n  {} Completed {} operations:", "✓".bright_green(), operation);
        println!("    {} {} successful", "✓".bright_green(), successful.to_string().bright_green());
        if failed > 0 {
            println!("    {} {} failed", "✗".bright_red(), failed.to_string().bright_red());
        }
        println!("    {} {} total", "●".bright_blue(), total.to_string().bright_white());
    }

    /// Print detailed failure list with error messages
    pub fn parallel_failures(failures: &[(String, String)]) {
        if failures.is_empty() {
            return;
        }
        
        let _lock = OUTPUT_LOCK.lock().unwrap();
        println!("\n  {} Failed conversions:", "✗".bright_red().bold());
        for (i, (file, error)) in failures.iter().enumerate() {
            println!("    {}. {} {}", 
                (i + 1).to_string().bright_red(),
                file.bright_white(),
                "→".bright_black()
            );
            println!("       {}", error.red());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn test_logger_creation() {
        // Just test that we can call the static methods without panicking
        Logger::info("Test message");
        Logger::success("Success message");
        Logger::warning("Warning message");
        Logger::error("Error message");
    }

    #[test]
    fn test_logger_with_paths() {
        let path = PathBuf::from("/test/path");
        Logger::file_operation("Processing", &path);
        Logger::workflow_start("Test Workflow", &path);
    }

    #[test]
    fn test_logger_formatting() {
        Logger::header("1.0.0");
        Logger::step(1, "Test Step");
        Logger::conversion("file.md", "file.pdf");
        Logger::stats("Count", "42");
        Logger::workflow_complete("Test complete");
    }

    #[test]
    fn test_parallel_logging() {
        // Test parallel completion logging
        Logger::parallel_complete(18, 2, 20, "test operation");
        
        // Test failure reporting
        let failures = vec![
            ("file1.md".to_string(), "LaTeX compilation error".to_string()),
            ("file2.md".to_string(), "Image processing failed".to_string()),
        ];
        Logger::parallel_failures(&failures);
        
        // Test with empty failures (should not print anything)
        let empty: Vec<(String, String)> = vec![];
        Logger::parallel_failures(&empty);
    }
}
