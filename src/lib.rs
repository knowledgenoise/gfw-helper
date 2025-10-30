//! # GFW Helper Library
//!
//! A comprehensive library for processing documentation and converting markdown to PDF.
//! This library provides utilities for:
//! - Sanitizing markdown content for LaTeX compilation
//! - Resizing images to prevent LaTeX errors
//! - Processing HTML documentation directories
//! - Converting markdown files to professional PDFs

pub mod cli;
pub mod commands;
pub mod logger;
pub mod parallel_processing;
pub mod processing;
pub mod utils;

// Re-export commonly used items
pub use logger::Logger;
pub use parallel_processing::{process_files_parallel, ParallelState};
pub use utils::{
    convert_svg_to_png, convert_webp_to_png, resize_image_if_needed, sanitize_markdown_content,
};

