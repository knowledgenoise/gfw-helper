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
pub mod processing;
pub mod utils;
pub mod logger;

// Re-export commonly used items
pub use utils::{sanitize_markdown_content, resize_image_if_needed, convert_webp_to_png, convert_svg_to_png};
pub use logger::Logger;
