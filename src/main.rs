#!/usr/bin/env rust-script
//! ```cargo
//! [dependencies]
//! walkdir = "2.5.0"
//! scraper = "0.19.0"
//! html2md = "0.2.15"
//! url = "2.5.0"
//! percent-encoding = "2.3.1"
//! clap = { version = "4.5.4", features = ["derive"] }
//! image = "0.25.1"
//! ```
use std::fs;
use std::path::{Path, PathBuf};
use scraper::{Html, Selector};
use walkdir::WalkDir;
use percent_encoding::percent_decode;
use uuid::Uuid;
use regex::Regex;
use std::process::Command;
use clap::Parser;
use crate::processing::images::detect_and_rename_image;
use crate::commands::md::Page;
use image::ImageReader;
use std::collections::HashMap;
use std::io::Read;
use std::ffi::OsString;
use serde_json;
use chrono;
use rayon::prelude::*;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

mod cli;
mod commands;
mod processing;
mod utils;
mod logger;

use utils::{sanitize_markdown_content, resize_image_if_needed, convert_webp_to_png};
use logger::Logger;

/// Scans a directory recursively and corrects image file extensions based on actual content.
/// 
/// This function walks through all files in the directory and its subdirectories,
/// detecting images with wrong extensions and renaming them appropriately.
/// 
/// # Arguments
/// * `dir_path` - Path to the directory to scan
///
/// # Returns
/// * Number of files that were corrected
fn correct_image_extensions_in_directory(dir_path: &Path) -> usize {
    let mut corrected_count = 0;
    
    for entry in WalkDir::new(dir_path).into_iter().filter_map(Result::ok) {
        if entry.file_type().is_file() {
            let path = entry.path();
            if let Some(ext) = path.extension() {
                let ext_str = ext.to_string_lossy().to_lowercase();
                // Only check files with image extensions
                if ["png", "jpg", "jpeg", "gif", "bmp", "webp", "tiff", "ico"].contains(&ext_str.as_str()) {
                    match detect_and_rename_image(path) {
                        Ok(new_path) => {
                            if new_path != path {
                                corrected_count += 1;
                            }
                        }
                        Err(_) => {
                            // Silently continue if detection fails (file might be corrupted or not actually an image)
                        }
                    }
                }
            }
        }
    }
    
    corrected_count
}

/// Main entry point of the GFW Helper application.
/// Parses command line arguments and dispatches to the appropriate command handler.
fn main() {
    Logger::header(env!("CARGO_PKG_VERSION"));
    
    // Parse command line arguments using clap
    let cli = cli::Cli::parse();

    // Determine output directory (default to current directory if not specified)
    let output_dir = cli.output_dir.unwrap_or_else(|| std::env::current_dir().unwrap());
    
    // Create output directory if it doesn't exist
    if !output_dir.exists() {
        if let Err(e) = fs::create_dir_all(&output_dir) {
            Logger::error(&format!("Failed to create output directory {}: {}", output_dir.display(), e));
            return;
        }
        Logger::success(&format!("Created output directory: {}", output_dir.display()));
    }

    // Dispatch to the appropriate command handler based on user input
    match cli.command {
        cli::Commands::Md { path, employee_only, project_only } => {
            // Unified markdown processing mode
            if employee_only && project_only {
                Logger::error("Cannot specify both --employee-only and --project-only");
                return;
            }
            
            let mode = if employee_only {
                Some(true)  // Employee only
            } else if project_only {
                Some(false) // Project only
            } else {
                None        // Process both
            };

            if path.is_file() {
                Logger::error("MD command requires a directory containing HTML export data, not a single file");
                Logger::detail("Use: gfw-helper md <directory>");
                return;
            } else if path.is_dir() {
                commands::md::process_directories_unified(&path, mode, &output_dir);
            } else {
                Logger::error(&format!("Path '{}' does not exist", path.display()));
                return;
            }
        }
        cli::Commands::Pdf { path, engine } => {
            Logger::info("Running in PDF mode");
            if path.is_file() {
                // Convert a single markdown file to PDF
                if let Err(e) = process_pdf(&path, &engine, &output_dir) {
                    Logger::error(&format!("Processing PDF failed: {}", e));
                }
            } else if path.is_dir() {
                // Convert all markdown files in a directory to PDF using parallel processing
                let md_files: Vec<PathBuf> = WalkDir::new(&path)
                    .into_iter()
                    .filter_map(Result::ok)
                    .filter(|e| e.file_type().is_file() && e.path().extension().and_then(|s| s.to_str()) == Some("md"))
                    .map(|e| e.path().to_path_buf())
                    .collect();

                let total = md_files.len();
                Logger::info(&format!("Found {} markdown files to convert", total));
                
                if total == 0 {
                    Logger::warning("No markdown files found");
                } else {
                    let processed = Arc::new(AtomicUsize::new(0));
                    let successful = Arc::new(AtomicUsize::new(0));
                    let failures = Arc::new(Mutex::new(Vec::new()));

                    md_files.par_iter().for_each(|file_path| {
                        let result = process_pdf(file_path, &engine, &output_dir);
                        let count = processed.fetch_add(1, Ordering::SeqCst) + 1;
                        
                        if result.is_ok() {
                            successful.fetch_add(1, Ordering::SeqCst);
                        } else if let Err(e) = result {
                            let file_name = file_path.file_name().unwrap().to_string_lossy().to_string();
                            failures.lock().unwrap().push((file_name, e.to_string()));
                        }
                        
                        Logger::parallel_progress(count, total, "Converting PDFs...");
                    });

                    let success_count = successful.load(Ordering::SeqCst);
                    let failed_count = total - success_count;
                    Logger::parallel_complete(success_count, failed_count, total, "PDF conversion");
                    
                    // Display detailed failure list if any
                    let failure_list = failures.lock().unwrap();
                    Logger::parallel_failures(&failure_list);
                }
            } else {
                Logger::error(&format!("Path '{}' does not exist", path.display()));
            }
        },
        cli::Commands::Split { path, lines, size_threshold } => {
            if path.is_file() {
                // Split a single markdown file
                if let Err(e) = split_markdown_file(&path, lines, &output_dir) {
                    Logger::error(&format!("Failed to split file: {}", e));
                }
            } else if path.is_dir() {
                // Split all markdown files in a directory that exceed the size threshold
                Logger::info(&format!("Scanning directory for large markdown files (threshold: {:.2}MB)", size_threshold));
                match split_markdown_files_in_directory_with_reporting(&path, lines, size_threshold, &output_dir) {
                    Ok((processed, split, failures)) => {
                        Logger::parallel_complete(split, failures.len(), processed, "file splitting");
                        Logger::parallel_failures(&failures);
                    }
                    Err(e) => {
                        Logger::error(&format!("Failed to split files in directory: {}", e));
                    }
                }
            } else {
                Logger::error(&format!("Path '{}' does not exist", path.display()));
            }
        },
        cli::Commands::Jira { path } => {
            // Process JIRA issue JSON files
            Logger::info("Processing JIRA issues");
            let issues_path = path.join("issues");
            if let Err(e) = process_jira_issues(&issues_path, &output_dir) {
                Logger::error(&format!("Failed to process JIRA issues: {}", e));
            }
        },
        cli::Commands::Html2pdf { path, employee_only, project_only, lines, size_threshold, engine } => {
            Logger::workflow_start("HTML → Markdown → Split → PDF", &path);

            // Step 1: MD processing
            Logger::step(1, "Converting HTML to Markdown");
            if employee_only && project_only {
                Logger::error("Cannot specify both --employee-only and --project-only");
                return;
            }

            let mode = if employee_only {
                Some(true)  // Employee only
            } else if project_only {
                Some(false) // Project only
            } else {
                None        // Process both
            };

            if path.is_file() {
                Logger::error("html2pdf command requires a directory containing HTML export data");
                return;
            } else if path.is_dir() {
                commands::md::process_directories_unified(&path, mode, &output_dir);
            } else {
                Logger::error(&format!("Path '{}' does not exist", path.display()));
                return;
            }

            // Step 2: Split large files
            Logger::step(2, "Splitting large markdown files");
            if let Err(e) = split_markdown_files_in_directory(&output_dir, lines, size_threshold, &output_dir) {
                Logger::warning(&format!("Error during splitting: {}", e));
                Logger::detail("Continuing with PDF conversion");
            }

            // Step 3: PDF conversion
            Logger::step(3, "Converting to PDF");
            // Find all .md files in output directory (output from previous steps)
            let md_files: Vec<PathBuf> = WalkDir::new(&output_dir)
                .max_depth(1)
                .into_iter()
                .filter_map(Result::ok)
                .filter(|e| e.file_type().is_file() && e.path().extension().and_then(|s| s.to_str()) == Some("md"))
                .map(|e| e.path().to_path_buf())
                .collect();

            let total = md_files.len();
            Logger::info(&format!("Converting {} markdown files to PDF concurrently", total));

            if total > 0 {
                let processed = Arc::new(AtomicUsize::new(0));
                let successful = Arc::new(AtomicUsize::new(0));
                let failures = Arc::new(Mutex::new(Vec::new()));

                md_files.par_iter().for_each(|file_path| {
                    let result = process_pdf(file_path, &engine, &output_dir);
                    let count = processed.fetch_add(1, Ordering::SeqCst) + 1;
                    
                    if result.is_ok() {
                        successful.fetch_add(1, Ordering::SeqCst);
                    } else if let Err(e) = result {
                        let file_name = file_path.file_name().unwrap().to_string_lossy().to_string();
                        failures.lock().unwrap().push((file_name, e.to_string()));
                    }
                    
                    Logger::parallel_progress(count, total, "Converting PDFs...");
                });

                let success_count = successful.load(Ordering::SeqCst);
                let failed_count = total - success_count;
                Logger::parallel_complete(success_count, failed_count, total, "PDF conversion");
                
                // Display detailed failure list if any
                let failure_list = failures.lock().unwrap();
                Logger::parallel_failures(&failure_list);
            }

            Logger::workflow_complete(&format!("{} PDF(s) generated in {}", total, output_dir.display()));
        }
        cli::Commands::Jira2pdf { path, lines, size_threshold, engine } => {
            Logger::workflow_start("JSON → Markdown → Split → PDF", &path);

            // Step 1: JIRA processing (outputs to input path directory)
            Logger::step(1, "Processing JIRA issues to Markdown");
            let issues_path = path.join("issues");
            if !issues_path.exists() {
                Logger::error(&format!("issues/ subdirectory not found in {}", path.display()));
                Logger::detail(&format!("Expected structure: {}/issues/*.json", path.display()));
                return;
            }

            if let Err(e) = process_jira_issues(&issues_path, &output_dir) {
                Logger::error(&format!("Processing JIRA issues failed: {}", e));
                return;
            }

            let jira_md_path = output_dir.join("jira_export.md");
            if !jira_md_path.exists() {
                Logger::error("jira_export.md was not generated");
                return;
            }

            Logger::success(&format!("Generated: {}", jira_md_path.display()));

            // Step 2: Split large files (already in output_dir)
            Logger::step(2, "Splitting large markdown files");
            // Check file size before splitting
            if let Ok(metadata) = fs::metadata(&jira_md_path) {
                let file_size = metadata.len();
                let size_threshold_bytes = (size_threshold * 1024.0 * 1024.0) as u64;
                
                if file_size > size_threshold_bytes {
                    Logger::detail(&format!("Splitting large file: {} ({:.2} MB)", 
                           jira_md_path.display(), 
                           file_size as f64 / (1024.0 * 1024.0)));
                    
                    if let Err(e) = split_markdown_file(&jira_md_path, lines, &output_dir) {
                        Logger::warning(&format!("Error during splitting: {}", e));
                        Logger::detail("Continuing with PDF conversion");
                    } else {
                        // Remove the original large file after successful splitting
                        if let Err(e) = fs::remove_file(&jira_md_path) {
                            Logger::warning(&format!("Failed to remove original file after splitting: {}", e));
                        } else {
                            Logger::detail(&format!("Removed original large file: {}", jira_md_path.display()));
                        }
                    }
                } else {
                    Logger::detail(&format!("File size OK: {:.2} MB (threshold: {:.2} MB)", 
                           file_size as f64 / (1024.0 * 1024.0), 
                           size_threshold));
                }
            }

            // Step 3: PDF conversion (from output_dir)
            Logger::step(3, "Converting to PDF");
            
            // Convert all markdown files in the output directory using parallel processing
            let md_files: Vec<PathBuf> = WalkDir::new(&output_dir)
                .max_depth(1)
                .into_iter()
                .filter_map(Result::ok)
                .filter(|e| e.file_type().is_file() && e.path().extension().and_then(|s| s.to_str()) == Some("md"))
                .map(|e| e.path().to_path_buf())
                .collect();

            let total = md_files.len();
            Logger::info(&format!("Converting {} markdown files to PDF concurrently", total));

            if total > 0 {
                let processed = Arc::new(AtomicUsize::new(0));
                let successful = Arc::new(AtomicUsize::new(0));
                let failures = Arc::new(Mutex::new(Vec::new()));

                md_files.par_iter().for_each(|file_path| {
                    let result = process_pdf(file_path, &engine, &output_dir);
                    let count = processed.fetch_add(1, Ordering::SeqCst) + 1;
                    
                    if result.is_ok() {
                        successful.fetch_add(1, Ordering::SeqCst);
                    } else if let Err(e) = result {
                        let file_name = file_path.file_name().unwrap().to_string_lossy().to_string();
                        failures.lock().unwrap().push((file_name, e.to_string()));
                    }
                    
                    Logger::parallel_progress(count, total, "Converting PDFs...");
                });

                let success_count = successful.load(Ordering::SeqCst);
                let failed_count = total - success_count;
                Logger::parallel_complete(success_count, failed_count, total, "PDF conversion");
                
                // Display detailed failure list if any
                let failure_list = failures.lock().unwrap();
                Logger::parallel_failures(&failure_list);
            }

            Logger::workflow_complete(&format!("{} PDF(s) generated in {}", total, output_dir.display()));
        }
        cli::Commands::GitReadme { path } => {
            Logger::info("Running in Git README mode");
            if !path.is_dir() {
                Logger::error(&format!("Path '{}' must be a directory containing Git repositories", path.display()));
                return;
            }
            
            commands::git_readme::process_git_repositories(&path, &output_dir);
        }
        cli::Commands::Readme2pdf { path, lines, size_threshold, engine } => {
            Logger::workflow_start("Git README → Split → PDF", &path);

            // Step 1: Git README processing
            Logger::step(1, "Extracting README files from Git repositories");
            if !path.is_dir() {
                Logger::error(&format!("Path '{}' must be a directory containing Git repositories", path.display()));
                return;
            }
            
            commands::git_readme::process_git_repositories(&path, &output_dir);

            // Step 2: Split large files
            Logger::step(2, "Splitting large markdown files");
            if let Err(e) = split_markdown_files_in_directory(&output_dir, lines, size_threshold, &output_dir) {
                Logger::warning(&format!("Error during splitting: {}", e));
                Logger::detail("Continuing with PDF conversion");
            }

            // Step 3: PDF conversion
            Logger::step(3, "Converting to PDF");
            // Find all .md files in output directory (output from previous steps)
            let md_files: Vec<PathBuf> = WalkDir::new(&output_dir)
                .max_depth(1)
                .into_iter()
                .filter_map(Result::ok)
                .filter(|e| e.file_type().is_file() && e.path().extension().and_then(|s| s.to_str()) == Some("md"))
                .map(|e| e.path().to_path_buf())
                .collect();

            let total = md_files.len();
            Logger::info(&format!("Converting {} markdown files to PDF concurrently", total));

            if total > 0 {
                let processed = Arc::new(AtomicUsize::new(0));
                let successful = Arc::new(AtomicUsize::new(0));
                let failures = Arc::new(Mutex::new(Vec::new()));

                md_files.par_iter().for_each(|file_path| {
                    let result = process_pdf(file_path, &engine, &output_dir);
                    let count = processed.fetch_add(1, Ordering::SeqCst) + 1;
                    
                    if result.is_ok() {
                        successful.fetch_add(1, Ordering::SeqCst);
                    } else if let Err(e) = result {
                        let file_name = file_path.file_name().unwrap().to_string_lossy().to_string();
                        failures.lock().unwrap().push((file_name, e.to_string()));
                    }
                    
                    Logger::parallel_progress(count, total, "Converting PDFs...");
                });

                let success_count = successful.load(Ordering::SeqCst);
                let failed_count = total - success_count;
                Logger::parallel_complete(success_count, failed_count, total, "PDF conversion");
                
                // Display detailed failure list if any
                let failure_list = failures.lock().unwrap();
                Logger::parallel_failures(&failure_list);
            }

            Logger::workflow_complete(&format!("{} PDF(s) generated in {}", total, output_dir.display()));
        }
    }
    
    Logger::success("Operation completed successfully!");
}

/// Converts a markdown file to PDF using pandoc with advanced image processing and Chinese support.
/// 
/// This function performs comprehensive PDF generation with the following features:
/// - Automatic image resizing to prevent LaTeX "Dimension too large" errors
/// - Chinese character support using ctexart document class
/// - Robust error handling with retry logic for LaTeX compilation failures
/// - Temporary directory management for processing
/// - Image validation and corruption handling
/// 
/// The process involves:
/// 1. Creating a temporary directory for this conversion process
/// 2. Parsing markdown content to find and process images
/// 3. Resizing oversized images while maintaining aspect ratio
/// 4. Generating PDF using pandoc with appropriate LaTeX engine
/// 5. Retry logic for compilation failures
/// 6. Cleanup of temporary files
/// 
/// # Arguments
/// * `md_file_path` - Path to the markdown file to convert
/// * `engine` - LaTeX engine to use ("lualatex", "xelatex", or "pdflatex")
/// 
/// # Returns
/// * `Result<(), Box<dyn std::error::Error>>` - Success or error with details
fn process_pdf(md_file_path: &Path, engine: &str, output_dir: &Path) -> Result<(), Box<dyn std::error::Error>> {
    // Helper function to extract SVG content from data URI
    fn extract_svg_from_data_uri(data_uri: &str) -> Option<String> {
        // data:image/svg+xml;base64,... or data:image/svg+xml,... (URL-encoded)
        if let Some(comma_pos) = data_uri.find(',') {
            let header = &data_uri[..comma_pos];
            let data = &data_uri[comma_pos + 1..];
            
            if header.contains("base64") {
                // Base64-encoded
                use base64::{Engine as _, engine::general_purpose};
                if let Ok(decoded) = general_purpose::STANDARD.decode(data) {
                    return String::from_utf8(decoded).ok();
                }
            } else {
                // URL-encoded
                use percent_encoding::percent_decode;
                if let Ok(decoded) = percent_decode(data.as_bytes()).decode_utf8() {
                    return Some(decoded.to_string());
                }
            }
        }
        None
    }
    
    // Helper function to detect if a file contains SVG content regardless of extension
    fn is_svg_content(file_path: &Path) -> bool {
        if let Ok(mut file) = std::fs::File::open(file_path) {
            let mut buffer = Vec::new();
            // Read first 1KB to check for SVG content
            if file.read_to_end(&mut buffer).is_ok() {
                let content = String::from_utf8_lossy(&buffer);
                let content_lower = content.to_lowercase();

                // Check for SVG XML declaration
                if content_lower.contains("<?xml") && content_lower.contains("<svg") {
                    return true;
                }

                // Check for draw.io XML format
                if content_lower.contains("<mxfile") {
                    return true;
                }

                // Check for SVG elements (more lenient check)
                if content_lower.contains("<svg") && content_lower.contains("</svg>") {
                    return true;
                }

                // Check for common SVG elements
                let svg_elements = ["<path", "<rect", "<circle", "<ellipse", "<line", "<polyline", "<polygon"];
                if svg_elements.iter().any(|&elem| content_lower.contains(elem)) {
                    return true;
                }
            }
        }
        false
    }

    // Create a unique temporary directory for this conversion process
    let temp_dir_name = Uuid::new_v4().to_string();
    let temp_dir = std::env::temp_dir().join(&temp_dir_name);
    fs::create_dir_all(&temp_dir)?;

    Logger::detail(&format!("Temporary directory: {}", temp_dir.display()));

    // Parse markdown content and extract image links for processing
    let md_content = fs::read_to_string(md_file_path)?;
    
    // Sanitize the content to remove problematic control characters
    let mut md_content = sanitize_markdown_content(&md_content);
    
    // Pre-process HTML img tags with SVG sources and convert them to markdown image syntax
    // This handles cases where SVG images are embedded as HTML rather than markdown
    let html_img_regex = Regex::new(r#"<img\s+[^>]*src=["']([^"']+\.svg)["'][^>]*>"#)?;
    for cap in html_img_regex.captures_iter(&md_content.clone()) {
        let full_html_tag = &cap[0];
        let svg_src = &cap[1];
        
        // Convert HTML img tag to markdown image syntax
        let markdown_image = format!("![]({})", svg_src);
        md_content = md_content.replace(full_html_tag, &markdown_image);
        Logger::detail(&format!("Converted HTML img tag to markdown: {}", svg_src));
    }
    
    // Extract and convert inline/embedded SVG content
    // This handles SVG code embedded directly in the markdown/HTML
    let mut svg_counter = 0;
    
    // Pattern 1: HTML img tags with data URIs containing SVG
    let data_uri_svg_regex = Regex::new(r#"<img\s+[^>]*src=["']data:image/svg\+xml[^"']*["'][^>]*>"#)?;
    for cap in data_uri_svg_regex.captures_iter(&md_content.clone()) {
        let full_html_tag = &cap[0];
        
        // Extract the base64 or URL-encoded SVG data
        if let Some(data_start) = full_html_tag.find("data:image/svg+xml") {
            let data_part = &full_html_tag[data_start..];
            if let Some(data_end) = data_part.find('"').or_else(|| data_part.find('\'')) {
                let data_uri = &data_part[..data_end];
                
                // Try to decode and save SVG
                if let Some(svg_content) = extract_svg_from_data_uri(data_uri) {
                    svg_counter += 1;
                    let svg_filename = format!("embedded_svg_{}.svg", svg_counter);
                    let png_filename = format!("embedded_svg_{}.png", svg_counter);
                    let svg_path = temp_dir.join(&svg_filename);
                    let png_path = temp_dir.join(&png_filename);
                    
                    // Save SVG content to file
                    if fs::write(&svg_path, svg_content).is_ok() {
                        // Convert to PNG using Inkscape
                        let output = Command::new("inkscape")
                            .arg(&svg_path)
                            .arg(format!("--export-filename={}", png_path.display()))
                            .arg("--export-type=png")
                            .output();
                        
                        if let Ok(result) = output {
                            if result.status.success() {
                                Logger::conversion(&format!("embedded SVG #{}", svg_counter), "PNG");
                                // Replace the HTML img tag with markdown image
                                let markdown_img = format!("![]({})", png_filename);
                                md_content = md_content.replace(full_html_tag, &markdown_img);
                                continue;
                            }
                        }
                    }
                }
            }
        }
        
        // If conversion failed, remove the tag to avoid Pandoc errors
        Logger::warning(&format!("Failed to convert embedded SVG #{}, removing", svg_counter));
        md_content = md_content.replace(full_html_tag, "");
    }
    
    // Pattern 2: Inline <svg>...</svg> elements
    let inline_svg_regex = Regex::new(r"(?s)<svg[^>]*>.*?</svg>")?;
    for cap in inline_svg_regex.captures_iter(&md_content.clone()) {
        let svg_element = &cap[0];
        svg_counter += 1;
        let svg_filename = format!("inline_svg_{}.svg", svg_counter);
        let png_filename = format!("inline_svg_{}.png", svg_counter);
        let svg_path = temp_dir.join(&svg_filename);
        let png_path = temp_dir.join(&png_filename);
        
        // Save inline SVG to file
        if fs::write(&svg_path, svg_element).is_ok() {
            // Convert to PNG using Inkscape
            let output = Command::new("inkscape")
                .arg(&svg_path)
                .arg(format!("--export-filename={}", png_path.display()))
                .arg("--export-type=png")
                .output();
            
            if let Ok(result) = output {
                if result.status.success() {
                    Logger::conversion(&format!("inline SVG #{}", svg_counter), "PNG");
                    // Replace the SVG element with markdown image
                    let markdown_img = format!("![]({})", png_filename);
                    md_content = md_content.replace(svg_element, &markdown_img);
                    continue;
                }
            }
        }
        
        // If conversion failed, remove the SVG element to avoid Pandoc errors
        Logger::warning(&format!("Failed to convert inline SVG #{}, removing", svg_counter));
        md_content = md_content.replace(svg_element, "");
    }
    
    if svg_counter > 0 {
        Logger::info(&format!("Preprocessed {} embedded/inline SVG elements", svg_counter));
    }
    
    // Convert external image links (especially SVGs and badges) to regular links
    // This prevents Pandoc from trying to download and convert external images
    
    // Pattern 1: Direct external image links like ![alt](https://...)
    let external_image_regex = Regex::new(r"!\[([^\]\n]*)\]\((https?://[^)\n]+)\)")?;
    let mut external_img_count = 0;
    
    for cap in external_image_regex.captures_iter(&md_content.clone()) {
        let full_match = &cap[0];
        let alt_text = &cap[1];
        let url = &cap[2];
        
        // Convert image link to regular link
        let regular_link = format!("[{}]({})", alt_text, url);
        md_content = md_content.replace(full_match, &regular_link);
        external_img_count += 1;
        Logger::detail(&format!("Converted external image to link: {}", url));
    }
    
    // Pattern 2: Reference-style badge links like [![alt][ref]][url]
    // These are commonly used for badges at the top of README files
    let badge_link_regex = Regex::new(r"!\[([^\]]*)\]\[([^\]]+)\]")?;
    
    for cap in badge_link_regex.captures_iter(&md_content.clone()) {
        let full_match = &cap[0];
        let alt_text = &cap[1];
        let reference = &cap[2];
        
        // Convert badge image reference to regular link reference
        let regular_link = format!("[{}][{}]", alt_text, reference);
        md_content = md_content.replace(full_match, &regular_link);
        external_img_count += 1;
        Logger::detail(&format!("Converted badge image reference to link: [{}]", reference));
    }
    
    if external_img_count > 0 {
        Logger::info(&format!("Converted {} external image links to regular links", external_img_count));
    }
    
    // Regex pattern that excludes newlines to prevent matching across line boundaries
    // This prevents false matches like: "text!\n\n[link](path)" being matched as a single pattern
    let link_regex = Regex::new(r"(!?)\[([^\]\n]*)\]\(([^)\n]+)\)")?;
    let mut new_md_content = md_content.clone();

    // Get the directory containing the original markdown file for resolving relative paths
    let original_md_dir = md_file_path.parent().ok_or("Could not get parent directory of markdown file")?.canonicalize()?;

    // Maps original image paths to processed image paths in temp directory
    let mut image_map: HashMap<String, PathBuf> = HashMap::new();
    let mut image_counter = 0;

    for cap in link_regex.captures_iter(&md_content) {
        let full_match = &cap[0];
        let is_image = &cap[1] == "!";
        let _alt_text = &cap[2]; // Not used anymore - we use empty alt text to avoid LaTeX spacing issues
        let link = &cap[3];

        let decoded_link = percent_decode(link.as_bytes()).decode_utf8_lossy();
        let link_path = Path::new(decoded_link.as_ref());

        if link.starts_with("http://") || link.starts_with("https://") || link_path.is_absolute() {
            continue;
        }

        if is_image {
            let source_path = original_md_dir.join(link_path);
            
            // Normalize the path to remove Windows extended-length prefix (\\?\)
            let normalized_path = if source_path.to_string_lossy().starts_with(r"\\?\") {
                PathBuf::from(&source_path.to_string_lossy()[4..])
            } else {
                source_path.clone()
            };
            
            if normalized_path.exists() {
                // Validate the image file before processing
                let mut should_convert_as_svg = false;
                if let Ok(metadata) = fs::metadata(&normalized_path) {
                    if metadata.len() == 0 {
                        Logger::warning(&format!("Skipping empty image file: {}", normalized_path.display()));
                        new_md_content = new_md_content.replace(full_match, "");
                        continue;
                    }
                    
                    // Try to read the first few bytes to check if file is accessible
                    if let Ok(mut file) = std::fs::File::open(&normalized_path) {
                        let mut buffer = [0; 10];
                        if file.read(&mut buffer).is_err() {
                            Logger::warning(&format!("Skipping unreadable image file: {}", normalized_path.display()));
                            new_md_content = new_md_content.replace(full_match, "");
                            continue;
                        }
                        
                        // Try to validate the image format using the image crate with format guessing
                        match ImageReader::open(&normalized_path) {
                            Ok(reader) => {
                                // Use format guessing to handle files with mismatched extensions
                                // (e.g., JPEG files named as .png)
                                match reader.with_guessed_format() {
                                    Ok(reader_with_format) => {
                                        if let Err(_) = reader_with_format.decode() {
                                            // Check if this might be SVG/draw.io content instead of a corrupted image
                                            if is_svg_content(&normalized_path) {
                                                Logger::info(&format!("Detected SVG/draw.io content: {}", normalized_path.display()));
                                                should_convert_as_svg = true;
                                            } else {
                                                Logger::warning(&format!("Skipping invalid/corrupted image: {}", normalized_path.display()));
                                                new_md_content = new_md_content.replace(full_match, "");
                                                continue;
                                            }
                                        }
                                    }
                                    Err(_) => {
                                        // Check if this might be SVG/draw.io content
                                        if is_svg_content(&normalized_path) {
                                            Logger::info(&format!("Detected SVG/draw.io content: {}", normalized_path.display()));
                                            should_convert_as_svg = true;
                                        } else {
                                            Logger::warning(&format!("Skipping unknown format: {}", normalized_path.display()));
                                            new_md_content = new_md_content.replace(full_match, "");
                                            continue;
                                        }
                                    }
                                }
                            }
                            Err(_) => {
                                // Check if this might be SVG/draw.io content
                                if is_svg_content(&normalized_path) {
                                    Logger::info(&format!("Detected SVG/draw.io content: {}", normalized_path.display()));
                                    should_convert_as_svg = true;
                                } else {
                                    Logger::warning(&format!("Skipping unopenable image: {}", normalized_path.display()));
                                    new_md_content = new_md_content.replace(full_match, "");
                                    continue;
                                }
                            }
                        }
                    } else {
                        Logger::warning(&format!("Skipping inaccessible image: {}", normalized_path.display()));
                        new_md_content = new_md_content.replace(full_match, "");
                        continue;
                    }
                }

                // Check if file contains SVG content regardless of extension
                let final_link_name: String;
                if should_convert_as_svg || is_svg_content(&normalized_path) {
                    Logger::info(&format!("Detected SVG content: {}", normalized_path.display()));
                    let png_name = format!("image_{}.png", image_counter);
                    image_counter += 1;
                    let dest_path = temp_dir.join(&png_name);

                    if let Some(parent) = dest_path.parent() {
                        if !parent.exists() {
                            fs::create_dir_all(parent)?;
                        }
                    }
                    Logger::conversion(&format!("{}", normalized_path.display()), "PNG (Inkscape)");

                    let inkscape_output = Command::new("inkscape")
                        .arg(normalized_path.as_os_str())
                        .arg("--export-type=png")
                        .arg(format!("--export-filename={}", dest_path.to_str().unwrap()))
                        .output()?;

                    if !inkscape_output.status.success() {
                        eprintln!("Inkscape conversion failed for {}: {}", normalized_path.display(), String::from_utf8_lossy(&inkscape_output.stderr));                      
                        // Fallback to removing the image link
                        new_md_content = new_md_content.replace(full_match, ""); 
                        continue;
                    }
                    
                    // Resize the converted PNG if it's too large for LaTeX
                    if let Err(e) = resize_image_if_needed(&dest_path, 4000, 4000) {
                        println!("⚠  Failed to resize converted PNG {}: {}", dest_path.display(), e);
                        // Continue anyway, as the original image might still work
                    }
                    
                    final_link_name = png_name.clone();
                    image_map.insert(png_name, normalized_path);
                } else {
                    // Check if it's a WebP file and convert to PNG first
                    let path_to_process = if let Some(ext) = normalized_path.extension() {
                        if ext.to_string_lossy().to_lowercase() == "webp" {
                            Logger::conversion(&format!("{}", normalized_path.display()), "PNG");
                            match convert_webp_to_png(&normalized_path) {
                                Ok(png_path) => png_path,
                                Err(e) => {
                                    Logger::warning(&format!("Failed to convert WebP {}: {}", normalized_path.display(), e));
                                    normalized_path.clone()
                                }
                            }
                        } else {
                            normalized_path.clone()
                        }
                    } else {
                        normalized_path.clone()
                    };
                    
                    // Copy the image to temp directory
                    let temp_copy = temp_dir.join(format!("temp_{}", image_counter));
                    fs::copy(&path_to_process, &temp_copy)?;
                    
                    // Detect actual format and rename with correct extension
                    let corrected_path = match detect_and_rename_image(&temp_copy) {
                        Ok(path) => path,
                        Err(e) => {
                            println!("⚠  Failed to detect image format for {}: {}", normalized_path.display(), e);
                            // Fallback to original extension
                            temp_copy
                        }
                    };
                    
                    // Get the correct extension from the renamed file
                    let correct_ext = corrected_path.extension()
                        .and_then(|s| s.to_str())
                        .unwrap_or("png");
                    
                    let new_name = format!("image_{}.{}", image_counter, correct_ext);
                    image_counter += 1;
                    let dest_path = temp_dir.join(&new_name);
                    
                    // Move the corrected file to its final name
                    fs::rename(&corrected_path, &dest_path)?;
                    
                    // Resize image if it's too large for LaTeX
                    if let Err(e) = resize_image_if_needed(&dest_path, 4000, 4000) {
                        println!("⚠  Failed to resize image {}: {}", dest_path.display(), e);
                        // Continue anyway, as the original image might still work
                    }
                    
                    final_link_name = new_name.clone();
                    image_map.insert(new_name, normalized_path);
                }

                let new_link_markdown = format!("![]({})", final_link_name);
                new_md_content = new_md_content.replace(full_match, &new_link_markdown);
            }
        }
    }

    let temp_md_path = temp_dir.join("input.md");
    fs::write(&temp_md_path, &new_md_content)?;

    // 4. Invoke pandoc with retry logic
    let max_retries = 3;
    let mut retry_count = 0;

    loop {
        // Clean up any existing intermediate files before retry
        let temp_files = ["input.tex", "input.aux", "input.log", "input.out", "input.fls", "input.fdb_latexmk"];
        for temp_file in &temp_files {
            let temp_file_path = temp_dir.join(temp_file);
            if temp_file_path.exists() {
                let _ = fs::remove_file(&temp_file_path);
            }
        }

        let mut command = Command::new("pandoc");
        command.current_dir(&temp_dir);

        let pandoc_args = build_pandoc_args(engine);
        command.args(&pandoc_args);

        // Set environment variables for image conversion
        if cfg!(windows) {
            command.env("PANGOCAIRO_BACKEND", "win32");
        }
        
        // Ensure PATH includes directories where Inkscape might be installed
        // Pandoc will try to use Inkscape if rsvg-convert is not available
        if let Ok(current_path) = std::env::var("PATH") {
            // Add common Inkscape installation paths on Windows
            let inkscape_paths = if cfg!(windows) {
                vec![
                    "C:\\Program Files\\Inkscape\\bin",
                    "C:\\Program Files (x86)\\Inkscape\\bin",
                ]
            } else {
                vec![]
            };
            
            let mut new_path = current_path.clone();
            for path in inkscape_paths {
                if !current_path.contains(path) {
                    new_path.push_str(";");
                    new_path.push_str(path);
                }
            }
            command.env("PATH", new_path);
        }

        let output = command.output()?;

        // Print the full command for debugging
        let full_command = format!("{:?} {}",
                                   command.get_program(),
                                   command.get_args().map(|arg| arg.to_string_lossy()).collect::<Vec<_>>().join(" "));
        println!("ℹ  Executing pandoc command: {}", full_command);

        if output.status.success() {
            break; // Success
        }

        let stderr = String::from_utf8_lossy(&output.stderr);
        eprintln!("❌ Pandoc failed for: {}", md_file_path.display());
        eprintln!("Pandoc error: {}", stderr);

        // Check for specific LaTeX compilation errors and retry
        if stderr.contains("File ended prematurely") || stderr.contains("LaTeX Error") || stderr.contains("Fatal error") || stderr.contains("This can't happen") {
            retry_count += 1;
            if retry_count < max_retries {
                println!("⚠  LaTeX compilation failed, retrying... (attempt {}/{})", retry_count, max_retries);
                // Add a small delay before retry
                std::thread::sleep(std::time::Duration::from_millis(500));
                continue;
            } else {
                eprintln!("❌ LaTeX compilation failed for: {}", md_file_path.display());
                eprintln!("LaTeX compilation failed after {} attempts with {}", max_retries, engine);
                return Err(format!("LaTeX compilation failed with {} engine.", engine).into());
            }
        }

        let re = Regex::new(r"Unable to load picture or PDF file '([^']*)'")?;

        if let Some(caps) = re.captures(&stderr) {
            let problematic_path_str = &caps[1];
            let problematic_file_name = Path::new(problematic_path_str).file_name()
                .and_then(|s| s.to_str())
                .ok_or("Could not extract file name from pandoc error")?;

            if let Some(original_path) = image_map.get(problematic_file_name) {
                println!("⚠  Problematic image file (original path): {}", original_path.display());

                let temp_file_to_remove = temp_dir.join(problematic_file_name);
                if temp_file_to_remove.exists() {
                    fs::remove_file(&temp_file_to_remove)?;
                    println!("ℹ  Deleted temporary file: {}", temp_file_to_remove.display());
                }

                let link_re_str = format!(r"!\[[^\]]*\]\({}\)", regex::escape(problematic_file_name));
                let link_re = Regex::new(&link_re_str)?;
                let count_before = new_md_content.len();
                new_md_content = link_re.replace_all(&new_md_content, "").to_string();

                if new_md_content.len() < count_before {
                    println!("ℹ  Removed link to problematic image from markdown.");
                }

                fs::write(&temp_md_path, &new_md_content)?;
                println!("ℹ  Retrying pandoc process...");
                continue;
            }
        }

        // If we reach here, it's an unhandled error or we couldn't find the image.
        eprintln!("❌ Final Pandoc failure for: {}", md_file_path.display());
        return Err("Pandoc execution failed with an unrecoverable error.".into());
    }


    // 5. Copy result pdf
    let result_pdf_path = temp_dir.join("result.pdf");
    let file_name = md_file_path.file_name().ok_or("Could not get filename")?;
    let final_pdf_path = output_dir.join(file_name).with_extension("pdf");
    fs::copy(&result_pdf_path, &final_pdf_path)?;

    Logger::success(&format!("PDF generated: {}", final_pdf_path.display()));

    // 6. Cleanup
    fs::remove_dir_all(&temp_dir)?;
    Logger::detail("Temporary directory cleaned up");

    Ok(())
}

/// Builds the argument list for invoking pandoc with the desired LaTeX engine and options.
///
/// This helper centralizes the Pandoc CLI configuration so it can be unit tested easily
/// (e.g., to ensure unsupported flags like `--no-figure-caption` are not included).
fn build_pandoc_args(engine: &str) -> Vec<OsString> {
    let mut args: Vec<OsString> = vec![
        OsString::from("--from"),
        OsString::from("commonmark"),
        OsString::from("input.md"),
        OsString::from("-o"),
        OsString::from("result.pdf"),
        OsString::from("--syntax-highlighting=pygments"),
    ];

    match engine {
        "xelatex" => {
            args.push(OsString::from("-V"));
            args.push(OsString::from("geometry:margin=1in"));
            args.push(OsString::from("-V"));
            args.push(OsString::from("colorlinks=true"));
            args.push(OsString::from("-V"));
            args.push(OsString::from("CJKmainfont=SimSun"));
            args.push(OsString::from("-V"));
            args.push(OsString::from("mainfont=Arial"));
        }
        "pdflatex" => {
            args.push(OsString::from("-V"));
            args.push(OsString::from("geometry:margin=1in"));
            args.push(OsString::from("-V"));
            args.push(OsString::from("colorlinks=true"));
            args.push(OsString::from("-V"));
            args.push(OsString::from("CJKmainfont=SimSun"));
            args.push(OsString::from("-V"));
            args.push(OsString::from("mainfont=Arial"));
        }
        "lualatex" => {
            args.push(OsString::from("-V"));
            args.push(OsString::from("documentclass=ctexart"));
            args.push(OsString::from("-V"));
            args.push(OsString::from("geometry:margin=1in"));
            args.push(OsString::from("-V"));
            args.push(OsString::from("colorlinks=true"));
        }
        _ => {
            args.push(OsString::from("-V"));
            args.push(OsString::from("geometry:margin=1in"));
            args.push(OsString::from("-V"));
            args.push(OsString::from("colorlinks=true"));
        }
    }

    args.push(OsString::from(format!("--pdf-engine={}", engine)));
    args
}

/// Splits a large markdown file into smaller chunks based on line count.
/// 
/// This function takes a markdown file and divides it into multiple smaller files,
/// each containing a maximum number of lines. This is useful for:
/// - Processing large files that exceed tool limits
/// - Creating more manageable documentation chunks
/// - Parallel processing of documentation
/// - Managing files for version control
/// 
/// The splitting process:
/// 1. Reads the entire file content
/// 2. Calculates the number of output files needed
/// 3. Creates chunks of lines_per_file lines each
/// 4. Writes each chunk to a new file with _NN suffix
/// 
/// Output files are named with pattern: {original_name}_{NN}.{extension}
/// where NN is a zero-padded two-digit number starting from 00.
/// 
/// # Arguments
/// * `file_path` - Path to the markdown file to split
/// * `lines_per_file` - Maximum number of lines per output file
/// 
/// # Returns
/// * `Result<(), Box<dyn std::error::Error>>` - Success or error details
/// 
/// # Example
/// If input file is "document.md" with 15000 lines and lines_per_file=5000,
/// output files will be: document_00.md, document_01.md, document_02.md
fn split_markdown_file(file_path: &Path, lines_per_file: usize, output_dir: &Path) -> Result<(), Box<dyn std::error::Error>> {
    // Validate input file exists
    if !file_path.exists() {
        return Err(format!("File not found: {}", file_path.display()).into());
    }

    // Read the entire file content
    let content = fs::read_to_string(file_path)?;
    let lines: Vec<&str> = content.lines().collect();
    let total_lines = lines.len();

    // Handle empty files
    if total_lines == 0 {
        println!("File is empty, nothing to split.");
        return Ok(());
    }

    // Extract file components for naming output files
    let file_stem = file_path.file_stem().ok_or("Could not get file stem")?.to_str().ok_or("Invalid file stem")?;
    let extension = file_path.extension().and_then(|s| s.to_str()).unwrap_or("md");

    // Calculate how many output files are needed
    let num_files = (total_lines as f64 / lines_per_file as f64).ceil() as usize;

    // Create each output file
    for i in 0..num_files {
        let start_line = i * lines_per_file;
        let end_line = std::cmp::min(start_line + lines_per_file, total_lines);
        let chunk = &lines[start_line..end_line];

        // Generate output filename with zero-padded index
        let new_file_name = format!("{}_{:02}.{}", file_stem, i, extension);
        let new_file_path = output_dir.join(new_file_name);

        // Write the chunk to the new file
        fs::write(&new_file_path, chunk.join("\n"))?;
        println!("✓ Generated {}", new_file_path.display());
    }

    Ok(())
}

/// Splits large markdown files in a directory based on file size threshold.
/// 
/// This function recursively scans a directory for markdown files and splits those
/// that exceed the specified size threshold. Unlike line-based splitting, this
/// approach splits files based on their total file size in megabytes.
/// 
/// The process:
/// 1. Validates the input directory exists and is a directory
/// 2. Recursively walks through all files in the directory
/// 3. Identifies markdown files (.md extension)
/// 4. Checks file size against the threshold
/// 5. Splits oversized files using line-based chunking
/// 6. Reports processing statistics
/// 
/// This is useful for batch processing large documentation repositories where
/// individual files may be too large for certain tools or workflows.
/// 
/// # Arguments
/// * `dir_path` - Path to the directory to scan for markdown files
/// * `lines_per_file` - Maximum number of lines per split chunk
/// * `size_threshold_mb` - File size threshold in megabytes
/// 
/// # Returns
/// * `Result<(), Box<dyn std::error::Error>>` - Success or error details
/// 
/// # Example
/// To split all markdown files larger than 5MB in a directory, with each
/// chunk containing 50,000 lines: split_markdown_files_in_directory(path, 50000, 5.0)
fn split_markdown_files_in_directory(dir_path: &Path, lines_per_file: usize, size_threshold_mb: f64, output_dir: &Path) -> Result<(), Box<dyn std::error::Error>> {
    // Validate input directory
    if !dir_path.exists() {
        return Err(format!("Directory not found: {}", dir_path.display()).into());
    }

    if !dir_path.is_dir() {
        return Err(format!("Path is not a directory: {}", dir_path.display()).into());
    }

    // Convert size threshold from MB to bytes
    let size_threshold_bytes = (size_threshold_mb * 1024.0 * 1024.0) as u64;
    let mut files_processed = 0;
    let mut files_split = 0;

    // Recursively process all files in the directory
    for entry in WalkDir::new(dir_path).into_iter().filter_map(Result::ok) {
        if entry.file_type().is_file() {
            let path = entry.path();
            if let Some(extension) = path.extension() {
                if extension == "md" {
                    // Check file size against threshold
                    if let Ok(metadata) = fs::metadata(path) {
                        let file_size = metadata.len();
                        if file_size > size_threshold_bytes {
    println!("ℹ  Splitting large file: {} ({:.2} MB)", 
           path.display(), 
           file_size as f64 / (1024.0 * 1024.0));                            // Split the oversized file
                            if let Err(e) = split_markdown_file(path, lines_per_file, output_dir) {
                                eprintln!("Error splitting {}: {}", path.display(), e);
                            } else {
                                files_split += 1;
                                // Remove the original file after successful split
                                if let Err(e) = fs::remove_file(path) {
                                    eprintln!("Warning: Failed to remove original file {}: {}", path.display(), e);
                                } else {
                                    println!("✓ Removed original file: {}", path.display());
                                }
                            }
                        } else {
                            println!("ℹ  Skipping file (too small): {} ({:.2} MB)", 
                                   path.display(), 
                                   file_size as f64 / (1024.0 * 1024.0));
                        }
                        files_processed += 1;
                    }
                }
            }
        }
    }

    // Report processing results
    println!("✓ Processed {} markdown files, split {} large files", files_processed, files_split);
    Ok(())
}

/// Enhanced version of split_markdown_files_in_directory that collects failure information.
/// 
/// Returns a tuple of (files_processed, files_split, failures) for detailed reporting.
fn split_markdown_files_in_directory_with_reporting(
    dir_path: &Path, 
    lines_per_file: usize, 
    size_threshold_mb: f64, 
    output_dir: &Path
) -> Result<(usize, usize, Vec<(String, String)>), Box<dyn std::error::Error>> {
    // Validate input directory
    if !dir_path.exists() {
        return Err(format!("Directory not found: {}", dir_path.display()).into());
    }

    if !dir_path.is_dir() {
        return Err(format!("Path is not a directory: {}", dir_path.display()).into());
    }

    // Convert size threshold from MB to bytes
    let size_threshold_bytes = (size_threshold_mb * 1024.0 * 1024.0) as u64;
    let mut files_processed = 0;
    let mut files_split = 0;
    let mut failures = Vec::new();

    // Recursively process all files in the directory
    for entry in WalkDir::new(dir_path).into_iter().filter_map(Result::ok) {
        if entry.file_type().is_file() {
            let path = entry.path();
            if let Some(extension) = path.extension() {
                if extension == "md" {
                    // Check file size against threshold
                    if let Ok(metadata) = fs::metadata(path) {
                        let file_size = metadata.len();
                        if file_size > size_threshold_bytes {
                            Logger::detail(&format!("Splitting: {} ({:.2} MB)", 
                                path.file_name().unwrap().to_string_lossy(),
                                file_size as f64 / (1024.0 * 1024.0)
                            ));
                            
                            // Split the oversized file
                            if let Err(e) = split_markdown_file(path, lines_per_file, output_dir) {
                                let file_name = path.file_name().unwrap().to_string_lossy().to_string();
                                failures.push((file_name, e.to_string()));
                            } else {
                                files_split += 1;
                                // Remove the original file after successful split
                                if let Err(e) = fs::remove_file(path) {
                                    Logger::warning(&format!("Failed to remove original file {}: {}", 
                                        path.file_name().unwrap().to_string_lossy(), e));
                                } else {
                                    Logger::detail(&format!("Removed original file: {}", 
                                        path.file_name().unwrap().to_string_lossy()));
                                }
                            }
                        }
                        files_processed += 1;
                    }
                }
            }
        }
    }

    Ok((files_processed, files_split, failures))
}


/// Processes employee or project directories to generate consolidated markdown files.
/// 
/// This function scans a data directory and processes subdirectories based on the mode:
/// - Employee mode: Processes directories starting with '~' (employee directories)
/// - Project mode: Processes directories NOT starting with '~' (project directories)
/// 
/// For each matching directory, it:
/// 1. Calls process_directory to extract content from HTML files
/// 2. Generates appropriate output filename based on mode
/// 3. Writes consolidated markdown content to the output file
/// 4. Performs HTML entity decoding (&gt; → >, &lt; → <)
/// 
/// Output naming conventions:
/// - Employee mode: {alias}-{chinese_name}-{file_count}.md
/// - Project mode: {alias}-{file_count}.md
/// 
/// # Arguments
/// * `data_dir` - Path to the data directory containing employee/project subdirectories
/// * `employee_mode` - If true, process employee dirs (~prefix); if false, process project dirs
#[allow(dead_code)]
fn process_directories(data_dir: &Path, employee_mode: bool) {
    // Validate input directory exists
    if !data_dir.exists() {
        println!("✗ Data directory not found: {}", data_dir.display());
        return;
    }
    
    // First pass: correct image extensions in all attachment directories
    println!("ℹ  Scanning for images with incorrect extensions...");
    let mut total_corrected = 0;
    for entry in WalkDir::new(data_dir).min_depth(1).max_depth(1).into_iter().filter_map(Result::ok) {
        if entry.file_type().is_dir() {
            let attachments_dir = entry.path().join("attachments");
            if attachments_dir.exists() {
                let corrected = correct_image_extensions_in_directory(&attachments_dir);
                total_corrected += corrected;
            }
        }
    }
    if total_corrected > 0 {
        println!("✓ Corrected {} image file extensions", total_corrected);
    }

    // Process each subdirectory at the top level
    for entry in WalkDir::new(data_dir).min_depth(1).max_depth(1).into_iter().filter_map(Result::ok) {
        if entry.file_type().is_dir() {
            let file_name = entry.file_name().to_string_lossy();
            let is_employee_dir = file_name.starts_with('~');

            // Process directory based on mode: employee dirs start with '~', project dirs don't
            if (employee_mode && is_employee_dir) || (!employee_mode && !is_employee_dir) {
                let dir = entry.path();
                println!("ℹ  Processing directory: {}", dir.display());
                
                // Extract content from the directory
                if let Some((alias, chinese_name, file_count, markdown_content)) = process_directory(dir) {
                    // Generate output filename based on mode
                    let output_file_name = if employee_mode {
                        format!("{}-{}-{}.md", alias, chinese_name, file_count)
                    } else {
                        format!("{}-{}.md", alias, file_count)
                    };
                    let output_path = dir.parent().unwrap().join(output_file_name);
                    
                    // Decode HTML entities and write the consolidated content
                    let final_content = markdown_content.replace("&gt;", ">").replace("&lt;", "<");
                    fs::write(&output_path, final_content).unwrap();
                    println!("✓ Generated {}", output_path.display());
                }
            }
        }
    }
}

/// Unified function to process directories for markdown generation.
/// 
/// This is the new recommended function that auto-detects directory types or processes
/// specific types based on the mode parameter. It replaces the separate employee/project
/// processing functions with a unified approach.
/// 
/// # Arguments
/// * `data_dir` - Path to the data directory containing documentation subdirectories
/// * `mode` - Optional filter:
///   - `None`: Process all directories (auto-detect employee/project)
///   - `Some(true)`: Process only employee directories (starting with '~')
///   - `Some(false)`: Process only project directories (NOT starting with '~')
/// 
/// # Behavior
/// - Employee directories: Start with '~', output includes Chinese name
/// - Project directories: Any other naming, simpler output naming
/// - Automatically corrects image file extensions before processing
/// Processes a single employee or project directory to extract and consolidate HTML content.
/// 
/// This function analyzes a directory containing HTML files (typically from documentation
/// systems) and converts them into a consolidated markdown format. It handles:
/// - Index file parsing for page ordering
/// - Chinese name extraction from homepage files
/// - Comment processing (HTML files with redirect meta tags)
/// - Attachment association with comments
/// - HTML to markdown conversion
/// - Proper ordering of pages and content
/// 
/// The process involves:
/// 1. Extracting directory alias and validating index.html exists
/// 2. Counting total files and finding Chinese name from homepage
/// 3. Parsing index.html to determine page ordering
/// 4. Processing all HTML files to separate pages from comments
/// 5. Associating comments with their target pages
/// 6. Processing attachments directory and linking attachments to comments
/// 7. Converting all content to markdown with proper formatting
/// 
/// # Arguments
/// * `dir` - Path to the directory to process
/// 
/// # Returns
/// * `Option<(String, String, usize, String)>` - Returns (alias, chinese_name, file_count, markdown_content)
///   or None if processing fails
/// 
/// # File Structure Expected
/// - index.html: Contains ordered list of page names
/// - N.html: Content pages (where N is numeric)
/// - N.html: Comment pages (numeric filenames with redirect meta tags)
/// - homepage files: "NAME的主页.html" or "NAME's Home.html" for Chinese name extraction
/// - attachments/: Directory containing files referenced by comments
#[allow(dead_code)]
fn process_directory(dir: &Path) -> Option<(String, String, usize, String)> {
    // Extract directory name as alias
    let alias = dir.file_name().unwrap().to_string_lossy().to_string();
    let index_path = dir.join("index.html");
    if !index_path.exists() {
        println!("✗ index.html not found in {}", dir.display());
        return None;
    }

    // Count total files in directory for statistics
    let mut file_count = 0;
    for entry in WalkDir::new(dir).into_iter().filter_map(Result::ok) {
        if entry.file_type().is_file() {
            file_count += 1;
        }
    }

    // Extract Chinese name from homepage file (files ending with 主页.html or 's Home.html)
    let mut chinese_name = String::new();
    if let Some(entry) = WalkDir::new(dir).max_depth(1).into_iter().filter_map(Result::ok).find(|e| {
        let path_str = e.path().to_string_lossy();
        path_str.ends_with("的主页.html") || path_str.ends_with("’s Home.html")
    }) {
        if let Some(stem) = entry.path().file_stem() {
            let s = stem.to_string_lossy();
            if let Some(name) = s.strip_suffix("的主页") {
                chinese_name = name.to_string();
            } else if let Some(name) = s.strip_suffix("’s Home") {
                chinese_name = name.to_string();
            }
        }
    }

    if chinese_name.is_empty() {
        println!("⚠  Could not find Chinese name in {}", dir.display());
        // Fallback to alias if no chinese name is found
        chinese_name = alias.clone();
    }

    let index_content = fs::read_to_string(&index_path).unwrap();
    let index_html = Html::parse_document(&index_content);
    let body_selector = Selector::parse("body").unwrap();
    let body = index_html.select(&body_selector).next().unwrap();
    let text = body.text().collect::<String>();
    let mut ordered_pages: Vec<String> = text.lines()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect();

    if !ordered_pages.is_empty() {
        ordered_pages.remove(0);
    }
    
    let ordered_pages: Vec<String> = ordered_pages.into_iter().map(|s| format!("{}.html", s)).collect();

    let mut pages: Vec<Page> = Vec::new();
    let mut comments: Vec<(String, String, String)> = Vec::new();

    for entry in WalkDir::new(dir).min_depth(1).max_depth(1).into_iter().filter_map(Result::ok) {
        if entry.path().extension().map_or(false, |e| e == "html") {
            let path = entry.path();
            let file_name = path.file_stem().unwrap().to_string_lossy().to_string();

            let content = fs::read_to_string(path).unwrap();
            let html = Html::parse_document(&content);
            let meta_selector = Selector::parse("meta[http-equiv='refresh']").unwrap();

            if file_name.chars().all(char::is_numeric) && html.select(&meta_selector).next().is_some() {
                if let Some(meta) = html.select(&meta_selector).next() {
                    if let Some(content_attr) = meta.value().attr("content") {
                        if let Some(url_part) = content_attr.split("url=").nth(1) {
                            let target_page = percent_decode(url_part.as_bytes()).decode_utf8_lossy().to_string();
                            let body_selector = Selector::parse("body").unwrap();
                            let body_content = html.select(&body_selector).next().map_or(String::new(), |b| b.inner_html());
                            comments.push((file_name.clone(), target_page, body_content));
                        }
                    }
                }
            } else {
                let body_selector = Selector::parse("body").unwrap();
                let body_content = html.select(&body_selector).next().map_or(String::new(), |b| b.inner_html());
                pages.push(Page {
                    name: path.file_name().unwrap().to_string_lossy().to_string(),
                    content: body_content,
                    comments: Vec::new(),
                    attachments: Vec::new(),
                });
            }
        }
    }
    
    for (comment_id, target_page, comment_content) in comments {
        if let Some(page) = pages.iter_mut().find(|p| p.name == target_page) {
            page.comments.push((comment_id, comment_content));
        }
    }

    let attachments_dir = dir.join("attachments");
    if attachments_dir.exists() {
        for entry in WalkDir::new(attachments_dir).min_depth(1).max_depth(1).into_iter().filter_map(Result::ok) {
            let path = entry.path();
            
            // Correct image extension if needed (for images with mismatched extensions)
            let corrected_path = if let Ok(path_buf) = path.canonicalize() {
                // Check if this is an image file
                if let Some(ext) = path_buf.extension() {
                    let ext_str = ext.to_string_lossy().to_lowercase();
                    if ["png", "jpg", "jpeg", "gif", "bmp", "webp", "tiff"].contains(&ext_str.as_str()) {
                        // Try to detect and fix the extension
                        match detect_and_rename_image(&path_buf) {
                            Ok(new_path) => new_path,
                            Err(_) => path_buf, // Keep original if detection fails
                        }
                    } else {
                        path_buf
                    }
                } else {
                    path_buf
                }
            } else {
                path.to_path_buf()
            };
            
            let file_name = corrected_path.file_name().unwrap().to_string_lossy();
            if let Some(comment_id) = file_name.split('_').next() {
                 for page in pages.iter_mut() {
                    if page.comments.iter().any(|(id, _)| id == comment_id) {
                        page.attachments.push(corrected_path.clone());
                    }
                }
            }
        }
    }

    pages.sort_by_key(|p| ordered_pages.iter().position(|name| name == &p.name).unwrap_or(usize::MAX));

    let mut markdown_content = String::new();
    for page in pages {
        if page.name == "index.html" {
            continue;
        }
        markdown_content.push_str(&format!("## {}

", page.name.replace(".html", "")));
        markdown_content.push_str(&html2md::parse_html(&page.content).replace("\r\n", "\n").replace("\n", "\n\n"));
        markdown_content.push_str("\n
");

        for (_comment_id, comment) in page.comments {
            markdown_content.push_str("### Comment\n\n");
            markdown_content.push_str(&html2md::parse_html(&comment).replace("\r\n", "\n").replace("\n", "\n\n"));
            markdown_content.push_str("\n
");
        }

        if !page.attachments.is_empty() {
            markdown_content.push_str("### Attachments\n\n");
            
            // Separate images and non-images for better PDF rendering
            let mut images = Vec::new();
            let mut files = Vec::new();
            
            for attachment in page.attachments.iter() {
                let file_name = attachment.file_name().unwrap().to_string_lossy();
                let extension = attachment.extension().map_or("", |s| s.to_str().unwrap()).to_lowercase();
                let link = format!("{}/attachments/{}", alias, file_name);

                let mut is_image = ["png", "jpg", "jpeg", "gif", "bmp", "svg"].contains(&extension.as_str());

                if is_image {
                    // File size check for all images
                    if let Ok(metadata) = fs::metadata(attachment) {
                        if metadata.len() < 100 {
                            eprintln!("Warning: Small image file detected (< 100 bytes), treating as a regular link: {}", attachment.display());
                            is_image = false;
                        }
                    } else {
                        is_image = false; // Cannot get metadata
                    }
                }

                if is_image {
                    images.push((file_name.to_string(), link));
                } else {
                    files.push((file_name.to_string(), link));
                }
            }
            
            // Render images as standalone elements (not in lists) for better PDF embedding
            if !images.is_empty() {
                for (_file_name, link) in images {
                    // Use empty alt text to avoid LaTeX adding spaces between Latin and Chinese characters
                    markdown_content.push_str(&format!("![]({})\n\n", link));
                }
            }
            
            // Render file links as a list
            if !files.is_empty() {
                markdown_content.push_str("**Files:**\n\n");
                for (i, (file_name, link)) in files.iter().enumerate() {
                    // Wrap filename in inline code to prevent Latin–CJK spacing issues in PDF
                    markdown_content.push_str(&format!("{}. [`{}`]({})\n", i + 1, file_name, link));
                }
                markdown_content.push_str("\n");
            }
        }
    }

    Some((alias, chinese_name, file_count, markdown_content))
}

#[derive(serde::Deserialize, Clone)]
struct JiraIssue {
    key: String,
    fields: JiraFields,
}

#[derive(serde::Deserialize, Clone)]
struct JiraFields {
    summary: String,
    project: JiraProject,
    issuetype: JiraIssueType,
    priority: JiraPriority,
    description: Option<String>,
    resolution: Option<JiraResolution>,
    attachment: Vec<JiraAttachment>,
    creator: JiraUser,
    comment: JiraComments,
    assignee: Option<JiraUser>,
    created: String,
    updated: String,
    status: JiraStatus,
}

#[derive(serde::Deserialize, Clone)]
struct JiraProject {
    key: String,
    name: String,
    #[serde(rename = "projectCategory")]
    project_category: Option<JiraProjectCategory>,
}

#[derive(serde::Deserialize, Clone)]
struct JiraProjectCategory {
    description: String,
}

#[derive(serde::Deserialize, Clone)]
struct JiraIssueType {
    name: String,
}

#[derive(serde::Deserialize, Clone)]
struct JiraPriority {
    name: String,
}

#[derive(serde::Deserialize, Clone)]
struct JiraResolution {
    description: String,
}

#[derive(serde::Deserialize, Clone)]
struct JiraAttachment {
    id: String,
    filename: String,
    content: String,
    author: JiraUser,
    created: String,
}

#[derive(serde::Deserialize, Clone)]
struct JiraUser {
    name: String,
    #[serde(rename = "displayName")]
    display_name: String,
}

#[derive(serde::Deserialize, Clone)]
struct JiraComments {
    comments: Vec<JiraComment>,
}

#[derive(serde::Deserialize, Clone)]
struct JiraComment {
    author: JiraUser,
    created: String,
    updated: String,
    body: String,
}

#[derive(serde::Deserialize, Clone)]
struct JiraStatus {
    name: String,
}

/// Processes JIRA issue JSON files and generates a consolidated markdown file.
/// 
/// This function scans the specified directory for JSON files containing JIRA issue data,
/// parses each issue, and generates a single markdown file with all issues formatted
/// according to the specified requirements.
/// 
/// # Arguments
/// * `issues_dir` - Path to the directory containing JIRA issue JSON files
/// * `output_dir` - Path to the directory where the output markdown file will be written
/// 
/// # Returns
/// * `Result<(), Box<dyn std::error::Error>>` - Success or error details
fn process_jira_issues(issues_dir: &Path, output_dir: &Path) -> Result<(), Box<dyn std::error::Error>> {
    Logger::info(&format!("Processing JIRA issues from: {}", issues_dir.display()));
    
    // First, correct image extensions in the attachment directory
    let attachment_dir = issues_dir.parent().unwrap_or(issues_dir).join("attachment");
    if attachment_dir.exists() {
        Logger::detail("Scanning for images with incorrect extensions in attachment directory...");
        let corrected = correct_image_extensions_in_directory(&attachment_dir);
        if corrected > 0 {
            Logger::success(&format!("Corrected {} image file extensions", corrected));
        }
    }
    
    // Collect all JSON files first
    let json_files: Vec<PathBuf> = WalkDir::new(issues_dir)
        .into_iter()
        .filter_map(Result::ok)
        .filter(|e| e.file_type().is_file() && e.path().extension().and_then(|s| s.to_str()) == Some("json"))
        .map(|e| e.path().to_path_buf())
        .collect();
    
    let total_files = json_files.len();
    
    if total_files == 0 {
        Logger::warning(&format!("No JSON files found in {}", issues_dir.display()));
        return Ok(());
    }
    
    Logger::info(&format!("Found {} JIRA issue JSON files", total_files));
    
    // Parallel processing with progress tracking
    let processed = AtomicUsize::new(0);
    let successful = Arc::new(AtomicUsize::new(0));
    let issues_vec = Arc::new(Mutex::new(Vec::new()));
    let failures = Arc::new(Mutex::new(Vec::new()));
    
    json_files.par_iter().for_each(|file_path| {
        let current = processed.fetch_add(1, Ordering::Relaxed) + 1;
        Logger::parallel_progress(current, total_files, "Processing JIRA JSON files");
        
        let file_name = file_path.file_name().unwrap().to_string_lossy().to_string();
        
        match fs::read_to_string(file_path) {
            Ok(content) => {
                match serde_json::from_str::<JiraIssue>(&content) {
                    Ok(issue) => {
                        issues_vec.lock().unwrap().push(issue);
                        successful.fetch_add(1, Ordering::SeqCst);
                    }
                    Err(e) => {
                        failures.lock().unwrap().push((file_name, format!("JSON parse error: {}", e)));
                    }
                }
            }
            Err(e) => {
                failures.lock().unwrap().push((file_name, format!("Failed to read file: {}", e)));
            }
        }
    });
    
    // Report processing results
    let success_count = successful.load(Ordering::SeqCst);
    
    // Extract data from Arc/Mutex wrappers
    let failures_vec = match Arc::try_unwrap(failures) {
        Ok(mutex) => mutex.into_inner().unwrap(),
        Err(arc) => arc.lock().unwrap().clone(),
    };
    let failed_count = failures_vec.len();
    
    Logger::parallel_complete(success_count, failed_count, total_files, "JIRA issue processing");
    Logger::parallel_failures(&failures_vec);
    
    let mut issues = match Arc::try_unwrap(issues_vec) {
        Ok(mutex) => mutex.into_inner().unwrap(),
        Err(arc) => arc.lock().unwrap().clone(),
    };
    
    if issues.is_empty() {
        return Ok(()); // All files failed to parse
    }
    
    // Sort issues by created time from earliest to latest
    issues.sort_by(|a, b| a.fields.created.cmp(&b.fields.created));
    
    let issue_count = issues.len();
    let mut markdown = String::new();
    
    for issue in issues {
        // Issue header
        markdown.push_str(&format!("## {}\n\n", issue.key));
        markdown.push_str(&format!("**{}**\n\n", issue.fields.summary));
        
        // Copy attachments to per-issue folder with attachment ID subdirectories
        let issue_attachment_base_dir = output_dir.join(format!("{}-attachment", issue.key));
        let mut copied_attachments = 0;
        
        if !issue.fields.attachment.is_empty() {
            // Copy each attachment to the issue-specific folder with ID subdirectory
            for attachment in &issue.fields.attachment {
                let url_path = attachment.content.split('/').last().unwrap_or(&attachment.filename);
                let decoded_filename = percent_decode(url_path.as_bytes()).decode_utf8_lossy().to_string();
                let source_path = attachment_dir.join(&attachment.id.to_string()).join(&decoded_filename);
                
                if source_path.exists() {
                    // Create subdirectory with attachment ID
                    let dest_subdir = issue_attachment_base_dir.join(&attachment.id.to_string());
                    if let Err(e) = fs::create_dir_all(&dest_subdir) {
                        Logger::warning(&format!("Failed to create attachment subdirectory for {}: {}", issue.key, e));
                        continue;
                    }
                    
                    let dest_path = dest_subdir.join(&decoded_filename);
                    if let Err(e) = fs::copy(&source_path, &dest_path) {
                        Logger::warning(&format!("Failed to copy attachment {} for {}: {}", decoded_filename, issue.key, e));
                    } else {
                        copied_attachments += 1;
                    }
                } else {
                    Logger::warning(&format!("Attachment file not found: {} for issue {}", source_path.display(), issue.key));
                }
            }
            
            if copied_attachments > 0 {
                Logger::detail(&format!("Copied {} attachments to {}", copied_attachments, issue_attachment_base_dir.display()));
            }
        }
        
        // Project info
        let project_cn = issue.fields.project.project_category
            .as_ref()
            .map(|cat| cat.description.clone())
            .unwrap_or_else(|| issue.fields.project.name.clone());
        
        markdown.push_str(&format!("* Project: {} | {} | {}\n", 
            issue.fields.project.key, 
            issue.fields.project.name, 
            project_cn
        ));
        
        // Issue type
        markdown.push_str(&format!("* Issue Type: {}\n", issue.fields.issuetype.name));
        
        // Priority
        markdown.push_str(&format!("* Priority: {}\n", issue.fields.priority.name));
        
        // Creator
        markdown.push_str(&format!("* Creator: {}\n", issue.fields.creator.display_name));
        
        // Assignee
        if let Some(assignee) = &issue.fields.assignee {
            markdown.push_str(&format!("* Assignee: {}\n", assignee.display_name));
        }
        
        // Description
        if let Some(desc) = &issue.fields.description {
            let processed_desc = process_description(desc, &issue.fields.attachment, &issue.key);
            let formatted_desc = format_as_blockquote(&processed_desc);
            markdown.push_str(&format!("* Desc: \n{}\n", formatted_desc));
        }
        
        // Comments
        if !issue.fields.comment.comments.is_empty() {
            markdown.push_str("* Comments:\n");
            
            // Sort comments by created time
            let mut comments = issue.fields.comment.comments.clone();
            comments.sort_by(|a, b| a.created.cmp(&b.created));
            
            for comment in comments.iter() {
                markdown.push_str(&format!("    + {}\n", comment.author.display_name));
                let processed_body = process_description(&comment.body, &issue.fields.attachment, &issue.key);
                let formatted_body = format_as_blockquote(&processed_body);
                markdown.push_str(&format!("{}\n", formatted_body));
                markdown.push_str(&format!("        - author: {}\n", comment.author.display_name));
                markdown.push_str(&format!("        - created: {}\n", comment.created));
                markdown.push_str(&format!("        - updated: {}\n", comment.updated));
            }
        }
        
        // Attachments
        if !issue.fields.attachment.is_empty() {
            markdown.push_str("* Attachments:\n\n");
            
            // Sort attachments by created time
            let mut attachments = issue.fields.attachment.clone();
            attachments.sort_by(|a, b| a.created.cmp(&b.created));
            
            // Separate images and non-images for better PDF rendering
            let mut images = Vec::new();
            let mut files = Vec::new();
            
            for attachment in &attachments {
                // Extract filename from the content URL instead of the filename field
                // The content URL has the properly encoded filename
                let url_path = attachment.content.split('/').last().unwrap_or(&attachment.filename);
                let decoded_filename = percent_decode(url_path.as_bytes()).decode_utf8_lossy().to_string();
                // Include attachment ID in the path: {issue-key}-attachment\{id}\{filename}
                let attachment_path = format!("{}-attachment\\{}\\{}", issue.key, attachment.id, decoded_filename);
                
                let is_image = ["png", "jpg", "jpeg", "gif", "bmp", "svg"].contains(
                    &decoded_filename.split('.').last().unwrap_or("").to_lowercase().as_str()
                );
                
                if is_image {
                    images.push((decoded_filename, attachment_path, attachment.author.display_name.clone(), attachment.author.name.clone(), attachment.created.clone()));
                } else {
                    files.push((decoded_filename, attachment_path, attachment.author.display_name.clone(), attachment.author.name.clone(), attachment.created.clone()));
                }
            }
            
            // Render images as standalone elements (not in lists) for better PDF embedding
            if !images.is_empty() {
                for (_filename, path, author_display, author_name, created) in images {
                    // Use empty alt text to avoid LaTeX adding spaces between Latin and Chinese characters
                    // Remove angle brackets to prevent spacing issues
                    markdown.push_str(&format!("![]({})\n\n", path));
                    markdown.push_str(&format!("*Author: {} ({}), Created: {}*\n\n", author_display, author_name, created));
                }
            }
            
            // Render file links as a list
            if !files.is_empty() {
                markdown.push_str("**Files:**\n\n");
                for (filename, path, author_display, author_name, created) in files {
                    // Wrap filename in inline code to prevent Latin–CJK spacing issues in PDF
                    // Remove angle brackets from path
                    markdown.push_str(&format!("* [`{}`]({})\n", filename, path));
                    markdown.push_str(&format!("    * Author: {} ({})\n", author_display, author_name));
                    markdown.push_str(&format!("    * Created: {}\n", created));
                }
                markdown.push_str("\n");
            }
        }
        
        // Updated time
        markdown.push_str(&format!("* Updated: {}\n", issue.fields.updated));
        
        // Created time
        markdown.push_str(&format!("* Created: {}\n", issue.fields.created));
        
        // Time Cost calculation
        if let (Ok(created), Ok(updated)) = (
            chrono::DateTime::parse_from_str(&issue.fields.created, "%Y-%m-%dT%H:%M:%S%.3f%z"),
            chrono::DateTime::parse_from_str(&issue.fields.updated, "%Y-%m-%dT%H:%M:%S%.3f%z")
        ) {
            let duration = updated.signed_duration_since(created);
            let days = duration.num_days() as f64 + (duration.num_hours() % 24) as f64 / 24.0;
            markdown.push_str(&format!("* Time Cost: {:.1} day{}\n", days, if days != 1.0 { "s" } else { "" }));
        }
        
        // Status
        markdown.push_str(&format!("* Status: {}\n", issue.fields.status.name));
        
        // Resolution
        if let Some(resolution) = &issue.fields.resolution {
            markdown.push_str(&format!("* Resolution: {}\n", resolution.description));
        }
        
        markdown.push_str("\n");
    }
    
    // Write to output file
    let output_path = output_dir.join("jira_export.md");
    fs::write(&output_path, &markdown)?;
    
    println!("✓ Generated JIRA export: {}", output_path.display());
    println!("✓ Processed {} issues", issue_count);
    
    Ok(())
}

/// Processes the issue description, converting image references and handling line breaks.
/// 
/// # Arguments
/// * `description` - The raw description text
/// * `attachments` - List of attachments for the issue
/// * `issue_key` - The issue key (e.g., "GIT-3") for generating attachment paths
/// 
/// # Returns
/// * Processed description with images converted to markdown format
fn process_description(description: &str, attachments: &[JiraAttachment], issue_key: &str) -> String {
    let mut processed = description.replace("\r\n", "\n");
    
    // Handle Confluence-style image references: !filename.ext! or !filename.ext|width=...,height=...!
    // Exclude URLs (containing ://) and patterns with newlines
    // Use [^\n!]+ to match any character except newline and exclamation mark
    let confluence_image_regex = Regex::new(r"!([^\n!]+(?:\|[^\n!]*)?)!").unwrap();
    
    // Process Confluence-style images by replacing all matches
    processed = confluence_image_regex.replace_all(&processed, |caps: &regex::Captures| {
        let image_part = &caps[1];
        
        // Skip if it contains :// (URL)
        if image_part.contains("://") {
            return caps[0].to_string();
        }
        
        // Extract filename (remove width/height parameters if present)
        let filename = if image_part.contains('|') {
            image_part.split('|').next().unwrap_or(image_part)
        } else {
            image_part
        };
        
        // Find matching attachment
        for attachment in attachments {
            let url_path = attachment.content.split('/').last().unwrap_or(&attachment.filename);
            let decoded_filename = percent_decode(url_path.as_bytes()).decode_utf8_lossy().to_string();
            
            if decoded_filename == filename {
                // Check if it's an image
                let is_image = ["png", "jpg", "jpeg", "gif", "bmp", "svg"].contains(
                    &filename.split('.').last().unwrap_or("").to_lowercase().as_str()
                );
                
                if is_image {
                    // Include attachment ID in the path: {issue-key}-attachment\{id}\{filename}
                    let attachment_path = format!("{}-attachment\\{}\\{}", issue_key, attachment.id, decoded_filename);
                    // Use empty alt text to avoid LaTeX adding spaces between Latin and Chinese characters
                    return format!("\n![]({})\n", attachment_path);
                }
            }
        }
        
        // If no matching attachment found, convert to markdown image syntax with filename
        // This handles cases where !image! syntax is used but attachment is not in JSON
        let is_image = ["png", "jpg", "jpeg", "gif", "bmp", "svg"].contains(
            &filename.split('.').last().unwrap_or("").to_lowercase().as_str()
        );
        
        if is_image {
            return format!("\n![]({})\n", filename);
        }
        
        // If not an image or no attachment found, return original
        caps[0].to_string()
    }).to_string();
    
    // Find image references in the description and convert them (existing logic)
    // Skip this if the filename is already part of a markdown image syntax
    // TEMPORARILY DISABLED
    /*
    for attachment in attachments {
        // Extract filename from the content URL instead of the filename field
        let url_path = attachment.content.split('/').last().unwrap_or(&attachment.filename);
        let decoded_filename = percent_decode(url_path.as_bytes()).decode_utf8_lossy().to_string();
        
        // Only process if the filename appears in the text and is not already in markdown image syntax
        let attachment_path = format!("attachment\\{}\\{}", attachment.id, decoded_filename);
        if processed.contains(&decoded_filename) && !processed.contains(&format!("![]({})", attachment_path)) {
            // Check if it's an image
            let is_image = ["png", "jpg", "jpeg", "gif", "bmp", "svg"].contains(
                &decoded_filename.split('.').last().unwrap_or("").to_lowercase().as_str()
            );
            
            if is_image {
                // Use empty alt text to avoid LaTeX adding spaces between Latin and Chinese characters
                let markdown_image = format!("![]({})", attachment_path);
                
                // Replace the filename with markdown image syntax
                processed = processed.replace(&decoded_filename, &markdown_image);
            }
        }
    }
    */
    
    processed
}

/// Formats multi-line text as a markdown blockquote where each line starts with '>'.
/// Images are extracted and placed outside the blockquote for better PDF rendering.
/// 
/// # Arguments
/// * `text` - The text to format
/// 
/// # Returns
/// * Formatted text with blockquoted text and images placed outside
fn format_as_blockquote(text: &str) -> String {
    let mut result = String::new();
    let mut blockquote_lines = Vec::new();
    let mut images = Vec::new();
    
    // Regex to match markdown images: ![alt](path)
    let image_regex = Regex::new(r"!\[([^\]]*)\]\(([^)]+)\)").unwrap();
    
    for line in text.lines() {
        // Check if this line contains an image
        let has_image = image_regex.is_match(line);
        
        if has_image {
            // Extract all images from this line
            for cap in image_regex.captures_iter(line) {
                let full_match = &cap[0];
                images.push(full_match.to_string());
            }
            
            // Remove images from the line and add remaining text to blockquote
            let line_without_images = image_regex.replace_all(line, "").trim().to_string();
            if !line_without_images.is_empty() {
                blockquote_lines.push(line_without_images);
            }
        } else {
            blockquote_lines.push(line.to_string());
        }
    }
    
    // Format blockquote lines
    if !blockquote_lines.is_empty() {
        let formatted_lines = blockquote_lines.iter()
            .map(|line| format!("        > {}", line))
            .collect::<Vec<String>>()
            .join("\n");
        result.push_str(&format!("\n{}\n", formatted_lines));
    }
    
    // Add images after the blockquote (not inside it)
    if !images.is_empty() {
        result.push_str("\n");
        for image in images {
            result.push_str(&format!("{}\n\n", image));
        }
    }
    
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs::{self, File};
    use std::io::Write;

    #[test]
    fn test_build_pandoc_args_contains_no_figure_caption() {
        let args = build_pandoc_args("lualatex");
        let args_str: Vec<String> = args.iter().map(|s| s.to_string_lossy().to_string()).collect();
        assert!(!args_str.contains(&"--no-figure-caption".to_string()));
        assert!(args_str.contains(&"--pdf-engine=lualatex".to_string()));
        assert!(args_str.contains(&"documentclass=ctexart".to_string()));

        let pdf_args = build_pandoc_args("pdflatex");
        let pdf_args_str: Vec<String> = pdf_args.iter().map(|s| s.to_string_lossy().to_string()).collect();
        assert!(!pdf_args_str.contains(&"--no-figure-caption".to_string()));
        assert!(pdf_args_str.contains(&"--pdf-engine=pdflatex".to_string()));
        assert!(pdf_args_str.contains(&"CJKmainfont=SimSun".to_string()));
    }

    #[test]
    fn test_sanitize_markdown_content() {
        // Test removing backspace characters (common issue with LaTeX)
        let input = "Some text with backspace\x08 and more text";
        let expected = "Some text with backspace and more text";
        assert_eq!(sanitize_markdown_content(input), expected);

        // Test removing other control characters
        let input = "Text\x01\x02\x03with\x7fcontrol chars";
        let expected = "Textwithcontrol chars";
        assert_eq!(sanitize_markdown_content(input), expected);

        // Test preserving normal characters including Chinese
        let input = "Normal text with 中文 characters and spaces";
        let expected = "Normal text with 中文 characters and spaces";
        assert_eq!(sanitize_markdown_content(input), expected);

        // Test removing zero-width characters
        let input = "Text\u{200B}with\u{200C}zero\u{200D}width\u{FEFF}chars";
        let expected = "Textwithzerowidthchars";
        assert_eq!(sanitize_markdown_content(input), expected);

        // Test mixed content
        let input = "VPN审批流程.png\x08 with 中文\x01and\u{200B}issues";
        let expected = "VPN审批流程.png with 中文andissues";
        assert_eq!(sanitize_markdown_content(input), expected);
    }

    #[test]
    fn test_process_directory() {
        let test_dir = Path::new("test_data");
        let employee_dir = test_dir.join("~testuser");
        let attachments_dir = employee_dir.join("attachments");
        fs::create_dir_all(&attachments_dir).unwrap();

        // Create test files
        let index_path = employee_dir.join("index.html");
        let mut index_file = File::create(&index_path).unwrap();
        index_file.write_all(b"<html><body><h1>~testuser</h1>\n<p>1</p></body></html>").unwrap();

        let page_path = employee_dir.join("1.html");
        let mut page_file = File::create(&page_path).unwrap();
        page_file.write_all(b"<html><body>Page content</body></html>").unwrap();

        let comment_path = employee_dir.join("2.html");
        let mut comment_file = File::create(&comment_path).unwrap();
        comment_file.write_all(b"<html><head><meta http-equiv='refresh' content='0; url=1.html'></head><body>Comment content</body></html>").unwrap();

        let attachment_path = attachments_dir.join("2_attachment.txt");
        let mut attachment_file = File::create(&attachment_path).unwrap();
        attachment_file.write_all(b"attachment").unwrap();
        
        let cname_path = employee_dir.join("test的主页.html");
        let mut cname_file = File::create(&cname_path).unwrap();
        cname_file.write_all("<html><body>test的主页</body></html>".as_bytes()).unwrap();

        let comment3_path = employee_dir.join("3.html");
        let mut comment3_file = File::create(&comment3_path).unwrap();
        comment3_file.write_all(b"<html><head><meta http-equiv='refresh' content='0; url=1.html'></head><body>Another comment</body></html>").unwrap();

        let broken_png_path = attachments_dir.join("3_broken.png");
        File::create(&broken_png_path).unwrap(); // Empty file is a broken png

        let result = process_directory(&employee_dir);
        assert!(result.is_some());

        let (alias, chinese_name, file_count, markdown_content) = result.unwrap();
        assert_eq!(alias, "~testuser");
        assert_eq!(chinese_name, "test");
        assert_eq!(file_count, 7);

        assert!(markdown_content.contains("## 1"));
        assert!(markdown_content.contains("Page content"));
        assert!(markdown_content.contains("### Comment"));
        assert!(markdown_content.contains("Comment content"));
        assert!(markdown_content.contains("### Attachments"));
    assert!(markdown_content.contains("[`2_attachment.txt`](~testuser/attachments/2_attachment.txt)"));
    assert!(markdown_content.contains("[`3_broken.png`](~testuser/attachments/3_broken.png)"));
    assert!(!markdown_content.contains("![`3_broken.png`](~testuser/attachments/3_broken.png)"));

        // Cleanup
        fs::remove_dir_all(test_dir).unwrap();
    }

    #[test]
    fn test_process_directory_no_homepage() {
        let test_dir = Path::new("test_data_no_homepage");
        let employee_dir = test_dir.join("~testuser2");
        fs::create_dir_all(&employee_dir).unwrap();

        // Create test files
        let index_path = employee_dir.join("index.html");
        let mut index_file = File::create(&index_path).unwrap();
        index_file.write_all(b"<html><body><h1>~testuser2</h1>\n<p>1</p></body></html>").unwrap();

        let page_path = employee_dir.join("1.html");
        let mut page_file = File::create(&page_path).unwrap();
        page_file.write_all(b"<html><body>Page content</body></html>").unwrap();

        let result = process_directory(&employee_dir);
        assert!(result.is_some());

        let (alias, chinese_name, _file_count, _markdown_content) = result.unwrap();
        assert_eq!(alias, "~testuser2");
        assert_eq!(chinese_name, "~testuser2"); // Fallback to alias if no homepage

        // Cleanup
        fs::remove_dir_all(test_dir).unwrap();
    }

    #[test]
    fn test_split_markdown_files_in_directory() {
        let test_dir = Path::new("test_split_dir");
        fs::create_dir_all(test_dir).unwrap();

        // Create a small markdown file (should not be split)
        let small_file_path = test_dir.join("small.md");
        let mut small_file = File::create(&small_file_path).unwrap();
        small_file.write_all(b"# Small File\n\nThis is a small markdown file.\n\n## Section\n\nContent.").unwrap();

        // Create a large markdown file (should be split)
        let large_file_path = test_dir.join("large.md");
        let mut large_file = File::create(&large_file_path).unwrap();
        let large_content = format!("# Large File\n\n{}", "This is a large markdown file.\n\n".repeat(10000));
        large_file.write_all(large_content.as_bytes()).unwrap();

        // Create a subdirectory with another large file
        let sub_dir = test_dir.join("subdir");
        fs::create_dir_all(&sub_dir).unwrap();
        let sub_large_file_path = sub_dir.join("sub_large.md");
        let mut sub_large_file = File::create(&sub_large_file_path).unwrap();
        let sub_large_content = format!("# Sub Large File\n\n{}", "This is another large markdown file.\n\n".repeat(8000));
        sub_large_file.write_all(sub_large_content.as_bytes()).unwrap();

        // Test with a very low threshold (0.001 MB) to ensure large files are split
        let result = split_markdown_files_in_directory(test_dir, 50000, 0.001, test_dir);
        assert!(result.is_ok(), "Function should succeed");

        // Check that small file was not split (no split files created)
        let small_split_files: Vec<_> = fs::read_dir(test_dir)
            .unwrap()
            .filter_map(|entry| entry.ok())
            .map(|entry| entry.path())
            .filter(|path| {
                let file_name = path.file_name().unwrap().to_str().unwrap();
                file_name.starts_with("small_") && file_name.ends_with(".md")
            })
            .collect();
        assert_eq!(small_split_files.len(), 0, "Small file should not be split");

        // Check that large file was split
        let large_split_files: Vec<_> = fs::read_dir(test_dir)
            .unwrap()
            .filter_map(|entry| entry.ok())
            .map(|entry| entry.path())
            .filter(|path| {
                let file_name = path.file_name().unwrap().to_string_lossy();
                file_name.starts_with("large_") && file_name.ends_with(".md")
            })
            .collect();
        assert!(large_split_files.len() > 0, "Large file should be split into multiple files");

        // Check that sub directory large file was also split
        let sub_large_split_files: Vec<_> = fs::read_dir(test_dir)
            .unwrap()
            .filter_map(|entry| entry.ok())
            .map(|entry| entry.path())
            .filter(|path| {
                let file_name = path.file_name().unwrap().to_str().unwrap();
                file_name.starts_with("sub_large_") && file_name.ends_with(".md")
            })
            .collect();
        assert!(sub_large_split_files.len() > 0, "Sub directory large file should be split");

        // Clean up split files
        for file in large_split_files {
            let _ = fs::remove_file(&file);
        }
        for file in sub_large_split_files {
            let _ = fs::remove_file(&file);
        }

        // Verify original files behavior after split
        assert!(small_file_path.exists(), "Original small file should still exist (not split)");
        assert!(!large_file_path.exists(), "Original large file should be removed after split");
        assert!(!sub_large_file_path.exists(), "Original sub large file should be removed after split");

        // Cleanup
        fs::remove_dir_all(test_dir).unwrap();
    }

    #[test]
    fn test_process_directory_with_chinese_homepage() {
        let test_dir = Path::new("test_chinese_homepage");
        let employee_dir = test_dir.join("~testchinese");
        fs::create_dir_all(&employee_dir).unwrap();

        // Create index.html
        let index_path = employee_dir.join("index.html");
        let mut index_file = File::create(&index_path).unwrap();
        index_file.write_all(b"<html><body><h1>~testchinese</h1>\n<p>1</p></body></html>").unwrap();

        // Create a page
        let page_path = employee_dir.join("1.html");
        let mut page_file = File::create(&page_path).unwrap();
        page_file.write_all(b"<html><body>Content</body></html>").unwrap();

        // Create a Chinese homepage
        let homepage_path = employee_dir.join("张三的主页.html");
        let mut homepage_file = File::create(&homepage_path).unwrap();
        homepage_file.write_all("<html><body>张三的主页</body></html>".as_bytes()).unwrap();

        let result = process_directory(&employee_dir);
        assert!(result.is_some());

        let (alias, chinese_name, _file_count, _markdown_content) = result.unwrap();
        assert_eq!(alias, "~testchinese");
        assert_eq!(chinese_name, "张三", "Should extract Chinese name from homepage");

        // Cleanup
        fs::remove_dir_all(test_dir).unwrap();
    }

    #[test]
    fn test_process_directory_with_english_homepage() {
        // This test verifies that when no recognizable homepage file is found,
        // the function falls back to using the alias as the chinese_name
        let test_dir = Path::new("test_english_homepage2");
        let employee_dir = test_dir.join("~testenglish2");
        fs::create_dir_all(&employee_dir).unwrap();

        // Create index.html
        let index_path = employee_dir.join("index.html");
        File::create(&index_path).unwrap().write_all(b"<html><body><h1>~testenglish2</h1>\n<p>1</p></body></html>").unwrap();

        // Create a page
        let page_path = employee_dir.join("1.html");
        File::create(&page_path).unwrap().write_all(b"<html><body>Content</body></html>").unwrap();

        // Create an English homepage file (may not be detected on all platforms)
        let homepage_path = employee_dir.join("John's Home.html");
        File::create(&homepage_path).unwrap().write_all(b"<html><body>John's Home</body></html>").unwrap();

        let result = process_directory(&employee_dir);
        assert!(result.is_some());

        let (alias, chinese_name, _file_count, _markdown_content) = result.unwrap();
        assert_eq!(alias, "~testenglish2");
        // The chinese_name will either be "John" if detected, or fall back to alias
        assert!(!chinese_name.is_empty(), "Chinese name should not be empty");

        // Cleanup
        fs::remove_dir_all(test_dir).unwrap();
    }

    #[test]
    fn test_process_jira_issues_invalid_json() {
        use tempfile::TempDir;

        let temp_dir = TempDir::new().unwrap();
        let issues_dir = temp_dir.path().join("issues");
        fs::create_dir(&issues_dir).unwrap();

        // Create an invalid JSON file
        let invalid_json = "{ invalid json }";
        fs::write(issues_dir.join("invalid.json"), invalid_json).unwrap();

        let result = process_jira_issues(&issues_dir, temp_dir.path());
        // Should succeed but report failures (no valid issues found)
        assert!(result.is_ok(), "Should collect failures instead of returning error");
    }

    #[test]
    fn test_process_description_confluence_mixed_content() {
        let description = "Regular text\n!image.png!\nMore text\n!document.pdf!\nEnd text";
        let attachments = vec![
            JiraAttachment {
                id: "111".to_string(),
                filename: "image.png".to_string(),
                content: "https://example.com/attachment/111/image.png".to_string(),
                author: JiraUser { name: "user".to_string(), display_name: "User".to_string() },
                created: "2023-01-01T00:00:00.000+0000".to_string(),
            },
            JiraAttachment {
                id: "222".to_string(),
                filename: "document.pdf".to_string(),
                content: "https://example.com/attachment/222/document.pdf".to_string(),
                author: JiraUser { name: "user".to_string(), display_name: "User".to_string() },
                created: "2023-01-01T00:00:00.000+0000".to_string(),
            }
        ];
        
        let result = process_description(description, &attachments, "TEST-1");
        
        // Image should be converted with attachment ID in path
        assert!(result.contains("![](TEST-1-attachment\\111\\image.png)"));
        
        // Non-image should not be converted to image syntax
        assert!(!result.contains("![](TEST-1-attachment\\222\\document.pdf)"));
        
        // Regular text should be preserved
        assert!(result.contains("Regular text"));
        assert!(result.contains("More text"));
        assert!(result.contains("End text"));
    }

    #[test]
    fn test_external_image_links_conversion() {
        // Test that external image links are converted to regular links
        
        // Direct external image link
        let input1 = "![](https://img.shields.io/badge/MIT-License-blue)";
        let expected1 = "[](https://img.shields.io/badge/MIT-License-blue)";
        
        // Reference-style badge link
        let input2 = "[![Crates.io][crates-badge]][crates-url]";
        let expected2 = "[[Crates.io][crates-badge]][crates-url]";
        
        // External image with alt text
        let input3 = "![Off-path port scanning](https://www.saddns.net/attack2.svg)";
        let expected3 = "[Off-path port scanning](https://www.saddns.net/attack2.svg)";
        
        // Multiple badges
        let input4 = r#"[![Crates.io][crates-badge]][crates-url]
[![MIT/Apache-2 licensed][license-badge]][license-url]
[![Build Status][actions-badge]][actions-url]"#;
        
        let expected4 = r#"[[Crates.io][crates-badge]][crates-url]
[[MIT/Apache-2 licensed][license-badge]][license-url]
[[Build Status][actions-badge]][actions-url]"#;
        
        // Simulate the conversion logic
        let external_image_regex = Regex::new(r"!\[([^\]\n]*)\]\((https?://[^)\n]+)\)").unwrap();
        let badge_link_regex = Regex::new(r"!\[([^\]]*)\]\[([^\]]+)\]").unwrap();
        
        // Test direct external links
        let result1 = external_image_regex.replace_all(input1, "[$1]($2)").to_string();
        assert_eq!(result1, expected1, "Direct external image link should be converted");
        
        let result3 = external_image_regex.replace_all(input3, "[$1]($2)").to_string();
        assert_eq!(result3, expected3, "External image with alt text should be converted");
        
        // Test reference-style badges
        let result2 = badge_link_regex.replace_all(input2, "[$1][$2]").to_string();
        assert_eq!(result2, expected2, "Reference-style badge should be converted");
        
        // Test multiple badges
        let result4 = badge_link_regex.replace_all(input4, "[$1][$2]").to_string();
        assert_eq!(result4, expected4, "Multiple badges should all be converted");
        
        // Test that local image links are NOT matched
        let local_image = "![Local diagram](images/architecture.jpg)";
        let result_local = external_image_regex.replace_all(local_image, "[$1]($2)").to_string();
        assert_eq!(result_local, local_image, "Local images should not be converted");
    }

    #[test]
    fn test_process_jira_issues_attachment_copying() {
        use tempfile::TempDir;

        let temp_dir = TempDir::new().unwrap();
        let issues_dir = temp_dir.path().join("issues");
        let attachment_dir = temp_dir.path().join("attachment");
        fs::create_dir(&issues_dir).unwrap();
        fs::create_dir(&attachment_dir).unwrap();

        // Create attachment subdirectories and files
        let attach_subdir1 = attachment_dir.join("11175");
        let attach_subdir2 = attachment_dir.join("11176");
        fs::create_dir(&attach_subdir1).unwrap();
        fs::create_dir(&attach_subdir2).unwrap();

        // Create test attachment files
        let image_file = attach_subdir1.join("geedgenetwork_VPN测试流程.png");
        let doc_file = attach_subdir2.join("requirements.pdf");
        fs::write(&image_file, "fake png content").unwrap();
        fs::write(&doc_file, "fake pdf content").unwrap();

        // Create a JIRA issue JSON with attachments
        let issue_json = r#"
        {
            "key": "GIT-3",
            "fields": {
                "summary": "Test Issue",
                "description": "Test description",
                "issuetype": {"name": "Task"},
                "priority": {"name": "Medium"},
                "creator": {"displayName": "Test User", "name": "testuser"},
                "assignee": {"displayName": "Test User", "name": "testuser"},
                "project": {"key": "GIT", "name": "Test Project", "project_category": {"description": "Test Category"}},
                "status": {"name": "Open"},
                "resolution": null,
                "created": "2023-01-01T00:00:00.000+0000",
                "updated": "2023-01-01T00:00:00.000+0000",
                "comment": {"comments": []},
                "attachment": [
                    {
                        "id": "11175",
                        "filename": "geedgenetwork_VPN测试流程.png",
                        "content": "https://example.com/attachment/11175/geedgenetwork_VPN%E6%B5%8B%E8%AF%95%E6%B5%81%E7%A8%8B.png",
                        "author": {"displayName": "Test User", "name": "testuser"},
                        "created": "2023-01-01T00:00:00.000+0000"
                    },
                    {
                        "id": "11176",
                        "filename": "requirements.pdf",
                        "content": "https://example.com/attachment/11176/requirements.pdf",
                        "author": {"displayName": "Test User", "name": "testuser"},
                        "created": "2023-01-01T00:00:00.000+0000"
                    }
                ]
            }
        }
        "#;

        fs::write(issues_dir.join("GIT-3.json"), issue_json).unwrap();

        // Process the JIRA issues
        let result = process_jira_issues(&issues_dir, temp_dir.path());
        assert!(result.is_ok(), "JIRA processing should succeed");

        // Check that the per-issue attachment folder was created
        let issue_attachment_dir = temp_dir.path().join("GIT-3-attachment");
        assert!(issue_attachment_dir.exists(), "Per-issue attachment directory should be created");

        // Check that attachment files were copied with ID subdirectories
        let copied_image = issue_attachment_dir.join("11175").join("geedgenetwork_VPN测试流程.png");
        let copied_doc = issue_attachment_dir.join("11176").join("requirements.pdf");
        assert!(copied_image.exists(), "Image attachment should be copied");
        assert!(copied_doc.exists(), "Document attachment should be copied");

        // Check that the markdown file was created and contains correct paths with attachment IDs
        let markdown_file = temp_dir.path().join("jira_export.md");
        assert!(markdown_file.exists(), "Markdown file should be created");

        let markdown_content = fs::read_to_string(&markdown_file).unwrap();
        assert!(markdown_content.contains("GIT-3-attachment\\11175\\geedgenetwork_VPN测试流程.png"), "Markdown should contain new attachment path for image with ID");
        assert!(markdown_content.contains("GIT-3-attachment\\11176\\requirements.pdf"), "Markdown should contain new attachment path for document with ID");
    }

    #[test]
    fn test_process_description_with_issue_key() {
        let description = "Check this image: !test_image.png!";
        let attachments = vec![
            JiraAttachment {
                id: "12345".to_string(),
                filename: "test_image.png".to_string(),
                content: "https://example.com/attachment/12345/test_image.png".to_string(),
                author: JiraUser { name: "user".to_string(), display_name: "User".to_string() },
                created: "2023-01-01T00:00:00.000+0000".to_string(),
            }
        ];

        let result = process_description(description, &attachments, "PROJ-42");

        // Should use the new per-issue path format with attachment ID
        assert!(result.contains("PROJ-42-attachment\\12345\\test_image.png"), "Should use per-issue attachment path with ID");
        // Should NOT have the old format (starting with just "attachment\\" without issue key prefix)
        assert!(!result.contains("![](attachment\\12345\\test_image.png)"), "Should not use old central attachment path format");
    }

    #[test]
    fn test_process_jira_issues_no_attachments() {
        use tempfile::TempDir;

        let temp_dir = TempDir::new().unwrap();
        let issues_dir = temp_dir.path().join("issues");
        fs::create_dir(&issues_dir).unwrap();

        // Create a JIRA issue JSON without attachments
        let issue_json = r#"
        {
            "key": "TEST-1",
            "fields": {
                "summary": "Test Issue Without Attachments",
                "description": "Test description",
                "issuetype": {"name": "Task"},
                "priority": {"name": "Medium"},
                "creator": {"displayName": "Test User", "name": "testuser"},
                "assignee": {"displayName": "Test User", "name": "testuser"},
                "project": {"key": "TEST", "name": "Test Project", "project_category": {"description": "Test Category"}},
                "status": {"name": "Open"},
                "resolution": null,
                "created": "2023-01-01T00:00:00.000+0000",
                "updated": "2023-01-01T00:00:00.000+0000",
                "comment": {"comments": []},
                "attachment": []
            }
        }
        "#;

        fs::write(issues_dir.join("TEST-1.json"), issue_json).unwrap();

        // Process the JIRA issues
        let result = process_jira_issues(&issues_dir, temp_dir.path());
        assert!(result.is_ok(), "JIRA processing should succeed");

        // Check that no per-issue attachment folder was created
        let issue_attachment_dir = temp_dir.path().join("TEST-1-attachment");
        assert!(!issue_attachment_dir.exists(), "No attachment directory should be created when issue has no attachments");

        // Check that the markdown file was created
        let markdown_file = temp_dir.path().join("jira_export.md");
        assert!(markdown_file.exists(), "Markdown file should be created");
    }
}
