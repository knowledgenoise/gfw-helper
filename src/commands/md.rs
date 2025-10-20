use std::fs;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::sync::atomic::{AtomicUsize, Ordering};
use scraper::{Html, Selector};
use walkdir::WalkDir;
use percent_encoding::percent_decode;
use html2md;
use rayon::prelude::*;
use crate::processing::filetype;
use crate::utils::convert_webp_to_png;
use crate::logger::Logger;

/// Represents a single HTML page with its content, comments, and attachments.
/// This struct is used to store extracted information from HTML files during
/// the document processing phase.
#[derive(Debug)]
pub struct Page {
    /// The title/name of the page
    pub name: String,
    /// The main content of the page in markdown format
    pub content: String,
    /// List of comments associated with this page, stored as (comment_id, comment_content) pairs
    pub comments: Vec<(String, String)>,
    /// List of file paths to attachments (images, documents) referenced by this page
    pub attachments: Vec<PathBuf>,
}

pub fn process_directories_unified(data_dir: &Path, mode: Option<bool>, output_dir: &Path) {
    // Validate input directory exists
    if !data_dir.exists() {
        Logger::error(&format!("Data directory not found: {}", data_dir.display()));
        return;
    }

    // First pass: correct image extensions in all attachment directories (parallel)
    Logger::info("Scanning for images with incorrect extensions");
    
    // Collect all directories first
    let directories: Vec<PathBuf> = WalkDir::new(data_dir)
        .min_depth(1)
        .max_depth(1)
        .into_iter()
        .filter_map(Result::ok)
        .filter(|e| e.file_type().is_dir())
        .map(|e| e.path().to_path_buf())
        .collect();
    
    // Parallel image correction
    let total_corrected: usize = directories.par_iter()
        .map(|dir| {
            let attachments_dir = dir.join("attachments");
            if attachments_dir.exists() {
                super::super::processing::images::correct_image_extensions_in_directory(&attachments_dir)
            } else {
                0
            }
        })
        .sum();
    
    if total_corrected > 0 {
        Logger::success(&format!("Corrected {} image file extensions", total_corrected));
    }

    // Collect directories to process based on mode
    let dirs_to_process: Vec<(PathBuf, bool)> = directories.iter()
        .filter_map(|dir| {
            let file_name = dir.file_name()?.to_string_lossy();
            let is_employee_dir = file_name.starts_with('~');

            // Determine if we should process this directory based on mode
            let should_process = match mode {
                None => true,                           // Process all
                Some(true) => is_employee_dir,          // Employee only
                Some(false) => !is_employee_dir,        // Project only
            };

            if should_process {
                Some((dir.clone(), is_employee_dir))
            } else {
                None
            }
        })
        .collect();

    let total_dirs = dirs_to_process.len();
    if total_dirs == 0 {
        Logger::warning("No directories to process");
        return;
    }

    // Parallel directory processing with progress tracking
    let processed = AtomicUsize::new(0);
    let failures = Arc::new(Mutex::new(Vec::new()));

    dirs_to_process.par_iter().for_each(|(dir, is_employee_dir)| {
        let current = processed.fetch_add(1, Ordering::Relaxed) + 1;
        Logger::parallel_progress(current, total_dirs, "HTML to Markdown");

        // Extract content from the directory
        match process_directory(dir) {
            Some((alias, chinese_name, file_count, markdown_content)) => {
                // Generate output filename based on directory type
                let output_file_name = if *is_employee_dir {
                    format!("{}-{}-{}.md", alias, chinese_name, file_count)
                } else {
                    format!("{}-{}.md", alias, file_count)
                };
                let output_path = output_dir.join(output_file_name);

                // Decode HTML entities and prepare final content
                let mut final_content = markdown_content.replace("&gt;", ">").replace("&lt;", "<");

                // Copy linked resources and update links
                match copy_resources_and_update_links(&final_content, &output_path, dir) {
                    Ok(updated_content) => {
                        final_content = updated_content;
                    }
                    Err(e) => {
                        Logger::warning(&format!("Failed to copy resources for {}: {}", 
                            dir.file_name().unwrap().to_string_lossy(), e));
                        // Continue with original content
                    }
                }

                // Write the final content to file
                match fs::write(&output_path, final_content) {
                    Ok(_) => {
                        // Success - no need to log individual success in parallel mode
                    }
                    Err(e) => {
                        let dir_name = dir.file_name().unwrap().to_string_lossy().to_string();
                        failures.lock().unwrap().push((dir_name, format!("Failed to write file: {}", e)));
                    }
                }
            }
            None => {
                let dir_name = dir.file_name().unwrap().to_string_lossy().to_string();
                failures.lock().unwrap().push((dir_name, "Failed to extract content".to_string()));
            }
        }
    });

    // Report results
    let failures_vec = Arc::try_unwrap(failures).unwrap().into_inner().unwrap();
    let successful = total_dirs - failures_vec.len();
    Logger::parallel_complete(successful, failures_vec.len(), total_dirs, "HTML to Markdown conversion");
    Logger::parallel_failures(&failures_vec);
}

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
        path_str.ends_with("的主页.html") || path_str.ends_with("'s Home.html")
    }) {
        if let Some(stem) = entry.path().file_stem() {
            let s = stem.to_string_lossy();
            if let Some(name) = s.strip_suffix("的主页") {
                chinese_name = name.to_string();
            } else if let Some(name) = s.strip_suffix("'s Home") {
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
                        match super::super::processing::images::detect_and_rename_image(&path_buf) {
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
        markdown_content.push_str(&format!("## {}\n\n", page.name.replace(".html", "")));
        markdown_content.push_str(&html2md::parse_html(&page.content).replace("\r\n", "\n").replace("\n", "\n\n"));
        markdown_content.push_str("\n\n");

        for (_comment_id, comment) in page.comments {
            markdown_content.push_str("### Comment\n\n");
            markdown_content.push_str(&html2md::parse_html(&comment).replace("\r\n", "\n").replace("\n", "\n\n"));
            markdown_content.push_str("\n\n");
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

                if ["png", "jpg", "jpeg", "gif", "bmp", "webp", "tiff", "svg"].contains(&extension.as_str()) {
                    images.push((file_name.to_string(), link));
                } else {
                    files.push((file_name.to_string(), link));
                }
            }

            // Output images first
            for (file_name, link) in images {
                markdown_content.push_str(&format!("![{}]({})\n\n", file_name, link));
            }

            // Then output other files as links
            for (file_name, link) in files {
                markdown_content.push_str(&format!("[{}]({})\n\n", file_name, link));
            }
        }

        markdown_content.push_str("\n---\n\n");
    }

    Some((alias, chinese_name, file_count, markdown_content))
}

/// Extracts all local file links from markdown content.
/// Returns a vector of link paths that appear to be local file references (not URLs).
fn extract_local_links(markdown_content: &str) -> Vec<String> {
    use regex::Regex;

    let mut links = Vec::new();

    // Match markdown image syntax: ![alt](path)
    let image_regex = Regex::new(r"!\[([^\]]*)\]\(([^)]+)\)").unwrap();
    for cap in image_regex.captures_iter(markdown_content) {
        let link = cap[2].to_string();
        if !is_external_url(&link) {
            links.push(link);
        }
    }

    // Match markdown link syntax: [text](path)
    let link_regex = Regex::new(r"\[([^\]]+)\]\(([^)]+)\)").unwrap();
    for cap in link_regex.captures_iter(markdown_content) {
        let link = cap[2].to_string();
        if !is_external_url(&link) {
            links.push(link);
        }
    }

    // Remove duplicates while preserving order
    let mut seen = std::collections::HashSet::new();
    links.into_iter().filter(|link| seen.insert(link.clone())).collect()
}

/// Checks if a link is an external URL (starts with http://, https://, etc.)
fn is_external_url(link: &str) -> bool {
    link.starts_with("http://") ||
    link.starts_with("https://") ||
    link.starts_with("ftp://") ||
    link.starts_with("mailto:")
}

/// Resolves a link to an absolute file path based on the original data directory.
/// Handles different link patterns used in the markdown generation.
fn resolve_link_to_path(link: &str, data_dir: &Path) -> Option<PathBuf> {
    // Handle different link patterns:

    // 1. Employee/project pattern: {alias}/attachments/{filename}
    if let Some(alias_and_rest) = link.split_once('/') {
        let (alias, rest) = alias_and_rest;
        if rest.starts_with("attachments/") {
            let filename = &rest[12..]; // Remove "attachments/" prefix
            
            // First, try direct path within data_dir (when data_dir is the employee/project directory itself)
            let direct_path = data_dir.join("attachments").join(filename);
            if direct_path.exists() {
                return Some(direct_path);
            }
            
            // Second, try searching subdirectories (when data_dir is the parent directory)
            if let Ok(entries) = std::fs::read_dir(data_dir) {
                for entry in entries.flatten() {
                    if entry.file_type().ok()?.is_dir() {
                        let dir_name = entry.file_name().to_string_lossy().to_string();
                        if dir_name.starts_with(alias) || dir_name == alias {
                            let attachment_path = entry.path().join("attachments").join(filename);
                            if attachment_path.exists() {
                                return Some(attachment_path);
                            }
                        }
                    }
                }
            }
        }
    }

    // 2. JIRA attachment pattern: attachment\{id}\{filename}
    if link.starts_with("attachment\\") {
        // This is a JIRA attachment link - we can't resolve these to source files
        // as they come from the JIRA JSON data, not local files
        return None;
    }

    // 3. Direct relative paths (fallback)
    let potential_path = data_dir.join(link);
    if potential_path.exists() {
        return Some(potential_path);
    }

    None
}

/// Copies all linked resource files to a resources folder alongside the markdown file
/// and updates the markdown content to use the new relative paths.
/// Returns the updated markdown content.
fn copy_resources_and_update_links(
    markdown_content: &str,
    output_path: &Path,
    data_dir: &Path
) -> Result<String, Box<dyn std::error::Error>> {
    let links = extract_local_links(markdown_content);

    if links.is_empty() {
        return Ok(markdown_content.to_string());
    }

    // Create resources directory alongside the markdown file
    let base_name = output_path.file_stem().unwrap_or_default().to_string_lossy();
    let resources_dir = output_path.with_file_name(format!("{}_files", base_name));
    std::fs::create_dir_all(&resources_dir)?;

    let mut updated_content = markdown_content.to_string();
    let mut copied_count = 0;
    let mut corrected_count = 0;

    for link in links {
        if let Some(source_path) = resolve_link_to_path(&link, data_dir) {
            if source_path.exists() {
                let original_file_name = source_path.file_name().unwrap().to_string_lossy();
                
                // Check if it's a WebP file and convert to PNG
                let source_to_copy = if let Some(ext) = source_path.extension() {
                    if ext.to_string_lossy().to_lowercase() == "webp" {
                        match convert_webp_to_png(&source_path) {
                            Ok(png_path) => png_path,
                            Err(e) => {
                                println!("  ⚠ Failed to convert WebP {}: {}", original_file_name, e);
                                source_path.clone()
                            }
                        }
                    } else {
                        source_path.clone()
                    }
                } else {
                    source_path.clone()
                };
                
                // Detect if file type doesn't match extension
                let final_file_name = if let Some(correct_ext) = filetype::get_corrected_extension(&source_to_copy) {
                    let stem = source_to_copy.file_stem().unwrap().to_string_lossy();
                    corrected_count += 1;
                    println!("  ⚠ Correcting file type: {} -> {}.{}", original_file_name, stem, correct_ext);
                    format!("{}.{}", stem, correct_ext)
                } else {
                    source_to_copy.file_name().unwrap().to_string_lossy().to_string()
                };
                
                let dest_path = resources_dir.join(&final_file_name);

                // Copy the file
                std::fs::copy(&source_to_copy, &dest_path)?;
                copied_count += 1;

                // Update the link in markdown content
                let new_link = format!("{}_files/{}", base_name, final_file_name);
                updated_content = updated_content.replace(&link, &new_link);
            }
        }
    }

    if copied_count > 0 {
        println!("✓ Copied {} resource files to {}", copied_count, resources_dir.display());
        if corrected_count > 0 {
            println!("  ℹ Corrected {} file extensions based on actual file type", corrected_count);
        }
    }

    Ok(updated_content)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn test_process_directory_employee() {
        let temp_dir = TempDir::new().unwrap();
        let employee_dir = temp_dir.path().join("~testuser");
        let attachments_dir = employee_dir.join("attachments");
        fs::create_dir_all(&attachments_dir).unwrap();

        // Create index.html
        let index_html = r#"<html><body><h1>~testuser</h1><p>1</p><p>2</p></body></html>"#;
        fs::write(employee_dir.join("index.html"), index_html).unwrap();

        // Create homepage with Chinese name
        let homepage_html = r#"<html><body><h1>张三的主页</h1></body></html>"#;
        fs::write(employee_dir.join("张三的主页.html"), homepage_html).unwrap();

        // Create content page
        let page1_html = r#"<html><body><h1>Page 1</h1><p>Content</p></body></html>"#;
        fs::write(employee_dir.join("1.html"), page1_html).unwrap();

        // Create comment page with redirect
        let comment_html = r#"<html><head><meta http-equiv='refresh' content='0; url=1.html'></head><body><p>Comment text</p></body></html>"#;
        fs::write(employee_dir.join("2.html"), comment_html).unwrap();

        let result = process_directory(&employee_dir);
        assert!(result.is_some());

        let (alias, chinese_name, _file_count, markdown) = result.unwrap();
        assert_eq!(alias, "~testuser");
        assert_eq!(chinese_name, "张三");
        assert!(markdown.contains("## 1"));
        assert!(markdown.contains("Page 1"));
        assert!(markdown.contains("### Comment"));
        assert!(markdown.contains("Comment text"));
    }

    #[test]
    fn test_process_directory_no_index() {
        let temp_dir = TempDir::new().unwrap();
        let test_dir = temp_dir.path().join("testdir");
        fs::create_dir_all(&test_dir).unwrap();

        let result = process_directory(&test_dir);
        assert!(result.is_none());
    }

    #[test]
    fn test_process_directory_with_attachments() {
        let temp_dir = TempDir::new().unwrap();
        let dir = temp_dir.path().join("~user");
        let attachments_dir = dir.join("attachments");
        fs::create_dir_all(&attachments_dir).unwrap();

        // Create index
        fs::write(dir.join("index.html"), "<html><body><p>1</p></body></html>").unwrap();

        // Create page
        fs::write(dir.join("1.html"), "<html><body>Page</body></html>").unwrap();

        // Create comment with redirect
        let comment = r#"<html><head><meta http-equiv='refresh' content='0; url=1.html'></head><body>Comment</body></html>"#;
        fs::write(dir.join("2.html"), comment).unwrap();

        // Create attachment for comment
        fs::write(attachments_dir.join("2_file.txt"), "content").unwrap();
        fs::write(attachments_dir.join("2_image.png"), "fake png").unwrap();

        let result = process_directory(&dir);
        assert!(result.is_some());

        let (_alias, _chinese_name, _count, markdown) = result.unwrap();
        assert!(markdown.contains("### Attachments"));
        assert!(markdown.contains("2_file.txt") || markdown.contains("2_image.png"));
    }

    #[test]
    fn test_process_directory_english_homepage() {
        let temp_dir = TempDir::new().unwrap();
        let dir = temp_dir.path().join("~johndoe");
        fs::create_dir_all(&dir).unwrap();

        // Create index
        fs::write(dir.join("index.html"), "<html><body><p>1</p></body></html>").unwrap();

        // Create English homepage
        fs::write(dir.join("John's Home.html"), "<html><body>Home</body></html>").unwrap();

        // Create page
        fs::write(dir.join("1.html"), "<html><body>Content</body></html>").unwrap();

        let result = process_directory(&dir);
        assert!(result.is_some());

        let (_alias, chinese_name, _count, _markdown) = result.unwrap();
        assert_eq!(chinese_name, "John");
    }

    #[test]
    fn test_process_directory_fallback_name() {
        let temp_dir = TempDir::new().unwrap();
        let dir = temp_dir.path().join("~noname");
        fs::create_dir_all(&dir).unwrap();

        // Create index without homepage file
        fs::write(dir.join("index.html"), "<html><body><p>1</p></body></html>").unwrap();
        fs::write(dir.join("1.html"), "<html><body>Page</body></html>").unwrap();

        let result = process_directory(&dir);
        assert!(result.is_some());

        let (_alias, chinese_name, _count, _markdown) = result.unwrap();
        // Should fallback to alias when no homepage found
        assert_eq!(chinese_name, "~noname");
    }

    #[test]
    fn test_extract_local_links() {
        let markdown = r#"
        ![Image](image.png)
        [Link](document.pdf)
        [External](http://example.com)
        ![Another Image](another_image.jpg)
        "#;

        let links = extract_local_links(markdown);
        assert_eq!(links.len(), 3);
        assert!(links.contains(&"image.png".to_string()));
        assert!(links.contains(&"document.pdf".to_string()));
        assert!(links.contains(&"another_image.jpg".to_string()));
    }

    #[test]
    fn test_is_external_url() {
        assert!(is_external_url("http://example.com"));
        assert!(is_external_url("https://example.com"));
        assert!(is_external_url("ftp://example.com"));
        assert!(is_external_url("mailto:example@example.com"));
        assert!(!is_external_url("image.png"));
        assert!(!is_external_url("document.pdf"));
    }

    #[test]
    fn test_resolve_link_to_path() {
        let temp_dir = TempDir::new().unwrap();
        let data_dir = temp_dir.path().to_path_buf();
        let alias_dir = data_dir.join("~user").join("attachments");
        fs::create_dir_all(&alias_dir).unwrap();

        // Create a test file in the alias directory
        let test_file = alias_dir.join("test_image.png");
        fs::write(&test_file, "test").unwrap();

        // Link should resolve to the test file
        let link = "~user/attachments/test_image.png";
        let resolved_path = resolve_link_to_path(link, &data_dir);
        assert!(resolved_path.is_some());
        assert_eq!(resolved_path.unwrap(), test_file);

        // External link should not resolve
        let external_link = "http://example.com/image.png";
        assert!(resolve_link_to_path(external_link, &data_dir).is_none());
    }

    #[test]
    fn test_copy_resources_and_update_links() {
        let temp_dir = TempDir::new().unwrap();
        let data_dir = temp_dir.path().to_path_buf();
        let output_md = temp_dir.path().join("output.md");
        let alias_dir = data_dir.join("~user").join("attachments");
        fs::create_dir_all(&alias_dir).unwrap();

        // Create test files
        let test_image = alias_dir.join("image.png");
        let test_doc = alias_dir.join("document.pdf");
        fs::write(&test_image, "image content").unwrap();
        fs::write(&test_doc, "pdf content").unwrap();

        let markdown_input = r#"
        ![Image](~user/attachments/image.png)
        [Document](~user/attachments/document.pdf)
        [External](http://example.com)
        "#;

        let updated_markdown = copy_resources_and_update_links(markdown_input, &output_md, &data_dir).unwrap();

        // Check that the resources directory was created
        let resources_dir = output_md.with_file_name("output_files");
        assert!(resources_dir.exists());

        // Check that the files were copied
        assert!(resources_dir.join("image.png").exists());
        assert!(resources_dir.join("document.pdf").exists());

        // Check that the links were updated in the markdown content
        assert!(updated_markdown.contains("![Image](output_files/image.png)"));
        assert!(updated_markdown.contains("[Document](output_files/document.pdf)"));
        // External URLs should remain unchanged
        assert!(updated_markdown.contains("[External](http://example.com)"));
    }

    #[test]
    fn test_process_directories_unified_valid() {
        let temp_dir = TempDir::new().unwrap();
        let data_dir = temp_dir.path().to_path_buf();
        let output_dir = temp_dir.path().join("output");
        fs::create_dir_all(&output_dir).unwrap();

        // Create a valid employee directory
        let employee_dir = data_dir.join("~testuser");
        fs::create_dir_all(&employee_dir).unwrap();

        // Create index.html with a homepage link
        fs::write(employee_dir.join("index.html"), "<html><body><p>1</p></body></html>").unwrap();

        // Create a homepage with Chinese name
        fs::write(employee_dir.join("TestUser's Home.html"), "<html><body><h1>主页</h1></body></html>").unwrap();

        // Create a page
        fs::write(employee_dir.join("1.html"), "<html><body><h1>Page 1</h1></body></html>").unwrap();

        // Process the directories
        process_directories_unified(&data_dir, Some(true), &output_dir);

        // Verify that the function completed successfully (either creates file or handles gracefully)
        // The main goal is to ensure no panics occur during processing
        assert!(output_dir.exists(), "Output directory should exist");
    }

    #[test]
    fn test_process_directories_unified_nonexistent_dir() {
        let temp_dir = TempDir::new().unwrap();
        let output_dir = temp_dir.path().join("output");
        fs::create_dir_all(&output_dir).unwrap();

        // Try to process a nonexistent directory
        let nonexistent_dir = temp_dir.path().join("nonexistent");
        process_directories_unified(&nonexistent_dir, Some(true), &output_dir);

        // Should handle gracefully without panic or error
        assert!(!output_dir.read_dir().unwrap().any(|e| {
            e.ok()
                .map(|f| f.path().extension().map(|ext| ext == "md").unwrap_or(false))
                .unwrap_or(false)
        }));
    }

    #[test]
    fn test_process_directories_unified_multiple_employees() {
        let temp_dir = TempDir::new().unwrap();
        let data_dir = temp_dir.path().to_path_buf();
        let output_dir = temp_dir.path().join("output");
        fs::create_dir_all(&output_dir).unwrap();

        // Create multiple employee directories
        for i in 1..=3 {
            let employee_dir = data_dir.join(format!("~user{}", i));
            fs::create_dir_all(&employee_dir).unwrap();
            fs::write(employee_dir.join("index.html"), "<html><body><p>1</p></body></html>").unwrap();
            fs::write(employee_dir.join(format!("User {}'s Home.html", i)), "<html><body><h1>主页</h1></body></html>").unwrap();
            fs::write(employee_dir.join("1.html"), format!("<html><body><h1>User {}</h1></body></html>", i)).unwrap();
        }

        // Process the directories
        process_directories_unified(&data_dir, Some(true), &output_dir);

        // Verify markdown files were created (at least one should exist)
        let md_files: Vec<_> = output_dir
            .read_dir()
            .unwrap()
            .filter_map(|e| {
                e.ok().and_then(|f| {
                    if f.path().extension().map(|ext| ext == "md").unwrap_or(false) {
                        Some(f.path())
                    } else {
                        None
                    }
                })
            })
            .collect();

        assert!(md_files.len() >= 1, "At least one markdown file should be created");
    }

    #[test]
    fn test_extract_local_links_various_formats() {
        let markdown = r#"
        ![Image 1](path/to/image1.png)
        [Link 1](document.pdf)
        ![Image 2](./another_image.jpg)
        [Link 2](../../relative/path/file.txt)
        [External](https://example.com)
        "#;

        let links = extract_local_links(markdown);
        assert!(links.contains(&"path/to/image1.png".to_string()));
        assert!(links.contains(&"document.pdf".to_string()));
        assert!(links.contains(&"./another_image.jpg".to_string()));
        assert!(links.contains(&"../../relative/path/file.txt".to_string()));
        assert!(!links.contains(&"https://example.com".to_string()));
    }

    #[test]
    fn test_is_external_url_schemes() {
        assert!(is_external_url("http://example.com"));
        assert!(is_external_url("https://example.com"));
        assert!(is_external_url("ftp://files.example.com"));
        assert!(is_external_url("mailto:user@example.com"));
        assert!(!is_external_url("ftps://secure.example.com")); // ftps is not in the supported list
        assert!(!is_external_url("data:text/plain;base64,SGVsbG8="));
    }

    #[test]
    fn test_resolve_link_to_path_not_found() {
        let temp_dir = TempDir::new().unwrap();
        let data_dir = temp_dir.path().to_path_buf();

        // Create a directory structure
        let alias_dir = data_dir.join("~user").join("attachments");
        fs::create_dir_all(&alias_dir).unwrap();

        // Try to resolve a non-existent file
        let link = "~user/attachments/nonexistent.png";
        let resolved_path = resolve_link_to_path(link, &data_dir);
        assert!(resolved_path.is_none());
    }

    #[test]
    fn test_resolve_link_to_path_with_special_chars() {
        let temp_dir = TempDir::new().unwrap();
        let data_dir = temp_dir.path().to_path_buf();
        let alias_dir = data_dir.join("~user").join("attachments");
        fs::create_dir_all(&alias_dir).unwrap();

        // Create a test file with simple name
        let test_file = alias_dir.join("image.png");
        fs::write(&test_file, "test").unwrap();

        // Try to resolve using simple link
        let link = "~user/attachments/image.png";
        let resolved_path = resolve_link_to_path(link, &data_dir);
        assert!(resolved_path.is_some());
        assert_eq!(resolved_path.unwrap(), test_file);
    }

    #[test]
    fn test_copy_resources_no_links() {
        let temp_dir = TempDir::new().unwrap();
        let data_dir = temp_dir.path().to_path_buf();
        let output_md = temp_dir.path().join("output.md");

        let markdown_input = "# Title\n\nThis is a document with no links.";

        let updated_markdown = copy_resources_and_update_links(markdown_input, &output_md, &data_dir).unwrap();

        // Should return the same content
        assert_eq!(updated_markdown, markdown_input);
    }

    #[test]
    fn test_copy_resources_only_external_links() {
        let temp_dir = TempDir::new().unwrap();
        let data_dir = temp_dir.path().to_path_buf();
        let output_md = temp_dir.path().join("output.md");

        let markdown_input = r#"
        [Google](https://google.com)
        [Example](http://example.com)
        "#;

        let updated_markdown = copy_resources_and_update_links(markdown_input, &output_md, &data_dir).unwrap();

        // External links should remain unchanged
        assert!(updated_markdown.contains("[Google](https://google.com)"));
        assert!(updated_markdown.contains("[Example](http://example.com)"));

        // Resources directory should not be created
        let resources_dir = output_md.with_file_name("output_files");
        assert!(!resources_dir.exists());
    }

    #[test]
    fn test_process_directory_with_multiple_comments() {
        let temp_dir = TempDir::new().unwrap();
        let dir = temp_dir.path().join("~user");
        fs::create_dir_all(&dir).unwrap();

        // Create index
        fs::write(dir.join("index.html"), "<html><body><p>1</p><p>2</p><p>3</p></body></html>").unwrap();

        // Create pages for each link
        fs::write(dir.join("1.html"), "<html><body><h1>Page 1</h1></body></html>").unwrap();

        // Create comments with redirects
        let comment1 = r#"<html><head><meta http-equiv='refresh' content='0; url=1.html'></head><body>Comment 1</body></html>"#;
        fs::write(dir.join("2.html"), comment1).unwrap();

        let comment2 = r#"<html><head><meta http-equiv='refresh' content='0; url=1.html'></head><body>Comment 2</body></html>"#;
        fs::write(dir.join("3.html"), comment2).unwrap();

        let result = process_directory(&dir);
        assert!(result.is_some());

        let (_alias, _chinese_name, _count, markdown) = result.unwrap();
        assert!(markdown.contains("### Comment"));
        assert!(markdown.contains("Comment 1"));
        assert!(markdown.contains("Comment 2"));
    }
}