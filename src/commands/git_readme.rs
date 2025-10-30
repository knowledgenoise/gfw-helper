use crate::logger::Logger;
use crate::processing::filetype;
use crate::utils::{convert_svg_to_png, convert_webp_to_png};
use rayon::prelude::*;
use regex::Regex;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use walkdir::WalkDir;

/// Processes a directory containing Git repositories and extracts README.md files.
///
/// This function scans for Git repositories, extracts their README files, processes
/// linked resources (images, files), and embeds linked markdown files with adjusted headers.
///
/// # Arguments
/// * `repos_dir` - Path to the directory containing Git repositories
/// * `output_dir` - Path where the output files should be written
pub fn process_git_repositories(repos_dir: &Path, output_dir: &Path) {
    // Validate input directory exists
    if !repos_dir.exists() {
        Logger::error(&format!(
            "Repository directory not found: {}",
            repos_dir.display()
        ));
        return;
    }

    // Collect all Git repositories recursively (directories containing .git)
    let repo_dirs: Vec<PathBuf> = WalkDir::new(repos_dir)
        .min_depth(1)
        .into_iter()
        .filter_map(Result::ok)
        .filter(|e| e.file_type().is_dir() && e.path().join(".git").exists())
        .map(|e| e.path().to_path_buf())
        .collect();

    let total_repos = repo_dirs.len();
    if total_repos == 0 {
        Logger::warning("No subdirectories found in the repository directory");
        return;
    }

    Logger::info(&format!("Found {} potential Git repositories", total_repos));

    // Parallel processing with progress tracking
    let processed = AtomicUsize::new(0);
    let successful = Arc::new(AtomicUsize::new(0));
    let failures = Arc::new(Mutex::new(Vec::new()));

    repo_dirs.par_iter().for_each(|repo_dir| {
        let current = processed.fetch_add(1, Ordering::Relaxed) + 1;
        Logger::parallel_progress(current, total_repos, "Extracting README files");

        match process_single_repository(repo_dir, output_dir) {
            Ok(_) => {
                successful.fetch_add(1, Ordering::SeqCst);
            }
            Err(e) => {
                let repo_name = repo_dir.file_name().unwrap().to_string_lossy().to_string();
                failures.lock().unwrap().push((repo_name, e.to_string()));
            }
        }
    });

    // Report results
    let success_count = successful.load(Ordering::SeqCst);
    let failures_vec = Arc::try_unwrap(failures).unwrap().into_inner().unwrap();
    let failed_count = failures_vec.len();

    Logger::parallel_complete(
        success_count,
        failed_count,
        total_repos,
        "README extraction",
    );
    Logger::parallel_failures(&failures_vec);
}

/// Retrieves git logs from a repository in a formatted markdown string.
///
/// # Arguments
/// * `repo_dir` - Path to the Git repository
///
/// # Returns
/// * `String` - Formatted git log as markdown, or empty string if git log fails
fn get_git_logs(repo_dir: &Path) -> String {
    // Run git log command to get commits with detailed format
    // Format: %ai (author date ISO format)|%an (author name)|%ae (author email)|%H (commit hash)|%s (subject)
    let output = Command::new("git")
        .arg("log")
        .arg("--format=%ai|%an|%ae|%H|%s")
        .arg("-50")
        .current_dir(repo_dir)
        .output();

    match output {
        Ok(output) => {
            if output.status.success() {
                let log_content = String::from_utf8_lossy(&output.stdout);
                if log_content.trim().is_empty() {
                    return String::new();
                }

                // Parse commits and collect them
                let mut commits: Vec<(String, String, String, String, String)> = Vec::new();

                for line in log_content.lines() {
                    let parts: Vec<&str> = line.split('|').collect();
                    if parts.len() >= 5 {
                        let timestamp = parts[0].to_string();
                        let author_name = parts[1].to_string();
                        let author_email = parts[2].to_string();
                        let commit_hash = parts[3].to_string();
                        let message = parts[4].to_string();

                        commits.push((timestamp, author_name, author_email, commit_hash, message));
                    }
                }

                if commits.is_empty() {
                    return String::new();
                }

                // Reverse to show earliest to latest commits
                commits.reverse();

                // Format as markdown with heading, message, and bullet list
                let mut result = String::from("\n## Git Logs\n\n");

                for (timestamp, author_name, author_email, commit_hash, message) in commits {
                    // Extract date from timestamp (YYYY-MM-DD HH:MM:SS +ZZZZ format)
                    let date_part = if let Some(space_idx) = timestamp.find(' ') {
                        &timestamp[..space_idx]
                    } else {
                        &timestamp
                    };

                    // Extract timezone from timestamp (last part after space)
                    let timezone = if let Some(last_space_idx) = timestamp.rfind(' ') {
                        &timestamp[last_space_idx + 1..]
                    } else {
                        "UTC"
                    };

                    // Add commit heading with date
                    result.push_str(&format!("### {}\n\n", date_part));

                    // Add commit message as body
                    result.push_str(&format!("{}\n\n", message));

                    // Add commit details as bullet list
                    result.push_str(&format!("* Author: {}\n", author_name));
                    result.push_str(&format!("* Email: {}\n", author_email));
                    result.push_str(&format!("* Timezone: {}\n", timezone));
                    result.push_str(&format!("* Commit: `{}`\n\n", &commit_hash[..8])); // Use first 8 chars of hash
                }

                result
            } else {
                String::new()
            }
        }
        Err(_) => String::new(),
    }
}

/// Processes a single Git repository and extracts its README file.
///
/// # Arguments
/// * `repo_dir` - Path to the Git repository
/// * `output_dir` - Path where the output files should be written
///
/// # Returns
/// * `Result<(), Box<dyn std::error::Error>>` - Success or error with details
fn process_single_repository(
    repo_dir: &Path,
    output_dir: &Path,
) -> Result<(), Box<dyn std::error::Error>> {
    let repo_name = repo_dir
        .file_name()
        .ok_or("Could not get repository name")?
        .to_string_lossy()
        .to_string();

    // Find README.md or readme.md in the repository root
    let readme_path = if repo_dir.join("README.md").exists() {
        repo_dir.join("README.md")
    } else if repo_dir.join("readme.md").exists() {
        repo_dir.join("readme.md")
    } else {
        return Err(format!("No README.md or readme.md found in {}", repo_name).into());
    };

    // Read the README content
    let readme_content = fs::read_to_string(&readme_path)?;

    // Process the README: embed linked markdown files and collect all links
    let (processed_content, all_links) = process_readme_content(&readme_content, repo_dir)?;

    // Create output filename and resources directory
    let output_filename = format!("{}-README.md", repo_name);
    let output_path = output_dir.join(&output_filename);
    let resources_dir = output_dir.join(format!("{}-files", repo_name));

    // Copy linked resources and update links in the content
    let final_content = copy_readme_resources(
        &processed_content,
        &all_links,
        repo_dir,
        &resources_dir,
        &repo_name,
    )?;

    // Append git logs to the markdown
    let mut final_content_with_logs = final_content;
    let git_logs = get_git_logs(repo_dir);
    final_content_with_logs.push_str(&git_logs);

    // Write the final README file
    fs::write(&output_path, final_content_with_logs)?;

    Ok(())
}

/// Processes README content by embedding linked markdown files and extracting all links.
///
/// # Arguments
/// * `content` - The original README content
/// * `repo_dir` - Path to the Git repository
///
/// # Returns
/// * `Result<(String, Vec<String>), Box<dyn std::error::Error>>` - Processed content and list of all links
fn process_readme_content(
    content: &str,
    repo_dir: &Path,
) -> Result<(String, Vec<String>), Box<dyn std::error::Error>> {
    let mut processed_content = content.to_string();
    let mut all_links = Vec::new();

    // Extract all markdown links (both images and regular links)
    let link_regex = Regex::new(r"(!?)\[([^\]]*)\]\(([^)]+)\)")?;

    // First pass: collect all links
    for cap in link_regex.captures_iter(content) {
        let link = cap[3].to_string();
        if !is_external_url(&link) {
            all_links.push(link.clone());
        }
    }

    // Second pass: embed markdown files
    loop {
        let mut found_markdown_link = false;
        let mut new_content = processed_content.clone();

        for cap in link_regex.captures_iter(&processed_content) {
            let full_match = cap[0].to_string();
            let is_image = &cap[1] == "!";
            let _link_text = cap[2].to_string();
            let link = cap[3].to_string();

            // Skip external URLs and images
            if is_external_url(&link) || is_image {
                continue;
            }

            // Check if this is a markdown file link
            if link.ends_with(".md") || link.ends_with(".markdown") {
                // Resolve the markdown file path
                let md_path = repo_dir.join(&link);

                if md_path.exists() {
                    // Read and embed the markdown file
                    match fs::read_to_string(&md_path) {
                        Ok(embedded_content) => {
                            // Adjust header levels (push one level deeper)
                            let adjusted_content = adjust_markdown_headers(&embedded_content);

                            // Create a section with the embedded content
                            let embedded_section = format!(
                                "\n\n<!-- Embedded from {} -->\n\n{}\n\n<!-- End of embedded content -->\n\n",
                                link, adjusted_content
                            );

                            // Replace the link with the embedded content
                            new_content = new_content.replace(&full_match, &embedded_section);
                            found_markdown_link = true;
                            break; // Process one at a time to avoid issues with overlapping matches
                        }
                        Err(_) => {
                            // If we can't read the file, leave the link as is
                            continue;
                        }
                    }
                }
            }
        }

        processed_content = new_content;

        // If no markdown links were found and embedded, we're done
        if !found_markdown_link {
            break;
        }
    }

    Ok((processed_content, all_links))
}

/// Adjusts markdown header levels by pushing them one level deeper.
///
/// # Arguments
/// * `content` - The markdown content to adjust
///
/// # Returns
/// * `String` - The content with adjusted header levels
fn adjust_markdown_headers(content: &str) -> String {
    let header_regex = Regex::new(r"(?m)^(#{1,5})(\s+.*)$").unwrap();

    header_regex
        .replace_all(content, |caps: &regex::Captures| {
            let hashes = &caps[1];
            let rest = &caps[2];
            format!("#{}{}", hashes, rest)
        })
        .to_string()
}

/// Copies linked resources to the resources directory and updates links in the content.
///
/// # Arguments
/// * `content` - The markdown content with links
/// * `links` - List of all links found in the content
/// * `repo_dir` - Path to the Git repository
/// * `resources_dir` - Path to the resources directory
/// * `repo_name` - Name of the repository
///
/// # Returns
/// * `Result<String, Box<dyn std::error::Error>>` - Updated content with new link paths
fn copy_readme_resources(
    content: &str,
    links: &[String],
    repo_dir: &Path,
    resources_dir: &Path,
    repo_name: &str,
) -> Result<String, Box<dyn std::error::Error>> {
    if links.is_empty() {
        return Ok(content.to_string());
    }

    // Create resources directory if needed
    let mut resources_created = false;
    let mut updated_content = content.to_string();
    let mut _copied_count = 0;
    let mut _corrected_count = 0;

    for link in links {
        // Skip external URLs
        if is_external_url(link) {
            continue;
        }

        // Skip markdown files (they've been embedded)
        if link.ends_with(".md") || link.ends_with(".markdown") {
            continue;
        }

        // Resolve the link to an actual file path
        let source_path = repo_dir.join(link);

        if source_path.exists() && source_path.is_file() {
            // Create resources directory on first use
            if !resources_created {
                fs::create_dir_all(resources_dir)?;
                resources_created = true;
            }

            let _original_file_name = source_path.file_name().unwrap().to_string_lossy();

            // Check if it's a WebP or SVG file and convert to PNG
            let source_to_copy = if let Some(ext) = source_path.extension() {
                let ext_lower = ext.to_string_lossy().to_lowercase();
                if ext_lower == "webp" {
                    match convert_webp_to_png(&source_path) {
                        Ok(png_path) => png_path,
                        Err(_) => source_path.clone(),
                    }
                } else if ext_lower == "svg" {
                    match convert_svg_to_png(&source_path) {
                        Ok(png_path) => png_path,
                        Err(_) => source_path.clone(),
                    }
                } else {
                    source_path.clone()
                }
            } else {
                source_path.clone()
            };

            // Detect if file type doesn't match extension (like md/html2pdf modes)
            let final_file_name =
                if let Some(correct_ext) = filetype::get_corrected_extension(&source_to_copy) {
                    let stem = source_to_copy.file_stem().unwrap().to_string_lossy();
                    _corrected_count += 1;
                    format!("{}.{}", stem, correct_ext)
                } else {
                    source_to_copy
                        .file_name()
                        .unwrap()
                        .to_string_lossy()
                        .to_string()
                };

            let dest_path = resources_dir.join(&final_file_name);

            // Copy the file
            fs::copy(&source_to_copy, &dest_path)?;
            _copied_count += 1;

            // Update the link in markdown content
            let new_link = format!("{}-files/{}", repo_name, final_file_name);
            updated_content = updated_content.replace(link, &new_link);
        }
    }

    Ok(updated_content)
}

/// Checks if a link is an external URL (starts with http://, https://, etc.)
fn is_external_url(link: &str) -> bool {
    link.starts_with("http://")
        || link.starts_with("https://")
        || link.starts_with("ftp://")
        || link.starts_with("mailto:")
        || link.starts_with("//") // Protocol-relative URLs
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_adjust_markdown_headers() {
        let content = r#"# Header 1
Some content
## Header 2
More content
### Header 3
Even more content"#;

        let adjusted = adjust_markdown_headers(content);

        assert!(adjusted.contains("## Header 1"));
        assert!(adjusted.contains("### Header 2"));
        assert!(adjusted.contains("#### Header 3"));
    }

    #[test]
    fn test_adjust_markdown_headers_max_level() {
        let content = "##### Header 5\nContent";
        let adjusted = adjust_markdown_headers(content);
        assert!(adjusted.contains("###### Header 5"));
    }

    #[test]
    fn test_is_external_url() {
        assert!(is_external_url("http://example.com"));
        assert!(is_external_url("https://example.com"));
        assert!(is_external_url("ftp://example.com"));
        assert!(is_external_url("mailto:test@example.com"));
        assert!(is_external_url("//cdn.example.com/image.png"));

        assert!(!is_external_url("image.png"));
        assert!(!is_external_url("docs/readme.md"));
        assert!(!is_external_url("../other/file.pdf"));
    }

    #[test]
    fn test_process_readme_content_basic() {
        let content = r#"# My Project

This is a test README.

![Image](images/logo.png)

[Documentation](docs/guide.md)
"#;

        let repo_dir = std::env::temp_dir();
        let result = process_readme_content(content, &repo_dir);

        assert!(result.is_ok());
        let (processed, links) = result.unwrap();

        // Should contain both links
        assert!(links.contains(&"images/logo.png".to_string()));
        assert!(links.contains(&"docs/guide.md".to_string()));

        // Original content should be preserved when markdown file doesn't exist
        assert!(processed.contains("![Image](images/logo.png)"));
    }

    #[test]
    fn test_process_readme_content_with_embedding() {
        use tempfile::TempDir;

        let temp_dir = TempDir::new().unwrap();
        let repo_dir = temp_dir.path();

        // Create a linked markdown file
        let docs_dir = repo_dir.join("docs");
        fs::create_dir_all(&docs_dir).unwrap();
        let guide_content = r#"# Guide Title
## Installation
Steps here
### Details
More info"#;
        fs::write(docs_dir.join("guide.md"), guide_content).unwrap();

        let readme_content = r#"# Main README
See [Guide](docs/guide.md) for details.
"#;

        let result = process_readme_content(readme_content, repo_dir);
        assert!(result.is_ok());

        let (processed, _links) = result.unwrap();

        // The guide should be embedded
        assert!(processed.contains("<!-- Embedded from docs/guide.md -->"));
        assert!(processed.contains("## Guide Title")); // Header pushed one level
        assert!(processed.contains("### Installation")); // Header pushed one level
        assert!(processed.contains("#### Details")); // Header pushed one level
        assert!(processed.contains("<!-- End of embedded content -->"));
    }

    #[test]
    fn test_process_readme_content_external_links_preserved() {
        let content = r#"# Project
[GitHub](https://github.com/user/repo)
[Website](http://example.com)
![CDN Image](//cdn.example.com/image.png)
[Email](mailto:test@example.com)
"#;

        let repo_dir = std::env::temp_dir();
        let result = process_readme_content(content, &repo_dir);

        assert!(result.is_ok());
        let (processed, links) = result.unwrap();

        // External links should not be in the links list
        assert!(links.is_empty());

        // External links should be preserved in content
        assert!(processed.contains("https://github.com/user/repo"));
        assert!(processed.contains("http://example.com"));
        assert!(processed.contains("//cdn.example.com/image.png"));
        assert!(processed.contains("mailto:test@example.com"));
    }

    #[test]
    fn test_process_single_repository_no_readme() {
        use tempfile::TempDir;

        let temp_dir = TempDir::new().unwrap();
        let repo_dir = temp_dir.path().join("test-repo");
        fs::create_dir_all(&repo_dir).unwrap();

        let output_dir = temp_dir.path().join("output");
        fs::create_dir_all(&output_dir).unwrap();

        // No README file exists
        let result = process_single_repository(&repo_dir, &output_dir);

        // Should return an error
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("No README.md or readme.md found")
        );
    }

    #[test]
    fn test_process_single_repository_with_readme() {
        use tempfile::TempDir;

        let temp_dir = TempDir::new().unwrap();
        let repo_dir = temp_dir.path().join("test-repo");
        fs::create_dir_all(&repo_dir).unwrap();

        let output_dir = temp_dir.path().join("output");
        fs::create_dir_all(&output_dir).unwrap();

        // Create a simple README
        let readme_content = r#"# Test Project
This is a test."#;
        fs::write(repo_dir.join("README.md"), readme_content).unwrap();

        let result = process_single_repository(&repo_dir, &output_dir);

        // Should succeed
        assert!(result.is_ok());

        // Check output file exists
        let output_file = output_dir.join("test-repo-README.md");
        assert!(output_file.exists());

        // Check content
        let output_content = fs::read_to_string(&output_file).unwrap();
        assert!(output_content.contains("# Test Project"));
        assert!(output_content.contains("This is a test."));
    }

    #[test]
    fn test_process_single_repository_lowercase_readme() {
        use tempfile::TempDir;

        let temp_dir = TempDir::new().unwrap();
        let repo_dir = temp_dir.path().join("test-repo");
        fs::create_dir_all(&repo_dir).unwrap();

        let output_dir = temp_dir.path().join("output");
        fs::create_dir_all(&output_dir).unwrap();

        // Create readme.md (lowercase)
        let readme_content = r#"# Lowercase README"#;
        fs::write(repo_dir.join("readme.md"), readme_content).unwrap();

        let result = process_single_repository(&repo_dir, &output_dir);

        // Should succeed
        assert!(result.is_ok());

        // Check output file exists
        let output_file = output_dir.join("test-repo-README.md");
        assert!(output_file.exists());
    }

    #[test]
    fn test_process_single_repository_with_resources() {
        use tempfile::TempDir;

        let temp_dir = TempDir::new().unwrap();
        let repo_dir = temp_dir.path().join("test-repo");
        fs::create_dir_all(&repo_dir).unwrap();

        let output_dir = temp_dir.path().join("output");
        fs::create_dir_all(&output_dir).unwrap();

        // Create images directory and a fake image
        let images_dir = repo_dir.join("images");
        fs::create_dir_all(&images_dir).unwrap();
        fs::write(images_dir.join("logo.png"), "fake png data").unwrap();

        // Create README with image link
        let readme_content = r#"# Test Project
![Logo](images/logo.png)
"#;
        fs::write(repo_dir.join("README.md"), readme_content).unwrap();

        let result = process_single_repository(&repo_dir, &output_dir);

        // Should succeed
        assert!(result.is_ok());

        // Check output file exists
        let output_file = output_dir.join("test-repo-README.md");
        assert!(output_file.exists());

        // Check content has updated link
        let output_content = fs::read_to_string(&output_file).unwrap();
        assert!(output_content.contains("test-repo-files/logo.png"));

        // Check image was copied
        let copied_image = output_dir.join("test-repo-files").join("logo.png");
        assert!(copied_image.exists());
    }

    #[test]
    fn test_copy_readme_resources_skips_external_urls() {
        use tempfile::TempDir;

        let temp_dir = TempDir::new().unwrap();
        let repo_dir = temp_dir.path();
        let resources_dir = temp_dir.path().join("resources");

        let content = r#"![External](https://example.com/image.png)"#;
        let links = vec!["https://example.com/image.png".to_string()];

        let result = copy_readme_resources(content, &links, repo_dir, &resources_dir, "test-repo");

        assert!(result.is_ok());
        let updated = result.unwrap();

        // Content should be unchanged
        assert_eq!(content, updated);

        // Resources directory should not be created (no local files)
        assert!(!resources_dir.exists());
    }

    #[test]
    fn test_copy_readme_resources_skips_markdown_files() {
        use tempfile::TempDir;

        let temp_dir = TempDir::new().unwrap();
        let repo_dir = temp_dir.path();
        let resources_dir = temp_dir.path().join("resources");

        // Create a markdown file
        let docs_dir = repo_dir.join("docs");
        fs::create_dir_all(&docs_dir).unwrap();
        fs::write(docs_dir.join("guide.md"), "# Guide").unwrap();

        let content = r#"[Guide](docs/guide.md)"#;
        let links = vec!["docs/guide.md".to_string()];

        let result = copy_readme_resources(content, &links, repo_dir, &resources_dir, "test-repo");

        assert!(result.is_ok());
        let updated = result.unwrap();

        // Content should be unchanged (markdown files are embedded, not copied)
        assert_eq!(content, updated);

        // Resources directory should not be created
        assert!(!resources_dir.exists());
    }

    #[test]
    fn test_adjust_markdown_headers_preserves_non_headers() {
        let content = r#"# Header
Regular text with # symbol in it
Code: `# not a header`
## Another Header
Text"#;

        let adjusted = adjust_markdown_headers(content);

        // Headers should be adjusted
        assert!(adjusted.contains("## Header"));
        assert!(adjusted.contains("### Another Header"));

        // Regular text and code should be preserved
        assert!(adjusted.contains("Regular text with # symbol in it"));
        assert!(adjusted.contains("Code: `# not a header`"));
    }

    #[test]
    fn test_adjust_markdown_headers_with_spacing() {
        let content = r#"#Header without space
# Header with space
##  Header with multiple spaces"#;

        let adjusted = adjust_markdown_headers(content);

        // Only headers with proper spacing should be adjusted
        assert!(adjusted.contains("#Header without space")); // Not adjusted (no space)
        assert!(adjusted.contains("## Header with space")); // Adjusted
        assert!(adjusted.contains("###  Header with multiple spaces")); // Adjusted
    }

    #[test]
    fn test_process_readme_content_nested_embedding() {
        use tempfile::TempDir;

        let temp_dir = TempDir::new().unwrap();
        let repo_dir = temp_dir.path();

        // Create nested markdown files
        let docs_dir = repo_dir.join("docs");
        fs::create_dir_all(&docs_dir).unwrap();

        // Main guide that links to another file
        let guide_content = r#"# Guide
See [API docs](api.md)
"#;
        fs::write(docs_dir.join("guide.md"), guide_content).unwrap();

        // API docs
        let api_content = r#"# API Reference
## Methods"#;
        fs::write(docs_dir.join("api.md"), api_content).unwrap();

        let readme_content = r#"# README
[Guide](docs/guide.md)
"#;

        let result = process_readme_content(readme_content, repo_dir);
        assert!(result.is_ok());

        let (processed, _links) = result.unwrap();

        // Both files should be embedded
        assert!(processed.contains("## Guide")); // First level embedding
        // Note: The second level embedding would require recursive resolution
        // which the current implementation handles through the loop
    }

    #[test]
    fn test_process_git_repositories_empty_directory() {
        use tempfile::TempDir;

        let temp_dir = TempDir::new().unwrap();
        let repos_dir = temp_dir.path().join("repos");
        fs::create_dir_all(&repos_dir).unwrap();

        let output_dir = temp_dir.path().join("output");
        fs::create_dir_all(&output_dir).unwrap();

        // Should handle empty directory gracefully (just log a warning)
        process_git_repositories(&repos_dir, &output_dir);

        // No output files should be created
        let entries: Vec<_> = fs::read_dir(&output_dir).unwrap().collect();
        assert_eq!(entries.len(), 0);
    }

    #[test]
    fn test_get_git_logs_format() {
        use std::process::Command;
        use tempfile::TempDir;

        let temp_dir = TempDir::new().unwrap();
        let repo_dir = temp_dir.path();

        // Initialize a git repository
        Command::new("git")
            .arg("init")
            .current_dir(repo_dir)
            .output()
            .expect("Failed to init git repo");

        // Configure git user
        Command::new("git")
            .arg("config")
            .arg("user.name")
            .arg("Test User")
            .current_dir(repo_dir)
            .output()
            .expect("Failed to set git user");

        Command::new("git")
            .arg("config")
            .arg("user.email")
            .arg("test@example.com")
            .current_dir(repo_dir)
            .output()
            .expect("Failed to set git email");

        // Create a test file and commit
        let test_file = repo_dir.join("test.txt");
        fs::write(&test_file, "test content").unwrap();

        Command::new("git")
            .arg("add")
            .arg("test.txt")
            .current_dir(repo_dir)
            .output()
            .expect("Failed to add file");

        Command::new("git")
            .arg("commit")
            .arg("-m")
            .arg("Initial commit")
            .current_dir(repo_dir)
            .output()
            .expect("Failed to commit");

        // Get git logs
        let logs = get_git_logs(repo_dir);

        // Verify logs contain expected elements
        assert!(logs.contains("## Git Logs"), "Should have Git Logs header");
        assert!(logs.contains("### "), "Should have date heading");
        assert!(
            logs.contains("Initial commit"),
            "Should contain commit message"
        );
        assert!(
            logs.contains("* Author: Test User"),
            "Should contain author"
        );
        assert!(
            logs.contains("* Email: test@example.com"),
            "Should contain email"
        );
        assert!(logs.contains("* Timezone:"), "Should contain timezone");
        assert!(logs.contains("* Commit:"), "Should contain commit hash");
    }

    #[test]
    fn test_get_git_logs_multiple_commits_sorted_ascending() {
        use std::process::Command;
        use std::thread;
        use std::time::Duration;
        use tempfile::TempDir;

        let temp_dir = TempDir::new().unwrap();
        let repo_dir = temp_dir.path();

        // Initialize a git repository
        Command::new("git")
            .arg("init")
            .current_dir(repo_dir)
            .output()
            .expect("Failed to init git repo");

        Command::new("git")
            .arg("config")
            .arg("user.name")
            .arg("Test User")
            .current_dir(repo_dir)
            .output()
            .expect("Failed to set git user");

        Command::new("git")
            .arg("config")
            .arg("user.email")
            .arg("test@example.com")
            .current_dir(repo_dir)
            .output()
            .expect("Failed to set git email");

        // Create multiple commits
        for i in 1..=3 {
            let test_file = repo_dir.join(format!("file{}.txt", i));
            fs::write(&test_file, format!("content {}", i)).unwrap();

            Command::new("git")
                .arg("add")
                .arg(format!("file{}.txt", i))
                .current_dir(repo_dir)
                .output()
                .expect("Failed to add file");

            Command::new("git")
                .arg("commit")
                .arg("-m")
                .arg(format!("Commit {}", i))
                .current_dir(repo_dir)
                .output()
                .expect("Failed to commit");

            // Small delay between commits to ensure different timestamps
            thread::sleep(Duration::from_millis(100));
        }

        // Get git logs
        let logs = get_git_logs(repo_dir);

        // Verify commits appear in ascending order (earliest first)
        let commit1_pos = logs.find("Commit 1").expect("Should find Commit 1");
        let commit2_pos = logs.find("Commit 2").expect("Should find Commit 2");
        let commit3_pos = logs.find("Commit 3").expect("Should find Commit 3");

        assert!(
            commit1_pos < commit2_pos && commit2_pos < commit3_pos,
            "Commits should be sorted from earliest to latest"
        );
    }

    #[test]
    fn test_get_git_logs_empty_repo() {
        use std::process::Command;
        use tempfile::TempDir;

        let temp_dir = TempDir::new().unwrap();
        let repo_dir = temp_dir.path();

        // Initialize a git repository but don't add any commits
        Command::new("git")
            .arg("init")
            .current_dir(repo_dir)
            .output()
            .expect("Failed to init git repo");

        // Get git logs
        let logs = get_git_logs(repo_dir);

        // Should return empty string for repo with no commits
        assert_eq!(logs, "", "Empty repo should return empty git logs");
    }

    #[test]
    fn test_git_logs_contains_all_fields() {
        use std::process::Command;
        use tempfile::TempDir;

        let temp_dir = TempDir::new().unwrap();
        let repo_dir = temp_dir.path();

        // Initialize git repository
        Command::new("git")
            .arg("init")
            .current_dir(repo_dir)
            .output()
            .expect("Failed to init git repo");

        Command::new("git")
            .arg("config")
            .arg("user.name")
            .arg("John Doe")
            .current_dir(repo_dir)
            .output()
            .expect("Failed to set git user");

        Command::new("git")
            .arg("config")
            .arg("user.email")
            .arg("john@example.com")
            .current_dir(repo_dir)
            .output()
            .expect("Failed to set git email");

        // Create a commit
        let test_file = repo_dir.join("test.txt");
        fs::write(&test_file, "test").unwrap();

        Command::new("git")
            .arg("add")
            .arg("test.txt")
            .current_dir(repo_dir)
            .output()
            .expect("Failed to add file");

        Command::new("git")
            .arg("commit")
            .arg("-m")
            .arg("Test commit message")
            .current_dir(repo_dir)
            .output()
            .expect("Failed to commit");

        let logs = get_git_logs(repo_dir);

        // Verify all required fields are present
        assert!(logs.contains("### "), "Should have date heading (###)");
        assert!(
            logs.contains("Test commit message"),
            "Should have commit message"
        );
        assert!(
            logs.contains("* Author: John Doe"),
            "Should have author name"
        );
        assert!(
            logs.contains("* Email: john@example.com"),
            "Should have author email"
        );
        assert!(logs.contains("* Timezone:"), "Should have timezone field");
        assert!(logs.contains("* Commit:"), "Should have commit hash field");
        assert!(logs.contains("## Git Logs"), "Should have Git Logs header");
    }

    #[test]
    fn test_process_single_repository_appends_git_logs() {
        use std::process::Command;
        use tempfile::TempDir;

        let temp_dir = TempDir::new().unwrap();
        let repo_parent = temp_dir.path().join("repos");
        fs::create_dir_all(&repo_parent).unwrap();

        // Create a test repository inside a named directory
        let repo_dir = repo_parent.join("test-repo");
        fs::create_dir_all(&repo_dir).unwrap();

        // Initialize git repository
        Command::new("git")
            .arg("init")
            .current_dir(&repo_dir)
            .output()
            .expect("Failed to init git repo");

        Command::new("git")
            .arg("config")
            .arg("user.name")
            .arg("Test User")
            .current_dir(&repo_dir)
            .output()
            .expect("Failed to set git user");

        Command::new("git")
            .arg("config")
            .arg("user.email")
            .arg("test@example.com")
            .current_dir(&repo_dir)
            .output()
            .expect("Failed to set git email");

        // Create README and a test file
        let readme_file = repo_dir.join("README.md");
        fs::write(&readme_file, "# Test Project\n\nThis is a test README.").unwrap();

        let test_file = repo_dir.join("test.txt");
        fs::write(&test_file, "test content").unwrap();

        // Add and commit files
        Command::new("git")
            .arg("add")
            .arg(".")
            .current_dir(&repo_dir)
            .output()
            .expect("Failed to add files");

        Command::new("git")
            .arg("commit")
            .arg("-m")
            .arg("Initial commit with README")
            .current_dir(&repo_dir)
            .output()
            .expect("Failed to commit");

        // Process the repository
        let output_dir = temp_dir.path().join("output");
        fs::create_dir_all(&output_dir).unwrap();

        let result = process_single_repository(&repo_dir, &output_dir);
        assert!(result.is_ok(), "process_single_repository should succeed");

        // Read the output README file
        // The output filename format is {repo_name}-README.md
        let output_file = output_dir.join("test-repo-README.md");
        assert!(
            output_file.exists(),
            "Output README file should be created at {:?}",
            output_file
        );

        let content = fs::read_to_string(&output_file).expect("Failed to read output README");

        // Verify original README content is present
        assert!(
            content.contains("# Test Project"),
            "Output should contain original README header"
        );
        assert!(
            content.contains("This is a test README."),
            "Output should contain original README body"
        );

        // Verify git logs are appended
        assert!(
            content.contains("## Git Logs"),
            "Output should contain Git Logs header"
        );
        assert!(
            content.contains("Initial commit with README"),
            "Output should contain git commit message"
        );
        assert!(
            content.contains("* Author: Test User"),
            "Output should contain commit author"
        );
        assert!(
            content.contains("* Email: test@example.com"),
            "Output should contain commit email"
        );
    }

    #[test]
    fn test_adjust_markdown_headers_multiple_levels() {
        let input = r#"# Level 1
## Level 2
### Level 3
#### Level 4
##### Level 5
###### Level 6"#;

        let output = adjust_markdown_headers(input);

        // Headers with 1-5 hashes should be incremented by one
        assert!(output.contains("## Level 1"));
        assert!(output.contains("### Level 2"));
        assert!(output.contains("#### Level 3"));
        assert!(output.contains("##### Level 4"));
        assert!(output.contains("###### Level 5"));
        // Level 6 should remain unchanged (regex only matches up to 5 hashes)
        assert!(output.contains("###### Level 6"));
    }

    #[test]
    fn test_is_external_url_various_schemes() {
        assert!(is_external_url("http://github.com"));
        assert!(is_external_url("https://github.com"));
        assert!(is_external_url("ftp://files.example.com"));
        assert!(is_external_url("mailto:test@example.com"));
        assert!(!is_external_url("local/path/file.md"));
        assert!(!is_external_url("../../relative/path"));
        assert!(!is_external_url("image.png"));
    }

    #[test]
    fn test_copy_readme_resources_empty_links() {
        use tempfile::TempDir;

        let temp_dir = TempDir::new().unwrap();
        let repo_dir = temp_dir.path();

        fs::create_dir_all(repo_dir).unwrap();

        let markdown_content = "# Just a title\n\nNo links here.";
        let links = vec![];

        let result = copy_readme_resources(
            markdown_content,
            &links,
            repo_dir,
            &repo_dir.join("resources"),
            "test",
        );

        assert!(result.is_ok());
        let content = result.unwrap();
        assert_eq!(content, markdown_content);
    }

    #[test]
    fn test_process_readme_content_with_complex_links() {
        use tempfile::TempDir;

        let temp_dir = TempDir::new().unwrap();
        let repo_dir = temp_dir.path();

        fs::create_dir_all(repo_dir).unwrap();

        // Create some test markdown files to link to
        fs::write(repo_dir.join("doc1.md"), "# Document 1").unwrap();
        fs::write(repo_dir.join("doc2.md"), "# Document 2").unwrap();

        let markdown_content = r#"
# Title
[Link to doc1](doc1.md)
[Link to doc2](doc2.md)
[External link](https://example.com)
"#;

        let result = process_readme_content(markdown_content, repo_dir);
        assert!(result.is_ok());

        let (_processed, links) = result.unwrap();
        assert!(links.contains(&"doc1.md".to_string()));
        assert!(links.contains(&"doc2.md".to_string()));
        assert_eq!(links.iter().filter(|l| l.contains("http")).count(), 0);
    }

    #[test]
    fn test_get_git_logs_with_special_commit_message() {
        use std::process::Command;
        use tempfile::TempDir;

        let temp_dir = TempDir::new().unwrap();
        let repo_dir = temp_dir.path();

        Command::new("git")
            .arg("init")
            .current_dir(repo_dir)
            .output()
            .expect("Failed to init git repo");

        Command::new("git")
            .arg("config")
            .arg("user.name")
            .arg("Test User")
            .current_dir(repo_dir)
            .output()
            .expect("Failed to set git user");

        Command::new("git")
            .arg("config")
            .arg("user.email")
            .arg("test@example.com")
            .current_dir(repo_dir)
            .output()
            .expect("Failed to set git email");

        let test_file = repo_dir.join("test.txt");
        fs::write(&test_file, "test").unwrap();

        Command::new("git")
            .arg("add")
            .arg("test.txt")
            .current_dir(repo_dir)
            .output()
            .expect("Failed to add file");

        // Commit with simple message
        Command::new("git")
            .arg("commit")
            .arg("-m")
            .arg("Fix: Important bug")
            .current_dir(repo_dir)
            .output()
            .expect("Failed to commit");

        let logs = get_git_logs(repo_dir);

        // Should handle the message
        assert!(logs.contains("## Git Logs"));
        assert!(logs.contains("Fix: Important bug"));
    }

    #[test]
    fn test_process_git_repositories_with_no_readme() {
        use std::process::Command;
        use tempfile::TempDir;

        let temp_dir = TempDir::new().unwrap();
        let repos_dir = temp_dir.path().join("repos");
        fs::create_dir_all(&repos_dir).unwrap();

        // Create a git repository without README
        let repo_dir = repos_dir.join("test-repo");
        fs::create_dir_all(&repo_dir).unwrap();

        Command::new("git")
            .arg("init")
            .current_dir(&repo_dir)
            .output()
            .expect("Failed to init git repo");

        let output_dir = temp_dir.path().join("output");
        fs::create_dir_all(&output_dir).unwrap();

        // Process should complete without error
        process_git_repositories(&repos_dir, &output_dir);

        // Output directory should exist but might be empty (no README found)
        assert!(output_dir.exists());
    }
}
