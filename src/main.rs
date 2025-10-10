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
use clap::{Parser, Subcommand};
use uuid::Uuid;
use regex::Regex;
use std::process::Command;
use image::{GenericImageView, ImageFormat};
use image::imageops::FilterType;
use image::ImageReader;
use std::collections::HashMap;
use std::io::Read;


/// Resizes an image if it exceeds the specified maximum dimensions.
/// 
/// This function prevents LaTeX "Dimension too large" errors by automatically resizing
/// oversized images while maintaining their aspect ratio. Images are resized down to
/// fit within the max_width x max_height bounds.
/// 
/// The resizing process:
/// 1. Opens and decodes the image to check current dimensions
/// 2. Returns early if the image is already within bounds
/// 3. Calculates new dimensions maintaining aspect ratio
/// 4. Resizes using Lanczos3 filter for high quality
/// 5. Saves the result as PNG format
/// 
/// # Arguments
/// * `image_path` - Path to the image file to potentially resize
/// * `max_width` - Maximum allowed width in pixels
/// * `max_height` - Maximum allowed height in pixels
/// 
/// # Returns
/// * `Result<(), Box<dyn std::error::Error>>` - Success or error details
/// 
/// # Notes
/// - Always saves as PNG format regardless of input format
/// - Uses high-quality Lanczos3 resampling filter
/// - Maintains aspect ratio during resizing
/// - Only resizes down, never enlarges images
fn resize_image_if_needed(image_path: &Path, max_width: u32, max_height: u32) -> Result<(), Box<dyn std::error::Error>> {
    // Open and decode the image to get its current dimensions
    let img = ImageReader::open(image_path)?.decode()?;
    
    let (width, height) = img.dimensions();
    
    // Early return if image is already within acceptable dimensions
    if width <= max_width && height <= max_height {
        return Ok(()); // No resizing needed
    }
    
    // Calculate new dimensions while maintaining aspect ratio
    let aspect_ratio = width as f32 / height as f32;
    let (new_width, new_height) = if width > height {
        // Landscape orientation: limit by width
        let new_width = max_width.min(width);
        let new_height = (new_width as f32 / aspect_ratio) as u32;
        (new_width, new_height)
    } else {
        // Portrait or square orientation: limit by height
        let new_height = max_height.min(height);
        let new_width = (new_height as f32 * aspect_ratio) as u32;
        (new_width, new_height)
    };
    
    // Resize the image using high-quality Lanczos3 filter
    let resized_img = img.resize(new_width, new_height, FilterType::Lanczos3);
    
    // Save the resized image back to the same path as PNG format
    resized_img.save_with_format(image_path, ImageFormat::Png)?;
    
    println!("ℹ  Resized image {} from {}x{} to {}x{}", 
             image_path.display(), width, height, new_width, new_height);
    
    Ok(())
}


#[derive(Parser, Debug)]
#[command(
    name = "gfw-helper",
    version,
    about = "A comprehensive tool for processing employee/project documentation and converting markdown to PDF.",
    long_about = r#"GFW Helper is a versatile tool designed to process documentation from employee and project directories,
automatically convert markdown files to high-quality PDFs with proper Chinese character support, and split large files.

FEATURES:
• Process employee directories (starting with ~) and generate consolidated markdown files
• Process project directories and create organized documentation
• Convert markdown to PDF with automatic image resizing and Chinese font support
• Split large markdown files into manageable chunks
• Handle complex documents with images, tables, and code blocks
• Automatic retry logic for LaTeX compilation failures
• Support for multiple PDF engines (xelatex, pdflatex, lualatex)

PDF CONVERSION FEATURES:
• Automatic image resizing to prevent LaTeX 'Dimension too large' errors (max 4000x4000)
• Chinese character support using ctexart document class with lualatex
• Syntax highlighting with pygments
• Color links and proper margins
• Graceful handling of corrupted/invalid images
• Temporary directory management for clean processing"#,
    after_help = r#"EXAMPLES:

EMPLOYEE PROCESSING:
    gfw-helper employee                                    # Process default 'data' directory
    gfw-helper employee -p /path/to/employee/data          # Process specific directory
    gfw-helper employee --path /docs/employees             # Linux path example

PROJECT PROCESSING:
    gfw-helper project                                     # Process default 'data' directory
    gfw-helper project -p /path/to/project/data            # Process specific directory
    gfw-helper project --path /docs/projects               # Linux path example

PDF CONVERSION:
    gfw-helper pdf -p document.md                           # Convert single file
    gfw-helper pdf -d ./docs                                # Convert all .md files in directory
    gfw-helper pdf -d data/employee --engine xelatex        # Use xelatex engine
    gfw-helper pdf -d data/project --engine lualatex        # Use lualatex (default, best for Chinese)

FILE SPLITTING:
    gfw-helper split -p large_file.md -l 10000              # Split by 10,000 lines
    gfw-helper split -d ./docs -s 5.0                       # Split files >5MB in directory
    gfw-helper split -d data -l 50000 -s 2.5                # Custom settings

WORKFLOW EXAMPLES:
    # Process employee data and convert to PDF
    gfw-helper employee -p data/employee
    gfw-helper pdf -d data/employee

    # Process project data, split large files, then convert
    gfw-helper project -p data/project
    gfw-helper split -d data/project -s 3.0
    gfw-helper pdf -d data/project

    # Full documentation pipeline
    gfw-helper employee && gfw-helper project && gfw-helper pdf -d data

NOTES:
• Employee directories must start with '~' (e.g., ~john-doe)
• Project directories are processed recursively
• PDF conversion automatically resizes images >4000px to prevent LaTeX errors
• Chinese characters are preserved using ctexart document class
• Invalid/corrupted images are skipped with warnings
• Temporary files are automatically cleaned up after processing"#
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Process employee directories and generate consolidated markdown documentation.
    ///
    /// This command scans for directories starting with '~' (e.g., ~john-doe, ~jane-smith-42)
    /// and processes each employee's documentation. It extracts information from HTML files,
    /// comments, and attachments, then generates a single markdown file for each employee
    /// named <alias>-<chinese_name>-<file_count>.md in the parent directory.
    ///
    /// The tool automatically detects:
    /// - Employee homepage (index.html)
    /// - Individual HTML pages with content and comments
    /// - Attachment files (images, documents)
    /// - Chinese names and aliases from directory names
    ///
    /// Output files contain:
    /// - Employee information header
    /// - All page content in chronological order
    /// - Comments and discussions
    /// - Links to attachments
    #[command(
        about = "Process employee directories (starting with ~) and generate consolidated markdown files",
        long_about = r#"Process employee directories and generate consolidated markdown documentation.

This command processes employee documentation by:
1. Scanning for directories starting with '~' (e.g., ~john-doe, ~张三-42)
2. Extracting content from HTML files, comments, and attachments
3. Generating consolidated markdown files named <alias>-<chinese_name>-<file_count>.md

FEATURES:
• Automatic detection of employee homepages and content pages
• Extraction of comments and discussions
• Attachment file discovery and linking
• Chinese character support in filenames and content
• File count tracking for organization

EXAMPLE OUTPUT:
  ~john-doe-张三-15.md (15 files processed)
  ~jane-smith-李四-8.md (8 files processed)"#
    )]
    Employee {
        /// Path to the directory containing employee folders (default: "data")
        #[arg(
            short,
            long,
            value_name = "DIR",
            default_value = "data",
            help = "Path to directory containing employee folders starting with '~'",
            long_help = r#"Path to the directory containing employee documentation folders.

Employee folders must start with '~' followed by the employee's alias.
Examples: ~john-doe, ~张三-42, ~mary-smith-15

The tool will scan this directory recursively for employee folders
and process each one individually."#
        )]
        path: PathBuf,
    },

    /// Process project directories and generate consolidated markdown documentation.
    ///
    /// This command processes project directories by scanning for HTML files and attachments,
    /// then generates consolidated markdown files for each project. Unlike employee processing,
    /// project directories don't have the '~' prefix requirement and are processed based on
    /// their content structure.
    ///
    /// The tool extracts:
    /// - Project documentation from HTML files
    /// - Comments and discussions
    /// - Attachment files and images
    /// - Project metadata and organization
    ///
    /// Output files are named <project_name>-<file_count>.md
    #[command(
        about = "Process project directories and generate consolidated markdown files",
        long_about = r#"Process project directories and generate consolidated markdown documentation.

This command processes project documentation by:
1. Scanning project directories for HTML files and attachments
2. Extracting content, comments, and project information
3. Generating consolidated markdown files named <project_name>-<file_count>.md

FEATURES:
• Automatic content extraction from HTML files
• Comment and discussion processing
• Attachment file discovery and linking
• Project organization and metadata extraction

EXAMPLE OUTPUT:
  CyberNarrator-3620-45.md (45 files processed)
  LIFE-92-23.md (23 files processed)"#
    )]
    Project {
        /// Path to the directory containing project folders (default: "data")
        #[arg(
            short,
            long,
            value_name = "DIR",
            default_value = "data",
            help = "Path to directory containing project folders",
            long_help = r#"Path to the directory containing project documentation folders.

Project folders can have any naming convention and will be processed
based on their content structure. The tool scans for HTML files,
comments, and attachments within each project directory."#
        )]
        path: PathBuf,
    },

    /// Convert markdown files to high-quality PDFs with advanced features.
    ///
    /// This command uses pandoc with LaTeX to convert markdown files to PDF format.
    /// It includes automatic image processing, Chinese character support, and robust
    /// error handling for complex documents.
    ///
    /// KEY FEATURES:
    /// - Automatic image resizing (max 4000x4000 to prevent LaTeX errors)
    /// - Chinese character support using ctexart document class
    /// - Syntax highlighting with pygments
    /// - Color links and professional formatting
    /// - Retry logic for LaTeX compilation failures
    /// - Graceful handling of corrupted images
    /// - Temporary directory management
    ///
    /// PDF ENGINES:
    /// - lualatex (default): Best Chinese support, recommended
    /// - xelatex: Good Chinese support, alternative option
    /// - pdflatex: Basic support, may have Chinese character issues
    #[command(
        about = "Convert markdown files to PDF with advanced features",
        long_about = r#"Convert markdown files to high-quality PDFs with comprehensive features.

This command provides professional PDF generation with:
• AUTOMATIC IMAGE PROCESSING: Resizes images >4000px to prevent LaTeX 'Dimension too large' errors
• CHINESE CHARACTER SUPPORT: Uses ctexart document class with lualatex for proper Unicode rendering
• SYNTAX HIGHLIGHTING: Code blocks rendered with pygments
• PROFESSIONAL FORMATTING: Color links, proper margins, clean layout
• ERROR RESILIENCE: Retry logic for compilation failures, skips corrupted images
• BATCH PROCESSING: Convert entire directories of markdown files

PDF ENGINES:
  lualatex (default): Best Chinese/Unicode support, recommended for mixed content
  xelatex: Good Chinese support, faster for simple documents
  pdflatex: Basic engine, may have issues with Chinese characters

IMAGE HANDLING:
  • Automatically resizes oversized images while maintaining aspect ratio
  • Skips corrupted/invalid images with warnings
  • Supports PNG, JPG, JPEG, SVG, and other common formats
  • Temporary processing to avoid modifying original files

OUTPUT:
  PDFs are generated alongside markdown files with .pdf extension
  Example: document.md → document.pdf"#
    )]
    Pdf {
        /// Path to a single markdown file to convert
        #[arg(
            short,
            long,
            value_name = "FILE",
            conflicts_with = "directory",
            help = "Path to a single markdown file to convert to PDF",
            long_help = r#"Path to a single markdown file for PDF conversion.

Use this option to convert one specific markdown file to PDF.
The PDF will be generated in the same directory with the same name
but .pdf extension.

Example: --path document.md → generates document.pdf"#
        )]
        path: Option<PathBuf>,

        /// Directory to scan for markdown files to convert
        #[arg(
            short = 'd',
            long,
            value_name = "DIR",
            conflicts_with = "path",
            help = "Directory to scan for markdown files to convert",
            long_help = r#"Directory to recursively scan for .md files to convert to PDF.

All markdown files (*.md) in the specified directory and its
subdirectories will be converted to PDF format.

Example: --directory ./docs → converts all .md files in ./docs/"#
        )]
        directory: Option<PathBuf>,

        /// PDF engine to use for LaTeX compilation
        #[arg(
            long,
            value_name = "ENGINE",
            default_value = "lualatex",
            help = "PDF engine: lualatex (default), xelatex, or pdflatex",
            long_help = r#"LaTeX engine to use for PDF compilation.

ENGINES:
  lualatex (default): Best Unicode/Chinese support, recommended
                     Uses ctexart document class for Chinese characters

  xelatex: Good Chinese support, alternative for complex documents
           May be faster than lualatex for simple content

  pdflatex: Basic engine, fastest but limited Chinese character support
            May produce errors with Chinese text

RECOMMENDATION: Use lualatex (default) for best Chinese character support"#
        )]
        engine: String,
    },

    /// Split large markdown files into smaller, manageable chunks.
    ///
    /// This command helps manage large documentation files by splitting them into smaller
    /// pieces based on line count or file size. This is useful for:
    /// - Processing large files that exceed tool limits
    /// - Creating more readable documentation chunks
    /// - Parallel processing of documentation
    /// - Managing files for version control
    ///
    /// SPLITTING MODES:
    /// - By line count: Fixed number of lines per file
    /// - By file size: Split files larger than threshold
    /// - Directory processing: Batch split multiple files
    ///
    /// Output files are named with _part_NN suffix.
    #[command(
        about = "Split large markdown files into smaller chunks",
        long_about = r#"Split large markdown files into smaller, manageable pieces.

This command helps manage oversized documentation by splitting files based on:
• Line count: Fixed number of lines per output file
• File size: Split files exceeding size threshold
• Directory processing: Batch split multiple files

USE CASES:
• Break up large documentation for easier processing
• Create manageable chunks for PDF conversion
• Prepare files for version control limitations
• Enable parallel processing of documentation

OUTPUT NAMING:
  Original: document.md
  Parts: document_part_01.md, document_part_02.md, etc.

SPLITTING METHODS:
  By lines: Each output file contains exactly N lines
  By size: Files larger than threshold are split proportionally"#
    )]
    Split {
        /// Path to a single markdown file to split
        #[arg(
            short = 'p',
            long,
            value_name = "FILE",
            conflicts_with = "directory",
            help = "Path to a single markdown file to split",
            long_help = r#"Path to a single markdown file to split into smaller chunks.

The file will be split based on the --lines parameter, with each
output file containing the specified number of lines.

Example: --path large.md --lines 10000"#
        )]
        path: Option<PathBuf>,

        /// Directory to scan for markdown files to split
        #[arg(
            short = 'd',
            long,
            value_name = "DIR",
            conflicts_with = "path",
            help = "Directory to scan for markdown files to split",
            long_help = r#"Directory to recursively scan for markdown files to split.

Files will be split based on the --size-threshold parameter.
Only files larger than the threshold will be processed.

Example: --directory ./docs --size-threshold 5.0"#
        )]
        directory: Option<PathBuf>,

        /// Number of lines per split file (default: 50000)
        #[arg(
            short = 'l',
            long,
            value_name = "LINES",
            default_value = "50000",
            help = "Number of lines per split file",
            long_help = r#"Maximum number of lines per output file when splitting.

This parameter controls how many lines each split file will contain.
Larger values create fewer, bigger files. Smaller values create
more, smaller files.

Default: 50000 lines per file
Recommended range: 10000-100000 lines"#
        )]
        lines: usize,

        /// Split files larger than this size in MB (default: 2.5)
        #[arg(
            short = 's',
            long,
            value_name = "MB",
            default_value = "2.5",
            help = "Split files larger than this size in MB",
            long_help = r#"File size threshold in megabytes for directory splitting.

When using --directory mode, only files larger than this size
will be split. Smaller files remain unchanged.

Default: 2.5 MB
Recommended range: 1.0-10.0 MB depending on use case"#
        )]
        size_threshold: f64,
    },
}

/// Represents a single HTML page with its content, comments, and attachments.
/// This struct is used to store extracted information from HTML files during
/// the document processing phase.
struct Page {
    /// The title/name of the page
    name: String,
    /// The main content of the page in markdown format
    content: String,
    /// List of comments associated with this page, stored as (comment_id, comment_content) pairs
    comments: Vec<(String, String)>,
    /// List of file paths to attachments (images, documents) referenced by this page
    attachments: Vec<PathBuf>,
}

/// Main entry point of the GFW Helper application.
/// Parses command line arguments and dispatches to the appropriate command handler.
fn main() {
    println!("🚀 GFW Helper v{} - Comprehensive Documentation Processor", env!("CARGO_PKG_VERSION"));
    println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    
    // Parse command line arguments using clap
    let cli = Cli::parse();

    // Dispatch to the appropriate command handler based on user input
    match &cli.command {
        Commands::Employee { path } => {
            // Process employee directories (those starting with ~)
            process_directories(path, true);
        }
        Commands::Project { path } => {
            // Process project directories (general project documentation)
            process_directories(path, false);
        }
        Commands::Pdf { path, directory, engine } => {
            print!("ℹ  Running in PDF mode...\n");
            if let Some(path) = path {
                // Convert a single markdown file to PDF
                if let Err(e) = process_pdf(path, engine) {
                    eprintln!("✗ Error processing PDF: {}", e);
                }
            } else if let Some(directory) = directory {
                // Convert all markdown files in a directory to PDF
                for entry in WalkDir::new(directory).into_iter().filter_map(Result::ok) {
                    if entry.file_type().is_file() && entry.path().extension().and_then(|s| s.to_str()) == Some("md") {
                        println!("ℹ  Processing markdown file: {}", entry.path().display());
                        if let Err(e) = process_pdf(entry.path(), engine) {
                            eprintln!("✗ Error converting {}: {}", entry.path().display(), e);
                        }
                    }
                }
            } else {
                println!("ℹ  Please provide either a file path (-p) or a directory path (-d).");
            }
        },
        Commands::Split { path, directory, lines, size_threshold } => {
            if let Some(file_path) = path {
                // Split a single markdown file
                if let Err(e) = split_markdown_file(&file_path, *lines) {
                    eprintln!("✗ Error splitting file: {}", e);
                }
            } else if let Some(dir_path) = directory {
                // Split all markdown files in a directory that exceed the size threshold
                if let Err(e) = split_markdown_files_in_directory(&dir_path, *lines, *size_threshold) {
                    eprintln!("✗ Error splitting files in directory: {}", e);
                }
            } else {
                println!("ℹ  Please provide either a file path (-p) or a directory path (-d).");
            }
        }
    }
    
    println!("✓ Operation completed successfully!");
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
/// 1. Creating a temporary directory for processing
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
fn process_pdf(md_file_path: &Path, engine: &str) -> Result<(), Box<dyn std::error::Error>> {
    // Create a unique temporary directory for this conversion process
    let temp_dir_name = Uuid::new_v4().to_string();
    let temp_dir = std::env::temp_dir().join(&temp_dir_name);
    fs::create_dir_all(&temp_dir)?;

    println!("ℹ  Temporary directory created at: {}", temp_dir.display());

    // Parse markdown content and extract image links for processing
    let md_content = fs::read_to_string(md_file_path)?;
    let link_regex = Regex::new(r"(!?)\[([^\]]*)\]\(([^)]+)\)")?;
    let mut new_md_content = md_content.clone();

    // Get the directory containing the original markdown file for resolving relative paths
    let original_md_dir = md_file_path.parent().ok_or("Could not get parent directory of markdown file")?.canonicalize()?;

    // Maps original image paths to processed image paths in temp directory
    let mut image_map: HashMap<String, PathBuf> = HashMap::new();
    let mut image_counter = 0;

    for cap in link_regex.captures_iter(&md_content) {
        let full_match = &cap[0];
        let is_image = &cap[1] == "!";
        let alt_text = &cap[2];
        let link = &cap[3];

        let decoded_link = percent_decode(link.as_bytes()).decode_utf8_lossy();
        let link_path = Path::new(decoded_link.as_ref());

        if link.starts_with("http://") || link.starts_with("https://") || link_path.is_absolute() {
            continue;
        }

        if is_image {
            let source_path = original_md_dir.join(link_path);
            if source_path.exists() {
                // Validate the image file before processing
                if let Ok(metadata) = fs::metadata(&source_path) {
                    if metadata.len() == 0 {
                        println!("⚠  Skipping empty image file: {}", source_path.display());
                        new_md_content = new_md_content.replace(full_match, "");
                        continue;
                    }
                    
                    // Try to read the first few bytes to check if file is accessible
                    if let Ok(mut file) = std::fs::File::open(&source_path) {
                        let mut buffer = [0; 10];
                        if file.read(&mut buffer).is_err() {
                            println!("⚠  Skipping unreadable image file: {}", source_path.display());
                            new_md_content = new_md_content.replace(full_match, "");
                            continue;
                        }
                        
                        // Try to validate the image format using the image crate
                        if let Ok(reader) = ImageReader::open(&source_path) {
                            if reader.decode().is_err() {
                                println!("⚠  Skipping invalid/corrupted image file: {}", source_path.display());
                                new_md_content = new_md_content.replace(full_match, "");
                                continue;
                            }
                        } else {
                            println!("⚠  Skipping image file that can't be opened: {}", source_path.display());
                            new_md_content = new_md_content.replace(full_match, "");
                            continue;
                        }
                    } else {
                        println!("⚠  Skipping inaccessible image file: {}", source_path.display());
                        new_md_content = new_md_content.replace(full_match, "");
                        continue;
                    }
                }

                let extension = source_path.extension().and_then(|s| s.to_str()).unwrap_or("").to_lowercase();
                let final_link_name: String;

                if extension == "svg" {
                    let png_name = format!("image_{}.png", image_counter);
                    image_counter += 1;
                    let dest_path = temp_dir.join(&png_name);

                    if let Some(parent) = dest_path.parent() {
                        if !parent.exists() {
                            fs::create_dir_all(parent)?;
                        }
                    }
                    println!("ℹ  Converting SVG {} to PNG using Inkscape...", source_path.display());

                    let inkscape_output = Command::new("inkscape")
                        .arg(source_path.as_os_str())
                        .arg("--export-type=png")
                        .arg(format!("--export-filename={}", dest_path.to_str().unwrap()))
                        .output()?;

                    if !inkscape_output.status.success() {
                        eprintln!("Inkscape conversion failed for {}: {}", source_path.display(), String::from_utf8_lossy(&inkscape_output.stderr));                      
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
                    image_map.insert(png_name, source_path);
                } else {
                    let new_name = format!("image_{}.{}", image_counter, extension);
                    image_counter += 1;
                    let dest_path = temp_dir.join(&new_name);

                    if let Some(parent) = dest_path.parent() {
                        fs::create_dir_all(parent)?;
                    }
                    fs::copy(&source_path, &dest_path)?;
                    
                    // Resize image if it's too large for LaTeX
                    if let Err(e) = resize_image_if_needed(&dest_path, 4000, 4000) {
                        println!("⚠  Failed to resize image {}: {}", dest_path.display(), e);
                        // Continue anyway, as the original image might still work
                    }
                    
                    final_link_name = new_name.clone();
                    image_map.insert(new_name, source_path);
                }

                let new_link_markdown = format!("![{}]({})", alt_text, final_link_name);
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
        command.current_dir(&temp_dir)
            .arg("--from")
            .arg("commonmark")
            .arg("input.md")
            .arg("-o")
            .arg("result.pdf")
            .arg("--highlight-style=pygments");

        // Add Unicode/Chinese support for different engines
        if engine == "xelatex" {
            command.arg("-V")
                .arg("geometry:margin=1in")
                .arg("-V")
                .arg("colorlinks=true")
                .arg("-V")
                .arg("CJKmainfont=SimSun") // Use SimSun for Chinese characters
                .arg("-V")
                .arg("mainfont=Arial"); // Fallback font
        } else if engine == "pdflatex" {
            command.arg("-V")
                .arg("geometry:margin=1in")
                .arg("-V")
                .arg("colorlinks=true")
                .arg("-V")
                .arg("CJKmainfont=SimSun")
                .arg("-V")
                .arg("mainfont=Arial");
        } else if engine == "lualatex" {
            // For LuaLaTeX, use ctex document class for Chinese support
            command.arg("-V")
                .arg("documentclass=ctexart")
                .arg("-V")
                .arg("geometry:margin=1in")
                .arg("-V")
                .arg("colorlinks=true");
        } else {
            // Default for other engines
            command.arg("-V")
                .arg("geometry:margin=1in")
                .arg("-V")
                .arg("colorlinks=true");
        }

        command.arg(format!("--pdf-engine={}", engine));

        if cfg!(windows) {
            command.env("PANGOCAIRO_BACKEND", "win32");
            println!("Setting PANGOCAIRO_BACKEND to win32");
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
        return Err("Pandoc execution failed with an unrecoverable error.".into());
    }


    // 5. Copy result pdf
    let result_pdf_path = temp_dir.join("result.pdf");
    let final_pdf_path = md_file_path.with_extension("pdf");
    fs::copy(&result_pdf_path, &final_pdf_path)?;

    println!("✓ PDF generated successfully at: {}", final_pdf_path.display());

    // 6. Cleanup
    fs::remove_dir_all(&temp_dir)?;
    println!("✓ Temporary directory cleaned up.");

    Ok(())
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
fn split_markdown_file(file_path: &Path, lines_per_file: usize) -> Result<(), Box<dyn std::error::Error>> {
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
    let parent_dir = file_path.parent().ok_or("Could not get parent directory")?;

    // Calculate how many output files are needed
    let num_files = (total_lines as f64 / lines_per_file as f64).ceil() as usize;

    // Create each output file
    for i in 0..num_files {
        let start_line = i * lines_per_file;
        let end_line = std::cmp::min(start_line + lines_per_file, total_lines);
        let chunk = &lines[start_line..end_line];

        // Generate output filename with zero-padded index
        let new_file_name = format!("{}_{:02}.{}", file_stem, i, extension);
        let new_file_path = parent_dir.join(new_file_name);

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
fn split_markdown_files_in_directory(dir_path: &Path, lines_per_file: usize, size_threshold_mb: f64) -> Result<(), Box<dyn std::error::Error>> {
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
                            if let Err(e) = split_markdown_file(path, lines_per_file) {
                                eprintln!("Error splitting {}: {}", path.display(), e);
                            } else {
                                files_split += 1;
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
fn process_directories(data_dir: &Path, employee_mode: bool) {
    // Validate input directory exists
    if !data_dir.exists() {
        println!("✗ Data directory not found: {}", data_dir.display());
        return;
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
            let file_name = path.file_name().unwrap().to_string_lossy();
            if let Some(comment_id) = file_name.split('_').next() {
                 for page in pages.iter_mut() {
                    if page.comments.iter().any(|(id, _)| id == comment_id) {
                        page.attachments.push(path.to_path_buf());
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
            for (i, attachment) in page.attachments.iter().enumerate() {
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
                    // Deeper check for raster images
                    if ["png", "jpg", "jpeg", "gif", "bmp"].contains(&extension.as_str()) {
                        let is_valid_image = (|| -> Result<(), Box<dyn std::error::Error>> {
                            let reader = ImageReader::open(attachment)?;
                            let formatted_reader = reader.with_guessed_format()?;
                            let dynamic_image = formatted_reader.decode()?;
                            let (width, height) = dynamic_image.dimensions();
                            if width <= 1 && height <= 1 {
                                return Err(format!("Image dimensions ({}x{}) are too small", width, height).into());
                            }
                            Ok(())
                        })().is_ok();

                        if !is_valid_image {
                            eprintln!("Warning: Invalid image detected (corrupt, un-decodable, or too small): {}", attachment.display());
                            is_image = false;
                        }
                    }
                    // For SVG, we rely on the extension and file size check.
                }

                if is_image {
                    markdown_content.push_str(&format!("{}. ![{}]({})
", i + 1, file_name, link));
                } else {
                    markdown_content.push_str(&format!("{}. [{}]({})
", i + 1, file_name, link));
                }
            }
            markdown_content.push_str("\n
");
        }
    }

    Some((alias, chinese_name, file_count, markdown_content))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs::{self, File};
    use std::io::Write;

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
        assert!(markdown_content.contains("[2_attachment.txt](~testuser/attachments/2_attachment.txt)"));
        assert!(markdown_content.contains("[3_broken.png](~testuser/attachments/3_broken.png)"));
        assert!(!markdown_content.contains("![3_broken.png](~testuser/attachments/3_broken.png)"));

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
        assert_eq!(chinese_name, "~testuser2"); // Fallback to alias

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
        let result = split_markdown_files_in_directory(test_dir, 50000, 0.001);
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
        let sub_large_split_files: Vec<_> = fs::read_dir(&sub_dir)
            .unwrap()
            .filter_map(|entry| entry.ok())
            .map(|entry| entry.path())
            .filter(|path| {
                let file_name = path.file_name().unwrap().to_str().unwrap();
                file_name.starts_with("sub_large_") && file_name.ends_with(".md")
            })
            .collect();
        assert!(sub_large_split_files.len() > 0, "Sub directory large file should be split");

        // Verify original files still exist
        assert!(small_file_path.exists(), "Original small file should still exist");
        assert!(large_file_path.exists(), "Original large file should still exist");
        assert!(sub_large_file_path.exists(), "Original sub large file should still exist");

        // Cleanup
        fs::remove_dir_all(test_dir).unwrap();
    }
}
