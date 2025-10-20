# gfw-helper

AI coding agent specification. Human documentation in README.md.

## Overview

GFW Helper is a comprehensive tool for processing employee and project documentation, JIRA issues, and converting markdown to PDF with automatic image resizing and Chinese character support.

## CLI

Implement CLI from Usage section. Support the following commands: `md`, `pdf`, `split`, `jira`, `html2pdf`, `jira2pdf`.

Global Options:
• `--output-dir` / `-o`: Output directory for generated files (default: current working directory)

Use structured argument parsing with clap. Dispatch to appropriate command handlers based on user input.

### md

Convert Confluence HTML exports to consolidated markdown documentation.

This command processes both employee and project documentation by:
1. Scanning directories for HTML files, comments, and attachments
2. Auto-detecting directory type (employee dirs start with '~')
3. Extracting and consolidating content
4. Correcting image file extensions
5. Generating organized markdown files

Directory Detection:
• Employee directories: Start with '~' (e.g., `~john-doe`, `~张三-42`)
  Output format: `<alias>-<chinese_name>-<file_count>.md`
• Project directories: Any other naming convention
  Output format: `<project_name>-<file_count>.md`

Arguments:
• `PATH`: Path to a directory containing documentation folders
• `--employee-only`: Process only directories starting with '~'
• `--project-only`: Process only directories NOT starting with '~'

Processing Steps:
1. Scan directory recursively for subdirectories
2. Classify each subdirectory as employee or project based on naming
3. Extract HTML content from files
4. Parse comments and discussions (typically in separate HTML files)
5. Extract attachments (images, documents)
6. Convert HTML to markdown using html2md
7. Consolidate all extracted content into single markdown file per directory
8. Correct image file extensions (detect JPEG stored as .png, etc.)
9. Create output markdown with file count in filename

Output Generation:
• For employee directories:
  - Parse directory name to extract alias and chinese name (format: `~alias-chinese_name-number`)
  - Generate: `<alias>-<chinese_name>-<file_count>.md`
  - Example: `~john-doe-张三-42` → `john-doe-张三-15.md`

• For project directories:
  - Use directory name as project name
  - Generate: `<project_name>-<file_count>.md`
  - Example: `CyberNarrator-3620` → `CyberNarrator-3620-45.md`

Image Handling:
• Detect and correct image file extensions based on actual file content
• Support detection for: JPEG, PNG, GIF, WEBP, SVG
• Rename files with incorrect extensions (e.g., file.png → file.jpg if content is JPEG)
• Convert WEBP to PNG format
• Convert SVG to PNG format

### pdf

Convert markdown files to PDF with automatic image resizing and Chinese character support.

Arguments:
• `PATH`: Single markdown file or directory containing .md files
• `--engine`: PDF engine to use (default: `xelatex`, options: `xelatex`, `pdflatex`, `lualatex`)

Processing (Single File):
1. Read markdown file
2. Sanitize markdown content for LaTeX compilation:
   - Escape special LaTeX characters
   - Handle code blocks properly
   - Preserve Chinese characters
3. Resize images exceeding 4000x4000 pixels to prevent LaTeX 'Dimension too large' error
4. Convert WEBP and SVG images to PNG format
5. Run pandoc with specified engine
6. Generate PDF output

Processing (Directory):
• Use parallel processing for multiple files
• Maintain progress tracking (current file / total files)
• Report successes and failures
• Skip corrupted/invalid images with warnings

LaTeX Configuration:
• Document class: `ctexart` (for Chinese character support with lualatex)
• Image resizing: Maximum 4000x4000 pixels
• Syntax highlighting: Enabled with pygments
• Color links: Enabled
• Proper margins and formatting

Error Handling:
• Gracefully handle corrupted/invalid images
• Implement automatic retry logic for compilation failures
• Clean up temporary files after processing
• Report detailed error messages for debugging

### split

Split large markdown files into manageable chunks.

Arguments:
• `PATH`: Single markdown file or directory containing .md files
• `--lines`: Lines per output file (default: 5000)
• `--size-threshold`: Only process files larger than this size in MB (default: 10.0)

Processing (Single File):
1. Read markdown file
2. Split by line count (default 5000 lines per chunk)
3. Generate output files with sequential numbering: `filename_1.md`, `filename_2.md`, etc.
4. Preserve markdown structure across splits

Processing (Directory):
• Process all .md files in directory
• Skip files smaller than `--size-threshold`
• Report processing statistics:
  - Files processed
  - Total files split
  - Total files skipped (too small)
  - Output directory location

### jira

Process JIRA issue JSON files and generate consolidated markdown documentation.

Arguments:
• `PATH`: Path to directory containing JIRA issue JSON files (typically `issues` subdirectory)

Processing:
1. Scan directory for JSON files containing JIRA issue data
2. Parse JSON files with structure:
   - Issue metadata (key, summary, description, etc.)
   - Status, priority, resolution
   - Project and issue type information
   - Comments and activity
   - Attachments
3. Convert issue descriptions (may be in JIRA markup format) to markdown:
   - Handle blockquotes and formatted text
   - Convert lists and code blocks
   - Preserve nested formatting
4. Process attachments embedded in descriptions
5. Consolidate all issues into single markdown file
6. Generate output: `jira_export.md` (or similar pattern)

JSON Structure Expected:
```json
{
  "issues": [
    {
      "key": "PROJ-123",
      "fields": {
        "summary": "Issue title",
        "description": "Issue description",
        "status": { "name": "In Progress" },
        "priority": { "name": "High" },
        "created": "2024-01-01T00:00:00Z",
        "updated": "2024-01-02T00:00:00Z",
        "project": { "key": "PROJ", "name": "Project Name" },
        "issuetype": { "name": "Bug" },
        "resolution": { "name": "Done" },
        "comment": { "comments": [...] },
        "attachment": [...]
      }
    }
  ]
}
```

Output Format:
• Single consolidated markdown file with all issues
• Structure: Issue key, title, status, priority, description, comments
• Preserve formatting and attachments references

### html2pdf

Complete workflow: HTML → Markdown → Split → PDF

This is a convenience command that combines `md`, `split`, and `pdf` operations in sequence.

Arguments:
• `PATH`: Path to directory containing HTML documentation
• `--employee-only`: Process only employee directories
• `--project-only`: Process only project directories
• `--lines`: Lines per split file (passed to split command)
• `--engine`: PDF engine (passed to pdf command)

Workflow:
1. Run `md` command on provided path (with employee/project filtering)
2. Run `split` command on generated markdown files
3. Run `pdf` command on all split markdown files
4. Generate final PDF documents

Output:
• All generated files in specified output directory
• Final PDFs with split chunks converted to individual PDFs

### jira2pdf

Complete workflow: JIRA JSON → Markdown → Split → PDF

Arguments:
• `PATH`: Path to JIRA data directory
• `--lines`: Lines per split file
• `--engine`: PDF engine

Workflow:
1. Run `jira` command on provided path
2. Run `split` command on generated markdown file
3. Run `pdf` command on all split markdown files
4. Generate final PDF documents

## Processing Features

### Image Handling

Image File Detection and Correction:
• Scan files in directory recursively
• Detect actual image type based on magic bytes / file headers
• Compare detected type with file extension
• Rename files to correct extension if mismatch found
• Support formats: JPEG, PNG, GIF, WEBP, SVG, APK, XAPK, JAR, PKG, Office documents

Supported Image Type Detection:
• JPEG: Magic bytes `FF D8 FF`
• PNG: Magic bytes `89 50 4E 47`
• GIF: Magic bytes `47 49 46`
• WEBP: Magic bytes `52 49 46 46 ... 57 45 42 50`
• SVG: XML declaration `<?xml` or `<svg` start tag

Image Format Conversion:
• WEBP → PNG: Use image library to decode WEBP and encode as PNG
• SVG → PNG: Use external tool (e.g., `convert` from ImageMagick)
• Preserve image quality during conversion

Image Resizing for LaTeX:
• Maximum dimensions: 4000x4000 pixels
• If image exceeds max dimensions:
  - Calculate aspect ratio
  - Resize proportionally to fit within bounds
  - Use image library for resizing (e.g., `image` crate in Rust)
• Apply to all images during PDF conversion process

### Markdown Processing

HTML to Markdown Conversion:
• Use html2md or similar library
• Extract text content from HTML tags
• Preserve structure (headings, lists, tables, code blocks)
• Handle special HTML entities and encoding

Markdown Sanitization for LaTeX:
• Escape special LaTeX characters: `\ { } $ # & % ^ _`
• Handle special sequences:
  - URLs with special characters
  - Mathematical notation
  - Code blocks with backticks
• Preserve markdown formatting while making LaTeX-compatible

Content Consolidation:
• Merge multiple HTML files into single markdown document
• Extract and organize comments as separate sections
• Include metadata (dates, authors, etc.)
• Maintain hierarchical structure with proper heading levels

### Logging and Progress

Implement structured logging with color-coded output:
• `Logger::header()`: Display version and section headers
• `Logger::info()`: General information messages
• `Logger::success()`: Operation completion messages
• `Logger::warning()`: Non-critical issues or skipped items
• `Logger::error()`: Critical errors and failures
• `Logger::detail()`: Detailed information for debugging

Progress Reporting:
• Display current operation and status
• Show file counts (current / total)
• Display statistics on completion:
  - Files processed
  - Items skipped
  - Errors encountered
• Use atomic counters for thread-safe progress tracking (when using parallel processing)

### Parallel Processing

For directory-wide operations:
• Use parallel processing for PDF conversion (multiple files)
• Maintain thread-safe operation using atomic counters and mutexes
• Report aggregated progress
• Continue processing on individual file failures
• Scale across available CPU cores

## File Type Detection

Detect files based on magic bytes and internal structure:

Office Documents:
• ZIP-based: Check for Office XML structure (`xl/`, `ppt/`, `word/` directories)
• File extensions: .docx, .xlsx, .pptx, .odt

Android Packages:
• APK: ZIP format with AndroidManifest.xml
• XAPK: ZIP format containing APK and additional files
• File extensions: .apk, .xapk

Archive Formats:
• JAR: ZIP format with META-INF/MANIFEST.MF
• PKG: macOS installer package
• File extensions: .jar, .pkg

Image Formats:
• Detect by magic bytes (as listed in Image Handling section)
• Verify extension matches detected format

## Output Handling

Directory Structure:
• Create output directory if it doesn't exist
• Generate files with descriptive names
• Organize by document type (employee, project, JIRA)

File Naming:
• Employee markdown: `<alias>-<chinese_name>-<file_count>.md`
• Project markdown: `<project_name>-<file_count>.md`
• Split files: `<original_name>_<sequence_number>.md` (e.g., `document_1.md`, `document_2.md`)
• PDF output: Same as markdown input but with `.pdf` extension

Error Reporting:
• Log all errors with context
• Continue processing on non-critical failures
• Report summary of failures at end
• Exit with appropriate status code

## Dependencies

Core Libraries:
• `clap`: Command-line argument parsing with derive macros
• `walkdir`: Directory traversal
• `scraper`: HTML parsing and element selection
• `html2md`: HTML to markdown conversion
• `url`: URL parsing and manipulation
• `percent-encoding`: URL encoding/decoding
• `uuid`: Unique identifier generation
• `regex`: Regular expression support
• `image`: Image format detection, reading, writing, and resizing
• `serde/serde_json`: JSON serialization/deserialization
• `chrono`: Date and time handling
• `zip`: ZIP archive handling
• `colored`: Terminal color output
• `rayon`: Parallel processing
• `base64`: Base64 encoding/decoding

Optional:
• `pandoc`: External tool for markdown to PDF conversion
• `ImageMagick convert`: External tool for SVG to PNG conversion

## Configuration

Environment-based Configuration:
• Read from command-line arguments
• Apply defaults for optional parameters
• Output directory: Current working directory or specified via `--output-dir`
• PDF engine: `xelatex` by default
• Split lines: 5000 lines per file by default
• Size threshold: 10 MB by default

## Implementation Notes

1. **Error Handling**: Gracefully handle missing files, invalid content, corrupted images, and compilation failures
2. **Image Validation**: Verify image integrity before processing and skip invalid files with warnings
3. **Temporary Files**: Clean up temporary files created during processing (pandoc temp dirs, etc.)
4. **Charset Support**: Properly handle UTF-8 encoding for Chinese characters and multilingual content
5. **Retry Logic**: Implement automatic retries for transient failures in PDF compilation
6. **Resource Cleanup**: Ensure proper cleanup of temporary directories and resources
7. **Progress Tracking**: Use atomic counters for thread-safe progress reporting
8. **Concurrency**: Use semaphores or similar mechanisms to limit concurrent operations

## Additional Links

- [Code](https://github.com/knowledgenoise/gfw-helper)
- [Issues](https://github.com/knowledgenoise/gfw-helper/issues)
- [Pull requests](https://github.com/knowledgenoise/gfw-helper/pulls)
- [README](./README.md)
