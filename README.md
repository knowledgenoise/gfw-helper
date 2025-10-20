# GFW Helper

[中文版](README_CN.md)

A comprehensive utility for processing employee and project documentation, managing JIRA issues, and converting Markdown files to professional-quality PDFs with advanced features including automatic image optimization, Chinese character support, and complete workflow automation.

## Features

- **Unified Document Processing**: Convert HTML document directories to integrated Markdown files with automatic employee/project detection
- **Self-contained Output**: Automatically copies all linked resources (images, attachments) to a companion folder for portable documentation
- **JIRA Issue Processing**: Process JIRA issue JSON exports and generate consolidated markdown documentation with issue tracking
- **Advanced PDF Generation**: Convert Markdown to professional PDFs with automatic image handling, Chinese character support, and SVG/draw.io conversion
- **Parallel Processing**: Concurrent HTML-to-Markdown conversion and PDF generation with real-time progress tracking for significantly faster batch operations
- **Optimized Logging**: Thread-safe logging with progress bars and summary statistics for clean output during parallel execution
- **File Splitting**: Split large Markdown files into manageable chunks for easier processing or version control
- **Image Optimization**: Automatically resize oversized images to prevent LaTeX compilation errors
- **WebP Support**: Automatically converts WebP images to PNG format for LaTeX compatibility
- **SVG & Draw.io Support**: Automatically detects and converts SVG content and draw.io XML files (even with PNG extension) to PNG format
- **Chinese Language Support**: Full Unicode support with proper font handling for Chinese characters
- **Batch Processing**: Process entire directories of Markdown files
- **Error Recovery**: Robust error handling with retry logic for LaTeX compilation failures
- **Complete Workflow Automation**: Single command to process HTML → Markdown → Split → PDF

## System Requirements

### System Dependencies

#### Pandoc
Used for Markdown to PDF conversion.
- **Windows**: Download from [pandoc.org](https://pandoc.org/installing.html)
- **macOS**: `brew install pandoc`
- **Linux**: `sudo apt-get install pandoc` (Ubuntu/Debian) or `sudo dnf install pandoc` (Fedora/RHEL)

#### Inkscape
Used for SVG to PNG conversion.
- **Windows**: Download from [inkscape.org](https://inkscape.org/release/)
- **macOS**: `brew install inkscape`
- **Linux**: `sudo apt-get install inkscape` (Ubuntu/Debian) or `sudo dnf install inkscape` (Fedora/RHEL)

#### LaTeX Distribution
Used for PDF generation with advanced formatting.

**Windows:**
- Install MiKTeX: Download from [miktex.org](https://miktex.org/download)
- Or install TeX Live: Download from [tug.org/texlive/](https://tug.org/texlive/)

**macOS:**
- Install MacTeX: Download from [tug.org/mactex/](https://tug.org/mactex/)
- Or use Homebrew: `brew install mactex`

**Linux:**
- Ubuntu/Debian: `sudo apt-get install texlive-full`
- Fedora/RHEL: `sudo dnf install texlive-scheme-full`
- Arch Linux: `sudo pacman -S texlive-most texlive-langchinese`

### Rust
The application is written in Rust. Install Rust from [rustup.rs](https://rustup.rs/):
```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
```

## Installation

### Compile from Source

#### Windows
```powershell
# Clone the repository
git clone https://github.com/knowledgenoise/gfw-helper.git
cd gfw-helper

# Build in release mode
cargo build --release

# Executable will be in target/release/gfw-helper.exe
```

#### macOS
```bash
# Clone the repository
git clone https://github.com/knowledgenoise/gfw-helper.git
cd gfw-helper

# Build in release mode
cargo build --release

# Executable will be in target/release/gfw-helper
```

#### Linux
```bash
# Clone the repository
git clone https://github.com/knowledgenoise/gfw-helper.git
cd gfw-helper

# Build in release mode
cargo build --release

# Executable will be in target/release/gfw-helper
```

### Pre-compiled Binaries
Check the [Releases](https://github.com/knowledgenoise/gfw-helper/releases) page for pre-compiled binaries.

## Usage

Main workflow: **HTML → Markdown → Split → PDF** or **JIRA JSON → Markdown → PDF**

### 1. Convert HTML Documents to Markdown (Unified Command)

Process employee directories (starting with `~`) or project directories using the unified `md` command:

```bash
# Auto-detect and process all directories (employee and project)
gfw-helper md /path/to/data

# Process only employee directories (starting with ~)
gfw-helper md /path/to/data --employee-only

# Process only project directories (non-employee)
gfw-helper md /path/to/data --project-only

# Specify output directory (default is current directory)
gfw-helper md /path/to/data --output-dir ./output
gfw-helper md /path/to/data -o results/
```

**Output:**
- Generates consolidated Markdown files in the current directory
- **Automatically copies all linked resources** (images, attachments) to a companion folder
- Creates self-contained, portable documentation packages

**Example output structure:**
```
employee-name-张三-15.md           # Main markdown file
employee-name-张三-15_files/        # Resources folder
├── screenshot.png
├── diagram.svg
└── document.pdf
```

This will scan the directory and convert HTML files to integrated Markdown files with automatic type detection. All referenced resources are copied and links are updated to maintain portability.

**File Type Correction Feature:**

The tool automatically detects file types by reading magic bytes (file signatures) and corrects extensions during resource copying. This is especially useful when files have incorrect extensions:

- ✅ **ZIP files named as `.png`** → Automatically renamed to `.zip`
- ✅ **JPEG files named as `.png`** → Automatically renamed to `.jpg`
- ✅ **Special ZIP-based formats preserved** → DOCX, XLSX, PPTX, APK, XAPK, JAR keep their extensions (not changed to .zip)
- ✅ Supports detection of: ZIP, RAR, 7z, PNG, JPEG, GIF, PDF, BMP, TIFF, WebP, GZIP, PKG (macOS installers)

**Smart ZIP-Based Format Detection:**
- **Microsoft Office files** (DOCX, XLSX, PPTX) are ZIP-based, detected by checking for `[Content_Types].xml`
- **Android packages** (APK) are ZIP-based, detected by checking for `AndroidManifest.xml`
- **Extended Android packages** (XAPK) are ZIP-based, detected by checking for `manifest.json`
- **Java archives** (JAR) are ZIP-based, detected by checking for `META-INF/MANIFEST.MF`

The tool intelligently preserves the original extensions of these special formats.

Example output:
```
ℹ  Processing employee directory: /home/user/docs/employee/~user
  ⚠ Correcting file type: document.png -> document.zip
  ⚠ Correcting file type: image.png -> image.jpg
✓ Copied 225 resource files (including report.docx, data.xlsx, app.apk, library.jar)
  ℹ Corrected 2 file extensions based on actual file type
```

All markdown links are automatically updated to reference the corrected filenames, ensuring complete integrity of your documentation.

### 2. Process JIRA Issues to Markdown

Process JIRA issue JSON exports and generate consolidated documentation:

```bash
# Process JIRA issues - looks for 'issues' subdirectory
gfw-helper jira /path/to/jira/data

# Output to specific directory
gfw-helper jira /path/to/jira/data -o ./output
```

This will:
- Scan for JSON files in the `issues` subdirectory
- Extract issue details, comments, attachments, and metadata
- Generate a consolidated markdown file with chronological sorting
- Include time cost calculations and proper formatting

### 3. Split Large Markdown Files (Optional)

If you have large Markdown files that need splitting:

```bash
# Split a single file by line count
gfw-helper split large-file.md --lines 50000

# Split all files larger than 5MB in a directory
gfw-helper split ./docs --size-threshold 5.0

# Output to specific directory
gfw-helper split large-file.md -o ./split_output
```

### 4. Convert Markdown to PDF

Convert Markdown files to high-quality PDFs with automatic image processing:

```bash
# Convert a single Markdown file
gfw-helper pdf document.md

# Convert all Markdown files in a directory (parallel processing)
gfw-helper pdf ./docs

# Specify LaTeX engine (lualatex recommended for Chinese support)
gfw-helper pdf document.md --engine lualatex

# Output to specific directory
gfw-helper pdf document.md -o ./pdfs
gfw-helper pdf ./docs --output-dir ./output
```

**PDF Conversion Features:**
- **Parallel Processing**: Multiple files are converted concurrently for faster batch processing
- **Real-time Progress**: Visual progress bar with percentage completion and statistics
- **Thread-safe Logging**: Clean, synchronized output without interleaved messages
- Automatic resizing of images >4000px to prevent LaTeX errors
- WebP to PNG conversion for LaTeX compatibility
- SVG and draw.io file detection and conversion to PNG (using Inkscape)
- Format validation and corrupted image detection
- Temporary directory processing (original files unchanged)

### 5. Complete Workflow Automation

Use the `html2pdf` command for end-to-end processing:

```bash
# Complete pipeline: HTML → Markdown → Split → PDF
gfw-helper html2pdf /path/to/data

# Process only employee documents
gfw-helper html2pdf /path/to/data --employee-only

# Custom split settings and PDF engine
gfw-helper html2pdf /path/to/data --lines 30000 --engine xelatex

# Output to specific directory
gfw-helper html2pdf /path/to/data -o ./output
gfw-helper html2pdf /path/to/data --output-dir results/

# Complete JIRA workflow: JSON → Markdown → Split → PDF
gfw-helper jira2pdf /path/to/jira/data -o ./jira_output
```

## PDF Engines

Choose the appropriate LaTeX engine based on your content:

- **`lualatex`** (Recommended): Best Chinese/Unicode support, uses ctexart document class
- **`xelatex`**: Good Chinese support, alternative for complex documents
- **`pdflatex`**: Basic engine, fastest but limited Chinese character support

## Image Processing

The tool automatically handles images in Markdown files:

- **Automatic Resizing**: Images larger than 4000px are resized to prevent LaTeX errors
- **WebP Conversion**: WebP images are automatically converted to PNG for LaTeX compatibility
- **Format Conversion**: SVG files are converted to PNG using Inkscape
- **Validation**: Detects and skips corrupted or invalid images with warnings
- **Aspect Ratio**: Maintains image aspect ratio when resizing

## JIRA Issue Processing

Process JIRA issue JSON exports to generate comprehensive documentation:

### Features
- **Complete Issue Extraction**: Title, description, status, priority, assignee, creator
- **Comment Processing**: Full comment history with author details and timestamps
- **Attachment Handling**: Proper linking with filename preservation and URL decoding
- **Time Tracking**: Creation date, update date, and calculated time cost in days
- **Chronological Sorting**: Issues sorted by creation time (earliest to latest)
- **Proper Formatting**: Blockquotes, links, and Chinese character support

### Input Structure
```
jira-data/
└── issues/
    ├── OMPUB-1.json
    ├── OMPUB-2.json
    ├── GIT-1.json
    └── ...
```

### Output
```
jira-data/
└── jira_export.md  # Consolidated documentation
```

### Example Output Format
```markdown
# OMPUB-1

**Issue Title**

* Project: Project Name | Category | 系统运维
* Issue Type: 任务
* Priority: High
* Creator: Author Name
* Assignee: Assignee Name
* Created: 2020-02-02T11:38:55.445+0800
* Time Cost: 19.2 days
* Status: 完成
* Resolution: 该问题的工作流程已完成。

Description content with proper blockquote formatting...

## Comments

* Author Name - 2020-02-02T11:38:55.445+0800
        > Comment content with blockquote formatting...

* Attachments:
    + [filename.pdf](<attachment\123\filename.pdf>)
        + Author: Author Name
        + Created: 2020-02-02T11:38:55.445+0800
```

## Directory Structure

### Input (HTML Documents)
```
data/
├── ~employee1/
│   ├── index.html
│   ├── 1.html
│   ├── 2.html
│   ├── employee1's Home.html
│   └── attachments/
│       ├── 2_document.pdf
│       └── 2_image.png
└── project1/
    ├── index.html
    ├── page1.html
    └── attachments/
```

### Output (Markdown)
```
data/
├── ~employee1-employee1-15.md
└── project1-15.md
```

### Output (PDF)
```
data/
├── ~employee1-employee1-15.pdf
└── project1-15.pdf
```

## Command Reference

### Markdown Processing Command
```bash
gfw-helper md <directory> [OPTIONS]

OPTIONS:
    --employee-only         Process only employee directories (starting with ~)
    --project-only          Process only project directories (non-employee)
    -o, --output-dir <DIR>  Output directory for generated files [default: current directory]
```

Processes HTML document directories and converts to Markdown with automatic employee/project type detection.

### JIRA Command
```bash
gfw-helper jira <parent-directory> [OPTIONS]

OPTIONS:
    -o, --output-dir <DIR>  Output directory for generated files [default: current directory]
```

Processes JIRA issue JSON files from the `issues` subdirectory and generates consolidated markdown documentation.

### PDF Command
```bash
gfw-helper pdf <path> [OPTIONS]

OPTIONS:
    --engine <ENGINE>       PDF engine: lualatex, xelatex, pdflatex [default: lualatex]
    -o, --output-dir <DIR>  Output directory for generated files [default: current directory]
```

Converts Markdown files to PDF. Accepts a single file or directory path.

### Split Command
```bash
gfw-helper split <path> [OPTIONS]

OPTIONS:
    --lines <LINES>              Number of lines per split file [default: 50000]
    --size-threshold <MB>        Split files larger than this size in MB [default: 2.5]
    -o, --output-dir <DIR>       Output directory for split files [default: current directory]
```

Splits large Markdown files into manageable chunks. Accepts a single file or directory path.

### Complete Workflow Command
```bash
gfw-helper html2pdf <directory> [OPTIONS]

OPTIONS:
    --employee-only           Process only employee directories
    --project-only            Process only project directories
    --lines <LINES>           Lines per split file [default: 50000]
    --size-threshold <MB>     Size threshold for splitting [default: 2.5]
    --engine <ENGINE>         PDF engine [default: lualatex]
    -o, --output-dir <DIR>    Output directory for all generated files [default: current directory]
```

Complete automation: HTML → Markdown → Split → PDF in a single command.

```bash
gfw-helper jira2pdf <directory> [OPTIONS]

OPTIONS:
    --lines <LINES>           Lines per split file [default: 50000]
    --size-threshold <MB>     Size threshold for splitting [default: 2.5]
    --engine <ENGINE>         PDF engine [default: lualatex]
    -o, --output-dir <DIR>    Output directory for all generated files [default: current directory]
```

Complete JIRA workflow: JSON → Markdown → Split → PDF in a single command.

## Development and Testing

### Running Tests

The project has comprehensive unit tests with >80% code coverage:

```bash
# Run all tests
cargo test

# Run tests with output
cargo test -- --nocapture

# Run only library tests
cargo test --lib

# Run integration tests
cargo test --test '*'
```

### Code Coverage

Generate code coverage reports:

```bash
# Install cargo-llvm-cov
cargo install cargo-llvm-cov

# Generate coverage report
cargo llvm-cov --html

# Open the report
# Windows: start target/llvm-cov/html/index.html
# Linux/Mac: open target/llvm-cov/html/index.html
```

### Code Quality

```bash
# Format code
cargo fmt

# Run linter
cargo clippy -- -D warnings

# Check compilation
cargo check
```

### Building

```bash
# Debug build
cargo build

# Release build (optimized)
cargo build --release

# Run without installing
cargo run -- md /path/to/data
```

## Troubleshooting

### LaTeX Compilation Errors
- Ensure a complete LaTeX distribution is installed
- For Chinese support, use the `lualatex` engine
- Check that all required LaTeX packages are installed
- If errors persist, try the `xelatex` engine as an alternative

### Image Processing Issues
- Verify Inkscape is installed and accessible in PATH
- Check that image files are not corrupted
- Large images (>4000px) will be automatically resized
- Draw.io XML files with PNG extensions will be automatically converted

### Missing Dependencies
- Run `pandoc --version` to verify pandoc installation
- Run `inkscape --version` to verify Inkscape installation
- Run `lualatex --version` (or `xelatex --version`) to verify LaTeX installation
- Ensure all tools are accessible in your system PATH

### Common Error Messages

**"Dimension too large" (LaTeX)**
- Images are too large - the tool automatically resizes them to 4000x4000px maximum
- If still failing, try manually resizing images before conversion

**"Unable to load picture or PDF file" (LaTeX)**
- Image file may be corrupted - the tool will skip it and show a warning
- Try regenerating the image or using a different format

**"File ended prematurely" (LaTeX)**
- LaTeX compilation issue - the tool has retry logic (3 attempts)
- Check that your LaTeX distribution is complete and up-to-date

## Project Structure

```
gfw-helper/
├── src/
│   ├── main.rs           # Main entry point and PDF processing
│   ├── lib.rs            # Library exports
│   ├── cli.rs            # Command-line interface definitions
│   ├── utils.rs          # Utility functions (sanitization, image resizing)
│   ├── commands/
│   │   ├── mod.rs        # Command modules
│   │   └── md.rs         # Markdown processing logic
│   └── processing/
│       ├── mod.rs        # Processing modules
│       └── images.rs     # Image detection and extension correction
├── tests/                # Integration tests (if any)
├── .github/
│   └── workflows/
│       └── ci.yml        # CI/CD pipeline for testing and coverage
├── Cargo.toml            # Dependencies and project metadata
└── README.md             # This file
```

## CI/CD

The project uses GitHub Actions for continuous integration:

- **Tests**: Run on push and PR for Linux, Windows, and macOS
- **Code Coverage**: Generates coverage reports and uploads to Codecov
- **Linting**: Checks code formatting and runs Clippy
- **Artifacts**: Coverage HTML reports available for download

View the workflow status in the [Actions tab](https://github.com/knowledgenoise/gfw-helper/actions).

## Contributing

1. Fork this repository
2. Create a feature branch
3. Make your changes
4. Add tests if applicable
5. Submit a pull request

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Acknowledgments

Built with Rust and powered by Pandoc for professional document processing.

