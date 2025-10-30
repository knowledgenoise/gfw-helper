# GFW Helper

[中文版](README_CN.md) | English

A comprehensive tool for processing employee and project documentation, managing JIRA issues, and converting Markdown files to professional-grade PDFs with advanced features like automatic image optimization, multi-language support (Chinese and Russian/Cyrillic), and complete workflow automation.

## Features

- **Unified Document Processing**: Automatically detect employee/project types and convert HTML document directories to consolidated Markdown files
- **Self-Contained Output**: Automatically copy all linked resources (images, attachments) to companion folders for portable document packages
- **JIRA Issue Processing**: Process JIRA issue JSON exports and generate consolidated Markdown documentation with issue tracking
- **Git Repository Processing**: Recursively extract README.md files from Git repositories with linked resources and embedded markdown files
- **Advanced PDF Generation**: Convert Markdown to professional PDFs with automatic image handling, multi-language support (Chinese and Russian/Cyrillic), SVG and draw.io conversion
- **Parallel Processing**: Concurrent HTML-to-Markdown conversion and PDF generation with real-time progress tracking for significantly faster batch operations
- **Optimized Logging**: Thread-safe logging with progress bars and statistics summaries, clean output during parallel execution
- **File Splitting**: Split large Markdown files into manageable chunks for easier handling or version control
- **Image Optimization**: Automatically resize oversized images to prevent LaTeX compilation errors
- **WebP Support**: Automatically convert WebP images to PNG format for LaTeX compatibility
- **SVG and Draw.io Support**: Auto-detect and convert SVG content and draw.io XML files (even when named as PNG) to PNG format
- **Chinese Language Support**: Full Unicode and Chinese character support with proper font handling using ctexart document class
- **Cyrillic/Russian Support**: Proper handling of Russian and other Cyrillic languages using fontspec with DejaVu Sans fonts
- **Batch Processing**: Process entire directories of Markdown files
- **Error Recovery**: Robust error handling with retry logic for LaTeX compilation failures
- **Complete Workflow Automation**: Single-command processing for HTML → Markdown → Split → PDF

## System Requirements

### System Dependencies

#### Pandoc
For Markdown to PDF conversion.
- **Windows**: Download from [pandoc.org](https://pandoc.org/installing.html)
- **macOS**: `brew install pandoc`
- **Linux**: `sudo apt-get install pandoc` (Ubuntu/Debian) or `sudo dnf install pandoc` (Fedora/RHEL)

#### Inkscape
For SVG to PNG conversion.
- **Windows**: Download from [inkscape.org](https://inkscape.org/release/)
- **macOS**: `brew install inkscape`
- **Linux**: `sudo apt-get install inkscape` (Ubuntu/Debian) or `sudo dnf install inkscape` (Fedora/RHEL)

#### LaTeX Distribution
For PDF generation with advanced formatting.

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

### Building from Source

#### Windows
```powershell
# Clone the repository
git clone https://github.com/knowledgenoise/gfw-helper.git
cd gfw-helper

# Build in release mode
cargo build --release

# Executable will be at target/release/gfw-helper.exe
```

#### macOS
```bash
# Clone the repository
git clone https://github.com/knowledgenoise/gfw-helper.git
cd gfw-helper

# Build in release mode
cargo build --release

# Executable will be at target/release/gfw-helper
```

#### Linux
```bash
# Clone the repository
git clone https://github.com/knowledgenoise/gfw-helper.git
cd gfw-helper

# Build in release mode
cargo build --release

# Executable will be at target/release/gfw-helper
```

### Pre-compiled Binaries
Check the [Releases](https://github.com/knowledgenoise/gfw-helper/releases) page for pre-compiled binaries.

## Usage

Main workflows:
- **HTML → Markdown → Split → PDF** (Confluence documentation)
- **JIRA JSON → Markdown → PDF** (JIRA issues)
- **Git README → Split → PDF** (Git repositories)

### 1. Convert HTML Documents to Markdown (Unified Command)

Use the unified `md` command to process employee directories (starting with `~`) or project directories:

```bash
# Automatically detect and process all directories (employee and project)
gfw-helper md /path/to/data

# Process only employee directories (starting with ~)
gfw-helper md /path/to/data --employee-only

# Process only project directories (non-employee)
gfw-helper md /path/to/data --project-only

# Specify output directory (defaults to current directory)
gfw-helper md /path/to/data --output-dir ./output
gfw-helper md /path/to/data -o results/
```

**Output:**
- Generates consolidated Markdown files in the current directory
- **Automatically copies all linked resources** (images, attachments) to companion folders
- Creates self-contained, portable document packages

**Example Output Structure:**
```
employee-name-张三-15.md           # Main Markdown file
employee-name-张三-15_files/        # Resources folder
├── screenshot.png
├── diagram.svg
└── document.pdf
```

This scans directories and automatically detects types, converting HTML files to consolidated Markdown. All referenced resources are copied and links are updated for portability.

**Automatic File Type Correction:**

The tool automatically detects file types by reading magic bytes (file signatures) and corrects extensions when copying resources. This is especially useful for files with incorrect extensions:

- ✅ **ZIP files named `.png`** → Automatically renamed to `.zip`
- ✅ **JPEG files named `.png`** → Automatically renamed to `.jpg`
- ✅ **Special ZIP formats preserved** → DOCX, XLSX, PPTX, APK, XAPK, JAR keep original extensions (not changed to .zip)
- ✅ Detection supported for: ZIP, RAR, 7z, PNG, JPEG, GIF, PDF, BMP, TIFF, WebP, GZIP, PKG (macOS installers)

**Smart ZIP Format Detection:**
- **Microsoft Office files** (DOCX, XLSX, PPTX) are ZIP-based, identified by checking for `[Content_Types].xml`
- **Android packages** (APK) are ZIP-based, identified by checking for `AndroidManifest.xml`
- **Extended Android packages** (XAPK) are ZIP-based, identified by checking for `manifest.json`
- **Java archives** (JAR) are ZIP-based, identified by checking for `META-INF/MANIFEST.MF`

The tool intelligently preserves the original extensions for these special formats.

Example output:
```
ℹ  Processing employee directory: /home/user/docs/employee/~user
  ⚠ Corrected file type: document.png -> document.zip
  ⚠ Corrected file type: image.png -> image.jpg
✓ Copied 225 resource files (including report.docx, data.xlsx, app.apk, library.jar)
  ℹ Corrected 2 file extensions based on actual file types
```

All markdown links are automatically updated to reference corrected filenames, ensuring document integrity.

### 2. Extract Git Repository README Files

Extract and process README.md files from Git repositories:

```bash
# Recursively find Git repositories and extract README files
gfw-helper git-readme /path/to/repos

# Output to specific directory
gfw-helper git-readme /path/to/repos -o ./output
```

This will:
- Recursively scan for Git repositories (directories containing `.git`)
- Extract README.md or readme.md files from each repository
- Copy all referenced images and files to `<repo-name>-files` directories
- Embed linked markdown files with adjusted header levels
- Verify file types for images and archives
- Generate `<repo-name>-README.md` files in the output directory

**Example Output Structure:**
```
output/
├── project1-README.md
├── project1-files/
│   ├── screenshot.png
│   └── diagram.svg
├── project2-README.md
└── project2-files/
    └── logo.png
```

### 3. Process JIRA Issues to Markdown

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
- Generate consolidated Markdown files sorted chronologically
- Include time cost calculations and proper formatting

### 4. Split Large Markdown Files (Optional)

If you have large Markdown files that need splitting:

```bash
# Split a single file by line count
gfw-helper split large-file.md --lines 50000

# Split all files in a directory larger than 5MB
gfw-helper split ./docs --size-threshold 5.0

# Output to specific directory
gfw-helper split large-file.md -o ./split_output
```

### 5. Convert Markdown to PDF

Convert Markdown files to high-quality PDFs with automatic image handling:

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
- **Parallel Processing**: Multiple files converted simultaneously for dramatically faster batch processing
- **Real-time Progress**: Visual progress bars showing completion percentage and statistics
- **Thread-safe Logging**: Clean, synchronized output with no interleaved messages
- Auto-resize images >4000px to prevent LaTeX errors
- WebP to PNG conversion for LaTeX compatibility
- SVG and draw.io file detection and conversion to PNG (using Inkscape)
- Format validation and corrupt image detection
- Multi-language support: Chinese (ctexart), Cyrillic/Russian (fontspec with DejaVu Sans)
- Temporary directory handling (original files unchanged)

### 6. Complete Workflow Automation

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

# Complete Git README workflow: Extract → Split → PDF
gfw-helper readme2pdf /path/to/repos -o ./readme_output
gfw-helper readme2pdf /path/to/repos --lines 30000 --engine xelatex
```

## PDF Engines

Choose the appropriate LaTeX engine based on your content:

- **`lualatex`** (recommended): Best multi-language/Unicode support, uses ctexart for Chinese and fontspec for Cyrillic/Russian
- **`xelatex`**: Good Unicode support, alternative for complex documents
- **`pdflatex`**: Basic engine, fastest but limited Unicode support

## Image Processing

The tool automatically handles images in Markdown files:

- **Auto-resizing**: Images larger than 4000px are resized to prevent LaTeX errors
- **WebP Conversion**: WebP images automatically converted to PNG for LaTeX compatibility
- **Format Conversion**: SVG files converted to PNG using Inkscape
- **Validation**: Detects and skips corrupted or invalid images with warnings
- **Aspect Ratio**: Maintains image aspect ratio when resizing

## JIRA Issue Processing

Process JIRA issue JSON exports to generate comprehensive documentation:

### Features
- **Complete Issue Extraction**: Title, description, status, priority, assignee, creator
- **Comment Processing**: Full comment history with author details and timestamps
- **Attachment Handling**: Proper links with filename preservation and URL decoding
- **Time Tracking**: Created date, updated date, and calculated days time cost
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
└── jira_export.md  # Consolidated document
```

### Example Output Format
```markdown
# OMPUB-1

**Issue Title**

* Project: Project Name | Category | System Operations
* Issue Type: Task
* Priority: High
* Creator: Author Name
* Assignee: Assignee Name
* Created: 2020-02-02T11:38:55.445+0800
* Time Cost: 19.2 days
* Status: Done
* Resolution: The workflow for this issue has been completed.

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
│   ├── employee1的主页.html
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

Processes HTML document directories and converts to Markdown. Automatically detects employee and project directories.

### JIRA Command
```bash
gfw-helper jira <parent-directory> [OPTIONS]

OPTIONS:
    -o, --output-dir <DIR>  Output directory for generated files [default: parent-directory]
```

Processes JIRA issue JSON files from the `issues` subdirectory and generates consolidated Markdown documentation.

**Features:**
- Processes JSON files in `<parent-directory>/issues/`
- Generates `jira_export.md` in the specified output directory
- Includes issue details, comments, attachments, and time tracking
- Sorts issues chronologically by creation time

### Git README Command
```bash
gfw-helper git-readme <path> [OPTIONS]

OPTIONS:
    -o, --output-dir <DIR>  Output directory for generated files [default: current directory]
```

Recursively extracts README.md files from Git repositories with linked resources.

**Features:**
- Recursively searches for Git repositories (checks for `.git` folders)
- Extracts README.md or readme.md from each repository
- Copies all referenced images and files to `<repo-name>-files` directories
- Embeds linked markdown files with adjusted header levels (## → ###)
- Verifies file types for images and archives
- Parallel processing of multiple repositories
- Generates `<repo-name>-README.md` files in output directory

### PDF Command
```bash
gfw-helper pdf <path> [OPTIONS]

OPTIONS:
    --engine <ENGINE>       PDF engine: lualatex, xelatex, pdflatex [default: lualatex]
    -o, --output-dir <DIR>  Output directory for generated files [default: current directory]
```

Converts Markdown files to PDF. Accepts single file or directory path.

**PDF Features:**
- Automatic image resizing (max 4000x4000px)
- SVG and draw.io file conversion to PNG
- Multi-language support: Chinese (ctexart), Cyrillic/Russian (fontspec with DejaVu Sans)
- Syntax highlighting using pygments
- Retry logic for LaTeX errors

### Split Command
```bash
gfw-helper split <path> [OPTIONS]

OPTIONS:
    --lines <LINES>              Lines per split file [default: 50000]
    --size-threshold <MB>        Split files larger than this size in MB [default: 2.5]
    -o, --output-dir <DIR>       Output directory for split files [default: current directory]
```

Splits large Markdown files into manageable chunks. Accepts single file or directory path.

### Complete Workflow Commands
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

Automates in a single command: HTML → Markdown → Split → PDF.

```bash
gfw-helper jira2pdf <directory> [OPTIONS]

OPTIONS:
    --lines <LINES>           Lines per split file [default: 50000]
    --size-threshold <MB>     Size threshold for splitting [default: 2.5]
    --engine <ENGINE>         PDF engine [default: lualatex]
    -o, --output-dir <DIR>    Output directory for all generated files [default: current directory]
```

Single command for JIRA workflow: JSON → Markdown → Split → PDF.

```bash
gfw-helper readme2pdf <directory> [OPTIONS]

OPTIONS:
    --lines <LINES>           Lines per split file [default: 50000]
    --size-threshold <MB>     Size threshold for splitting [default: 2.5]
    --engine <ENGINE>         PDF engine [default: lualatex]
    -o, --output-dir <DIR>    Output directory for all generated files [default: current directory]
```

Complete workflow for Git repositories: Extract README → Split → PDF.

## Development and Testing

### Running Tests

The project has comprehensive unit tests with >80% code coverage:

```bash
# Run all tests
cargo test

# Run tests with output
cargo test -- --nocapture

# Run library tests only
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
- Ensure all tools are accessible in system PATH

### Font Errors (Russian/Cyrillic Support)

**Automatic Font Detection:**
The tool automatically detects if **DejaVu Sans** is installed and uses it for enhanced Cyrillic/Russian support. If not found, it falls back to **Arial** (universally available).

**Check which font is being used:**
```bash
cargo run -- pdf your-file.md -o output --verbose
# Look for: "DejaVu Sans font detected" or "DejaVu Sans not found - using Arial"
```

**For better Cyrillic/Russian support:**
Install **DejaVu Sans** fonts - the tool will automatically detect and use them:

**Windows (Run PowerShell as Administrator):**
```powershell
# Download DejaVu Sans fonts
Invoke-WebRequest -Uri "https://github.com/dejavu-fonts/dejavu-fonts/releases/download/version_2_37/dejavu-fonts-ttf-2.37.zip" -OutFile "$env:TEMP\dejavu-fonts.zip"
Expand-Archive -Path "$env:TEMP\dejavu-fonts.zip" -DestinationPath "$env:TEMP\dejavu-fonts" -Force

# Install fonts
$fonts = Get-ChildItem "$env:TEMP\dejavu-fonts\dejavu-fonts-ttf-2.37\ttf\*.ttf"
$fontsFolder = (New-Object -ComObject Shell.Application).Namespace(0x14)
foreach ($font in $fonts) {
    $fontsFolder.CopyHere($font.FullName, 0x10)
}
Write-Host "DejaVu fonts installed. Tool will auto-detect on next run."
```

**Linux (Ubuntu/Debian):**
```bash
sudo apt update
sudo apt install fonts-dejavu fonts-dejavu-extra
fc-cache -fv
```

**Linux (Fedora/RHEL):**
```bash
sudo dnf install dejavu-sans-fonts dejavu-sans-mono-fonts
fc-cache -fv
```

**macOS:**
```bash
brew tap homebrew/cask-fonts
brew install --cask font-dejavu
```

After installation, verify:
```bash
fc-list | grep -i dejavu  # Linux/macOS
```

**Note:** No need to change code or rebuild - the tool auto-detects installed fonts at runtime.

### Common Error Messages

**"Dimension too large" (LaTeX)**
- Image is too large - the tool will automatically resize it to max 4000x4000px
- If it still fails, try manually resizing the image before conversion

**"Unable to load picture or PDF file" (LaTeX)**
- Image file may be corrupted - the tool will skip it with a warning
- Try regenerating the image or using a different format

**"File ended prematurely" (LaTeX)**
- LaTeX compilation issue - the tool has retry logic (3 attempts)
- Check that your LaTeX distribution is complete and up-to-date

## Project Structure

```
gfw-helper/
├── src/
│   ├── main.rs                  # Main entry point and PDF processing
│   ├── lib.rs                   # Library exports
│   ├── cli.rs                   # Command-line interface definition
│   ├── logger.rs                # Thread-safe logging with progress tracking
│   ├── parallel_processing.rs   # Parallel execution utilities
│   ├── utils.rs                 # Utility functions (sanitization, image resize)
│   ├── commands/
│   │   ├── mod.rs               # Command modules
│   │   ├── md.rs                # Markdown processing logic
│   │   └── git_readme.rs        # Git README generation
│   └── processing/
│       ├── mod.rs               # Processing modules
│       ├── images.rs            # Image detection and extension correction
│       └── filetype.rs          # File type verification
├── tests/                       # Integration tests
├── .github/
│   └── workflows/
│       └── ci.yml               # CI/CD pipeline for testing and coverage
├── Cargo.toml                   # Dependencies and project metadata
├── README.md                    # This file
└── README_CN.md                 # Chinese documentation
```

## CI/CD

The project uses GitHub Actions for continuous integration:

- **Testing**: Runs on Linux, Windows, and macOS for pushes and PRs
- **Code Coverage**: Generates coverage reports and uploads to Codecov
- **Linting**: Checks code formatting and runs Clippy
- **Artifacts**: Coverage HTML reports available for download

View workflow status in the [Actions tab](https://github.com/knowledgenoise/gfw-helper/actions).

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests if applicable
5. Submit a pull request

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Acknowledgements

Built with Rust, powered by Pandoc for professional document processing.
