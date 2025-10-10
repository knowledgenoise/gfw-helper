# GFW Helper

[中文版](README_CN.md)

GFW Helper is a comprehensive tool designed to process __geedge_docs__'s employee and project documents, and convert Markdown files into high-quality PDFs with advanced features.

## Features

- **Employee/Project Document Processing**: Convert HTML document directories to integrated Markdown files
- **Advanced PDF Generation**: Convert Markdown to professional PDFs with automatic image handling and Chinese character support
- **File Splitting**: Split large Markdown files into manageable chunks for easier processing or version control
- **Image Optimization**: Automatically resize oversized images to prevent LaTeX compilation errors
- **Chinese Language Support**: Full Unicode support with proper font handling for Chinese characters
- **Batch Processing**: Process entire directories of Markdown files
- **Error Recovery**: Robust error handling with retry logic for LaTeX compilation failures

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

# Executable will be in target\release\gfw-helper.exe
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

Main workflow: **HTML → Markdown → Split → PDF**

### 1. Convert HTML Documents to Markdown

Process employee directories (directories starting with `~`) or project directories:

```bash
# Process employee directory
gfw-helper employee --path /path/to/data/directory

# Process project directory
gfw-helper project --path /path/to/data/directory
```

This will scan the directory and convert HTML files to integrated Markdown files.

### 2. Split Large Markdown Files (Optional)

If you have large Markdown files that need splitting:

```bash
# Split a single file by line count
gfw-helper split --path large-file.md --lines 50000

# Split all files larger than 5MB in a directory
gfw-helper split --directory ./docs --size-threshold 5.0
```

### 3. Convert Markdown to PDF

Convert Markdown files to high-quality PDFs:

```bash
# Convert a single Markdown file
gfw-helper pdf --path document.md

# Convert all Markdown files in a directory
gfw-helper pdf --directory ./docs

# Specify LaTeX engine (lualatex recommended for Chinese support)
gfw-helper pdf --path document.md --engine lualatex
```

### Complete Workflow Example

```bash
# 1. Process HTML documents to Markdown
gfw-helper employee --path ./data

# 2. Split any large files (optional)
gfw-helper split --directory ./data --size-threshold 2.5

# 3. Convert to PDF
gfw-helper pdf --directory ./data --engine lualatex
```

## PDF Engines

Choose the appropriate LaTeX engine based on your content:

- **`lualatex`** (Recommended): Best Chinese/Unicode support, uses ctexart document class
- **`xelatex`**: Good Chinese support, alternative for complex documents
- **`pdflatex`**: Basic engine, fastest but limited Chinese character support

## Image Processing

The tool automatically handles images in Markdown files:

- **Automatic Resizing**: Images larger than 4000px are resized to prevent LaTeX errors
- **Format Conversion**: SVG files are converted to PNG using Inkscape
- **Validation**: Detects and skips corrupted or invalid images with warnings
- **Aspect Ratio**: Maintains image aspect ratio when resizing

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

### Employee Command
```bash
gfw-helper employee --path <directory>
```
Process directories starting with `~` and generate integrated Markdown files.

### Project Command
```bash
gfw-helper project --path <directory>
```
Process general project directories and generate integrated Markdown files.

### PDF Command
```bash
gfw-helper pdf [OPTIONS]

OPTIONS:
    -p, --path <FILE>        Path to a single Markdown file
    -d, --directory <DIR>    Directory to scan for Markdown files
    --engine <ENGINE>        PDF engine: lualatex, xelatex, pdflatex [default: lualatex]
```

### Split Command
```bash
gfw-helper split [OPTIONS]

OPTIONS:
    -p, --path <FILE>           Path to a single Markdown file to split
    -d, --directory <DIR>       Directory to scan for files to split
    -l, --lines <LINES>         Number of lines per split file [default: 50000]
    -s, --size-threshold <MB>   Split files larger than this size (MB) [default: 2.5]
```

## Troubleshooting

### LaTeX Compilation Errors
- Ensure a complete LaTeX distribution is installed
- For Chinese support, use the `lualatex` engine
- Check that all required LaTeX packages are installed

### Image Processing Issues
- Verify Inkscape is installed and accessible in PATH
- Check that image files are not corrupted
- Large images (>4000px) will be automatically resized

### Missing Dependencies
- Run `pandoc --version` to verify pandoc installation
- Run `inkscape --version` to verify Inkscape installation
- Run `pdflatex --version` to verify LaTeX installation

## Contributing

1. Fork this repository
2. Create a feature branch
3. Make your changes
4. Add tests if applicable
5. Submit a pull request

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Author

KnowledgeNoise
