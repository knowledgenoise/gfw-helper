# GFW Helper - AI Coding Agent Instructions

## Project Overview
GFW Helper is a Rust CLI tool for processing documentation workflows: HTML→Markdown→Split→PDF. It specializes in Confluence exports, JIRA processing, and LaTeX-compatible PDF generation with multi-language support (Chinese and Russian/Cyrillic).

## Architecture Patterns

### Command Structure
- **CLI Layer**: `src/cli.rs` defines all commands using clap derive macros
- **Command Handlers**: `src/commands/` contains business logic for each command (md, pdf, split, jira, etc.)
- **Processing Modules**: `src/processing/` handles specialized tasks (image detection, file type verification)
- **Utilities**: `src/utils.rs` provides image processing, markdown sanitization, and conversion helpers
- **Logger**: `src/logger.rs` provides thread-safe, colored output with progress tracking

### Key Workflows
1. **Document Processing**: HTML files → consolidated markdown → optional splitting → PDF generation
2. **Image Pipeline**: File type detection → extension correction → format conversion (WebP→PNG, SVG→PNG) → resizing for LaTeX
3. **Parallel Processing**: Directory operations use `rayon` for concurrent file processing with atomic progress counters

## Critical Developer Knowledge

### Image Processing Pipeline
- **Extension Correction**: `src/processing/images.rs::detect_and_rename_image()` fixes misnamed files (JPEG as .png)
- **Magic Bytes Detection**: Files verified by content, not extension - handles ZIP-based formats (DOCX, APK, JAR)
- **LaTeX Limits**: Images auto-resized to 4000x4000px max to prevent "Dimension too large" errors
- **Format Conversion**: WebP/SVG automatically converted to PNG for LaTeX compatibility

### LaTeX/PDF Generation
- **Engine Selection**: `lualatex` (default) for multi-language support, uses `ctexart` for Chinese and `fontspec` with DejaVu Sans for Cyrillic/Russian
- **Retry Logic**: 3-attempt retry for LaTeX compilation failures with specific error pattern matching
- **Content Sanitization**: `escape_latex_special_chars()` protects special LaTeX characters outside code blocks
- **Line Length**: `enforce_line_length()` wraps long lines to prevent LaTeX parsing issues (8000 char limit)

### Logging & Progress
- **Thread Safety**: All logging uses `OUTPUT_LOCK` mutex for clean parallel output
- **Progress Tracking**: `Logger::parallel_progress()` with atomic counters for concurrent operations
- **Verbose Mode**: `Logger::detail()` only shows in verbose mode, `Logger::set_verbose()` at startup

### Directory Processing Patterns
- **Employee Detection**: Directories starting with `~` (e.g., `~john-doe-张三-42`)
- **Output Naming**: Employee: `{alias}-{chinese_name}-{file_count}.md`, Project: `{project_name}-{file_count}.md`
- **Resource Copying**: Companion `_files/` directories for referenced assets with portable link updates

## Build & Test Commands
```bash
# Development
cargo build               # Debug build
cargo build --release     # Optimized build
cargo test                # Run all tests
cargo test -- --nocapture # Tests with output

# Code Quality
cargo fmt                 # Format code
cargo clippy -- -D warnings # Lint with warnings as errors
cargo llvm-cov --html     # Generate coverage report

# Run examples
cargo run -- md data/     # Process documentation
cargo run -- pdf docs/   # Convert to PDF
```

## Common Extension Points

### Adding New Commands
1. Add variant to `cli::Commands` enum in `src/cli.rs`
2. Create handler module in `src/commands/`
3. Add match arm in `main.rs::main()`
4. Follow existing patterns for progress reporting and error handling

### Image Format Support
- Extend `detect_and_rename_image()` with new format detection
- Add conversion logic in main processing pipeline
- Update magic bytes patterns in image processing modules

### PDF Engine Support
- Extend `build_pandoc_args()` in `main.rs` with engine-specific parameters
- Test with multi-language support requirements (Chinese, Russian/Cyrillic)
- Consider LaTeX package dependencies for new engines

## Integration Requirements
- **External Dependencies**: Pandoc (required), Inkscape (SVG conversion), LaTeX distribution
- **File System**: Heavy reliance on temporary directories for processing - ensure cleanup
- **Parallel Safety**: Use atomic counters and mutexes for any shared state in concurrent operations
- **Error Recovery**: Follow existing retry patterns for external tool failures (LaTeX, Inkscape)