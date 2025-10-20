use clap::{Parser, Subcommand};
use std::path::PathBuf;

#[derive(Parser, Debug)]
#[command(
    name = "gfw-helper",
    version,
    about = "A comprehensive tool for processing employee/project documentation, JIRA issues, and converting markdown to PDF.",
    long_about = r#"GFW Helper is a versatile tool designed to process documentation from employee and project directories,
automatically convert markdown files to high-quality PDFs with proper Chinese character support, process JIRA issue data,
split large files, and provide complete workflow automation.

FEATURES:
- Process employee directories (starting with ~) and generate consolidated markdown files
- Process project directories and create organized documentation
- Process JIRA issue JSON files and generate consolidated markdown with issue tracking
- Convert markdown to PDF with automatic image resizing and Chinese font support
- Split large markdown files into manageable chunks
- Complete workflow automation (HTML → Markdown → Split → PDF)
- Handle complex documents with images, tables, and code blocks
- Automatic retry logic for LaTeX compilation failures
- Support for multiple PDF engines (xelatex, pdflatex, lualatex)

PDF CONVERSION FEATURES:
- Automatic image resizing to prevent LaTeX 'Dimension too large' errors (max 4000x4000)
- Chinese character support using ctexart document class with lualatex
- Syntax highlighting with pygments
- Color links and proper margins
- Graceful handling of corrupted/invalid images
- Temporary directory management for clean processing"#,
    after_help = r##"EXAMPLES:

MARKDOWN CONVERSION:
    gfw-helper md data                                      # Process 'data' directory (auto-detect employee/project)
    gfw-helper md /path/to/docs                             # Process specific directory
    gfw-helper md /path/to/docs --employee-only             # Process only employee directories (~*)
    gfw-helper md /path/to/docs --project-only              # Process only project directories

JIRA PROCESSING:
    gfw-helper jira data                                    # Process 'data/issues' directory
    gfw-helper jira /path/to/jira                           # Process specific parent directory

PDF CONVERSION:
    gfw-helper pdf document.md                              # Convert single file
    gfw-helper pdf docs/                                    # Convert all .md files in directory
    gfw-helper pdf docs/ --engine xelatex                   # Use xelatex engine

FILE SPLITTING:
    gfw-helper split large_file.md                          # Split single file by line count
    gfw-helper split docs/                                  # Split all large .md files in directory
    gfw-helper split docs/ --lines 10000                    # Split by 10,000 lines
    gfw-helper split docs/ --size-threshold 5.0             # Split files >5MB

COMPLETE WORKFLOW:
    gfw-helper html2pdf data                                  # HTML → Markdown → Split → PDF (complete pipeline)
    gfw-helper html2pdf /path/to/docs --employee-only          # Process only employee docs
    gfw-helper html2pdf docs/ --lines 30000 --engine xelatex   # Custom split & PDF settings
    gfw-helper jira2pdf /path/to/jira/data                   # JIRA JSON → Markdown → Split → PDF

WORKFLOW EXAMPLES:
    # Individual steps (manual workflow)
    gfw-helper md data/employee --employee-only
    gfw-helper split data/employee/
    gfw-helper pdf data/employee/

    # Complete automated workflow (equivalent to above)
    gfw-helper html2pdf data/employee --employee-only

    # Process project data with custom settings
    gfw-helper html2pdf data/project --project-only --lines 30000 --engine xelatex

    # Process JIRA issues and generate documentation
    gfw-helper jira /path/to/jira/
    gfw-helper pdf jira_export.md

    # Or use complete JIRA workflow
    gfw-helper jira2pdf /path/to/jira/data
    
    # Full documentation pipeline
    gfw-helper md data/ && gfw-helper pdf data/

NOTES:
- All output files are generated in the current working directory
- Employee directories must start with '~' (e.g., ~john-doe)
- Project directories are processed recursively
- PDF conversion automatically resizes images >4000px to prevent LaTeX errors
- Chinese characters are preserved using ctexart document class
- Invalid/corrupted images are skipped with warnings
- Temporary files are automatically cleaned up after processing"#

NOTES:
- All output files are generated in the current working directory
- Employee directories must start with '~' (e.g., ~john-doe)
- Project directories are processed recursively
- PDF conversion automatically resizes images >4000px to prevent LaTeX errors
- Chinese characters are preserved using ctexart document class
- Invalid/corrupted images are skipped with warnings
- Temporary files are automatically cleaned up after processing"##
    )]
pub struct Cli {
    /// Output directory for generated files (default: current directory)
    #[arg(
        short = 'o',
        long = "output-dir",
        value_name = "DIR",
        global = true,
        help = "Output directory for generated files",
        long_help = r#"Set the output directory for all generated files.

By default, files are generated in the current working directory.
This option allows you to specify a different output location.

The directory will be created if it doesn't exist.

EXAMPLES:
  -o output/               # Output to 'output' directory
  --output-dir results/    # Output to 'results' directory
  -o ../docs/              # Output to parent's docs directory

This option works with all commands (md, pdf, split, jira, html2pdf, jira2pdf)."#
    )]
    pub output_dir: Option<PathBuf>,

    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand, Debug)]
pub enum Commands {
    /// Convert Confluence HTML exports to consolidated markdown documentation.
    ///
    /// This unified command processes both employee and project directories by extracting
    /// content from HTML files, comments, and attachments, then generating consolidated
    /// markdown files. It automatically detects the directory type and adjusts its behavior.
    ///
    /// Directory detection:
    /// - Employee directories: Start with '~' (e.g., ~john-doe, ~张三-42)
    /// - Project directories: Any other naming convention
    ///
    /// The tool extracts:
    /// - Documentation content from HTML files
    /// - Comments and discussions
    /// - Attachment files (images, documents)
    /// - Metadata and organization info
    ///
    /// Output files:
    /// - Employee: <alias>-<chinese_name>-<file_count>.md
    /// - Project: <project_name>-<file_count>.md
    #[command(
        about = "Convert Confluence HTML to markdown (auto-detects employee/project directories)",
        long_about = r#"Convert Confluence HTML exports to consolidated markdown documentation.

This command processes both employee and project documentation by:
1. Scanning directories for HTML files, comments, and attachments
2. Auto-detecting directory type (employee dirs start with '~')
3. Extracting and consolidating content
4. Correcting image file extensions (e.g., JPEG files named as .png)
5. Generating organized markdown files

DIRECTORY TYPES:
- Employee: Directories starting with '~' (e.g., ~john-doe, ~张三-42)
  Output: <alias>-<chinese_name>-<file_count>.md

- Project: All other directories
  Output: <project_name>-<file_count>.md

FEATURES:
- Automatic directory type detection
- HTML to markdown conversion
- Comment and discussion extraction
- Image file extension correction (JPEG as .png, etc.)
- Attachment linking with proper formatting
- Chinese character support
- File count tracking

FLAGS:
- --employee-only: Process only directories starting with '~'
- --project-only: Process only directories NOT starting with '~'

EXAMPLE OUTPUT:
  ~john-doe-张三-15.md (employee, 15 files)
  CyberNarrator-3620-45.md (project, 45 files)"#
    )]
    Md {
        /// Path to a file or directory to process
        #[arg(
            value_name = "PATH",
            help = "Path to a markdown file or directory containing documentation folders",
            long_help = r#"Path to process. Can be:
- A single markdown file: Process only that file
- A directory: Process all documentation folders in that directory

If a directory is provided, it will auto-detect employee/project directories.
Employee directories start with '~' (e.g., ~john-doe, ~张三-42).
Output files are generated in the current working directory."#
        )]
        path: PathBuf,

        /// Process only employee directories (starting with '~')
        #[arg(
            long,
            help = "Process only employee directories (directories starting with '~')"
        )]
        employee_only: bool,

        /// Process only project directories (NOT starting with '~')
        #[arg(
            long,
            help = "Process only project directories (directories NOT starting with '~')"
        )]
        project_only: bool,
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
- AUTOMATIC IMAGE PROCESSING: Resizes images >4000px to prevent LaTeX "Dimension too large" errors
- CHINESE CHARACTER SUPPORT: Uses ctexart document class with lualatex for proper Unicode rendering
- SYNTAX HIGHLIGHTING: Code blocks rendered with pygments
- PROFESSIONAL FORMATTING: Color links, proper margins, clean layout
- ERROR RESILIENCE: Retry logic for compilation failures, skips corrupted images
- BATCH PROCESSING: Convert entire directories of markdown files

PDF ENGINES:
  lualatex (default): Best Chinese/Unicode support, recommended for mixed content
  xelatex: Good Chinese support, faster for simple documents
  pdflatex: Basic engine, fastest but limited Chinese character support

IMAGE HANDLING:
  - Automatically resizes oversized images while maintaining aspect ratio
  - Skips corrupted/invalid images with warnings
  - Supports PNG, JPG, JPEG, and other common formats
  - Automatically detects and converts SVG content (including draw.io files) to PNG regardless of file extension
  - Temporary processing to avoid modifying original files

OUTPUT:
  PDFs are generated alongside markdown files with .pdf extension
  Example: document.md → document.pdf"#
    )]
    Pdf {
        /// Path to a markdown file or directory to convert to PDF
        #[arg(
            value_name = "PATH",
            help = "Path to a markdown file or directory to convert to PDF",
            long_help = r#"Path to convert to PDF. Can be:
- A single markdown file: Convert only that file
- A directory: Convert all .md files in that directory

PDFs are generated in the current working directory with the same name
but .pdf extension. Images are automatically resized if needed."#
        )]
        path: PathBuf,

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
- Line count: Fixed number of lines per output file
- File size: Split files exceeding size threshold
- Directory processing: Batch split multiple files

USE CASES:
- Break up large documentation for easier processing
- Create manageable chunks for PDF conversion
- Prepare files for version control limitations
- Enable parallel processing of documentation

OUTPUT NAMING:
  Original: document.md
  Parts: document_part_01.md, document_part_02.md, etc.

SPLITTING METHODS:
  By lines: Each output file contains exactly N lines
  By size: Files larger than threshold are split proportionally"#
    )]
    Split {
        /// Path to a markdown file or directory to split
        #[arg(
            value_name = "PATH",
            help = "Path to a markdown file or directory to split",
            long_help = r#"Path to split. Can be:
- A single markdown file: Split only that file
- A directory: Split all .md files in that directory that exceed the size threshold

Split files are generated in the current working directory with _part_NN suffixes."#
        )]
        path: PathBuf,

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

    /// Process JIRA issue JSON files and generate consolidated markdown documentation.
    ///
    /// This command processes JIRA issue data exported as JSON files and converts them
    /// into a single consolidated markdown file. It extracts issue details, comments,
    /// attachments, and other metadata to create comprehensive documentation.
    ///
    /// The tool processes:
    /// - Issue summaries, descriptions, and metadata
    /// - Comments with author information and timestamps
    /// - Attachments with proper linking
    /// - Project information and status details
    ///
    /// Output file is named jira_export.md in the input directory.
    #[command(
        about = "Process JIRA issue JSON files and generate consolidated markdown",
        long_about = r#"Process JIRA issue JSON files and generate consolidated markdown documentation.

This command processes JIRA issue data by:
1. Scanning for JSON files in the specified directory's 'issues' subdirectory
2. Extracting comprehensive issue details including comments, attachments, and metadata
3. Generating a consolidated markdown file named jira_export.md in the parent directory

FEATURES:
- Complete issue information extraction (title, description, status, priority, etc.)
- Comment processing with author details and timestamps
- Attachment linking with proper filename handling and URL decoding
- Project and status information with resolution details
- Issue creation and update timestamps with time cost calculations
- Proper blockquote formatting for multi-line content
- Chinese character support throughout
- Chronological sorting by issue creation time

OUTPUT FEATURES:
- Issues sorted by creation time (earliest to latest)
- Time cost calculation showing days between creation and last update
- Proper markdown formatting with blockquotes and links
- Attachment links with angle brackets for spaced filenames
- Preserved original filenames including special characters

EXAMPLE OUTPUT:
  jira_export.md (containing all processed issues with full details)"#
    )]
    Jira {
        /// Path to the directory containing the JIRA 'issues' subdirectory with JSON files
        #[arg(
            short,
            long,
            value_name = "DIR",
            default_value = "data",
            help = "Path to directory containing the JIRA 'issues' subdirectory with JSON files",
            long_help = r#"Path to the directory containing the JIRA 'issues' subdirectory with JSON files.

The program will automatically append 'issues' to the provided path to locate the JSON files.
For example, if you provide '/path/to/jira', it will look for files in '/path/to/jira/issues/'

Each JSON file should be named by issue ID (e.g., OMPUB-1343.json)
and contain the exported JIRA issue data.

Example: --path /path/to/jira (will process /path/to/jira/issues/*.json)"#
        )]
        path: PathBuf,
    },

    /// Complete workflow: Convert HTML to markdown, split large files, then generate PDFs.
    /// This command combines the md, split, and pdf commands into a single convenient workflow.
    #[command(
        about = "Complete workflow: HTML → Markdown → Split → PDF",
        long_about = r#"Complete documentation processing workflow that combines multiple steps:

1. MD: Convert Confluence HTML exports to consolidated markdown files
2. SPLIT: Split any large markdown files into manageable chunks  
3. PDF: Convert all markdown files to high-quality PDFs

This command is equivalent to running:
  gfw-helper md <path>
  gfw-helper split <path> 
  gfw-helper pdf <path>

The workflow processes employee/project directories automatically, splits oversized files,
and generates professional PDFs with proper Chinese character support.

OUTPUT:
- Markdown files in current directory (from md step)
- Split files in current directory (from split step) 
- PDF files in current directory (from pdf step)

All output files are generated in the current working directory."#
    )]
    Html2pdf {
        /// Path to the directory containing documentation folders to process
        #[arg(
            value_name = "PATH",
            help = "Path to directory containing documentation folders",
            long_help = r#"Path to the directory containing HTML export data.

This directory should contain employee/project folders with Confluence HTML exports.
Employee directories start with '~' (e.g., ~john-doe).

The complete workflow will:
1. Process all directories and generate markdown files
2. Split any markdown files larger than the default threshold
3. Convert all markdown files to PDF format"#
        )]
        path: PathBuf,

        /// Process only employee directories (starting with '~')
        #[arg(
            long,
            help = "Process only employee directories (directories starting with '~')"
        )]
        employee_only: bool,

        /// Process only project directories (NOT starting with '~')
        #[arg(
            long,
            help = "Process only project directories (directories NOT starting with '~')"
        )]
        project_only: bool,

        /// Number of lines per split file (default: 50000)
        #[arg(
            long,
            value_name = "LINES",
            default_value = "50000",
            help = "Number of lines per split file"
        )]
        lines: usize,

        /// Split files larger than this size in MB (default: 2.5)
        #[arg(
            long,
            value_name = "MB",
            default_value = "2.5",
            help = "Split files larger than this size in MB"
        )]
        size_threshold: f64,

        /// PDF engine to use for LaTeX compilation
        #[arg(
            long,
            value_name = "ENGINE",
            default_value = "lualatex",
            help = "PDF engine: lualatex (default), xelatex, or pdflatex"
        )]
        engine: String,
    },

    /// Complete workflow: JIRA JSON → Markdown → Split → PDF
    ///
    /// This command automates the entire JIRA documentation pipeline:
    /// 1. Process JIRA issue JSON files from issues/ subdirectory
    /// 2. Generate consolidated jira_export.md file
    /// 3. Split the file if it exceeds size thresholds
    /// 4. Convert to PDF with proper formatting and Chinese support
    ///
    /// This is equivalent to running:
    /// ```text
    /// gfw-helper jira /path/to/data
    /// gfw-helper split jira_export.md
    /// gfw-helper pdf jira_export.md
    /// ```
    #[command(
        about = "Complete JIRA workflow: JSON → Markdown → Split → PDF",
        long_about = r#"Complete automation for JIRA issue documentation.

This command processes JIRA issue JSON files and converts them to PDF in one step:
1. Processes JSON files from the issues/ subdirectory
2. Generates consolidated jira_export.md
3. Splits large files if needed
4. Converts to professional PDF with Chinese support

WORKFLOW:
1. JIRA Processing: Extracts issues, comments, attachments, time tracking
2. File Splitting: Splits files >2.5MB (or custom threshold)
3. PDF Conversion: Generates high-quality PDFs with lualatex

FEATURES:
- Chronological issue sorting (earliest to latest)
- Complete comment history with timestamps
- Attachment links with proper formatting
- Time cost calculations
- Chinese character support
- Syntax highlighting in PDFs

EXAMPLE:
  gfw-helper jira2pdf /path/to/jira/data
  gfw-helper jira2pdf /data --lines 30000 --engine xelatex"#
    )]
    Jira2pdf {
        /// Path to the parent directory containing issues/ subdirectory
        #[arg(
            value_name = "PATH",
            help = "Path to directory containing issues/ subdirectory with JSON files",
            long_help = r#"Path to the parent directory that contains the issues/ subdirectory.

The structure should be:
  parent-directory/
  └── issues/
      ├── PROJ-1.json
      ├── PROJ-2.json
      └── ...

The jira_export.md file will be created in the parent directory.
PDF output will also be generated in the parent directory."#
        )]
        path: PathBuf,

        /// Number of lines per split file (default: 50000)
        #[arg(
            long,
            value_name = "LINES",
            default_value = "50000",
            help = "Number of lines per split file"
        )]
        lines: usize,

        /// Split files larger than this size in MB (default: 2.5)
        #[arg(
            long,
            value_name = "MB",
            default_value = "2.5",
            help = "Split files larger than this size in MB"
        )]
        size_threshold: f64,

        /// PDF engine to use for LaTeX compilation
        #[arg(
            long,
            value_name = "ENGINE",
            default_value = "lualatex",
            help = "PDF engine: lualatex (default), xelatex, or pdflatex"
        )]
        engine: String,
    },

    /// Process Git repositories and extract README.md files.
    ///
    /// This command recursively scans for Git repositories (directories containing .git),
    /// extracts README.md or readme.md files from each repository, and copies them to the
    /// output directory with proper naming. It also handles linked resources (images, files)
    /// and embeds linked markdown files.
    ///
    /// FEATURES:
    /// - Recursive Git repository detection (searches for .git folders)
    /// - Automatic README file detection (README.md or readme.md)
    /// - Copy referenced images and files to <repo-name>-files directory
    /// - Embed linked markdown files with header level adjustment
    /// - File type verification for images and archives
    /// - Parallel processing for multiple repositories
    ///
    /// OUTPUT:
    /// - <repo-name>-README.md files in the output directory
    /// - <repo-name>-files directories for referenced resources
    #[command(
        about = "Extract README.md files from Git repositories",
        long_about = r#"Process Git repositories and extract README.md files with linked resources.

This command recursively searches for Git repositories (directories containing .git):
1. Recursively scans for Git repositories (checks for .git folders)
2. Finds README.md or readme.md files in each repository
3. Copies README files to output directory as <repo-name>-README.md
4. Processes linked images and files, copying them to <repo-name>-files
5. Embeds linked markdown files with adjusted header levels
6. Verifies actual file types (like md mode and html2pdf mode)

EMBEDDED MARKDOWN:
When a README links to another markdown file, it will be embedded inline.
All headers in the embedded markdown are pushed one level deeper:
  ## Header → ### Header
  ### Header → #### Header

FILE TYPE VERIFICATION:
Images and archives are checked for correct file types, similar to md and html2pdf modes.

EXAMPLE:
    gfw-helper git-readme /path/to/geedge/mesalab_git
    gfw-helper git-readme /path/to/repos -o output/

OUTPUT STRUCTURE:
  output/
  ├── repo1-README.md
  ├── repo1-files/
  │   ├── image1.png
  │   └── diagram.svg
  ├── repo2-README.md
  └── repo2-files/
      └── screenshot.jpg"#
    )]
    GitReadme {
        /// Path to directory containing Git repositories
        #[arg(
            value_name = "PATH",
            help = "Path to directory to search for Git repositories",
            long_help = r#"Path to the directory to search for Git repositories.

The command will recursively search for directories containing .git folders.
Each Git repository should contain a README.md or readme.md file.
The command will process each repository in parallel and extract the README files
with all linked resources."#
        )]
        path: PathBuf,
    },

    /// Complete workflow: Git README → Markdown processing → Split → PDF
    ///
    /// This command automates the entire Git repository documentation pipeline:
    /// 1. Recursively find and extract README.md files from Git repositories
    /// 2. Process and copy all linked resources
    /// 3. Split large files if needed
    /// 4. Convert to PDF with proper formatting and Chinese support
    ///
    /// This is equivalent to running:
    /// ```text
    /// gfw-helper git-readme <path>
    /// gfw-helper split <output-dir>
    /// gfw-helper pdf <output-dir>
    /// ```
    #[command(
        about = "Complete workflow: Git README → Split → PDF",
        long_about = r#"Complete automation for Git repository documentation.

This command recursively searches for Git repositories and converts READMEs to PDF in one step:
1. Recursively finds Git repositories (searches for .git folders)
2. Extracts README.md files from all Git repositories
3. Processes and embeds linked markdown files
4. Copies all referenced images and files
5. Verifies file types for images and archives
6. Splits large files if needed
7. Converts to professional PDF with Chinese support

WORKFLOW:
1. Git README Processing: Extracts and processes README files
2. File Splitting: Splits files >2.5MB (or custom threshold)
3. PDF Conversion: Generates high-quality PDFs with lualatex

FEATURES:
- Parallel processing of multiple repositories
- Embedded markdown with header adjustments
- File type verification
- Chinese character support
- Syntax highlighting in PDFs
- Failed file reporting

EXAMPLE:
    gfw-helper readme2pdf /path/to/geedge/mesalab_git
    gfw-helper readme2pdf /path/to/repos --lines 30000 --engine xelatex"#
    )]
    Readme2pdf {
        /// Path to directory to search for Git repositories
        #[arg(
            value_name = "PATH",
            help = "Path to directory to search for Git repositories",
            long_help = r#"Path to the directory to search for Git repositories.

The command will recursively search for directories containing .git folders.
Each Git repository should contain a README.md or readme.md file.
The command will:
1. Extract and process README files
2. Split large files
3. Convert to PDF

All output files are generated in the output directory."#
        )]
        path: PathBuf,

        /// Number of lines per split file (default: 50000)
        #[arg(
            long,
            value_name = "LINES",
            default_value = "50000",
            help = "Number of lines per split file"
        )]
        lines: usize,

        /// Split files larger than this size in MB (default: 2.5)
        #[arg(
            long,
            value_name = "MB",
            default_value = "2.5",
            help = "Split files larger than this size in MB"
        )]
        size_threshold: f64,

        /// PDF engine to use for LaTeX compilation
        #[arg(
            long,
            value_name = "ENGINE",
            default_value = "lualatex",
            help = "PDF engine: lualatex (default), xelatex, or pdflatex"
        )]
        engine: String,
    },
}

