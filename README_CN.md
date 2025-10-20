# GFW Helper

一个全面的工具，用于处理员工和项目文档、管理 JIRA 问题，并将 Markdown 文件转换为专业级 PDF，支持自动图像优化、中文字符支持和完整的工作流自动化等高级功能。

## 功能特性

- **统一文档处理**：自动检测员工/项目类型，将 HTML 文档目录转换为整合的 Markdown 文件
- **自包含输出**：自动复制所有链接的资源（图像、附件）到配套文件夹，生成可移植的文档包
- **JIRA 问题处理**：处理 JIRA 问题 JSON 导出并生成带有问题跟踪的整合 Markdown 文档
- **高级 PDF 生成**：将 Markdown 转换为专业 PDF，自动处理图像、支持中文字符、SVG 和 draw.io 转换
- **并行处理**：并发 HTML 到 Markdown 转换和 PDF 生成，实时进度跟踪，显著提高批量操作速度
- **优化日志**：线程安全的日志输出，带进度条和统计摘要，并行执行时输出清晰
- **文件分割**：将大型 Markdown 文件分割为可管理的块，便于处理或版本控制
- **图像优化**：自动调整超大图像尺寸，防止 LaTeX 编译错误
- **WebP 支持**：自动将 WebP 图像转换为 PNG 格式，兼容 LaTeX
- **SVG 和 Draw.io 支持**：自动检测并转换 SVG 内容和 draw.io XML 文件（即使扩展名为 PNG）为 PNG 格式
- **中文语言支持**：完整的 Unicode 支持，正确处理中文字符的字体
- **批量处理**：处理整个目录的 Markdown 文件
- **错误恢复**：强大的错误处理，具有 LaTeX 编译失败的重试逻辑
- **完整工作流自动化**：单个命令处理 HTML → Markdown → 分割 → PDF

## 系统要求

### 系统依赖

#### Pandoc
用于 Markdown 到 PDF 的转换。
- **Windows**：从 [pandoc.org](https://pandoc.org/installing.html) 下载
- **macOS**：`brew install pandoc`
- **Linux**：`sudo apt-get install pandoc` (Ubuntu/Debian) 或 `sudo dnf install pandoc` (Fedora/RHEL)

#### Inkscape
用于 SVG 到 PNG 的转换。
- **Windows**：从 [inkscape.org](https://inkscape.org/release/) 下载
- **macOS**：`brew install inkscape`
- **Linux**：`sudo apt-get install inkscape` (Ubuntu/Debian) 或 `sudo dnf install inkscape` (Fedora/RHEL)

#### LaTeX 发行版
用于具有高级格式的 PDF 生成。

**Windows：**
- 安装 MiKTeX：从 [miktex.org](https://miktex.org/download) 下载
- 或安装 TeX Live：从 [tug.org/texlive/](https://tug.org/texlive/) 下载

**macOS：**
- 安装 MacTeX：从 [tug.org/mactex/](https://tug.org/mactex/) 下载
- 或使用 Homebrew：`brew install mactex`

**Linux：**
- Ubuntu/Debian：`sudo apt-get install texlive-full`
- Fedora/RHEL：`sudo dnf install texlive-scheme-full`
- Arch Linux：`sudo pacman -S texlive-most texlive-langchinese`

### Rust
应用程序使用 Rust 编写。从 [rustup.rs](https://rustup.rs/) 安装 Rust：
```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
```

## 安装

### 从源码编译

#### Windows
```powershell
# 克隆仓库
git clone https://github.com/knowledgenoise/gfw-helper.git
cd gfw-helper

# 以发布模式编译
cargo build --release

# 可执行文件将在 target/release/gfw-helper.exe
```

#### macOS
```bash
# 克隆仓库
git clone https://github.com/knowledgenoise/gfw-helper.git
cd gfw-helper

# 以发布模式编译
cargo build --release

# 可执行文件将在 target/release/gfw-helper
```

#### Linux
```bash
# 克隆仓库
git clone https://github.com/knowledgenoise/gfw-helper.git
cd gfw-helper

# 以发布模式编译
cargo build --release

# 可执行文件将在 target/release/gfw-helper
```

### 预编译二进制文件
请查看 [Releases](https://github.com/knowledgenoise/gfw-helper/releases) 页面获取预编译二进制文件。

## 使用方法

主要工作流程：**HTML → Markdown → 分割 → PDF** 或 **JIRA JSON → Markdown → PDF**

### 1. 将 HTML 文档转换为 Markdown（统一命令）

使用统一的 `md` 命令处理员工目录（以 `~` 开头）或项目目录：

```bash
# 自动检测并处理所有目录（员工和项目）
gfw-helper md /path/to/data

# 仅处理员工目录（以 ~ 开头）
gfw-helper md /path/to/data --employee-only

# 仅处理项目目录（非员工）
gfw-helper md /path/to/data --project-only

# 指定输出目录（默认为当前目录）
gfw-helper md /path/to/data --output-dir ./output
gfw-helper md /path/to/data -o results/
```

**输出：**
- 在当前目录生成整合的 Markdown 文件
- **自动复制所有链接的资源**（图像、附件）到配套文件夹
- 创建自包含、可移植的文档包

**输出结构示例：**
```
employee-name-张三-15.md           # 主 Markdown 文件
employee-name-张三-15_files/        # 资源文件夹
├── screenshot.png
├── diagram.svg
└── document.pdf
```

这将扫描目录并自动检测类型，将 HTML 文件转换为整合的 Markdown 文件。所有引用的资源都会被复制，链接会更新以保持可移植性。

**文件类型自动修正功能：**

工具通过读取魔术字节（文件签名）自动检测文件类型，并在复制资源时修正扩展名。这对于扩展名错误的文件特别有用：

- ✅ **ZIP 文件命名为 `.png`** → 自动重命名为 `.zip`
- ✅ **JPEG 文件命名为 `.png`** → 自动重命名为 `.jpg`
- ✅ **特殊 ZIP 格式得到保留** → DOCX、XLSX、PPTX、APK、XAPK、JAR 保持原扩展名（不会改为 .zip）
- ✅ 支持检测：ZIP、RAR、7z、PNG、JPEG、GIF、PDF、BMP、TIFF、WebP、GZIP、PKG（macOS 安装包）

**智能 ZIP 格式检测：**
- **Microsoft Office 文件**（DOCX、XLSX、PPTX）基于 ZIP 格式，通过检查 `[Content_Types].xml` 识别
- **Android 包**（APK）基于 ZIP 格式，通过检查 `AndroidManifest.xml` 识别
- **扩展 Android 包**（XAPK）基于 ZIP 格式，通过检查 `manifest.json` 识别
- **Java 归档**（JAR）基于 ZIP 格式，通过检查 `META-INF/MANIFEST.MF` 识别

工具智能地保留这些特殊格式的原始扩展名。

示例输出：
```
ℹ  处理员工目录：/home/user/docs/employee/~user
  ⚠ 修正文件类型：document.png -> document.zip
  ⚠ 修正文件类型：image.png -> image.jpg
✓ 已复制 225 个资源文件（包括 report.docx、data.xlsx、app.apk、library.jar）
  ℹ 根据实际文件类型修正了 2 个文件扩展名
```

所有 markdown 链接会自动更新以引用修正后的文件名，确保文档的完整性。

### 2. 将 JIRA 问题处理为 Markdown

处理 JIRA 问题 JSON 导出并生成整合文档：

```bash
# 处理 JIRA 问题 - 查找 'issues' 子目录
gfw-helper jira /path/to/jira/data

# 输出到特定目录
gfw-helper jira /path/to/jira/data -o ./output
```

这将：
- 在 `issues` 子目录中扫描 JSON 文件
- 提取问题详情、评论、附件和元数据
- 生成按时间顺序排序的整合 Markdown 文件
- 包含时间成本计算和正确格式

### 3. 分割大型 Markdown 文件（可选）

如果您有需要分割的大型 Markdown 文件：

```bash
# 按行数分割单个文件
gfw-helper split large-file.md --lines 50000

# 分割目录中所有大于 5MB 的文件
gfw-helper split ./docs --size-threshold 5.0

# 输出到特定目录
gfw-helper split large-file.md -o ./split_output
```

### 4. 将 Markdown 转换为 PDF

将 Markdown 文件转换为高质量 PDF，自动处理图像：

```bash
# 转换单个 Markdown 文件
gfw-helper pdf document.md

# 转换目录中的所有 Markdown 文件（并行处理）
gfw-helper pdf ./docs

# 指定 LaTeX 引擎（推荐中文支持使用 lualatex）
gfw-helper pdf document.md --engine lualatex

# 输出到特定目录
gfw-helper pdf document.md -o ./pdfs
gfw-helper pdf ./docs --output-dir ./output
```

**PDF 转换功能：**
- **并行处理**：多个文件同时转换，大幅提升批量处理速度
- **实时进度**：可视化进度条显示完成百分比和统计信息
- **线程安全日志**：清晰、同步的输出，无交错信息
- 自动调整 >4000px 的图像大小以防止 LaTeX 错误
- WebP 转 PNG，兼容 LaTeX
- SVG 和 draw.io 文件检测并转换为 PNG（使用 Inkscape）
- 格式验证和损坏图像检测
- 临时目录处理（原文件不变）

### 5. 完整工作流自动化

使用 `html2pdf` 命令进行端到端处理：

```bash
# 完整管道：HTML → Markdown → 分割 → PDF
gfw-helper html2pdf /path/to/data

# 仅处理员工文档
gfw-helper html2pdf /path/to/data --employee-only

# 自定义分割设置和 PDF 引擎
gfw-helper html2pdf /path/to/data --lines 30000 --engine xelatex

# 输出到特定目录
gfw-helper html2pdf /path/to/data -o ./output
gfw-helper html2pdf /path/to/data --output-dir results/

# 完整 JIRA 工作流：JSON → Markdown → 分割 → PDF
gfw-helper jira2pdf /path/to/jira/data -o ./jira_output
```

### 4. 将 Markdown 转换为 PDF

将 Markdown 文件转换为高质量 PDF：

```bash
# 转换单个 Markdown 文件
gfw-helper pdf --path document.md

# 转换目录中的所有 Markdown 文件
gfw-helper pdf --directory ./docs

# 指定 LaTeX 引擎（推荐使用 lualatex 以获得中文支持）
gfw-helper pdf --path document.md --engine lualatex
```

### 完整工作流程示例

```bash
# 1. 将 HTML 文档处理为 Markdown
gfw-helper employee --path ./data

# 2. 分割任何大型文件（可选）
gfw-helper split --directory ./data --size-threshold 2.5

# 3. 转换为 PDF
gfw-helper pdf --directory ./data --engine lualatex

# 替代方案：处理 JIRA 问题
gfw-helper jira --path /path/to/jira/data
gfw-helper pdf --path /path/to/jira/data/jira_export.md --engine lualatex
```

## PDF 引擎

根据您的内容选择合适的 LaTeX 引擎：

- **`lualatex`** （推荐）：最佳中文/Unicode 支持，使用 ctexart 文档类
- **`xelatex`**：良好的中文支持，复杂文档的替代选择
- **`pdflatex`**：基本引擎，最快但中文字符支持有限

## 图像处理

该工具自动处理 Markdown 文件中的图像：

- **自动调整大小**：大于 4000px 的图像会被调整大小以防止 LaTeX 错误
- **WebP 转换**：WebP 图像自动转换为 PNG 以兼容 LaTeX
- **格式转换**：SVG 文件使用 Inkscape 转换为 PNG
- **验证**：检测并跳过损坏或无效的图像，并发出警告
- **纵横比**：调整大小时保持图像纵横比

## JIRA 问题处理

处理 JIRA 问题 JSON 导出以生成综合文档：

### 功能特性
- **完整问题提取**：标题、描述、状态、优先级、负责人、创建者
- **评论处理**：完整的评论历史，包括作者详情和时间戳
- **附件处理**：正确的链接，保留文件名和 URL 解码
- **时间跟踪**：创建日期、更新日期和计算的天数时间成本
- **时间顺序排序**：按创建时间排序问题（最早到最新）
- **正确格式**：块引用、链接和中文字符支持

### 输入结构
```
jira-data/
└── issues/
    ├── OMPUB-1.json
    ├── OMPUB-2.json
    ├── GIT-1.json
    └── ...
```

### 输出
```
jira-data/
└── jira_export.md  # 整合文档
```

### 输出格式示例
```markdown
# OMPUB-1

**问题标题**

* 项目: 项目名称 | 类别 | 系统运维
* 问题类型: 任务
* 优先级: High
* 创建者: 作者姓名
* 负责人: 负责人姓名
* 创建时间: 2020-02-02T11:38:55.445+0800
* 时间成本: 19.2 天
* 状态: 完成
* 解决方案: 该问题的工作流程已完成。

描述内容带有正确的块引用格式...

## 评论

* 作者姓名 - 2020-02-02T11:38:55.445+0800
        > 评论内容带有块引用格式...

* 附件:
    + [filename.pdf](<attachment\123\filename.pdf>)
        + 作者: 作者姓名
        + 创建时间: 2020-02-02T11:38:55.445+0800
```

## 目录结构

### 输入（HTML 文档）
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

### 输出（Markdown）
```
data/
├── ~employee1-employee1-15.md
└── project1-15.md
```

### 输出（PDF）
```
data/
├── ~employee1-employee1-15.pdf
└── project1-15.pdf
```

## 命令参考

### Markdown 处理命令
```bash
gfw-helper md <directory> [OPTIONS]

OPTIONS:
    --employee-only         仅处理员工目录（以 ~ 开头）
    --project-only          仅处理项目目录（非员工）
    -o, --output-dir <DIR>  生成文件的输出目录 [默认：当前目录]
```

处理 HTML 文档目录并转换为 Markdown。自动检测员工和项目目录。

### JIRA 命令
```bash
gfw-helper jira <parent-directory> [OPTIONS]

OPTIONS:
    -o, --output-dir <DIR>  生成文件的输出目录 [默认：parent-directory]
```

处理 `issues` 子目录中的 JIRA 问题 JSON 文件并生成整合的 Markdown 文档。

**功能特性：**
- 处理 `<parent-directory>/issues/` 中的 JSON 文件
- 在指定的输出目录中生成 `jira_export.md`
- 包含问题详情、评论、附件和时间跟踪
- 按创建时间顺序排序问题

### PDF 命令
```bash
gfw-helper pdf <path> [OPTIONS]

OPTIONS:
    --engine <ENGINE>       PDF 引擎：lualatex、xelatex、pdflatex [默认：lualatex]
    -o, --output-dir <DIR>  生成文件的输出目录 [默认：当前目录]
```

将 Markdown 文件转换为 PDF。接受单个文件或目录路径。

**PDF 功能：**
- 自动调整图像大小（最大 4000x4000px）
- SVG 和 draw.io 文件转换为 PNG
- 使用 ctexart 支持中文字符
- 使用 pygments 进行语法高亮
- LaTeX 错误的重试逻辑

### Split 命令
```bash
gfw-helper split <path> [OPTIONS]

OPTIONS:
    --lines <LINES>              每个分割文件的行数 [默认：50000]
    --size-threshold <MB>        分割大于此大小的文件，单位 MB [默认：2.5]
    -o, --output-dir <DIR>       分割文件的输出目录 [默认：当前目录]
```

将大型 Markdown 文件分割为可管理的块。接受单个文件或目录路径。

### 完整工作流命令
```bash
gfw-helper html2pdf <directory> [OPTIONS]

OPTIONS:
    --employee-only           仅处理员工目录
    --project-only            仅处理项目目录
    --lines <LINES>           每个分割文件的行数 [默认：50000]
    --size-threshold <MB>     分割的大小阈值 [默认：2.5]
    --engine <ENGINE>         PDF 引擎 [默认：lualatex]
    -o, --output-dir <DIR>    所有生成文件的输出目录 [默认：当前目录]
```

单个命令完成自动化：HTML → Markdown → 分割 → PDF。

```bash
gfw-helper jira2pdf <directory> [OPTIONS]

OPTIONS:
    --lines <LINES>           每个分割文件的行数 [默认：50000]
    --size-threshold <MB>     分割的大小阈值 [默认：2.5]
    --engine <ENGINE>         PDF 引擎 [默认：lualatex]
    -o, --output-dir <DIR>    所有生成文件的输出目录 [默认：当前目录]
```

单个命令完成 JIRA 工作流：JSON → Markdown → 分割 → PDF。

## 开发和测试

### 运行测试

项目具有全面的单元测试，代码覆盖率 >80%：

```bash
# 运行所有测试
cargo test

# 运行测试并显示输出
cargo test -- --nocapture

# 仅运行库测试
cargo test --lib

# 运行集成测试
cargo test --test '*'
```

### 代码覆盖率

生成代码覆盖率报告：

```bash
# 安装 cargo-llvm-cov
cargo install cargo-llvm-cov

# 生成覆盖率报告
cargo llvm-cov --html

# 打开报告
# Windows: start target/llvm-cov/html/index.html
# Linux/Mac: open target/llvm-cov/html/index.html
```

### 代码质量

```bash
# 格式化代码
cargo fmt

# 运行 linter
cargo clippy -- -D warnings

# 检查编译
cargo check
```

### 构建

```bash
# 调试构建
cargo build

# 发布构建（优化）
cargo build --release

# 不安装直接运行
cargo run -- md /path/to/data
```

## 故障排除

### LaTeX 编译错误
- 确保已安装完整的 LaTeX 发行版
- 对于中文支持，请使用 `lualatex` 引擎
- 检查所有必需的 LaTeX 包是否已安装
- 如果错误持续存在，尝试使用 `xelatex` 引擎作为替代方案

### 图像处理问题
- 验证 Inkscape 已安装并可在 PATH 中访问
- 检查图像文件是否损坏
- 大图像（>4000px）将被自动调整大小
- 具有 PNG 扩展名的 draw.io XML 文件将自动转换

### 缺少依赖项
- 运行 `pandoc --version` 验证 pandoc 安装
- 运行 `inkscape --version` 验证 Inkscape 安装
- 运行 `lualatex --version`（或 `xelatex --version`）验证 LaTeX 安装
- 确保所有工具都可在系统 PATH 中访问

### 常见错误消息

**"Dimension too large"（LaTeX）**
- 图像太大 - 工具会自动将其调整为最大 4000x4000px
- 如果仍然失败，请尝试在转换前手动调整图像大小

**"Unable to load picture or PDF file"（LaTeX）**
- 图像文件可能已损坏 - 工具将跳过它并显示警告
- 尝试重新生成图像或使用不同格式

**"File ended prematurely"（LaTeX）**
- LaTeX 编译问题 - 工具具有重试逻辑（3 次尝试）
- 检查您的 LaTeX 发行版是否完整且最新

## 项目结构

```
gfw-helper/
├── src/
│   ├── main.rs           # 主入口点和 PDF 处理
│   ├── lib.rs            # 库导出
│   ├── cli.rs            # 命令行界面定义
│   ├── utils.rs          # 实用函数（清理、图像调整）
│   ├── commands/
│   │   ├── mod.rs        # 命令模块
│   │   └── md.rs         # Markdown 处理逻辑
│   └── processing/
│       ├── mod.rs        # 处理模块
│       └── images.rs     # 图像检测和扩展名更正
├── tests/                # 集成测试（如有）
├── .github/
│   └── workflows/
│       └── ci.yml        # 测试和覆盖率的 CI/CD 管道
├── Cargo.toml            # 依赖项和项目元数据
└── README_CN.md          # 本文件
```

## CI/CD

项目使用 GitHub Actions 进行持续集成：

- **测试**：在 Linux、Windows 和 macOS 上针对推送和 PR 运行
- **代码覆盖率**：生成覆盖率报告并上传到 Codecov
- **Linting**：检查代码格式并运行 Clippy
- **工件**：覆盖率 HTML 报告可供下载

在 [Actions 选项卡](https://github.com/knowledgenoise/gfw-helper/actions)中查看工作流状态。

## 贡献

1. Fork 此仓库
2. 创建功能分支
3. 进行更改
4. 如适用，添加测试
5. 提交拉取请求

## 许可证

本项目采用 MIT 许可证 - 有关详细信息，请参阅 LICENSE 文件。

## 致谢

使用 Rust 构建，由 Pandoc 提供专业文档处理支持。
