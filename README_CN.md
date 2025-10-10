# GFW Helper

GFW Helper 是一个全面的工具，旨在处理geedge_docs中的员工和项目文档，并将 Markdown 文件转换为支持高级功能的高质量 PDF。

## 功能特性

- **员工/项目文档处理**：将 HTML 文档目录转换为整合的 Markdown 文件
- **高级 PDF 生成**：将 Markdown 转换为专业 PDF，自动处理图像并支持中文字符
- **文件分割**：将大型 Markdown 文件分割为可管理的块，便于处理或版本控制
- **图像优化**：自动调整超大图像尺寸，防止 LaTeX 编译错误
- **中文语言支持**：完整的 Unicode 支持，正确处理中文字符的字体
- **批量处理**：处理整个目录的 Markdown 文件
- **错误恢复**：强大的错误处理，具有 LaTeX 编译失败的重试逻辑

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

# 可执行文件将在 target\release\gfw-helper.exe
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

主要工作流程：**HTML → Markdown → 分割 → PDF**

### 1. 将 HTML 文档转换为 Markdown

处理员工目录（以 `~` 开头的目录）或项目目录：

```bash
# 处理员工目录
gfw-helper employee --path /path/to/data/directory

# 处理项目目录
gfw-helper project --path /path/to/data/directory
```

这将扫描目录并将 HTML 文件转换为整合的 Markdown 文件。

### 2. 分割大型 Markdown 文件（可选）

如果您有需要分割的大型 Markdown 文件：

```bash
# 按行数分割单个文件
gfw-helper split --path large-file.md --lines 50000

# 分割目录中所有大于 5MB 的文件
gfw-helper split --directory ./docs --size-threshold 5.0
```

### 3. 将 Markdown 转换为 PDF

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
```

## PDF 引擎

根据您的内容选择合适的 LaTeX 引擎：

- **`lualatex`** （推荐）：最佳中文/Unicode 支持，使用 ctexart 文档类
- **`xelatex`**：良好的中文支持，复杂文档的替代选择
- **`pdflatex`**：基本引擎，最快但中文字符支持有限

## 图像处理

该工具自动处理 Markdown 文件中的图像：

- **自动调整大小**：大于 4000px 的图像会被调整大小以防止 LaTeX 错误
- **格式转换**：SVG 文件使用 Inkscape 转换为 PNG
- **验证**：检测并跳过损坏或无效的图像，并显示警告
- **宽高比**：调整大小时保持图像的宽高比

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

### Employee 命令
```bash
gfw-helper employee --path <directory>
```
处理以 `~` 开头的目录并生成整合的 Markdown 文件。

### Project 命令
```bash
gfw-helper project --path <directory>
```
处理通用项目目录并生成整合的 Markdown 文件。

### PDF 命令
```bash
gfw-helper pdf [OPTIONS]

OPTIONS:
    -p, --path <FILE>        单个 Markdown 文件的路径
    -d, --directory <DIR>    要扫描 Markdown 文件的目录
    --engine <ENGINE>        PDF 引擎：lualatex、xelatex、pdflatex [默认：lualatex]
```

### Split 命令
```bash
gfw-helper split [OPTIONS]

OPTIONS:
    -p, --path <FILE>           要分割的单个 Markdown 文件路径
    -d, --directory <DIR>       要扫描分割文件的目录
    -l, --lines <LINES>         每个分割文件的行数 [默认：50000]
    -s, --size-threshold <MB>   分割大于此大小的文件（MB）[默认：2.5]
```

## 故障排除

### LaTeX 编译错误
- 确保已安装完整的 LaTeX 发行版
- 对于中文支持，请使用 `lualatex` 引擎
- 检查所有必需的 LaTeX 包是否已安装

### 图像处理问题
- 验证 Inkscape 已安装并可在 PATH 中访问
- 检查图像文件是否损坏
- 大图像（>4000px）将被自动调整大小

### 缺少依赖项
- 运行 `pandoc --version` 验证 pandoc 安装
- 运行 `inkscape --version` 验证 Inkscape 安装
- 运行 `pdflatex --version` 验证 LaTeX 安装

## 贡献

1. Fork 此仓库
2. 创建功能分支
3. 进行更改
4. 如适用，添加测试
5. 提交拉取请求

## 许可证

本项目采用 MIT 许可证 - 有关详细信息，请参阅 LICENSE 文件。

## 作者

KnowledgeNoise