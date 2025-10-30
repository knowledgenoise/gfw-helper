use std::fs::File;
use std::io::{Read, Seek};
use std::path::Path;
use zip::ZipArchive;

/// Checks if a ZIP file is actually a Microsoft Office document (DOCX, XLSX, PPTX).
/// Office documents are ZIP files with specific internal structure.
/// This function handles both normal and corrupted Office files by checking for
/// the [Content_Types].xml signature in the raw file bytes.
fn is_office_document(path: &Path) -> bool {
    // First check if the extension suggests it's an Office document
    if let Some(ext) = path.extension() {
        let ext_lower = ext.to_string_lossy().to_lowercase();
        if ["docx", "xlsx", "pptx", "doc", "xls", "ppt"].contains(&ext_lower.as_str()) {
            // If it has an Office extension, assume it's an Office document
            return true;
        }
    }

    // Try to read the file as a ZIP archive
    let file = match File::open(path) {
        Ok(f) => f,
        Err(_) => {
            // Can't open file, try the raw byte check below
            return is_office_by_raw_bytes(path);
        }
    };

    let mut archive = match ZipArchive::new(file) {
        Ok(a) => a,
        Err(_) => {
            // ZIP archive is corrupted, try raw byte check
            return is_office_by_raw_bytes(path);
        }
    };

    // Office documents contain specific files:
    // - [Content_Types].xml (all Office docs)
    // - word/document.xml (DOCX)
    // - xl/workbook.xml (XLSX)
    // - ppt/presentation.xml (PPTX)

    // Check for [Content_Types].xml which is present in all Office documents
    (0..archive.len()).any(|i| {
        archive.by_index(i).ok().map_or(false, |f| f.name() == "[Content_Types].xml")
    })
}

/// Helper function to detect Office files by searching for the [Content_Types].xml
/// signature in raw file bytes. This works even on corrupted or incomplete ZIP files.
fn is_office_by_raw_bytes(path: &Path) -> bool {
    let mut file = match File::open(path) {
        Ok(f) => f,
        Err(_) => return false,
    };

    // Read up to 64KB to search for [Content_Types].xml
    let mut buffer = vec![0u8; 65536];
    let bytes_read = match file.read(&mut buffer) {
        Ok(n) => n,
        Err(_) => return false,
    };

    if bytes_read == 0 {
        return false;
    }

    // Search for "[Content_Types].xml" signature (17 bytes)
    // This string appears near the beginning of Office documents
    let search_bytes = b"[Content_Types].xml";
    buffer[..bytes_read]
        .windows(search_bytes.len())
        .any(|window| window == search_bytes)
}

/// Detects the specific Office document format (DOCX, XLSX, or PPTX)
/// by looking for format-specific files in the archive.
fn detect_office_format(path: &Path) -> Option<String> {
    // If it already has an Office extension, return it
    if let Some(ext) = path.extension() {
        let ext_lower = ext.to_string_lossy().to_lowercase();
        match ext_lower.as_str() {
            "docx" | "doc" => return Some("docx".to_string()),
            "xlsx" | "xls" => return Some("xlsx".to_string()),
            "pptx" | "ppt" => return Some("pptx".to_string()),
            _ => {}
        }
    }

    // Try to read the ZIP archive and look for format-specific files
    let file = match File::open(path) {
        Ok(f) => f,
        Err(_) => {
            // If we can't open as ZIP, try raw byte search
            return detect_office_format_by_raw_bytes(path);
        }
    };

    let mut archive = match ZipArchive::new(file) {
        Ok(a) => a,
        Err(_) => {
            // If ZIP is corrupted, try raw byte search
            return detect_office_format_by_raw_bytes(path);
        }
    };

    // Check for format-specific files in the archive
    let files: Vec<String> = (0..archive.len())
        .filter_map(|i| archive.by_index(i).ok().map(|f| f.name().to_string()))
        .collect();

    // DOCX: contains word/document.xml
    if files.iter().any(|f| f.starts_with("word/")) {
        return Some("docx".to_string());
    }

    // XLSX: contains xl/workbook.xml
    if files.iter().any(|f| f.starts_with("xl/")) {
        return Some("xlsx".to_string());
    }

    // PPTX: contains ppt/presentation.xml
    if files.iter().any(|f| f.starts_with("ppt/")) {
        return Some("pptx".to_string());
    }

    // Default to XLSX if we can't determine (most common for corrupted Office files)
    Some("xlsx".to_string())
}

/// Helper to detect Office format by searching for format-specific signatures in raw bytes.
/// This works on corrupted or incomplete Office files.
fn detect_office_format_by_raw_bytes(path: &Path) -> Option<String> {
    let mut file = match File::open(path) {
        Ok(f) => f,
        Err(_) => return None,
    };

    let mut buffer = vec![0u8; 65536];
    let bytes_read = match file.read(&mut buffer) {
        Ok(n) => n,
        Err(_) => return None,
    };

    if bytes_read == 0 {
        return None;
    }

    let text = String::from_utf8_lossy(&buffer[..bytes_read]);

    // Search for format-specific markers
    if text.contains("word/") {
        return Some("docx".to_string());
    }
    if text.contains("xl/") {
        return Some("xlsx".to_string());
    }
    if text.contains("ppt/") {
        return Some("pptx".to_string());
    }

    // Default to XLSX if we detect Office but can't determine format
    Some("xlsx".to_string())
}

/// Checks if a ZIP file is actually an APK (Android Package) file.
/// APK files are ZIP files that contain AndroidManifest.xml.
fn is_apk_file(path: &Path) -> bool {
    let file = match File::open(path) {
        Ok(f) => f,
        Err(_) => return false,
    };

    let mut archive = match ZipArchive::new(file) {
        Ok(a) => a,
        Err(_) => return false,
    };

    // APK files always contain AndroidManifest.xml at the root
    (0..archive.len()).any(|i| {
        archive.by_index(i).ok().map_or(false, |f| f.name() == "AndroidManifest.xml")
    })
}

/// Checks if a ZIP file is actually an XAPK (Extended Android Package) file.
/// XAPK files are ZIP files that contain manifest.json.
fn is_xapk_file(path: &Path) -> bool {
    let file = match File::open(path) {
        Ok(f) => f,
        Err(_) => return false,
    };

    let mut archive = match ZipArchive::new(file) {
        Ok(a) => a,
        Err(_) => return false,
    };

    // XAPK files contain manifest.json at the root
    (0..archive.len()).any(|i| {
        archive.by_index(i).ok().map_or(false, |f| f.name() == "manifest.json")
    })
}

/// Checks if a ZIP file is actually a JAR (Java Archive) file.
/// JAR files are ZIP files that contain META-INF/MANIFEST.MF.
fn is_jar_file(path: &Path) -> bool {
    let file = match File::open(path) {
        Ok(f) => f,
        Err(_) => return false,
    };

    let mut archive = match ZipArchive::new(file) {
        Ok(a) => a,
        Err(_) => return false,
    };

    // JAR files always contain META-INF/MANIFEST.MF
    (0..archive.len()).any(|i| {
        archive.by_index(i).ok().map_or(false, |f| f.name() == "META-INF/MANIFEST.MF")
    })
}

/// Checks if a file is actually a PKG (macOS installer package) file.
/// Some PKG files are ZIP-based flat packages, while others use XAR format.
/// We check the file extension to preserve PKG files.
fn is_pkg_file(path: &Path) -> bool {
    if let Some(ext) = path.extension() {
        ext.to_string_lossy().to_lowercase() == "pkg"
    } else {
        false
    }
}

/// Checks if a file is an EDDX (Edraw) file.
/// EDDX files are ZIP-based but should keep their .eddx extension.
fn is_eddx_file(path: &Path) -> bool {
    if let Some(ext) = path.extension() {
        ext.to_string_lossy().to_lowercase() == "eddx"
    } else {
        false
    }
}

/// Checks if a file is an XMIND (mind mapping) file.
/// XMIND files are ZIP-based but should keep their .xmind extension.
fn is_xmind_file(path: &Path) -> bool {
    if let Some(ext) = path.extension() {
        ext.to_string_lossy().to_lowercase() == "xmind"
    } else {
        false
    }
}

/// Checks if a file is a text configuration file (Cisco, network device configs, etc.)
/// These files start with configuration markers like "!" or "version" and contain
/// network/system configuration commands.
fn is_config_file(buffer: &[u8]) -> bool {
    if buffer.is_empty() {
        return false;
    }

    // Convert first bytes to string for checking
    if let Ok(text) = String::from_utf8(buffer[0..std::cmp::min(256, buffer.len())].to_vec()) {
        // Cisco configuration files typically start with "!" (Cisco comment/header marker)
        // Examples: "!Command:", "!Running configuration", "!interface", etc.
        if text.trim_start().starts_with('!') {
            return true;
        }

        // Check for common config file patterns
        let lines: Vec<&str> = text.lines().take(5).collect();
        for line in lines {
            let trimmed = line.trim();
            // Cisco/network device config patterns
            if trimmed.starts_with("version ")
                || trimmed.starts_with("hostname ")
                || trimmed.starts_with("interface ")
                || trimmed.starts_with("feature ")
                || trimmed.starts_with("vlan ")
                || trimmed.starts_with("vrf context")
                || trimmed.starts_with("ip domain-lookup")
                || trimmed.starts_with("spanning-tree")
                || trimmed.starts_with("username ")
                || trimmed.starts_with("snmp-server")
                || trimmed.starts_with("ip route")
                || trimmed.starts_with("route ")
                || trimmed.starts_with("bgp ")
                || trimmed.starts_with("router ")
                || trimmed.starts_with("access-list")
                || trimmed.starts_with("permit ")
                || trimmed.starts_with("deny ")
            {
                return true;
            }
        }
    }

    false
}

/// Checks if a file is a text file with UTF-8 BOM (Byte Order Mark).
/// These are typically plain text files saved with UTF-8 BOM encoding.
/// UTF-8 BOM starts with bytes EF BB BF
fn is_utf8_bom_text_file(buffer: &[u8]) -> bool {
    if buffer.len() < 3 {
        return false;
    }

    // Check for UTF-8 BOM: EF BB BF
    if buffer[0] == 0xEF && buffer[1] == 0xBB && buffer[2] == 0xBF {
        // It has a UTF-8 BOM, assume it's a text file
        // The actual content after the BOM should be readable text
        if buffer.len() > 3 {
            // Try to decode the content after BOM as UTF-8 to verify it's text
            if let Ok(text) = String::from_utf8(buffer[3..std::cmp::min(256, buffer.len())].to_vec()) {
                // Check if it looks like text (mostly printable characters)
                let printable_ratio = text
                    .chars()
                    .filter(|c| c.is_ascii_graphic() || c.is_whitespace())
                    .count() as f32
                    / text.len() as f32;
                
                return printable_ratio > 0.8; // At least 80% printable characters
            }
        }
    }
    
    false
}

/// Checks if a file is a shell script (bash, sh, etc.)
/// Shell scripts start with a shebang line like #!/bin/bash, #!/bin/sh, etc.
fn is_shell_script(buffer: &[u8]) -> bool {
    if buffer.len() < 4 {
        return false;
    }

    // Check for shebang: #! (0x23 0x21)
    if buffer[0] != 0x23 || buffer[1] != 0x21 {
        return false;
    }

    // Check if it's followed by a shell path
    if let Ok(text) = String::from_utf8(buffer[0..std::cmp::min(256, buffer.len())].to_vec()) {
        let first_line = text.lines().next().unwrap_or("");
        // Look for common shell shebangs
        if first_line.contains("/bin/bash")
            || first_line.contains("/bin/sh")
            || first_line.contains("/bin/zsh")
            || first_line.contains("/bin/dash")
            || first_line.contains("/usr/bin/env bash")
            || first_line.contains("/usr/bin/env sh")
        {
            return true;
        }
    }

    false
}

/// Checks if a file is a Microsoft Word XML document.
/// These are the older Word XML format (not ZIP-based .docx), identified by
/// the <?mso-application progid="Word.Document"?> processing instruction.
fn is_word_xml_file(buffer: &[u8]) -> bool {
    if buffer.is_empty() {
        return false;
    }

    if let Ok(text) = String::from_utf8(buffer[0..std::cmp::min(512, buffer.len())].to_vec()) {
        let text_lower = text.to_lowercase();
        // Check for Microsoft Office XML markers
        // Word XML: <?mso-application progid="Word.Document"?>
        // Excel XML: <?mso-application progid="Excel.Sheet"?>
        // PowerPoint XML: <?mso-application progid="PowerPoint.Show"?>
        if text_lower.contains("<?mso-application") {
            if text_lower.contains("word.document") {
                return true;
            }
            // Could extend to detect Excel/PowerPoint XML if needed
            if text_lower.contains("excel.sheet") || text_lower.contains("powerpoint.show") {
                return true;
            }
        }
    }

    false
}

/// Checks if a file is an SVG (Scalable Vector Graphics) file.
/// SVG files are XML-based and contain an <svg> root element.
fn is_svg_file(buffer: &[u8]) -> bool {
    if buffer.is_empty() {
        return false;
    }

    if let Ok(text) = String::from_utf8(buffer[0..std::cmp::min(1024, buffer.len())].to_vec()) {
        let text_lower = text.to_lowercase();
        // Check for SVG markers: <svg tag or <?xml with svg
        // SVG files typically start with <?xml or directly with <svg
        if text_lower.contains("<svg") || (text_lower.contains("<?xml") && text_lower.contains("<svg")) {
            return true;
        }
        
        // Check for draw.io XML format (starts with <mxfile)
        // draw.io is an SVG-based diagram tool that produces XML files
        if text_lower.contains("<mxfile") {
            return true;
        }
    }

    false
}

/// Checks if a file is a YAML file.
/// YAML files use key: value syntax and may start with --- document separator.
fn is_yaml_file(buffer: &[u8]) -> bool {
    if buffer.is_empty() {
        return false;
    }

    if let Ok(text) = String::from_utf8(buffer[0..std::cmp::min(512, buffer.len())].to_vec()) {
        let lines: Vec<&str> = text.lines().take(10).collect();
        let mut yaml_score = 0;
        let mut has_yaml_syntax = false;

        for line in lines {
            let trimmed = line.trim();
            
            // Skip empty lines
            if trimmed.is_empty() {
                continue;
            }
            
            // YAML document separator
            if trimmed == "---" || trimmed == "..." {
                yaml_score += 3;
                has_yaml_syntax = true;
                continue;
            }
            
            // YAML comment (starts with #)
            if trimmed.starts_with('#') {
                yaml_score += 1;
                continue;
            }
            
            // YAML key: value pattern (colon followed by space or newline)
            // This is the key difference from properties files which use =
            // Don't match if the line also contains = (that's properties format)
            // Don't match if it contains ": (that's JSON format like "key": "value")
            if trimmed.contains(':') && !trimmed.contains('=') && !trimmed.contains("\":") && !trimmed.starts_with('-') {
                let parts: Vec<&str> = trimmed.splitn(2, ':').collect();
                if parts.len() == 2 {
                    let key = parts[0].trim();
                    let value = parts[1].trim();
                    // YAML keys shouldn't contain spaces (unless quoted)
                    // and value is separated by colon-space
                    if !key.is_empty() && (value.is_empty() || parts[1].starts_with(' ')) {
                        yaml_score += 2;
                        has_yaml_syntax = true;
                    }
                }
            }
        }

        // Require both score and actual YAML syntax (not just comments)
        // This prevents properties files with # comments from being misidentified
        yaml_score >= 2 && has_yaml_syntax
    } else {
        false
    }
}

/// Checks if a file is a properties file (Java properties, QA automation, etc.)
/// Properties files contain key=value pairs with optional # comments.
fn is_properties_file(buffer: &[u8]) -> bool {
    if buffer.is_empty() {
        return false;
    }

    if let Ok(text) = String::from_utf8(buffer[0..std::cmp::min(512, buffer.len())].to_vec()) {
        let lines: Vec<&str> = text.lines().take(10).collect();
        let mut properties_score = 0;

        for line in lines {
            let trimmed = line.trim();
            
            // Skip empty lines
            if trimmed.is_empty() {
                continue;
            }
            
            // Check for comment lines (# or !)
            if trimmed.starts_with('#') || trimmed.starts_with('!') {
                properties_score += 1;
                continue;
            }
            
            // Check for key=value pattern
            if trimmed.contains('=') && !trimmed.starts_with('[') {
                // Should have alphanumeric/underscore/dot in key part
                let parts: Vec<&str> = trimmed.splitn(2, '=').collect();
                if parts.len() == 2 {
                    let key = parts[0].trim();
                    if key.chars().all(|c| c.is_alphanumeric() || c == '_' || c == '.' || c == '-') {
                        properties_score += 2;
                    }
                }
            }
        }

        // If we found comments and key=value pairs, likely a properties file
        properties_score >= 2
    } else {
        false
    }
}

/// Detects the actual file type by reading magic bytes from the file header.
/// Returns the appropriate file extension based on the detected type.
///
/// # Arguments
/// * `path` - Path to the file to analyze
///
/// # Returns
/// * `Some(extension)` - The detected file extension (e.g., "zip", "png", "jpg")
/// * `None` - If the file type cannot be determined
pub fn detect_file_type(path: &Path) -> Option<String> {
    let mut file = File::open(path).ok()?;
    // Read first 32 bytes for magic number detection
    // But we'll read more if needed for text-based format detection
    let mut buffer = vec![0u8; 32];

    let bytes_read = file.read(&mut buffer).ok()?;
    if bytes_read < 4 {
        return None;
    }

    // Check magic bytes to identify file type
    match &buffer[0..4] {
        // ZIP archive (PK\x03\x04 or PK\x05\x06 for empty archives)
        // BUT: Check if it's actually a special ZIP-based format first
        [0x50, 0x4B, 0x03, 0x04] | [0x50, 0x4B, 0x05, 0x06] => {
            // Check for APK (Android Package)
            if is_apk_file(path) {
                return Some("apk".to_string()); // Correct to .apk extension
            }

            // Check for XAPK (Extended Android Package)
            if is_xapk_file(path) {
                return Some("xapk".to_string()); // Correct to .xapk extension
            }

            // Check for JAR (Java Archive)
            if is_jar_file(path) {
                return Some("jar".to_string()); // Correct to .jar extension
            }

            // Check for Office documents (DOCX, XLSX, PPTX)
            // Even if it's misnamed (e.g., as .png), suggest the correct Office extension
            if is_office_document(path) {
                // Determine which Office format it is by checking internal structure
                if let Some(office_format) = detect_office_format(path) {
                    return Some(office_format);
                }
                return None; // Let it keep its original extension if we can't determine format
            }

            // Check for PKG (macOS installer - some use ZIP format)
            if is_pkg_file(path) {
                return None; // Let it keep its .pkg extension
            }

            // Check for EDDX (Edraw files)
            if is_eddx_file(path) {
                return None; // Let it keep its .eddx extension
            }

            // Check for XMIND (mind mapping files)
            if is_xmind_file(path) {
                return None; // Let it keep its .xmind extension
            }

            // Regular ZIP file
            Some("zip".to_string())
        }

        // PNG (89 50 4E 47)
        [0x89, 0x50, 0x4E, 0x47] => Some("png".to_string()),

        // JPEG (FF D8 FF)
        [0xFF, 0xD8, 0xFF, _] => Some("jpg".to_string()),

        // GIF (GIF87a or GIF89a)
        [0x47, 0x49, 0x46, 0x38] if bytes_read >= 6 && (buffer[4] == 0x37 || buffer[4] == 0x39) => {
            Some("gif".to_string())
        }

        // PDF (%PDF)
        [0x25, 0x50, 0x44, 0x46] => Some("pdf".to_string()),

        // RAR archive (Rar!\x1A\x07)
        [0x52, 0x61, 0x72, 0x21] => Some("rar".to_string()),

        // 7z archive (37 7A BC AF 27 1C)
        [0x37, 0x7A, 0xBC, 0xAF] if bytes_read >= 6 => Some("7z".to_string()),

        // GZIP (1F 8B)
        [0x1F, 0x8B, _, _] => Some("gz".to_string()),

        // BMP (42 4D)
        [0x42, 0x4D, _, _] => Some("bmp".to_string()),

        // TIFF (Little Endian: 49 49 2A 00, Big Endian: 4D 4D 00 2A)
        [0x49, 0x49, 0x2A, 0x00] | [0x4D, 0x4D, 0x00, 0x2A] => Some("tiff".to_string()),

        // WebP (RIFF....WEBP)
        [0x52, 0x49, 0x46, 0x46] if bytes_read >= 12 && &buffer[8..12] == b"WEBP" => {
            Some("webp".to_string())
        }

        // PKG (macOS installer packages use XAR format: xar!)
        [0x78, 0x61, 0x72, 0x21] => Some("pkg".to_string()),

        // DEB package (Debian/Ubuntu package files use 'ar' archive format: !<arch>)
        // Magic bytes: 21 3C 61 72 63 68 3E ("!<arch>")
        [0x21, 0x3C, 0x61, 0x72] if bytes_read >= 8 && &buffer[4..8] == b"ch>\n" => {
            // Don't suggest changing .deb files - they should keep their extension
            if let Some(ext) = path.extension() {
                let ext_str = ext.to_string_lossy().to_lowercase();
                if ext_str == "deb" {
                    return None;
                }
            }
            Some("deb".to_string())
        }

        // PCAP (Wireshark network capture file)
        // PCAPNG format: 0A 0D 0D 0A (magic number for section header block)
        [0x0A, 0x0D, 0x0D, 0x0A] => Some("pcapng".to_string()),

        // PCAP format (global header): A1 B2 C3 D4 (big-endian) or D4 C3 B2 A1 (little-endian)
        [0xA1, 0xB2, 0xC3, 0xD4] | [0xD4, 0xC3, 0xB2, 0xA1] => Some("pcap".to_string()),

        // JSON file (starts with { or [, often misnamed as .png by Confluence/draw.io)
        // BUT: Don't suggest changing .txt files to .json
        [0x7B, ..] | [0x5B, ..] => {
            // Don't change .txt files to .json even if they contain JSON content
            if let Some(ext) = path.extension() {
                if ext.to_string_lossy().to_lowercase() == "txt" {
                    return None;
                }
            }

            // Verify it's actually JSON by checking for common JSON patterns
            if bytes_read >= 20 {
                let text = String::from_utf8_lossy(&buffer[0..bytes_read]);
                // Check if it looks like JSON structure
                if text.trim_start().starts_with('{') || text.trim_start().starts_with('[') {
                    // Look for JSON patterns like "key": or {"
                    if text.contains("\":") || text.contains("\": ") || text.contains("{\"") {
                        return Some("json".to_string());
                    }
                }
            }
            None
        }

        _ => {
            // For text-based file detection, we need more data than just the first 32 bytes
            // Read up to 4KB for better pattern matching
            let mut extended_buffer = vec![0u8; 4096];
            file.seek(std::io::SeekFrom::Start(0)).ok()?;
            let extended_bytes_read = file.read(&mut extended_buffer).ok()?;
            
            // Check for email files (EML/MIME format)
            // Email files typically start with headers like "Received:", "From:", "X-", etc.
            if bytes_read >= 32 {
                let text = String::from_utf8_lossy(&buffer[0..bytes_read]);
                let first_line = text.lines().next().unwrap_or("").trim();
                
                // Check for common email headers
                if first_line.starts_with("Received:") 
                    || first_line.starts_with("From:") 
                    || first_line.starts_with("X-") 
                    || first_line.starts_with("Return-Path:")
                    || first_line.starts_with("Delivered-To:") {
                    // Don't suggest changing .eml or .txt files
                    if let Some(ext) = path.extension() {
                        let ext_str = ext.to_string_lossy().to_lowercase();
                        if ext_str == "eml" || ext_str == "txt" {
                            return None;
                        }
                    }
                    return Some("eml".to_string());
                }
            }
            
            // Check for UTF-8 BOM text files
            // These are typically plain text files saved with UTF-8 BOM encoding
            if is_utf8_bom_text_file(&buffer) {
                // Don't suggest changing .txt files
                if let Some(ext) = path.extension() {
                    let ext_str = ext.to_string_lossy().to_lowercase();
                    if ext_str == "txt" || ext_str == "dat" || ext_str == "csv" {
                        return None;
                    }
                }
                return Some("txt".to_string());
            }
            
            // Check for configuration files (Cisco, network device configs, etc.)
            // These have patterns like "!Command:", "version X.Y", "interface", etc.
            if is_config_file(&buffer) {
                // Don't suggest changing .txt or .conf files
                if let Some(ext) = path.extension() {
                    let ext_str = ext.to_string_lossy().to_lowercase();
                    if ext_str == "txt" || ext_str == "conf" || ext_str == "config" {
                        return None;
                    }
                }
                return Some("txt".to_string());
            }
            
            // Check for shell scripts (bash, sh, etc.)
            // Shell scripts start with shebang: #!/bin/bash, #!/bin/sh, etc.
            if is_shell_script(&buffer) {
                // Don't suggest changing .sh or .txt files
                if let Some(ext) = path.extension() {
                    let ext_str = ext.to_string_lossy().to_lowercase();
                    if ext_str == "sh" || ext_str == "bash" || ext_str == "txt" || ext_str == "script" {
                        return None;
                    }
                }
                return Some("sh".to_string());
            }
            
            // Check for Microsoft Word XML documents
            // These are older Word XML format files (not ZIP-based .docx)
            // Identified by <?mso-application progid="Word.Document"?> marker
            // NOTE: Must be checked BEFORE SVG since both are XML-based
            if is_word_xml_file(&extended_buffer[0..extended_bytes_read.min(512)]) {
                // Don't suggest changing .xml, .docx, or .doc files
                if let Some(ext) = path.extension() {
                    let ext_str = ext.to_string_lossy().to_lowercase();
                    if ext_str == "xml" || ext_str == "docx" || ext_str == "doc" {
                        return None;
                    }
                }
                // Suggest .xml extension for Word XML files (not .docx which is ZIP-based)
                return Some("xml".to_string());
            }
            
            // Check for SVG files (Scalable Vector Graphics)
            // SVG files are XML-based and contain <svg> tags
            // NOTE: Must be checked BEFORE properties since SVG attributes contain = signs
            // Use extended buffer for better pattern detection
            if is_svg_file(&extended_buffer[0..extended_bytes_read.min(4096)]) {
                // Don't suggest changing .svg files - they should remain as SVG
                // SVG files will be converted to PNG during image processing
                if let Some(ext) = path.extension() {
                    let ext_str = ext.to_string_lossy().to_lowercase();
                    if ext_str == "svg" {
                        return None;
                    }
                }
                return Some("svg".to_string());
            }
            
            // Check for YAML files (YAML Ain't Markup Language)
            // YAML files use key: value syntax (colon-space, not equals)
            // NOTE: Must be checked BEFORE properties since both can have # comments
            // Use extended buffer for better pattern detection
            if is_yaml_file(&extended_buffer[0..extended_bytes_read.min(4096)]) {
                // Don't suggest changing .yaml or .yml files
                if let Some(ext) = path.extension() {
                    let ext_str = ext.to_string_lossy().to_lowercase();
                    if ext_str == "yaml" || ext_str == "yml" {
                        return None;
                    }
                }
                return Some("yaml".to_string());
            }
            
            // Check for properties files (Java properties, QA automation, etc.)
            // Properties files contain key=value pairs with optional # comments
            // NOTE: Must be checked AFTER shell scripts, SVG, and YAML since they can contain = or #
            // Use extended buffer for better pattern detection
            if is_properties_file(&extended_buffer[0..extended_bytes_read.min(4096)]) {
                // Don't suggest changing .properties or .txt files
                if let Some(ext) = path.extension() {
                    let ext_str = ext.to_string_lossy().to_lowercase();
                    if ext_str == "properties" || ext_str == "txt" || ext_str == "conf" {
                        return None;
                    }
                }
                return Some("properties".to_string());
            }
            
            // Check for CSV files (text files with comma-separated values)
            // CSV files don't have magic bytes, so we check content patterns
            // NOTE: Must be checked AFTER shell scripts and properties since they can contain commas
            if extended_bytes_read >= 20 {
                let text = String::from_utf8_lossy(&extended_buffer[0..extended_bytes_read]);
                // Check for CSV patterns: contains commas and looks like structured data
                // Typical pattern: header row with comma-separated field names
                if text.contains(',') && !text.contains("\":") {
                    let first_line = text.lines().next().unwrap_or("");
                    // Check if it looks like a CSV header (multiple commas, alphanumeric + underscores)
                    let comma_count = first_line.matches(',').count();
                    if comma_count >= 2 {
                        // Check if first line contains typical CSV header characters
                        // Support both ASCII and non-ASCII encodings (UTF-8, GBK, etc.)
                        let has_alpha = first_line
                            .chars()
                            .any(|c| c.is_alphabetic() || c.is_numeric() || c == '_');
                        
                        // Calculate printability based on character count, not byte count
                        // (Important for multi-byte encodings like UTF-8, GBK, etc.)
                        let char_count = first_line.chars().count();
                        let printable_count = first_line
                            .chars()
                            .filter(|c| {
                                // Accept printable ASCII, common punctuation, and non-ASCII Unicode characters
                                c.is_ascii_graphic() 
                                || c.is_ascii_whitespace() 
                                || !c.is_ascii()  // Allow non-ASCII (including Chinese, etc.)
                                || *c == '\n' 
                                || *c == '\r'
                            })
                            .count();
                        let mostly_printable = printable_count as f32 / char_count as f32 > 0.7;

                        if has_alpha && mostly_printable {
                            // Don't suggest changing .txt or .csv files
                            if let Some(ext) = path.extension() {
                                let ext_str = ext.to_string_lossy().to_lowercase();
                                if ext_str == "txt" || ext_str == "csv" {
                                    return None;
                                }
                            }
                            return Some("csv".to_string());
                        }
                    }
                }
            }
            None
        }
    }
}

/// Gets the correct file extension for a file, detecting mismatches.
/// If the actual file type doesn't match the current extension, returns the correct one.
/// Also handles files with no extension by detecting the type and returning the correct extension.
///
/// # Arguments
/// * `path` - Path to the file
///
/// # Returns
/// * `Some(extension)` - The correct extension if mismatch is detected or file has no extension
/// * `None` - If extension matches or type cannot be determined
pub fn get_corrected_extension(path: &Path) -> Option<String> {
    let detected_ext = detect_file_type(path)?;

    // Check if file has an extension
    if let Some(current_ext) = path.extension() {
        let current_ext_str = current_ext.to_str()?.to_lowercase();

        // Special case: .tgz files are gzipped tar archives, don't change to .gz
        if current_ext_str == "tgz" && detected_ext == "gz" {
            return None;
        }

        // If extensions don't match, return the correct one
        if current_ext_str != detected_ext {
            return Some(detected_ext);
        } else {
            return None;
        }
    } else {
        // File has no extension, so return the detected extension
        // This handles files like "temp_0" or "image_0" that should get proper extensions
        return Some(detected_ext);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::io::Write;
    use tempfile::TempDir;

    #[test]
    fn test_detect_zip_file() {
        let temp_dir = TempDir::new().unwrap();
        let zip_path = temp_dir.path().join("test.zip");

        // Create a minimal ZIP file (PK header)
        let mut file = File::create(&zip_path).unwrap();
        file.write_all(&[0x50, 0x4B, 0x03, 0x04]).unwrap();

        let detected = detect_file_type(&zip_path);
        assert_eq!(detected, Some("zip".to_string()));
    }

    #[test]
    fn test_detect_png_file() {
        let temp_dir = TempDir::new().unwrap();
        let png_path = temp_dir.path().join("test.png");

        // PNG magic bytes
        let mut file = File::create(&png_path).unwrap();
        file.write_all(&[0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A])
            .unwrap();

        let detected = detect_file_type(&png_path);
        assert_eq!(detected, Some("png".to_string()));
    }

    #[test]
    fn test_detect_jpeg_file() {
        let temp_dir = TempDir::new().unwrap();
        let jpg_path = temp_dir.path().join("test.jpg");

        // JPEG magic bytes
        let mut file = File::create(&jpg_path).unwrap();
        file.write_all(&[0xFF, 0xD8, 0xFF, 0xE0]).unwrap();

        let detected = detect_file_type(&jpg_path);
        assert_eq!(detected, Some("jpg".to_string()));
    }

    #[test]
    fn test_detect_pdf_file() {
        let temp_dir = TempDir::new().unwrap();
        let pdf_path = temp_dir.path().join("test.pdf");

        // PDF magic bytes
        let mut file = File::create(&pdf_path).unwrap();
        file.write_all(b"%PDF-1.4").unwrap();

        let detected = detect_file_type(&pdf_path);
        assert_eq!(detected, Some("pdf".to_string()));
    }

    #[test]
    fn test_get_corrected_extension_mismatch() {
        let temp_dir = TempDir::new().unwrap();
        let file_path = temp_dir.path().join("fake.png");

        // Create a ZIP file with PNG extension
        let mut file = File::create(&file_path).unwrap();
        file.write_all(&[0x50, 0x4B, 0x03, 0x04]).unwrap();

        let corrected = get_corrected_extension(&file_path);
        assert_eq!(corrected, Some("zip".to_string()));
    }

    #[test]
    fn test_get_corrected_extension_no_mismatch() {
        let temp_dir = TempDir::new().unwrap();
        let png_path = temp_dir.path().join("test.png");

        // Create a real PNG file
        let mut file = File::create(&png_path).unwrap();
        file.write_all(&[0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A])
            .unwrap();

        let corrected = get_corrected_extension(&png_path);
        assert_eq!(corrected, None); // No correction needed
    }

    #[test]
    fn test_detect_gif87a_file() {
        let temp_dir = TempDir::new().unwrap();
        let gif_path = temp_dir.path().join("test.gif");

        // GIF87a magic bytes
        let mut file = File::create(&gif_path).unwrap();
        file.write_all(b"GIF87a").unwrap();

        let detected = detect_file_type(&gif_path);
        assert_eq!(detected, Some("gif".to_string()));
    }

    #[test]
    fn test_detect_gif89a_file() {
        let temp_dir = TempDir::new().unwrap();
        let gif_path = temp_dir.path().join("test.gif");

        // GIF89a magic bytes
        let mut file = File::create(&gif_path).unwrap();
        file.write_all(b"GIF89a").unwrap();

        let detected = detect_file_type(&gif_path);
        assert_eq!(detected, Some("gif".to_string()));
    }

    #[test]
    fn test_detect_rar_file() {
        let temp_dir = TempDir::new().unwrap();
        let rar_path = temp_dir.path().join("test.rar");

        // RAR magic bytes
        let mut file = File::create(&rar_path).unwrap();
        file.write_all(&[0x52, 0x61, 0x72, 0x21, 0x1A, 0x07])
            .unwrap();

        let detected = detect_file_type(&rar_path);
        assert_eq!(detected, Some("rar".to_string()));
    }

    #[test]
    fn test_detect_7z_file() {
        let temp_dir = TempDir::new().unwrap();
        let sz_path = temp_dir.path().join("test.7z");

        // 7z magic bytes
        let mut file = File::create(&sz_path).unwrap();
        file.write_all(&[0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C])
            .unwrap();

        let detected = detect_file_type(&sz_path);
        assert_eq!(detected, Some("7z".to_string()));
    }

    #[test]
    fn test_detect_gzip_file() {
        let temp_dir = TempDir::new().unwrap();
        let gz_path = temp_dir.path().join("test.gz");

        // GZIP magic bytes
        let mut file = File::create(&gz_path).unwrap();
        file.write_all(&[0x1F, 0x8B, 0x08, 0x00]).unwrap();

        let detected = detect_file_type(&gz_path);
        assert_eq!(detected, Some("gz".to_string()));
    }

    #[test]
    fn test_detect_bmp_file() {
        let temp_dir = TempDir::new().unwrap();
        let bmp_path = temp_dir.path().join("test.bmp");

        // BMP magic bytes
        let mut file = File::create(&bmp_path).unwrap();
        file.write_all(&[0x42, 0x4D, 0x00, 0x00]).unwrap();

        let detected = detect_file_type(&bmp_path);
        assert_eq!(detected, Some("bmp".to_string()));
    }

    #[test]
    fn test_detect_tiff_little_endian() {
        let temp_dir = TempDir::new().unwrap();
        let tiff_path = temp_dir.path().join("test.tiff");

        // TIFF Little Endian magic bytes
        let mut file = File::create(&tiff_path).unwrap();
        file.write_all(&[0x49, 0x49, 0x2A, 0x00]).unwrap();

        let detected = detect_file_type(&tiff_path);
        assert_eq!(detected, Some("tiff".to_string()));
    }

    #[test]
    fn test_detect_tiff_big_endian() {
        let temp_dir = TempDir::new().unwrap();
        let tiff_path = temp_dir.path().join("test.tiff");

        // TIFF Big Endian magic bytes
        let mut file = File::create(&tiff_path).unwrap();
        file.write_all(&[0x4D, 0x4D, 0x00, 0x2A]).unwrap();

        let detected = detect_file_type(&tiff_path);
        assert_eq!(detected, Some("tiff".to_string()));
    }

    #[test]
    fn test_detect_webp_file() {
        let temp_dir = TempDir::new().unwrap();
        let webp_path = temp_dir.path().join("test.webp");

        // WebP magic bytes: RIFF....WEBP
        let mut file = File::create(&webp_path).unwrap();
        file.write_all(b"RIFF\x00\x00\x00\x00WEBP").unwrap();

        let detected = detect_file_type(&webp_path);
        assert_eq!(detected, Some("webp".to_string()));
    }

    #[test]
    fn test_detect_pkg_file() {
        let temp_dir = TempDir::new().unwrap();
        let pkg_path = temp_dir.path().join("test.pkg");

        // PKG (XAR) magic bytes: xar!
        let mut file = File::create(&pkg_path).unwrap();
        file.write_all(b"xar!\x00\x1c\x00\x01").unwrap();

        let detected = detect_file_type(&pkg_path);
        assert_eq!(detected, Some("pkg".to_string()));
    }

    #[test]
    fn test_get_corrected_extension_pkg_as_zip() {
        let temp_dir = TempDir::new().unwrap();
        let fake_zip = temp_dir.path().join("installer.zip");

        // Create a PKG file with wrong extension
        let mut file = File::create(&fake_zip).unwrap();
        file.write_all(b"xar!\x00\x1c\x00\x01").unwrap();

        let corrected = get_corrected_extension(&fake_zip);
        assert_eq!(corrected, Some("pkg".to_string()));
    }

    #[test]
    fn test_detect_empty_zip_archive() {
        let temp_dir = TempDir::new().unwrap();
        let zip_path = temp_dir.path().join("empty.zip");

        // Empty ZIP archive magic bytes
        let mut file = File::create(&zip_path).unwrap();
        file.write_all(&[0x50, 0x4B, 0x05, 0x06]).unwrap();

        let detected = detect_file_type(&zip_path);
        assert_eq!(detected, Some("zip".to_string()));
    }

    #[test]
    fn test_detect_unknown_file_type() {
        let temp_dir = TempDir::new().unwrap();
        let unknown_path = temp_dir.path().join("test.txt");

        // Random bytes that don't match any known format
        let mut file = File::create(&unknown_path).unwrap();
        file.write_all(b"Hello World!").unwrap();

        let detected = detect_file_type(&unknown_path);
        assert_eq!(detected, None);
    }

    #[test]
    fn test_detect_file_too_small() {
        let temp_dir = TempDir::new().unwrap();
        let small_path = temp_dir.path().join("small.dat");

        // File with less than 4 bytes
        let mut file = File::create(&small_path).unwrap();
        file.write_all(&[0x50, 0x4B]).unwrap();

        let detected = detect_file_type(&small_path);
        assert_eq!(detected, None);
    }

    #[test]
    fn test_detect_nonexistent_file() {
        let temp_dir = TempDir::new().unwrap();
        let nonexistent = temp_dir.path().join("does_not_exist.bin");

        let detected = detect_file_type(&nonexistent);
        assert_eq!(detected, None);
    }

    #[test]
    fn test_get_corrected_extension_no_extension() {
        let temp_dir = TempDir::new().unwrap();
        let no_ext_path = temp_dir.path().join("noextension");

        // Create a ZIP file without extension
        let mut file = File::create(&no_ext_path).unwrap();
        file.write_all(&[0x50, 0x4B, 0x03, 0x04]).unwrap();

        let corrected = get_corrected_extension(&no_ext_path);
        // Now should return the detected extension for files without extension
        assert_eq!(
            corrected,
            Some("zip".to_string()),
            "Files without extension should get the detected extension"
        );
    }

    #[test]
    fn test_get_corrected_extension_image_no_extension() {
        let temp_dir = TempDir::new().unwrap();
        let no_ext_path = temp_dir.path().join("image_0");

        // Create a PNG file without extension (like temp_0, image_0, etc.)
        let mut file = File::create(&no_ext_path).unwrap();
        file.write_all(&[0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A])
            .unwrap();

        let corrected = get_corrected_extension(&no_ext_path);
        // Should detect as PNG and return the extension
        assert_eq!(
            corrected,
            Some("png".to_string()),
            "Image files without extension should get .png"
        );
    }

    #[test]
    fn test_get_corrected_extension_jpeg_as_png() {
        let temp_dir = TempDir::new().unwrap();
        let file_path = temp_dir.path().join("photo.png");

        // Create a JPEG file with PNG extension
        let mut file = File::create(&file_path).unwrap();
        file.write_all(&[0xFF, 0xD8, 0xFF, 0xE0]).unwrap();

        let corrected = get_corrected_extension(&file_path);
        assert_eq!(corrected, Some("jpg".to_string()));
    }

    #[test]
    fn test_get_corrected_extension_rar_as_zip() {
        let temp_dir = TempDir::new().unwrap();
        let file_path = temp_dir.path().join("archive.zip");

        // Create a RAR file with ZIP extension
        let mut file = File::create(&file_path).unwrap();
        file.write_all(&[0x52, 0x61, 0x72, 0x21, 0x1A, 0x07])
            .unwrap();

        let corrected = get_corrected_extension(&file_path);
        assert_eq!(corrected, Some("rar".to_string()));
    }

    #[test]
    fn test_jpeg_variant_markers() {
        let temp_dir = TempDir::new().unwrap();

        // Test different JPEG markers (JFIF, EXIF, etc.)
        let markers = vec![0xE0, 0xE1, 0xE2, 0xE8, 0xDB];

        for (i, marker) in markers.iter().enumerate() {
            let jpg_path = temp_dir.path().join(format!("test{}.jpg", i));
            let mut file = File::create(&jpg_path).unwrap();
            file.write_all(&[0xFF, 0xD8, 0xFF, *marker]).unwrap();

            let detected = detect_file_type(&jpg_path);
            assert_eq!(
                detected,
                Some("jpg".to_string()),
                "Failed to detect JPEG with marker 0x{:02X}",
                marker
            );
        }
    }

    #[test]
    fn test_office_document_not_changed() {
        use std::io::Write;
        use zip::write::{FileOptions, ZipWriter};

        let temp_dir = TempDir::new().unwrap();

        // Create a minimal Office document (DOCX) with correct extension
        let docx_path = temp_dir.path().join("document.docx");
        let file = File::create(&docx_path).unwrap();
        let mut zip = ZipWriter::new(file);

        // Add [Content_Types].xml which identifies it as an Office document
        let options = FileOptions::default();
        zip.start_file("[Content_Types].xml", options).unwrap();
        zip.write_all(b"<?xml version=\"1.0\"?><Types></Types>")
            .unwrap();
        zip.finish().unwrap();

        // Should return the Office format (docx)
        let detected = detect_file_type(&docx_path);
        assert_eq!(
            detected,
            Some("docx".to_string()),
            "Office documents should be identified as their Office format"
        );
    }

    #[test]
    fn test_regular_zip_still_detected() {
        use std::io::Write;
        use zip::write::{FileOptions, ZipWriter};

        let temp_dir = TempDir::new().unwrap();

        // Create a regular ZIP file without Office structure
        let zip_path = temp_dir.path().join("archive.zip");
        let file = File::create(&zip_path).unwrap();
        let mut zip = ZipWriter::new(file);

        // Add a normal file (not [Content_Types].xml)
        let options = FileOptions::default();
        zip.start_file("readme.txt", options).unwrap();
        zip.write_all(b"Hello World").unwrap();
        zip.finish().unwrap();

        // Should detect as ZIP since it's not an Office document
        let detected = detect_file_type(&zip_path);
        assert_eq!(detected, Some("zip".to_string()));
    }

    #[test]
    fn test_office_document_with_wrong_extension() {
        use std::io::Write;
        use zip::write::{FileOptions, ZipWriter};

        let temp_dir = TempDir::new().unwrap();

        // Create an Office document with .png extension (misnamed)
        let fake_png_path = temp_dir.path().join("document.png");
        let file = File::create(&fake_png_path).unwrap();
        let mut zip = ZipWriter::new(file);

        let options = FileOptions::default();
        zip.start_file("[Content_Types].xml", options).unwrap();
        zip.write_all(b"<?xml version=\"1.0\"?><Types></Types>")
            .unwrap();
        
        // Add DOCX-specific structure
        zip.start_file("word/document.xml", options).unwrap();
        zip.write_all(b"<?xml version=\"1.0\"?><document></document>")
            .unwrap();
        
        zip.finish().unwrap();

        // Should suggest correcting to docx since it's misnamed
        let corrected = get_corrected_extension(&fake_png_path);
        assert_eq!(
            corrected,
            Some("docx".to_string()),
            "Misnamed Office document should suggest correct Office extension"
        );
    }

    #[test]
    fn test_real_zip_with_png_extension() {
        use std::io::Write;
        use zip::write::{FileOptions, ZipWriter};

        let temp_dir = TempDir::new().unwrap();

        // Create a regular ZIP with PNG extension
        let fake_png_path = temp_dir.path().join("archive.png");
        let file = File::create(&fake_png_path).unwrap();
        let mut zip = ZipWriter::new(file);

        let options = FileOptions::default();
        zip.start_file("data.txt", options).unwrap();
        zip.write_all(b"Some data").unwrap();
        zip.finish().unwrap();

        // Should correct to .zip since it's not an Office document
        let corrected = get_corrected_extension(&fake_png_path);
        assert_eq!(
            corrected,
            Some("zip".to_string()),
            "Regular ZIP with wrong extension should be corrected"
        );
    }

    #[test]
    fn test_apk_file_not_changed() {
        use std::io::Write;
        use zip::write::{FileOptions, ZipWriter};

        let temp_dir = TempDir::new().unwrap();

        // Create a minimal APK file (Android Package)
        let apk_path = temp_dir.path().join("app.apk");
        let file = File::create(&apk_path).unwrap();
        let mut zip = ZipWriter::new(file);

        // Add AndroidManifest.xml which identifies it as an APK
        let options = FileOptions::default();
        zip.start_file("AndroidManifest.xml", options).unwrap();
        zip.write_all(b"<?xml version=\"1.0\"?><manifest></manifest>")
            .unwrap();
        zip.finish().unwrap();

        // Should detect as APK (not ZIP)
        let detected = detect_file_type(&apk_path);
        assert_eq!(detected, Some("apk".to_string()), "APK files should be detected as 'apk'");
    }

    #[test]
    fn test_apk_with_wrong_extension() {
        use std::io::Write;
        use zip::write::{FileOptions, ZipWriter};

        let temp_dir = TempDir::new().unwrap();

        // Create an APK file with .png extension (misnamed)
        let fake_png_path = temp_dir.path().join("app.png");
        let file = File::create(&fake_png_path).unwrap();
        let mut zip = ZipWriter::new(file);

        let options = FileOptions::default();
        zip.start_file("AndroidManifest.xml", options).unwrap();
        zip.write_all(b"<?xml version=\"1.0\"?><manifest></manifest>")
            .unwrap();
        zip.finish().unwrap();

        // Should suggest correcting to .apk extension since it's an APK
        let corrected = get_corrected_extension(&fake_png_path);
        assert_eq!(
            corrected, Some("apk".to_string()),
            "APK files with wrong extension should be corrected to .apk"
        );
    }

    #[test]
    fn test_xapk_file_not_changed() {
        use std::io::Write;
        use zip::write::{FileOptions, ZipWriter};

        let temp_dir = TempDir::new().unwrap();

        // Create a minimal XAPK file (Extended Android Package)
        let xapk_path = temp_dir.path().join("app.xapk");
        let file = File::create(&xapk_path).unwrap();
        let mut zip = ZipWriter::new(file);

        // Add manifest.json which identifies it as an XAPK
        let options = FileOptions::default();
        zip.start_file("manifest.json", options).unwrap();
        zip.write_all(b"{\"package_name\":\"com.example.app\"}")
            .unwrap();
        zip.finish().unwrap();

        // Should detect as XAPK (not ZIP)
        let detected = detect_file_type(&xapk_path);
        assert_eq!(detected, Some("xapk".to_string()), "XAPK files should be detected as 'xapk'");
    }

    #[test]
    fn test_xapk_with_wrong_extension() {
        use std::io::Write;
        use zip::write::{FileOptions, ZipWriter};

        let temp_dir = TempDir::new().unwrap();

        // Create an XAPK file with .zip extension (misnamed)
        let fake_zip_path = temp_dir.path().join("app.zip");
        let file = File::create(&fake_zip_path).unwrap();
        let mut zip = ZipWriter::new(file);

        let options = FileOptions::default();
        zip.start_file("manifest.json", options).unwrap();
        zip.write_all(b"{\"package_name\":\"com.example.app\"}")
            .unwrap();
        zip.finish().unwrap();

        // Should suggest correcting to .xapk extension since it's an XAPK
        let corrected = get_corrected_extension(&fake_zip_path);
        assert_eq!(
            corrected, Some("xapk".to_string()),
            "XAPK files with wrong extension should be corrected to .xapk"
        );
    }

    #[test]
    fn test_jar_file_not_changed() {
        use std::io::Write;
        use zip::write::{FileOptions, ZipWriter};

        let temp_dir = TempDir::new().unwrap();

        // Create a minimal JAR file (Java Archive)
        let jar_path = temp_dir.path().join("library.jar");
        let file = File::create(&jar_path).unwrap();
        let mut zip = ZipWriter::new(file);

        // Add META-INF/MANIFEST.MF which identifies it as a JAR
        let options = FileOptions::default();
        zip.start_file("META-INF/MANIFEST.MF", options).unwrap();
        zip.write_all(b"Manifest-Version: 1.0\nMain-Class: com.example.Main\n")
            .unwrap();
        zip.finish().unwrap();

        // Should detect as JAR (not ZIP)
        let detected = detect_file_type(&jar_path);
        assert_eq!(detected, Some("jar".to_string()), "JAR files should be detected as 'jar'");
    }

    #[test]
    fn test_jar_with_wrong_extension() {
        use std::io::Write;
        use zip::write::{FileOptions, ZipWriter};

        let temp_dir = TempDir::new().unwrap();

        // Create a JAR file with .png extension (misnamed)
        let fake_png_path = temp_dir.path().join("library.png");
        let file = File::create(&fake_png_path).unwrap();
        let mut zip = ZipWriter::new(file);

        let options = FileOptions::default();
        zip.start_file("META-INF/MANIFEST.MF", options).unwrap();
        zip.write_all(b"Manifest-Version: 1.0\nMain-Class: com.example.Main\n")
            .unwrap();
        zip.finish().unwrap();

        // Should suggest correcting to .jar extension since it's a JAR
        let corrected = get_corrected_extension(&fake_png_path);
        assert_eq!(
            corrected, Some("jar".to_string()),
            "JAR files with wrong extension should be corrected to .jar"
        );
    }

    #[test]
    fn test_tgz_not_changed_to_gz() {
        let temp_dir = TempDir::new().unwrap();
        let tgz_path = temp_dir.path().join("archive.tgz");

        // Create a gzip file (tgz files are gzipped tar archives)
        let mut file = File::create(&tgz_path).unwrap();
        file.write_all(&[0x1F, 0x8B, 0x08, 0x00]).unwrap(); // GZIP magic bytes

        // Should NOT suggest changing .tgz to .gz
        let corrected = get_corrected_extension(&tgz_path);
        assert_eq!(corrected, None, ".tgz files should not be changed to .gz");
    }

    #[test]
    fn test_detect_json_file_with_object() {
        let temp_dir = TempDir::new().unwrap();
        let json_path = temp_dir.path().join("data.json");

        // Create a JSON file starting with {
        let json_content = r#"{
    "signatures": [
        {
            "signature_id": 4473,
            "signature_name": "test"
        }
    ]
}"#;
        fs::write(&json_path, json_content).unwrap();

        let detected = detect_file_type(&json_path);
        assert_eq!(
            detected,
            Some("json".to_string()),
            "JSON files starting with {{ should be detected"
        );
    }

    #[test]
    fn test_detect_json_file_with_array() {
        let temp_dir = TempDir::new().unwrap();
        let json_path = temp_dir.path().join("array.json");

        // Create a JSON file starting with [
        let json_content = r#"[
    {
        "id": 1,
        "name": "test"
    }
]"#;
        fs::write(&json_path, json_content).unwrap();

        let detected = detect_file_type(&json_path);
        assert_eq!(
            detected,
            Some("json".to_string()),
            "JSON files starting with [ should be detected"
        );
    }

    #[test]
    fn test_detect_json_misnamed_as_png() {
        let temp_dir = TempDir::new().unwrap();
        let fake_png_path = temp_dir.path().join("image.png");

        // Create a JSON file misnamed as PNG (common with Confluence/draw.io exports)
        let json_content = r#"{"type": "diagram", "version": "1.0"}"#;
        fs::write(&fake_png_path, json_content).unwrap();

        let detected = detect_file_type(&fake_png_path);
        assert_eq!(
            detected,
            Some("json".to_string()),
            "JSON files misnamed as PNG should be detected as JSON"
        );

        // Verify correction suggests .json
        let corrected = get_corrected_extension(&fake_png_path);
        assert_eq!(
            corrected,
            Some("json".to_string()),
            "Should suggest correcting .png to .json"
        );
    }

    #[test]
    fn test_json_with_whitespace() {
        let temp_dir = TempDir::new().unwrap();
        let json_path = temp_dir.path().join("whitespace.json");

        // JSON with leading whitespace - magic byte detection won't work
        // because the first byte is whitespace, not '{'
        let json_content = "  \n\t{\n\t\"key\": \"value\"\n}";
        fs::write(&json_path, json_content).unwrap();

        let detected = detect_file_type(&json_path);
        assert_eq!(
            detected, None,
            "JSON with leading whitespace won't be detected by magic byte check"
        );
    }

    #[test]
    fn test_not_json_starts_with_brace() {
        let temp_dir = TempDir::new().unwrap();
        let text_path = temp_dir.path().join("notjson.txt");

        // Text file that starts with { but isn't JSON (no proper structure)
        let content = "{ this is just some text, not json at all";
        fs::write(&text_path, content).unwrap();

        let detected = detect_file_type(&text_path);
        assert_eq!(
            detected, None,
            "Text starting with {{ but without JSON structure should not be detected as JSON"
        );
    }

    #[test]
    fn test_json_misnamed_as_png_with_markdown_link() {
        // This test demonstrates the issue where JSON files misnamed as .png
        // cause "Referenced image not found" errors because:
        // 1. Markdown references image.png
        // 2. File is actually JSON content with .png extension
        // 3. File type detection identifies it as JSON
        // 4. But markdown still references the .png name
        
        let temp_dir = TempDir::new().unwrap();
        let fake_png = temp_dir.path().join("diagram.png");
        
        // Create a JSON file with .png extension (common with Confluence/draw.io exports)
        let json_content = r#"{
            "version": "1.0",
            "type": "diagram",
            "shapes": [
                {"id": 1, "type": "rectangle", "x": 10, "y": 20}
            ]
        }"#;
        fs::write(&fake_png, json_content).unwrap();
        
        // Verify detection identifies it as JSON, not PNG
        let detected_type = detect_file_type(&fake_png);
        assert_eq!(
            detected_type,
            Some("json".to_string()),
            "File should be detected as JSON despite .png extension"
        );
        
        // Verify correction suggests .json extension
        let corrected_ext = get_corrected_extension(&fake_png);
        assert_eq!(
            corrected_ext,
            Some("json".to_string()),
            "Should suggest correcting .png to .json"
        );
        
        // The expected behavior:
        // - Original markdown: ![diagram](diagram.png)
        // - File gets detected as JSON
        // - File should be renamed: diagram.png -> diagram.json
        // - Markdown should be updated: ![diagram](diagram.json) OR removed entirely
        // - This prevents "Referenced image not found" errors
        
        // Simulate the correction
        let corrected_name = if let Some(ext) = corrected_ext {
            let stem = fake_png.file_stem().unwrap().to_string_lossy();
            temp_dir.path().join(format!("{}.{}", stem, ext))
        } else {
            fake_png.clone()
        };
        
        // In real code, the file would be renamed and markdown updated
        assert_eq!(
            corrected_name.extension().unwrap().to_str().unwrap(),
            "json",
            "Corrected filename should have .json extension"
        );
    }

    #[test]
    fn test_multiple_format_corrections_with_links() {
        // Test that multiple misnamed files can be detected and corrected
        let temp_dir = TempDir::new().unwrap();
        
        // Scenario 1: JSON as PNG (needs >= 20 bytes to be detected)
        let json_as_png = temp_dir.path().join("data.png");
        fs::write(&json_as_png, r#"{"key": "value", "id": 123}"#).unwrap();
        assert_eq!(detect_file_type(&json_as_png), Some("json".to_string()));
        assert_eq!(
            get_corrected_extension(&json_as_png),
            Some("json".to_string()),
            "JSON misnamed as .png should be corrected to .json"
        );
        
        // Scenario 2: JPEG as PNG - needs proper JPEG header with enough data
        let jpeg_as_png = temp_dir.path().join("photo.png");
        // JPEG header: FF D8 FF E0 + minimal JFIF marker
        let mut jpeg_data = vec![0xFF, 0xD8, 0xFF, 0xE0, 0x00, 0x10];
        jpeg_data.extend_from_slice(b"JFIF"); // JFIF marker
        jpeg_data.extend(vec![0; 10]); // Padding
        fs::write(&jpeg_as_png, jpeg_data).unwrap();
        assert_eq!(detect_file_type(&jpeg_as_png), Some("jpg".to_string()));
        assert_eq!(
            get_corrected_extension(&jpeg_as_png),
            Some("jpg".to_string()),
            "JPEG misnamed as .png should be corrected to .jpg"
        );
        
        // Scenario 3: Actual PNG (no correction needed)
        let real_png = temp_dir.path().join("image.png");
        let png_magic = vec![0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A]; // PNG header
        fs::write(&real_png, png_magic).unwrap();
        assert_eq!(detect_file_type(&real_png), Some("png".to_string()));
        assert_eq!(
            get_corrected_extension(&real_png),
            None,
            "Real PNG should not need correction"
        );
    }

    #[test]
    fn test_zip_based_formats_not_corrected_as_json() {
        // Ensure ZIP-based formats (DOCX, APK, JAR) aren't misidentified as JSON
        // even though they might contain JSON files inside
        let temp_dir = TempDir::new().unwrap();
        
        let apk_path = temp_dir.path().join("app.apk");
        let mut file = File::create(&apk_path).unwrap();
        // APK is a ZIP file
        file.write_all(&[0x50, 0x4B, 0x03, 0x04]).unwrap();
        file.write_all(b"PK\x03\x04").unwrap();
        
        let detected = detect_file_type(&apk_path);
        assert_eq!(detected, Some("zip".to_string()), "APK should be detected as ZIP");
        
        // Should not suggest changing to .json
        let corrected = get_corrected_extension(&apk_path);
        assert_eq!(corrected, Some("zip".to_string()), "Should suggest .zip, not .json");
    }

    #[test]
    fn test_eddx_files_not_changed_to_zip() {
        // EDDX (Edraw) files are ZIP-based but should keep their .eddx extension
        let temp_dir = TempDir::new().unwrap();
        let eddx_path = temp_dir.path().join("diagram.eddx");
        
        // Create a ZIP file (EDDX files are ZIP-based)
        let mut file = File::create(&eddx_path).unwrap();
        file.write_all(&[0x50, 0x4B, 0x03, 0x04]).unwrap(); // ZIP magic bytes
        
        // Should NOT suggest changing .eddx to .zip
        let corrected = get_corrected_extension(&eddx_path);
        assert_eq!(corrected, None, ".eddx files should not be changed to .zip");
    }

    #[test]
    fn test_xmind_files_not_changed_to_zip() {
        // XMIND (mind mapping) files are ZIP-based but should keep their .xmind extension
        let temp_dir = TempDir::new().unwrap();
        let xmind_path = temp_dir.path().join("mindmap.xmind");
        
        // Create a ZIP file (XMIND files are ZIP-based)
        let mut file = File::create(&xmind_path).unwrap();
        file.write_all(&[0x50, 0x4B, 0x03, 0x04]).unwrap(); // ZIP magic bytes
        
        // Should NOT suggest changing .xmind to .zip
        let corrected = get_corrected_extension(&xmind_path);
        assert_eq!(corrected, None, ".xmind files should not be changed to .zip");
    }

    #[test]
    fn test_txt_files_not_changed_to_json() {
        // TXT files containing JSON should not be suggested to change to .json
        let temp_dir = TempDir::new().unwrap();
        let txt_path = temp_dir.path().join("data.txt");
        
        // Create a TXT file with JSON content (>= 20 bytes for JSON detection)
        let json_content = r#"{"key": "value", "id": 123}"#;
        fs::write(&txt_path, json_content).unwrap();
        
        // Should detect as JSON internally
        let detected = detect_file_type(&txt_path);
        assert_eq!(detected, None, "TXT files should not be detected as JSON");
        
        // Should NOT suggest changing .txt to .json
        let corrected = get_corrected_extension(&txt_path);
        assert_eq!(corrected, None, ".txt files should not be changed to .json even if they contain JSON");
    }

    #[test]
    fn test_zip_based_special_formats_preserved() {
        // Test that multiple ZIP-based formats are preserved
        let temp_dir = TempDir::new().unwrap();
        let zip_magic = vec![0x50, 0x4B, 0x03, 0x04];
        
        // Test EDDX
        let eddx = temp_dir.path().join("file.eddx");
        fs::write(&eddx, &zip_magic).unwrap();
        assert_eq!(get_corrected_extension(&eddx), None, "EDDX should be preserved");
        
        // Test XMIND
        let xmind = temp_dir.path().join("file.xmind");
        fs::write(&xmind, &zip_magic).unwrap();
        assert_eq!(get_corrected_extension(&xmind), None, "XMIND should be preserved");
        
        // Test PKG
        let pkg = temp_dir.path().join("file.pkg");
        fs::write(&pkg, &zip_magic).unwrap();
        assert_eq!(get_corrected_extension(&pkg), None, "PKG should be preserved");
        
        
        // But a regular ZIP with wrong extension should be corrected
        let fake_png = temp_dir.path().join("file.png");
        fs::write(&fake_png, &zip_magic).unwrap();
        assert_eq!(get_corrected_extension(&fake_png), Some("zip".to_string()), "ZIP as PNG should be corrected");
    }

    #[test]
    fn test_csv_file_detection() {
        // Test CSV file detection (files misnamed as PNG)
        let temp_dir = TempDir::new().unwrap();
        let csv_as_png = temp_dir.path().join("data.png");
        
        // Create CSV content similar to the real-world case
        let csv_content = "addr_format,ip1,ip2,type,method,confidence,confidence_level,is_valid\n\
                          Single,192.168.1.1,192.168.1.1,0,passive_ml,88,confirmed,1\n\
                          Rrange,192.168.1.1,192.168.1.12,1,acitve_probe,58,tentative,0\n";
        fs::write(&csv_as_png, csv_content).unwrap();
        
        // Should detect as CSV
        let detected = detect_file_type(&csv_as_png);
        assert_eq!(detected, Some("csv".to_string()), "CSV file should be detected");
        
        // Should suggest correcting .png to .csv
        let corrected = get_corrected_extension(&csv_as_png);
        assert_eq!(corrected, Some("csv".to_string()), "CSV misnamed as .png should be corrected to .csv");
    }

    #[test]
    fn test_csv_file_with_txt_extension() {
        // CSV files with .txt extension should NOT be changed
        let temp_dir = TempDir::new().unwrap();
        let csv_as_txt = temp_dir.path().join("data.txt");
        
        let csv_content = "name,age,city\nAlice,30,NYC\nBob,25,LA\n";
        fs::write(&csv_as_txt, csv_content).unwrap();
        
        // Should NOT suggest changing .txt to .csv
        let corrected = get_corrected_extension(&csv_as_txt);
        assert_eq!(corrected, None, ".txt files should not be changed to .csv even if they contain CSV");
    }

    #[test]
    fn test_csv_file_with_csv_extension() {
        // CSV files with .csv extension should not be changed
        let temp_dir = TempDir::new().unwrap();
        let csv_file = temp_dir.path().join("data.csv");
        
        let csv_content = "id,name,value\n1,test,100\n2,demo,200\n";
        fs::write(&csv_file, csv_content).unwrap();
        
        // Should NOT suggest changing (already correct)
        let corrected = get_corrected_extension(&csv_file);
        assert_eq!(corrected, None, ".csv files should not need correction");
    }

    #[test]
    fn test_csv_detection_requires_multiple_commas() {
        // Files with just one comma should not be detected as CSV
        let temp_dir = TempDir::new().unwrap();
        let not_csv = temp_dir.path().join("notcsv.png");
        
        let content = "Just some text, with a comma\nBut not structured data\n";
        fs::write(&not_csv, content).unwrap();
        
        // Should NOT detect as CSV (only 1 comma, not structured)
        let detected = detect_file_type(&not_csv);
        assert_eq!(detected, None, "Text with few commas should not be detected as CSV");
    }

    #[test]
    fn test_eml_email_detection() {
        // Test email file (EML) detection
        let temp_dir = TempDir::new().unwrap();
        let eml_as_png = temp_dir.path().join("email.png");
        
        let email_content = "X-QQ-mid: bizesmtp42t1627452248tr306fai\n\
                             Received: from example.com (unknown [47.93.59.84])\n\
                             \tby smtp.example.com (ESMTP) with SMTP id 0\n\
                             From: sender@example.com\n\
                             To: recipient@example.com\n\
                             Subject: Test Email\n\n\
                             Email body content here.";
        fs::write(&eml_as_png, email_content).unwrap();
        
        // Should detect as EML
        let detected = detect_file_type(&eml_as_png);
        assert_eq!(detected, Some("eml".to_string()), "Email file should be detected as EML");
        
        // Should suggest correcting .png to .eml
        let corrected = get_corrected_extension(&eml_as_png);
        assert_eq!(corrected, Some("eml".to_string()), "Email misnamed as .png should be corrected to .eml");
    }

    #[test]
    fn test_eml_with_received_header() {
        // Test email detection with Received header first
        let temp_dir = TempDir::new().unwrap();
        let eml_file = temp_dir.path().join("message.png");
        
        let email_content = "Received: from server.example.com\n\
                             \tby mail.example.com with SMTP; Wed, 28 Jul 2021 14:04:08\n\
                             Message-ID: <abc123@example.com>\n";
        fs::write(&eml_file, email_content).unwrap();
        
        let detected = detect_file_type(&eml_file);
        assert_eq!(detected, Some("eml".to_string()), "Email starting with Received header should be detected");
    }

    #[test]
    fn test_eml_file_with_eml_extension() {
        // EML files with .eml extension should not be changed
        let temp_dir = TempDir::new().unwrap();
        let eml_file = temp_dir.path().join("message.eml");
        
        let email_content = "From: test@example.com\nTo: user@example.com\nSubject: Test\n\nBody";
        fs::write(&eml_file, email_content).unwrap();
        
        // Should NOT suggest changing (already correct)
        let corrected = get_corrected_extension(&eml_file);
        assert_eq!(corrected, None, ".eml files should not need correction");
    }

    #[test]
    fn test_eml_file_with_txt_extension() {
        // Email files with .txt extension should NOT be changed
        let temp_dir = TempDir::new().unwrap();
        let eml_as_txt = temp_dir.path().join("email.txt");
        
        let email_content = "X-Mailer: TestClient\nFrom: sender@example.com\n";
        fs::write(&eml_as_txt, email_content).unwrap();
        
        // Should NOT suggest changing .txt to .eml
        let corrected = get_corrected_extension(&eml_as_txt);
        assert_eq!(corrected, None, ".txt files should not be changed to .eml even if they contain email headers");
    }

    #[test]
    fn test_real_world_email_case() {
        // Test with actual email content from user's file
        let temp_dir = TempDir::new().unwrap();
        let email_file = temp_dir.path().join("39126132_attachments_image2021-7-28_17-9-18.png");
        
        let email_content = "X-QQ-mid: bizesmtp42t1627452248tr306fai\n\
                             Received: from GeedegeNetworks-CN-OA-001 (unknown [47.93.59.84])\n\
                             \tby esmtp6.qq.com (ESMTP) with SMTP id 0\n\
                             \tfor <dongxiaoyan@geedgenetworks.com>; Wed, 28 Jul 2021 14:04:08 +0800 (CST)\n";
        fs::write(&email_file, email_content).unwrap();
        
        let detected = detect_file_type(&email_file);
        assert_eq!(detected, Some("eml".to_string()), "Real-world email case should be detected");
        
        let corrected = get_corrected_extension(&email_file);
        assert_eq!(corrected, Some("eml".to_string()), "Should correct from .png to .eml");
    }

    #[test]
    fn test_csv_vs_json_distinction() {
        // Ensure JSON is not misidentified as CSV
        let temp_dir = TempDir::new().unwrap();
        
        // JSON with commas should be detected as JSON, not CSV
        let json_file = temp_dir.path().join("data.png");
        let json_content = r#"{"name": "test", "values": [1, 2, 3], "count": 10}"#;
        fs::write(&json_file, json_content).unwrap();
        
        let detected = detect_file_type(&json_file);
        assert_eq!(detected, Some("json".to_string()), "JSON should be detected as JSON, not CSV");
    }

    #[test]
    fn test_real_world_csv_case() {
        // Test the actual file case from the user's report
        let temp_dir = TempDir::new().unwrap();
        let fake_png = temp_dir.path().join("129087777_attachments_image-2023-5-31_14-46-16.png");
        
        // Exact content from the real file
        let csv_content = "addr_format,ip1,ip2,type,method,confidence,confidence_level,is_valid\n\
                          Single,192.168.1.1,192.168.1.1,0,passive_ml,88,confirmed,1\n\
                          Rrange,192.168.1.1,192.168.1.12,1,acitve_probe,58,tentative,0\n\
                          CIDR,192.168.1.1,24,1,acitve_probe,58,tentative,1\n";
        fs::write(&fake_png, csv_content).unwrap();
        
        // Should detect as CSV
        let detected = detect_file_type(&fake_png);
        assert_eq!(
            detected,
            Some("csv".to_string()),
            "Real-world IP address CSV should be detected"
        );
        
        // Should suggest correction
        let corrected = get_corrected_extension(&fake_png);
        assert_eq!(
            corrected,
            Some("csv".to_string()),
            "Should suggest correcting misnamed CSV file"
        );
    }

    #[test]
    fn test_simple_csv_detection() {
        let temp_dir = TempDir::new().unwrap();
        let csv_file = temp_dir.path().join("data.png");
        // Need at least 20 bytes for CSV detection
        fs::write(&csv_file, "Name,Age,City\nAlice,30,NYC\nBob,25,SF\n").unwrap();
        
        let detected = detect_file_type(&csv_file);
        assert_eq!(detected, Some("csv".to_string()), "Simple CSV should be detected");
        
        let corrected = get_corrected_extension(&csv_file);
        assert_eq!(corrected, Some("csv".to_string()), "Should suggest CSV extension");
    }

    #[test]
    fn test_simple_json_detection() {
        let temp_dir = TempDir::new().unwrap();
        let json_file = temp_dir.path().join("data.png");
        fs::write(&json_file, r#"{"key": "value", "data": 123}"#).unwrap();
        
        let detected = detect_file_type(&json_file);
        assert_eq!(detected, Some("json".to_string()), "Simple JSON should be detected");
        
        let corrected = get_corrected_extension(&json_file);
        assert_eq!(corrected, Some("json".to_string()), "Should suggest JSON extension");
    }

    #[test]
    fn test_cisco_config_file_detection() {
        // Test Cisco network device configuration file
        let temp_dir = TempDir::new().unwrap();
        let config_file = temp_dir.path().join("124747817_attachments_image-2023-12-11_11-14-12.png");
        
        let cisco_config = "!Command: show running-config
!Running configuration last done at: Mon Dec 11 10:09:19 2023
!Time: Mon Dec 11 10:11:14 2023

version 9.3(8) Bios:version  
system memory-thresholds minor 88 severe 90 critical 93

hostname NX2
vdc NX2 id 1
  limit-resource vlan minimum 16 maximum 4094
  feature lacp
  feature vpc

interface Ethernet1/1
  switchport mode trunk
  channel-group 100 mode active
";
        fs::write(&config_file, cisco_config).unwrap();
        
        // Should detect as text/config file
        let detected = detect_file_type(&config_file);
        assert_eq!(
            detected,
            Some("txt".to_string()),
            "Cisco configuration should be detected as text file"
        );
        
        // Should suggest correction from .png to .txt
        let corrected = get_corrected_extension(&config_file);
        assert_eq!(
            corrected,
            Some("txt".to_string()),
            "Should suggest correcting from .png to .txt"
        );
    }

    #[test]
    fn test_config_file_with_version_keyword() {
        // Test config file with "version" keyword (another common pattern)
        let temp_dir = TempDir::new().unwrap();
        let config_file = temp_dir.path().join("network-config.png");
        
        let config_content = "version 15.0
hostname router1
interface FastEthernet0/0
 ip address 192.168.1.1 255.255.255.0
 no shutdown
ip route 0.0.0.0 0.0.0.0 192.168.1.254
";
        fs::write(&config_file, config_content).unwrap();
        
        let detected = detect_file_type(&config_file);
        assert_eq!(
            detected,
            Some("txt".to_string()),
            "Config file with version keyword should be detected"
        );
    }

    #[test]
    fn test_config_file_not_misidentified_as_csv() {
        // Ensure config files with commas aren't misidentified as CSV
        let temp_dir = TempDir::new().unwrap();
        let config_file = temp_dir.path().join("config.png");
        
        let config_content = "!Config file with comma in comment, don't confuse with CSV
version 9.3(8)
hostname switch1
interface Ethernet1/1
 switchport mode trunk
 channel-group 100 mode active, lacp mode
";
        fs::write(&config_file, config_content).unwrap();
        
        let detected = detect_file_type(&config_file);
        assert_eq!(
            detected,
            Some("txt".to_string()),
            "Config file should be detected as text, not CSV"
        );
    }

    #[test]
    fn test_bash_script_detection() {
        // Test bash shell script detection
        let temp_dir = TempDir::new().unwrap();
        let script_file = temp_dir.path().join("deploy.png");
        
        let bash_script = "#!/bin/bash
# This is a bash script
echo \"Hello World\"
for i in {1..10}; do
  echo \"Count: $i\"
done
";
        fs::write(&script_file, bash_script).unwrap();
        
        let detected = detect_file_type(&script_file);
        assert_eq!(
            detected,
            Some("sh".to_string()),
            "Bash script should be detected as .sh file"
        );
        
        // Should suggest correction from .png to .sh
        let corrected = get_corrected_extension(&script_file);
        assert_eq!(
            corrected,
            Some("sh".to_string()),
            "Should suggest correcting from .png to .sh"
        );
    }

    #[test]
    fn test_shell_script_not_detected_as_csv() {
        // Ensure shell scripts with commas aren't misidentified as CSV
        let temp_dir = TempDir::new().unwrap();
        let script_file = temp_dir.path().join("config_loader.png");
        
        let script_content = "#!/bin/bash
# Configuration loader script
data_id=(
  active_defence_event.json
  bgp_record.json
  config.json
)

for id in \"${data_id[@]}\"; do
  curl -X DELETE \"http://nacos:8848/configs?id=$id\"
  echo \"Deleted $id\"
done
";
        fs::write(&script_file, script_content).unwrap();
        
        let detected = detect_file_type(&script_file);
        assert_eq!(
            detected,
            Some("sh".to_string()),
            "Shell script should be detected as .sh, not CSV despite having commas"
        );
    }

    #[test]
    fn test_shell_script_not_changed_if_already_sh() {
        // Shell script with correct .sh extension should not be changed
        let temp_dir = TempDir::new().unwrap();
        let script_file = temp_dir.path().join("script.sh");
        
        let bash_script = "#!/bin/bash
echo \"Already correct extension\"
";
        fs::write(&script_file, bash_script).unwrap();
        
        // Should NOT suggest changing .sh files
        let corrected = get_corrected_extension(&script_file);
        assert_eq!(
            corrected,
            None,
            ".sh files should not need correction"
        );
    }

    #[test]
    fn test_properties_file_detection() {
        // Test QA automation properties file detection
        let temp_dir = TempDir::new().unwrap();
        let props_file = temp_dir.path().join("selectors.png");
        
        let properties_content = "# Login page elements
loginPage_userName_posName = \"username\"
loginPage_passwd_posName = \"password\"
loginPage_signIn_posId = \"login\"

# Main page navigation
mainPage_navigationBar_logo_posCss = \".tsg-img-logo\"
mainPage_input_language_posXpath = \"//input[@id='language']\"
";
        fs::write(&props_file, properties_content).unwrap();
        
        let detected = detect_file_type(&props_file);
        assert_eq!(
            detected,
            Some("properties".to_string()),
            "Properties file should be detected as .properties"
        );
        
        // Should suggest correction from .png to .properties
        let corrected = get_corrected_extension(&props_file);
        assert_eq!(
            corrected,
            Some("properties".to_string()),
            "Should suggest correcting from .png to .properties"
        );
    }

    #[test]
    fn test_properties_file_not_changed_if_correct() {
        // Properties file with correct .properties extension should not be changed
        let temp_dir = TempDir::new().unwrap();
        let props_file = temp_dir.path().join("config.properties");
        
        let properties_content = "# Configuration file
server.port = 8080
server.host = localhost
database.url = jdbc:mysql://localhost/db
";
        fs::write(&props_file, properties_content).unwrap();
        
        // Should NOT suggest changing .properties files
        let corrected = get_corrected_extension(&props_file);
        assert_eq!(
            corrected,
            None,
            ".properties files should not need correction"
        );
    }

    #[test]
    fn test_properties_file_not_misidentified_as_shell_script() {
        // Ensure properties files with # comments aren't misidentified as shell scripts
        let temp_dir = TempDir::new().unwrap();
        let props_file = temp_dir.path().join("test.png");
        
        let properties_content = "# This looks like a comment but is properties
ui.button.save = Save Button
ui.label.message = Configuration message
xpath.login.input = //input[@name='login']
";
        fs::write(&props_file, properties_content).unwrap();
        
        let detected = detect_file_type(&props_file);
        assert_eq!(
            detected,
            Some("properties".to_string()),
            "Properties file should be detected, not confused with shell script"
        );
    }

    #[test]
    fn test_svg_file_detection() {
        // Test SVG file detection - basic SVG
        let temp_dir = TempDir::new().unwrap();
        let svg_file = temp_dir.path().join("image.svg");
        
        let svg_content = r#"<?xml version="1.0" encoding="UTF-8"?>
<svg xmlns="http://www.w3.org/2000/svg" width="100" height="100">
  <circle cx="50" cy="50" r="40" fill="red"/>
</svg>"#;
        fs::write(&svg_file, svg_content).unwrap();
        
        // Should NOT detect as any other format (keep .svg)
        let detected = detect_file_type(&svg_file);
        assert_eq!(
            detected,
            None,
            "SVG files with .svg extension should not be changed"
        );
        
        // Should NOT suggest changing .svg files
        let corrected = get_corrected_extension(&svg_file);
        assert_eq!(
            corrected,
            None,
            ".svg files should not need correction"
        );
    }

    #[test]
    fn test_svg_file_misnamed_as_png() {
        // Test SVG file misnamed as PNG
        let temp_dir = TempDir::new().unwrap();
        let fake_png = temp_dir.path().join("diagram.png");
        
        let svg_content = r#"<?xml version="1.0"?>
<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 200 200">
  <rect x="10" y="10" width="80" height="80" fill="blue"/>
</svg>"#;
        fs::write(&fake_png, svg_content).unwrap();
        
        // Should detect as SVG
        let detected = detect_file_type(&fake_png);
        assert_eq!(
            detected,
            Some("svg".to_string()),
            "SVG content should be detected even with wrong extension"
        );
        
        // Should suggest correction from .png to .svg
        let corrected = get_corrected_extension(&fake_png);
        assert_eq!(
            corrected,
            Some("svg".to_string()),
            "Should suggest correcting from .png to .svg"
        );
    }

    #[test]
    fn test_svg_not_misidentified_as_properties() {
        // Critical test: SVG files should NOT be detected as properties files
        // This was the bug - SVG attributes like x="10" y="20" were triggering properties detection
        let temp_dir = TempDir::new().unwrap();
        let svg_file = temp_dir.path().join("fastjson-json.svg");
        
        let svg_content = r#"<svg width="800" height="600" xmlns="http://www.w3.org/2000/svg">
  <rect x="10" y="20" width="100" height="50" fill="green"/>
  <text x="30" y="45" font-size="12" fill="white">FastJSON</text>
  <line x1="50" y1="70" x2="150" y2="70" stroke="black"/>
</svg>"#;
        fs::write(&svg_file, svg_content).unwrap();
        
        // With .svg extension, should return None (keep the extension)
        let detected = detect_file_type(&svg_file);
        assert_eq!(
            detected,
            None,
            "SVG with .svg extension should not be changed"
        );
        
        // Should NOT suggest correction (already correct)
        let corrected = get_corrected_extension(&svg_file);
        assert_eq!(
            corrected,
            None,
            "SVG files with .svg extension should not need correction"
        );
    }

    #[test]
    fn test_svg_without_xml_declaration() {
        // Some SVG files don't have <?xml> declaration
        let temp_dir = TempDir::new().unwrap();
        let svg_file = temp_dir.path().join("simple.png");
        
        let svg_content = r#"<svg xmlns="http://www.w3.org/2000/svg" width="50" height="50">
  <circle cx="25" cy="25" r="20" fill="yellow"/>
</svg>"#;
        fs::write(&svg_file, svg_content).unwrap();
        
        // Should still detect as SVG
        let detected = detect_file_type(&svg_file);
        assert_eq!(
            detected,
            Some("svg".to_string()),
            "SVG without XML declaration should still be detected"
        );
    }

    #[test]
    fn test_deb_file_detection() {
        // Test Debian package file detection
        let temp_dir = TempDir::new().unwrap();
        let deb_file = temp_dir.path().join("package.deb");
        
        // DEB files are 'ar' archives starting with "!<arch>\n"
        let deb_magic = b"!<arch>\ndebian-binary   ";
        fs::write(&deb_file, deb_magic).unwrap();
        
        // Should NOT detect as any other format (keep .deb)
        let detected = detect_file_type(&deb_file);
        assert_eq!(
            detected,
            None,
            "DEB files with .deb extension should not be changed"
        );
        
        // Should NOT suggest changing .deb files
        let corrected = get_corrected_extension(&deb_file);
        assert_eq!(
            corrected,
            None,
            ".deb files should not need correction"
        );
    }

    #[test]
    fn test_deb_file_misnamed() {
        // Test DEB file misnamed as another extension
        let temp_dir = TempDir::new().unwrap();
        let fake_txt = temp_dir.path().join("package.txt");
        
        // DEB file with wrong extension
        let deb_magic = b"!<arch>\ndebian-binary   ";
        fs::write(&fake_txt, deb_magic).unwrap();
        
        // Should detect as DEB
        let detected = detect_file_type(&fake_txt);
        assert_eq!(
            detected,
            Some("deb".to_string()),
            "DEB content should be detected even with wrong extension"
        );
        
        // Should suggest correction from .txt to .deb
        let corrected = get_corrected_extension(&fake_txt);
        assert_eq!(
            corrected,
            Some("deb".to_string()),
            "Should suggest correcting to .deb"
        );
    }

    #[test]
    fn test_yaml_file_detection() {
        // Test YAML file detection
        let temp_dir = TempDir::new().unwrap();
        let yaml_file = temp_dir.path().join("config.yaml");
        
        let yaml_content = r#"---
# Configuration file
server:
  port: 8080
  host: localhost
database:
  url: jdbc:mysql://localhost/db
  username: admin
"#;
        fs::write(&yaml_file, yaml_content).unwrap();
        
        // Should NOT detect as any other format (keep .yaml)
        let detected = detect_file_type(&yaml_file);
        assert_eq!(
            detected,
            None,
            "YAML files with .yaml extension should not be changed"
        );
        
        // Should NOT suggest changing .yaml files
        let corrected = get_corrected_extension(&yaml_file);
        assert_eq!(
            corrected,
            None,
            ".yaml files should not need correction"
        );
    }

    #[test]
    fn test_yaml_file_misnamed_as_properties() {
        // Critical test: YAML files should NOT be detected as properties files
        let temp_dir = TempDir::new().unwrap();
        let fake_props = temp_dir.path().join("flink-conf.properties");
        
        let yaml_content = r#"# Flink configuration
jobmanager.rpc.address: localhost
jobmanager.rpc.port: 6123
taskmanager.numberOfTaskSlots: 2
parallelism.default: 1
"#;
        fs::write(&fake_props, yaml_content).unwrap();
        
        // Should detect as YAML (uses : not =)
        let detected = detect_file_type(&fake_props);
        assert_eq!(
            detected,
            Some("yaml".to_string()),
            "YAML content should be detected as YAML, not properties"
        );
        
        // Should suggest correction from .properties to .yaml
        let corrected = get_corrected_extension(&fake_props);
        assert_eq!(
            corrected,
            Some("yaml".to_string()),
            "Should suggest correcting to .yaml"
        );
    }

    #[test]
    fn test_yaml_vs_properties_distinction() {
        // Ensure YAML (key: value) is distinguished from properties (key=value)
        let temp_dir = TempDir::new().unwrap();
        
        // YAML file
        let yaml_file = temp_dir.path().join("config.txt");
        let yaml_content = "database:\n  host: localhost\n  port: 5432\n";
        fs::write(&yaml_file, yaml_content).unwrap();
        
        let yaml_detected = detect_file_type(&yaml_file);
        assert_eq!(
            yaml_detected,
            Some("yaml".to_string()),
            "YAML with colon syntax should be detected as YAML"
        );
        
        // Properties file - use a proper Java properties format
        let props_file = temp_dir.path().join("app.properties");
        let props_content = "# Database configuration\ndatabase.host=localhost\ndatabase.port=5432\ndatabase.name=mydb\n";
        fs::write(&props_file, props_content).unwrap();
        
        // Properties files with .properties extension should return None (already correct)
        let props_corrected = get_corrected_extension(&props_file);
        assert_eq!(
            props_corrected,
            None,
            "Properties files with .properties extension should not need correction"
        );
    }

    #[test]
    fn test_yml_extension_also_preserved() {
        // Test that .yml extension is also preserved (alternate YAML extension)
        let temp_dir = TempDir::new().unwrap();
        let yml_file = temp_dir.path().join("config.yml");
        
        let yaml_content = "key: value\nanother_key: another_value\n";
        fs::write(&yml_file, yaml_content).unwrap();
        
        // Should NOT suggest changing .yml files
        let corrected = get_corrected_extension(&yml_file);
        assert_eq!(
            corrected,
            None,
            ".yml files should not need correction"
        );
    }

    #[test]
    fn test_utf8_bom_text_file_detection() {
        // Test UTF-8 BOM text file detection
        let temp_dir = TempDir::new().unwrap();
        let bom_file = temp_dir.path().join("data.png"); // Misnamed as PNG
        
        // UTF-8 BOM followed by text content (similar to the real files)
        let mut content = vec![0xEF, 0xBB, 0xBF]; // UTF-8 BOM
        content.extend_from_slice(b"-->IP[ /Masks|| /CIDR]#Port[ /Accurate]
Item Rows(100)
2001:250::/30#0-65535
2001:255::/32#0-65535
");
        fs::write(&bom_file, content).unwrap();
        
        // Should detect as TXT (text file with BOM)
        let detected = detect_file_type(&bom_file);
        assert_eq!(
            detected,
            Some("txt".to_string()),
            "UTF-8 BOM text files should be detected as text"
        );
        
        // Should suggest correction from .png to .txt
        let corrected = get_corrected_extension(&bom_file);
        assert_eq!(
            corrected,
            Some("txt".to_string()),
            "Should suggest correcting to .txt"
        );
    }

    #[test]
    fn test_utf8_bom_txt_file_preserved() {
        // Test that UTF-8 BOM text files with .txt extension are not changed
        let temp_dir = TempDir::new().unwrap();
        let txt_file = temp_dir.path().join("data.txt");
        
        // UTF-8 BOM followed by text content
        let mut content = vec![0xEF, 0xBB, 0xBF]; // UTF-8 BOM
        content.extend_from_slice(b"Some text data\nWith multiple lines\n");
        fs::write(&txt_file, content).unwrap();
        
        // Should NOT suggest changing .txt files
        let corrected = get_corrected_extension(&txt_file);
        assert_eq!(
            corrected,
            None,
            ".txt files should not need correction"
        );
    }

    #[test]
    fn test_drawio_xml_detection() {
        // Test draw.io XML file detection (often misnamed as PNG)
        let temp_dir = TempDir::new().unwrap();
        let drawio_as_png = temp_dir.path().join("diagram.png");
        
        // draw.io XML content
        let drawio_content = r#"<mxfile host="Electron" modified="2023-04-18T01:58:05.938Z" agent="5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) draw.io/14.6.13" etag="abcdef123456" version="14.6.13" type="device">
  <diagram id="test" name="Diagram">
    <mxGraphModel dx="1200" dy="800" grid="1" gridSize="10" guides="1" tooltips="1" connect="1" arrows="1" fold="1" page="1" pageScale="1" pageWidth="827" pageHeight="1169" background="ffffff" math="0" shadow="0">
      <root>
        <mxCell id="0" style="edgeStyle=orthogonalEdgeStyle;rounded=0;orthogonalLoop=1;jettySize=auto;html=1;" edge="1" parent="1" source="2" target="3">
          <mxGeometry relative="1" as="geometry" />
        </mxCell>
      </root>
    </mxGraphModel>
  </diagram>
</mxfile>"#;
        fs::write(&drawio_as_png, drawio_content).unwrap();
        
        // Should detect as SVG (draw.io is SVG-based)
        let detected = detect_file_type(&drawio_as_png);
        assert_eq!(
            detected,
            Some("svg".to_string()),
            "draw.io XML files should be detected as SVG"
        );
        
        // Should suggest correction from .png to .svg
        let corrected = get_corrected_extension(&drawio_as_png);
        assert_eq!(
            corrected,
            Some("svg".to_string()),
            "Should suggest correcting .png to .svg for draw.io files"
        );
    }

    #[test]
    fn test_drawio_with_svg_extension() {
        // Test that draw.io files with .svg extension are not changed
        let temp_dir = TempDir::new().unwrap();
        let drawio_file = temp_dir.path().join("diagram.svg");
        
        let drawio_content = r#"<mxfile host="Electron" modified="2023-04-18T01:58:05.938Z" agent="5.0" version="14.6.13">
  <diagram id="test" name="Diagram">
    <mxGraphModel>
      <root><mxCell id="0" /></root>
    </mxGraphModel>
  </diagram>
</mxfile>"#;
        fs::write(&drawio_file, drawio_content).unwrap();
        
        // Should NOT suggest changing .svg files
        let corrected = get_corrected_extension(&drawio_file);
        assert_eq!(
            corrected,
            None,
            ".svg files should not need correction"
        );
    }

    #[test]
    fn test_pcapng_detection() {
        // Test PCAPNG (Wireshark) file detection
        let temp_dir = TempDir::new().unwrap();
        let pcapng_as_png = temp_dir.path().join("capture.png");
        
        // PCAPNG magic bytes: 0A 0D 0D 0A followed by section header
        let pcapng_header = vec![
            0x0A, 0x0D, 0x0D, 0x0A, // PCAPNG magic
            0xC0, 0x00, 0x00, 0x00, // Section header block
            0x4D, 0x3C, 0x2B, 0x1A, // More header data
        ];
        fs::write(&pcapng_as_png, pcapng_header).unwrap();
        
        // Should detect as PCAPNG
        let detected = detect_file_type(&pcapng_as_png);
        assert_eq!(detected, Some("pcapng".to_string()), "PCAPNG file should be detected");
        
        // Should suggest correcting .png to .pcapng
        let corrected = get_corrected_extension(&pcapng_as_png);
        assert_eq!(corrected, Some("pcapng".to_string()), "PCAPNG misnamed as .png should be corrected");
    }

    #[test]
    fn test_pcap_detection_little_endian() {
        // Test PCAP (little-endian) file detection
        let temp_dir = TempDir::new().unwrap();
        let pcap_as_png = temp_dir.path().join("capture.png");
        
        // PCAP little-endian magic bytes: D4 C3 B2 A1
        let pcap_header = vec![0xD4, 0xC3, 0xB2, 0xA1, 0x02, 0x00, 0x04, 0x00];
        fs::write(&pcap_as_png, pcap_header).unwrap();
        
        // Should detect as PCAP
        let detected = detect_file_type(&pcap_as_png);
        assert_eq!(detected, Some("pcap".to_string()), "PCAP file should be detected");
        
        // Should suggest correcting .png to .pcap
        let corrected = get_corrected_extension(&pcap_as_png);
        assert_eq!(corrected, Some("pcap".to_string()), "PCAP misnamed as .png should be corrected");
    }

    #[test]
    fn test_pcap_detection_big_endian() {
        // Test PCAP (big-endian) file detection
        let temp_dir = TempDir::new().unwrap();
        let pcap_as_png = temp_dir.path().join("capture.png");
        
        // PCAP big-endian magic bytes: A1 B2 C3 D4
        let pcap_header = vec![0xA1, 0xB2, 0xC3, 0xD4, 0x00, 0x02, 0x00, 0x04];
        fs::write(&pcap_as_png, pcap_header).unwrap();
        
        // Should detect as PCAP
        let detected = detect_file_type(&pcap_as_png);
        assert_eq!(detected, Some("pcap".to_string()), "PCAP file should be detected");
        
        // Should suggest correcting .png to .pcap
        let corrected = get_corrected_extension(&pcap_as_png);
        assert_eq!(corrected, Some("pcap".to_string()), "PCAP misnamed as .png should be corrected");
    }

    #[test]
    fn test_csv_with_gbk_encoding() {
        // Test CSV detection with GBK-encoded Chinese text
        let temp_dir = TempDir::new().unwrap();
        let csv_as_png = temp_dir.path().join("data.png");
        
        // GBK-encoded CSV with Chinese headers: "长度,个数,acc" (Length, Count, Accuracy)
        // These are the actual GBK bytes for the Chinese headers followed by ASCII
        let gbk_csv_content = vec![
            // 长度 (Length in GBK)
            0xB3, 0xA4, // 长
            0xB6, 0xC8, // 度
            0x2C,       // comma
            // 个数 (Count in GBK)
            0xB8, 0xF6, // 个
            0xCA, 0xFD, // 数
            0x2C,       // comma
            // acc (ASCII)
            0x61, 0x63, 0x63, // "acc"
            0x0D, 0x0A, // CRLF
            // Data row 1
            0x33, 0x2C, 0x33, 0x2C, 0x30, 0x2E, 0x39, 0x33, // "3,3,0.93"
            0x37, 0x34, 0x35, 0x32, 0x39, 0x30, 0x31, // "7452901"
            0x0D, 0x0A, // CRLF
            // Data row 2
            0x34, 0x2C, 0x34, 0x2C, 0x30, 0x2E, 0x39, 0x35, // "4,4,0.95"
            0x33, 0x37, 0x32, 0x35, 0x34, 0x39, // "372549"
            0x0D, 0x0A, // CRLF
        ];
        fs::write(&csv_as_png, &gbk_csv_content).unwrap();
        
        // Should detect as CSV despite non-ASCII encoding
        let detected = detect_file_type(&csv_as_png);
        assert_eq!(detected, Some("csv".to_string()), "GBK-encoded CSV file should be detected");
        
        // Should suggest correcting .png to .csv
        let corrected = get_corrected_extension(&csv_as_png);
        assert_eq!(corrected, Some("csv".to_string()), "GBK CSV misnamed as .png should be corrected to .csv");
    }

    #[test]
    fn test_word_xml_detection() {
        // Test Word XML format detection
        let temp_dir = TempDir::new().unwrap();
        let word_xml_as_png = temp_dir.path().join("document.png");
        
        // Microsoft Word XML format (older XML-based format, not ZIP-based .docx)
        let word_xml_content = r#"<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<?mso-application progid="Word.Document"?>
<w:wordDocument xmlns:w="http://schemas.microsoft.com/office/word/2003/wordml">
  <w:body>
    <w:p>
      <w:r>
        <w:t>This is a Word XML document</w:t>
      </w:r>
    </w:p>
  </w:body>
</w:wordDocument>"#;
        
        fs::write(&word_xml_as_png, word_xml_content.as_bytes()).unwrap();
        
        // Should detect as Word XML
        let detected = detect_file_type(&word_xml_as_png);
        assert_eq!(detected, Some("xml".to_string()), "Word XML file should be detected as xml");
        
        // Should suggest correcting .png to .xml
        let corrected = get_corrected_extension(&word_xml_as_png);
        assert_eq!(corrected, Some("xml".to_string()), "Word XML misnamed as .png should be corrected to .xml");
    }

    #[test]
    fn test_word_xml_vs_svg_distinction() {
        // Ensure Word XML is not confused with SVG
        let temp_dir = TempDir::new().unwrap();
        
        // Word XML file
        let word_xml = temp_dir.path().join("word.xml");
        let word_xml_content = r#"<?xml version="1.0"?>
<?mso-application progid="Word.Document"?>
<w:wordDocument xmlns:w="http://schemas.microsoft.com/office/word/2003/wordml">
  <w:body><w:p><w:r><w:t>Text</w:t></w:r></w:p></w:body>
</w:wordDocument>"#;
        fs::write(&word_xml, word_xml_content.as_bytes()).unwrap();
        
        // SVG file
        let svg_file = temp_dir.path().join("image.xml");
        let svg_content = r#"<?xml version="1.0"?>
<svg xmlns="http://www.w3.org/2000/svg" width="100" height="100">
  <circle cx="50" cy="50" r="40" fill="blue"/>
</svg>"#;
        fs::write(&svg_file, svg_content.as_bytes()).unwrap();
        
        // Word XML should be detected as xml (not svg)
        let word_detected = detect_file_type(&word_xml);
        assert_eq!(word_detected, None, "Word XML with .xml extension should not be corrected");
        
        // SVG should still be detected as svg
        let svg_detected = detect_file_type(&svg_file);
        assert_eq!(svg_detected, Some("svg".to_string()), "SVG file should be detected as svg even with .xml extension");
    }
}




