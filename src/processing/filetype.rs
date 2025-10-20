use std::fs::File;
use std::io::Read;
use std::path::Path;
use zip::ZipArchive;

/// Checks if a ZIP file is actually a Microsoft Office document (DOCX, XLSX, PPTX).
/// Office documents are ZIP files with specific internal structure.
fn is_office_document(path: &Path) -> bool {
    // First check if the extension suggests it's an Office document
    if let Some(ext) = path.extension() {
        let ext_lower = ext.to_string_lossy().to_lowercase();
        if ["docx", "xlsx", "pptx", "doc", "xls", "ppt"].contains(&ext_lower.as_str()) {
            // If it has an Office extension, assume it's an Office document
            return true;
        }
    }
    
    // Otherwise, check the internal structure
    let file = match File::open(path) {
        Ok(f) => f,
        Err(_) => return false,
    };
    
    let mut archive = match ZipArchive::new(file) {
        Ok(a) => a,
        Err(_) => return false,
    };
    
    // Office documents contain specific files:
    // - [Content_Types].xml (all Office docs)
    // - word/document.xml (DOCX)
    // - xl/workbook.xml (XLSX)
    // - ppt/presentation.xml (PPTX)
    
    // Check for [Content_Types].xml which is present in all Office documents
    archive.by_name("[Content_Types].xml").is_ok()
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
    archive.by_name("AndroidManifest.xml").is_ok()
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
    archive.by_name("manifest.json").is_ok()
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
    archive.by_name("META-INF/MANIFEST.MF").is_ok()
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
    let mut buffer = vec![0u8; 32]; // Read first 32 bytes for magic number detection
    
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
                return None; // Let it keep its .apk extension
            }
            
            // Check for XAPK (Extended Android Package)
            if is_xapk_file(path) {
                return None; // Let it keep its .xapk extension
            }
            
            // Check for JAR (Java Archive)
            if is_jar_file(path) {
                return None; // Let it keep its .jar extension
            }
            
            // Check for Office documents (DOCX, XLSX, PPTX)
            if is_office_document(path) {
                return None; // Let it keep its original Office extension
            }
            
            // Check for PKG (macOS installer - some use ZIP format)
            if is_pkg_file(path) {
                return None; // Let it keep its .pkg extension
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
        
        _ => None,
    }
}

/// Gets the correct file extension for a file, detecting mismatches.
/// If the actual file type doesn't match the current extension, returns the correct one.
///
/// # Arguments
/// * `path` - Path to the file
///
/// # Returns
/// * `Some(extension)` - The correct extension if mismatch is detected
/// * `None` - If extension matches or type cannot be determined
pub fn get_corrected_extension(path: &Path) -> Option<String> {
    let current_ext = path.extension()?.to_str()?.to_lowercase();
    let detected_ext = detect_file_type(path)?;
    
    // If extensions don't match, return the correct one
    if current_ext != detected_ext {
        Some(detected_ext)
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
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
        file.write_all(&[0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A]).unwrap();
        
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
        file.write_all(&[0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A]).unwrap();
        
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
        file.write_all(&[0x52, 0x61, 0x72, 0x21, 0x1A, 0x07]).unwrap();
        
        let detected = detect_file_type(&rar_path);
        assert_eq!(detected, Some("rar".to_string()));
    }

    #[test]
    fn test_detect_7z_file() {
        let temp_dir = TempDir::new().unwrap();
        let sz_path = temp_dir.path().join("test.7z");
        
        // 7z magic bytes
        let mut file = File::create(&sz_path).unwrap();
        file.write_all(&[0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C]).unwrap();
        
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
        assert_eq!(corrected, None); // Can't correct if no extension exists
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
        file.write_all(&[0x52, 0x61, 0x72, 0x21, 0x1A, 0x07]).unwrap();
        
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
            assert_eq!(detected, Some("jpg".to_string()),
                      "Failed to detect JPEG with marker 0x{:02X}", marker);
        }
    }

    #[test]
    fn test_office_document_not_changed() {
        use std::io::Write;
        use zip::write::{FileOptions, ZipWriter};
        
        let temp_dir = TempDir::new().unwrap();
        
        // Create a minimal Office document (DOCX)
        let docx_path = temp_dir.path().join("document.docx");
        let file = File::create(&docx_path).unwrap();
        let mut zip = ZipWriter::new(file);
        
        // Add [Content_Types].xml which identifies it as an Office document
        let options = FileOptions::default();
        zip.start_file("[Content_Types].xml", options).unwrap();
        zip.write_all(b"<?xml version=\"1.0\"?><Types></Types>").unwrap();
        zip.finish().unwrap();
        
        // Should NOT detect as ZIP since it's an Office document
        let detected = detect_file_type(&docx_path);
        assert_eq!(detected, None, "Office documents should not be changed to .zip");
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
        zip.write_all(b"<?xml version=\"1.0\"?><Types></Types>").unwrap();
        zip.finish().unwrap();
        
        // Should NOT try to correct extension since it's an Office document
        let corrected = get_corrected_extension(&fake_png_path);
        assert_eq!(corrected, None, "Office documents should keep their extension even if misnamed");
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
        assert_eq!(corrected, Some("zip".to_string()), "Regular ZIP with wrong extension should be corrected");
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
        zip.write_all(b"<?xml version=\"1.0\"?><manifest></manifest>").unwrap();
        zip.finish().unwrap();
        
        // Should NOT detect as ZIP since it's an APK
        let detected = detect_file_type(&apk_path);
        assert_eq!(detected, None, "APK files should not be changed to .zip");
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
        zip.write_all(b"<?xml version=\"1.0\"?><manifest></manifest>").unwrap();
        zip.finish().unwrap();
        
        // Should NOT try to correct extension since it's an APK
        let corrected = get_corrected_extension(&fake_png_path);
        assert_eq!(corrected, None, "APK files should keep their extension even if misnamed");
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
        zip.write_all(b"{\"package_name\":\"com.example.app\"}").unwrap();
        zip.finish().unwrap();
        
        // Should NOT detect as ZIP since it's an XAPK
        let detected = detect_file_type(&xapk_path);
        assert_eq!(detected, None, "XAPK files should not be changed to .zip");
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
        zip.write_all(b"{\"package_name\":\"com.example.app\"}").unwrap();
        zip.finish().unwrap();
        
        // Should NOT try to correct extension since it's an XAPK
        let corrected = get_corrected_extension(&fake_zip_path);
        assert_eq!(corrected, None, "XAPK files should keep their extension even if misnamed");
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
        zip.write_all(b"Manifest-Version: 1.0\nMain-Class: com.example.Main\n").unwrap();
        zip.finish().unwrap();
        
        // Should NOT detect as ZIP since it's a JAR
        let detected = detect_file_type(&jar_path);
        assert_eq!(detected, None, "JAR files should not be changed to .zip");
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
        zip.write_all(b"Manifest-Version: 1.0\nMain-Class: com.example.Main\n").unwrap();
        zip.finish().unwrap();
        
        // Should NOT try to correct extension since it's a JAR
        let corrected = get_corrected_extension(&fake_png_path);
        assert_eq!(corrected, None, "JAR files should keep their extension even if misnamed");
    }
}
