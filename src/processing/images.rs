use std::fs;
use std::path::Path;
use walkdir::WalkDir;
use image::{ImageFormat, ImageReader};

/// Detects the actual image format and renames the file with the correct extension.
///
/// This function is crucial for handling images with mismatched extensions
/// (e.g., JPEG files named as .png), which can cause failures in image processing.
///
/// # Arguments
/// * `image_path` - Path to the image file
///
/// # Returns
/// * `Ok(PathBuf)` - The path with correct extension (may be unchanged if already correct)
/// * `Err` - If there was a problem detecting format or renaming
///
/// # Examples
/// A file named "image.png" containing JPEG data will be renamed to "image.jpg"
pub fn detect_and_rename_image(image_path: &Path) -> Result<std::path::PathBuf, Box<dyn std::error::Error>> {
    let reader = ImageReader::open(image_path)?
        .with_guessed_format()?;

    let detected_format = reader.format();
    let current_ext = image_path.extension().and_then(|s| s.to_str()).unwrap_or("");

    // Map format to extension
    let correct_ext = match detected_format {
        Some(ImageFormat::Png) => "png",
        Some(ImageFormat::Jpeg) => "jpg",
        Some(ImageFormat::Gif) => "gif",
        Some(ImageFormat::WebP) => "webp",
        Some(ImageFormat::Bmp) => "bmp",
        Some(ImageFormat::Tiff) => "tiff",
        Some(ImageFormat::Ico) => "ico",
        _ => current_ext, // Keep original if format unknown
    };

    // If extension matches, return original path
    if current_ext.eq_ignore_ascii_case(correct_ext) {
        return Ok(image_path.to_path_buf());
    }

    // Create new path with correct extension
    let new_path = image_path.with_extension(correct_ext);

    // Rename the file
    fs::rename(image_path, &new_path)?;

    use crate::logger::Logger;
    Logger::detail(&format!("Corrected extension: {} → {}",
             image_path.file_name().unwrap().to_string_lossy(),
             new_path.file_name().unwrap().to_string_lossy()));

    Ok(new_path)
}

/// Scans a directory recursively and corrects image file extensions based on actual content.
///
/// This function walks through all files in the directory and its subdirectories,
/// detecting images with wrong extensions and renaming them appropriately.
///
/// # Arguments
/// * `dir_path` - Path to the directory to scan
///
/// # Returns
/// * Number of files that were corrected
pub fn correct_image_extensions_in_directory(dir_path: &Path) -> usize {
    let mut corrected_count = 0;

    for entry in WalkDir::new(dir_path).into_iter().filter_map(Result::ok) {
        if entry.file_type().is_file() {
            let path = entry.path();
            if let Some(ext) = path.extension() {
                let ext_str = ext.to_string_lossy().to_lowercase();
                // Only check files with image extensions
                if ["png", "jpg", "jpeg", "gif", "bmp", "webp", "tiff", "ico"].contains(&ext_str.as_str()) {
                    match detect_and_rename_image(path) {
                        Ok(new_path) => {
                            if new_path != path {
                                corrected_count += 1;
                            }
                        }
                        Err(_) => {
                            // Silently continue if detection fails (file might be corrupted or not actually an image)
                        }
                    }
                }
            }
        }
    }

    corrected_count
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::TempDir;

    /// Helper function to create a simple PNG image data (1x1 red pixel)
    fn create_test_png_data() -> Vec<u8> {
        vec![
            0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A, // PNG signature
            0x00, 0x00, 0x00, 0x0D, 0x49, 0x48, 0x44, 0x52, // IHDR chunk
            0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01,
            0x08, 0x02, 0x00, 0x00, 0x00, 0x90, 0x77, 0x53,
            0xDE, 0x00, 0x00, 0x00, 0x0C, 0x49, 0x44, 0x41,
            0x54, 0x08, 0xD7, 0x63, 0xF8, 0xCF, 0xC0, 0x00,
            0x00, 0x03, 0x01, 0x01, 0x00, 0x18, 0xDD, 0x8D,
            0xB4, 0x00, 0x00, 0x00, 0x00, 0x49, 0x45, 0x4E,
            0x44, 0xAE, 0x42, 0x60, 0x82,
        ]
    }

    /// Helper function to create a simple JPEG image data
    fn create_test_jpeg_data() -> Vec<u8> {
        vec![
            0xFF, 0xD8, 0xFF, 0xE0, 0x00, 0x10, 0x4A, 0x46, // JPEG signature
            0x49, 0x46, 0x00, 0x01, 0x01, 0x00, 0x00, 0x01,
            0x00, 0x01, 0x00, 0x00, 0xFF, 0xD9,
        ]
    }

    #[test]
    fn test_detect_and_rename_image_correct_extension() {
        let temp_dir = TempDir::new().unwrap();
        let image_path = temp_dir.path().join("test.png");
        
        // Create a file with correct PNG extension and PNG data
        let mut file = fs::File::create(&image_path).unwrap();
        file.write_all(&create_test_png_data()).unwrap();
        drop(file);

        let result = detect_and_rename_image(&image_path).unwrap();
        
        // Should return the same path since extension is correct
        assert_eq!(result, image_path);
        assert!(result.exists());
    }

    #[test]
    fn test_detect_and_rename_image_wrong_extension() {
        let temp_dir = TempDir::new().unwrap();
        let image_path = temp_dir.path().join("test.png");
        
        // Create a file with .png extension but JPEG data
        let mut file = fs::File::create(&image_path).unwrap();
        file.write_all(&create_test_jpeg_data()).unwrap();
        drop(file);

        let result = detect_and_rename_image(&image_path).unwrap();
        
        // Should be renamed to .jpg
        assert_eq!(result.extension().unwrap(), "jpg");
        assert!(result.exists());
        assert!(!image_path.exists());
    }

    #[test]
    fn test_detect_and_rename_image_invalid_file() {
        let temp_dir = TempDir::new().unwrap();
        let image_path = temp_dir.path().join("invalid.png");
        
        // Create a file with invalid image data
        let mut file = fs::File::create(&image_path).unwrap();
        file.write_all(b"This is not an image").unwrap();
        drop(file);

        let result = detect_and_rename_image(&image_path);
        
        // detect_and_rename_image returns the original path unchanged if format can't be detected
        // or returns an error if the file can't be opened/read
        assert!(result.is_err() || result.unwrap() == image_path);
    }

    #[test]
    fn test_correct_image_extensions_in_directory() {
        let temp_dir = TempDir::new().unwrap();
        
        // Create test images with mismatched extensions
        let correct_png = temp_dir.path().join("correct.png");
        fs::write(&correct_png, &create_test_png_data()).unwrap();
        
        let wrong_png = temp_dir.path().join("wrong.png");
        fs::write(&wrong_png, &create_test_jpeg_data()).unwrap();
        
        let correct_jpg = temp_dir.path().join("correct.jpg");
        fs::write(&correct_jpg, &create_test_jpeg_data()).unwrap();
        
        // Create a non-image file
        let text_file = temp_dir.path().join("text.txt");
        fs::write(&text_file, b"Not an image").unwrap();
        
        let corrected = correct_image_extensions_in_directory(temp_dir.path());
        
        // Should correct 1 file (wrong.png -> wrong.jpg)
        assert_eq!(corrected, 1);
        
        // Verify files
        assert!(correct_png.exists());
        assert!(!wrong_png.exists());
        assert!(temp_dir.path().join("wrong.jpg").exists());
        assert!(correct_jpg.exists());
        assert!(text_file.exists());
    }

    #[test]
    fn test_correct_image_extensions_empty_directory() {
        let temp_dir = TempDir::new().unwrap();
        
        let corrected = correct_image_extensions_in_directory(temp_dir.path());
        
        // No files to correct
        assert_eq!(corrected, 0);
    }

    #[test]
    fn test_correct_image_extensions_nested_directories() {
        let temp_dir = TempDir::new().unwrap();
        let sub_dir = temp_dir.path().join("subdir");
        fs::create_dir(&sub_dir).unwrap();
        
        // Create images in nested directory
        let wrong_nested = sub_dir.join("nested.png");
        fs::write(&wrong_nested, &create_test_jpeg_data()).unwrap();
        
        let corrected = correct_image_extensions_in_directory(temp_dir.path());
        
        // Should find and correct nested files
        assert_eq!(corrected, 1);
        assert!(!wrong_nested.exists());
        assert!(sub_dir.join("nested.jpg").exists());
    }
}