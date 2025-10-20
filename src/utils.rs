//! Utility functions for markdown processing and image handling
//!
//! This module provides core utility functions that are used throughout the application:
//! - Content sanitization for LaTeX compatibility
//! - Image resizing and validation
//! - File system operations

use std::path::Path;
use image::{GenericImageView, ImageFormat, imageops::FilterType, ImageReader};

/// Sanitizes markdown content by removing problematic control characters that can cause LaTeX errors.
///
/// This function removes:
/// - Backspace characters (0x08, represented as ^^H in LaTeX errors)
/// - Other control characters (0x00-0x1F) except tab, newline, and carriage return
/// - Zero-width spaces and other invisible Unicode characters
///
/// These characters often appear in content copied from terminals or certain applications
/// and cause LaTeX compilation to fail with errors like:
/// "Text line contains an invalid character"
///
/// # Arguments
/// * `content` - The markdown content to sanitize
///
/// # Returns
/// * Sanitized content safe for LaTeX processing
///
/// # Examples
/// ```
/// use gfw_helper::sanitize_markdown_content;
///
/// let input = "Text with backspace\x08 character";
/// let output = sanitize_markdown_content(input);
/// assert_eq!(output, "Text with backspace character");
/// ```
pub fn sanitize_markdown_content(content: &str) -> String {
    content.chars()
        .filter(|c| {
            let ch = *c;
            // Keep tab (0x09), newline (0x0A), and carriage return (0x0D)
            if ch == '\t' || ch == '\n' || ch == '\r' {
                return true;
            }
            // Remove other control characters (0x00-0x1F)
            if ch < ' ' {
                return false;
            }
            // Remove DEL character (0x7F)
            if ch == '\x7F' {
                return false;
            }
            // Remove zero-width characters that can cause issues
            if ch == '\u{200B}' || // Zero-width space
               ch == '\u{200C}' || // Zero-width non-joiner
               ch == '\u{200D}' || // Zero-width joiner
               ch == '\u{FEFF}'    // Zero-width no-break space (BOM)
            {
                return false;
            }
            true
        })
        .collect()
}

/// Resizes an image if it exceeds the specified maximum dimensions.
///
/// This function prevents LaTeX "Dimension too large" errors by automatically resizing
/// oversized images while maintaining their aspect ratio. Images are resized down to
/// fit within the max_width x max_height bounds.
///
/// The resizing process:
/// 1. Opens and decodes the image to check current dimensions
/// 2. Returns early if the image is already within bounds
/// 3. Calculates new dimensions maintaining aspect ratio
/// 4. Resizes using Lanczos3 filter for high quality
/// 5. Saves the result as PNG format
///
/// # Arguments
/// * `image_path` - Path to the image file to potentially resize
/// * `max_width` - Maximum allowed width in pixels
/// * `max_height` - Maximum allowed height in pixels
///
/// # Returns
/// * `Result<(), Box<dyn std::error::Error>>` - Success or error details
///
/// # Notes
/// - Always saves as PNG format regardless of input format
/// - Uses high-quality Lanczos3 resampling filter
/// - Maintains aspect ratio during resizing
/// - Only resizes down, never enlarges images
///
/// # Examples
/// ```no_run
/// use gfw_helper::resize_image_if_needed;
/// use std::path::Path;
///
/// let image_path = Path::new("large_image.png");
/// resize_image_if_needed(image_path, 4000, 4000).unwrap();
/// ```
pub fn resize_image_if_needed(image_path: &Path, max_width: u32, max_height: u32) -> Result<(), Box<dyn std::error::Error>> {
    // Open and decode the image with format guessing to handle mismatched extensions
    let img = ImageReader::open(image_path)?
        .with_guessed_format()?
        .decode()?;

    let (width, height) = img.dimensions();

    // Early return if image is already within acceptable dimensions
    if width <= max_width && height <= max_height {
        return Ok(()); // No resizing needed
    }

    // Calculate new dimensions while maintaining aspect ratio
    let aspect_ratio = width as f32 / height as f32;
    let (new_width, new_height) = if width > height {
        // Landscape orientation: limit by width
        let new_width = max_width.min(width);
        let new_height = (new_width as f32 / aspect_ratio) as u32;
        (new_width, new_height)
    } else {
        // Portrait or square orientation: limit by height
        let new_height = max_height.min(height);
        let new_width = (new_height as f32 * aspect_ratio) as u32;
        (new_width, new_height)
    };

    // Resize the image using high-quality Lanczos3 filter
    let resized_img = img.resize(new_width, new_height, FilterType::Lanczos3);

    // Save the resized image back to the same path as PNG format
    resized_img.save_with_format(image_path, ImageFormat::Png)?;

    use crate::logger::Logger;
    Logger::detail(&format!("Resized image {} from {}x{} to {}x{}",
             image_path.display(), width, height, new_width, new_height));

    Ok(())
}

/// Converts a WebP image to PNG format.
///
/// This function is necessary because LaTeX (used by pandoc for PDF generation) does not
/// support WebP format natively. The function reads the WebP file, decodes it, and saves
/// it as PNG with the same base filename.
///
/// # Arguments
/// * `webp_path` - Path to the WebP image file
///
/// # Returns
/// * `Ok(PathBuf)` - Path to the newly created PNG file
/// * `Err` - If there was a problem reading the WebP or writing the PNG
///
/// # Example
/// ```no_run
/// use std::path::Path;
/// use gfw_helper::convert_webp_to_png;
///
/// let webp_path = Path::new("image.webp");
/// let png_path = convert_webp_to_png(webp_path).unwrap();
/// // png_path will be "image.png"
/// ```
pub fn convert_webp_to_png(webp_path: &Path) -> Result<std::path::PathBuf, Box<dyn std::error::Error>> {
    // Open and decode the WebP image
    let img = ImageReader::open(webp_path)?
        .with_guessed_format()?
        .decode()?;

    // Create new path with .png extension
    let png_path = webp_path.with_extension("png");

    // Save as PNG
    img.save_with_format(&png_path, ImageFormat::Png)?;

    use crate::logger::Logger;
    Logger::conversion(
        &webp_path.file_name().unwrap().to_string_lossy(),
        &png_path.file_name().unwrap().to_string_lossy()
    );

    Ok(png_path)
}

/// Converts an SVG image to PNG format using Inkscape.
///
/// This function is necessary because LaTeX (used by pandoc for PDF generation) does not
/// reliably support SVG format. The function calls Inkscape to convert the SVG to PNG.
/// If Inkscape is not available, it returns an error.
///
/// # Arguments
/// * `svg_path` - Path to the SVG image file
///
/// # Returns
/// * `Ok(PathBuf)` - Path to the newly created PNG file
/// * `Err` - If Inkscape is not found or conversion fails
///
/// # Example
/// ```no_run
/// use std::path::Path;
/// use gfw_helper::convert_svg_to_png;
///
/// let svg_path = Path::new("diagram.svg");
/// let png_path = convert_svg_to_png(svg_path).unwrap();
/// // png_path will be "diagram.png"
/// ```
pub fn convert_svg_to_png(svg_path: &Path) -> Result<std::path::PathBuf, Box<dyn std::error::Error>> {
    use std::process::Command;

    // Create new path with .png extension
    let png_path = svg_path.with_extension("png");

    // Try to convert using Inkscape
    let output = Command::new("inkscape")
        .arg(svg_path)
        .arg(format!("--export-filename={}", png_path.display()))
        .arg("--export-type=png")
        .output();

    match output {
        Ok(result) if result.status.success() => {
            use crate::logger::Logger;
            Logger::conversion(
                &svg_path.file_name().unwrap().to_string_lossy(),
                &png_path.file_name().unwrap().to_string_lossy()
            );
            Ok(png_path)
        }
        Ok(result) => {
            let stderr = String::from_utf8_lossy(&result.stderr);
            Err(format!("Inkscape conversion failed: {}", stderr).into())
        }
        Err(e) => {
            Err(format!("Inkscape not found or failed to execute: {}. Please install Inkscape.", e).into())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn test_sanitize_markdown_content_backspace() {
        let input = "Some text with backspace\x08 and more text";
        let expected = "Some text with backspace and more text";
        assert_eq!(sanitize_markdown_content(input), expected);
    }

    #[test]
    fn test_sanitize_markdown_content_control_chars() {
        let input = "Text\x01\x02\x03with\x7fcontrol chars";
        let expected = "Textwithcontrol chars";
        assert_eq!(sanitize_markdown_content(input), expected);
    }

    #[test]
    fn test_sanitize_markdown_content_preserves_normal() {
        let input = "Normal text with 中文 characters and spaces";
        let expected = "Normal text with 中文 characters and spaces";
        assert_eq!(sanitize_markdown_content(input), expected);
    }

    #[test]
    fn test_sanitize_markdown_content_zero_width() {
        let input = "Text\u{200B}with\u{200C}zero\u{200D}width\u{FEFF}chars";
        let expected = "Textwithzerowidthchars";
        assert_eq!(sanitize_markdown_content(input), expected);
    }

    #[test]
    fn test_sanitize_markdown_content_preserves_tabs_newlines() {
        let input = "Line1\nLine2\r\nWith\ttab";
        let expected = "Line1\nLine2\r\nWith\ttab";
        assert_eq!(sanitize_markdown_content(input), expected);
    }

    #[test]
    fn test_sanitize_markdown_content_mixed() {
        let input = "VPN审批流程.png\x08 with 中文\x01and\u{200B}issues";
        let expected = "VPN审批流程.png with 中文andissues";
        assert_eq!(sanitize_markdown_content(input), expected);
    }

    #[test]
    fn test_sanitize_markdown_content_empty() {
        let input = "";
        let expected = "";
        assert_eq!(sanitize_markdown_content(input), expected);
    }

    /// Helper to create a minimal valid PNG (1x1 red pixel)
    fn create_test_png(path: &Path, width: u32, height: u32) -> Result<(), Box<dyn std::error::Error>> {
        use image::{ImageBuffer, Rgb};
        let img = ImageBuffer::from_fn(width, height, |_x, _y| {
            Rgb([255u8, 0u8, 0u8])
        });
        img.save_with_format(path, ImageFormat::Png)?;
        Ok(())
    }

    #[test]
    fn test_resize_image_if_needed_no_resize() {
        let temp_dir = TempDir::new().unwrap();
        let image_path = temp_dir.path().join("small.png");
        
        // Create a small image (100x100)
        create_test_png(&image_path, 100, 100).unwrap();
        
        // Try to resize with larger bounds
        let result = resize_image_if_needed(&image_path, 4000, 4000);
        assert!(result.is_ok());
        
        // Image should remain the same size
        let img = image::open(&image_path).unwrap();
        assert_eq!(img.dimensions(), (100, 100));
    }

    #[test]
    fn test_resize_image_if_needed_landscape() {
        let temp_dir = TempDir::new().unwrap();
        let image_path = temp_dir.path().join("landscape.png");
        
        // Create a landscape image (5000x3000)
        create_test_png(&image_path, 5000, 3000).unwrap();
        
        // Resize to max 4000x4000
        let result = resize_image_if_needed(&image_path, 4000, 4000);
        assert!(result.is_ok());
        
        // Check that image was resized
        let img = image::open(&image_path).unwrap();
        let (width, height) = img.dimensions();
        assert!(width <= 4000);
        assert!(height <= 4000);
        // Check aspect ratio maintained (approximately)
        let ratio = width as f32 / height as f32;
        assert!((ratio - 5000.0 / 3000.0).abs() < 0.01);
    }

    #[test]
    fn test_resize_image_if_needed_portrait() {
        let temp_dir = TempDir::new().unwrap();
        let image_path = temp_dir.path().join("portrait.png");
        
        // Create a portrait image (2000x6000)
        create_test_png(&image_path, 2000, 6000).unwrap();
        
        // Resize to max 4000x4000
        let result = resize_image_if_needed(&image_path, 4000, 4000);
        assert!(result.is_ok());
        
        // Check that image was resized
        let img = image::open(&image_path).unwrap();
        let (width, height) = img.dimensions();
        assert!(width <= 4000);
        assert!(height <= 4000);
        // Check aspect ratio maintained (approximately)
        let ratio = width as f32 / height as f32;
        assert!((ratio - 2000.0 / 6000.0).abs() < 0.01);
    }

    #[test]
    fn test_resize_image_if_needed_nonexistent() {
        let temp_dir = TempDir::new().unwrap();
        let image_path = temp_dir.path().join("nonexistent.png");
        
        let result = resize_image_if_needed(&image_path, 4000, 4000);
        assert!(result.is_err());
    }

    /// Helper to create a minimal valid WebP image
    fn create_test_webp(path: &Path) -> Result<(), Box<dyn std::error::Error>> {
        use image::{ImageBuffer, Rgb};
        let img = ImageBuffer::from_fn(10, 10, |_x, _y| {
            Rgb([0u8, 255u8, 0u8]) // Green pixel
        });
        img.save_with_format(path, ImageFormat::WebP)?;
        Ok(())
    }

    #[test]
    fn test_convert_webp_to_png() {
        let temp_dir = TempDir::new().unwrap();
        let webp_path = temp_dir.path().join("test.webp");
        
        // Create a WebP image
        create_test_webp(&webp_path).unwrap();
        assert!(webp_path.exists());
        
        // Convert to PNG
        let result = convert_webp_to_png(&webp_path);
        assert!(result.is_ok());
        
        let png_path = result.unwrap();
        assert_eq!(png_path.extension().unwrap(), "png");
        assert!(png_path.exists());
        
        // Verify the PNG can be opened and has correct dimensions
        let img = image::open(&png_path).unwrap();
        assert_eq!(img.dimensions(), (10, 10));
    }

    #[test]
    fn test_convert_webp_to_png_nonexistent() {
        let temp_dir = TempDir::new().unwrap();
        let webp_path = temp_dir.path().join("nonexistent.webp");
        
        let result = convert_webp_to_png(&webp_path);
        assert!(result.is_err());
    }

    #[test]
    fn test_convert_webp_to_png_preserves_name() {
        let temp_dir = TempDir::new().unwrap();
        let webp_path = temp_dir.path().join("my_image.webp");
        
        // Create a WebP image
        create_test_webp(&webp_path).unwrap();
        
        // Convert to PNG
        let png_path = convert_webp_to_png(&webp_path).unwrap();
        
        // Check that the base name is preserved
        assert_eq!(png_path.file_stem().unwrap(), "my_image");
        assert_eq!(png_path.extension().unwrap(), "png");
    }
}
