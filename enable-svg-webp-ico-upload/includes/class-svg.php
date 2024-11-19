<?php
require_once __DIR__ . '/vendor/autoload.php';

use enshrined\svgSanitize\Sanitizer;

class ITC_SVG_Upload_Svg {

    public function __construct() {
    }

    // Allow SVG uploads
    public function secure_svg_allow_uploads($mime_types) {
        $mime_types['svg'] = 'image/svg+xml';
        return $mime_types;
    }

    // Sanitize SVG during upload
    public function secure_svg_sanitize_upload($upload) {
        // Ensure user is authorized
        if (!current_user_can('upload_files')) {
            return new WP_Error('permission_error', __('You are not allowed to upload SVG files.'));
        }

        // Check if the uploaded file is an SVG
        $filetype = wp_check_filetype($upload['name']);
        if ('svg' !== $filetype['ext'] || 'image/svg+xml' !== $filetype['type']) {
            return $upload; // Skip non-SVG uploads
        }

        // Ensure the file size is within limits (e.g., 3MB)
        if ($upload['size'] > 3072 * 1024) {
            unlink($upload['file']);
            return new WP_Error('file_size_error', __('SVG file is too large.'));
        }

        // Validate the uploaded file is a valid SVG
        $dirty_svg = file_get_contents($upload['file']);
        if (!$dirty_svg) {
            unlink($upload['file']);
            return new WP_Error('file_read_error', __('Unable to read the uploaded SVG file.'));
        }

        // Disable XML external entity loading to prevent XXE attacks
        libxml_disable_entity_loader(true);

        // Parse the SVG content to confirm it is a valid XML file with an <svg> root tag
        $xml = @simplexml_load_string($dirty_svg);
        if ($xml === false || $xml->getName() !== 'svg') {
            unlink($upload['file']);
            return new WP_Error('invalid_svg', __('The uploaded file is not a valid SVG.'));
        }

        // Sanitize the SVG content with a strict whitelist of allowed tags and attributes
        $sanitizer = new Sanitizer();
        
        // Allow basic SVG and path tags with safe attributes
        $sanitizer->addAllowedTag('svg', ['width', 'height', 'viewBox', 'xmlns']);
        $sanitizer->addAllowedTag('path', ['d', 'fill', 'stroke', 'stroke-width']);
        
        // Remove potentially dangerous SVG attributes like event handlers (e.g., onload, onclick, etc.)
        $sanitizer->removeAllowedAttribute('svg', 'onload');
        $sanitizer->removeAllowedAttribute('svg', 'onclick');
        $sanitizer->removeAllowedAttribute('path', 'onload');
        $sanitizer->removeAllowedAttribute('path', 'onclick');

        // Sanitize the SVG file content
        $clean_svg = $sanitizer->sanitize($dirty_svg);

        if (!$clean_svg) {
            unlink($upload['file']);
            error_log('Failed SVG sanitization for user ID: ' . get_current_user_id());
            return new WP_Error('sanitize_error', __('SVG sanitization failed. Upload aborted.'));
        }

        // Overwrite the file with sanitized SVG content
        file_put_contents($upload['file'], $clean_svg);

        // Secure the file permissions
        chmod($upload['file'], 0644);

        // Return the sanitized upload data
        return $upload;
    }
}
