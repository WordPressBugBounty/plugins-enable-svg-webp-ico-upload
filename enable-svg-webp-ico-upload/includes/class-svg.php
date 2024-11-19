<?php
require_once __DIR__ . '/vendor/autoload.php';

use enshrined\svgSanitize\Sanitizer;

class ITC_SVG_Upload_Svg {

    public function __construct() {}

    // Allow SVG uploads
    public function secure_svg_allow_uploads($mime_types) {
        $mime_types['svg'] = 'image/svg+xml';
        return $mime_types;
    }

    // Sanitize SVG during upload
    public function secure_svg_sanitize_upload($upload) {
        // Ensure user is authorized
        if (!current_user_can('upload_files')) {
            return new WP_Error('permission_error', __('You are not allowed to upload SVG files.', 'enable-svg-webp-ico-upload'));
        }

        // Check if the 'name' key exists in the $upload array
        if (isset($upload['name'])) {
            $filetype = wp_check_filetype($upload['name']);
            if ('svg' !== $filetype['ext'] || 'image/svg+xml' !== $filetype['type']) {
                return $upload; // Skip non-SVG uploads
            }
        } else {
            return $upload;
        }

        // Ensure the file size is within limits (e.g., 3MB)
        if ($upload['size'] > 3072 * 1024) { // Check if file size exceeds 3MB
            wp_delete_file($upload['file']); 
            return new WP_Error('file_size_error', __('SVG file is too large.', 'enable-svg-webp-ico-upload'));
        }

        // Validate the uploaded file is a valid SVG
        $response = wp_remote_get($upload['file']);
        if (is_wp_error($response) || wp_remote_retrieve_response_code($response) !== 200) {
            wp_delete_file($upload['file']);
            return new WP_Error('file_read_error', __('Unable to read the uploaded SVG file.', 'enable-svg-webp-ico-upload'));
        }

        $dirty_svg = wp_remote_retrieve_body($response);

        // Disable XML external entity loading to prevent XXE attacks
        libxml_use_internal_errors(true);

        // Parse the SVG content to confirm it is a valid XML file with an <svg> root tag
        $xml = @simplexml_load_string($dirty_svg);
        if ($xml === false || $xml->getName() !== 'svg') {
            wp_delete_file($upload['file']); 
            return new WP_Error('invalid_svg', __('The uploaded file is not a valid SVG.', 'enable-svg-webp-ico-upload'));
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
        
        // Remove other potentially dangerous attributes such as "style" or any JavaScript attributes
        $sanitizer->removeAllowedAttribute('svg', 'style');
        $sanitizer->removeAllowedAttribute('path', 'style');

        // Sanitize the SVG file content
        $clean_svg = $sanitizer->sanitize($dirty_svg);

        global $wp_filesystem;

        // Initialize the WP_Filesystem API
        if (!WP_Filesystem()) {
            return new WP_Error('filesystem_error', __('Failed to initialize filesystem.', 'enable-svg-webp-ico-upload'));
        }

        // Check if sanitization failed
        if (!$clean_svg) {
            wp_delete_file($upload['file']); // Use wp_delete_file() for deletion
            if (defined('WP_DEBUG') && WP_DEBUG) {
                do_action('log_event', 'SVG sanitization failed.', ['user_id' => get_current_user_id()]);
            }
            return new WP_Error('sanitize_error', __('SVG sanitization failed. Upload aborted.', 'enable-svg-webp-ico-upload'));
        }

        // Overwrite the file with sanitized SVG content
        if (!$wp_filesystem->put_contents($upload['file'], $clean_svg, FS_CHMOD_FILE)) {
            return new WP_Error('write_error', __('Failed to write sanitized SVG content to file.', 'enable-svg-webp-ico-upload'));
        }

        // Return the sanitized upload data
        return $upload;
    }
}
