<?php
require_once __DIR__ . '/vendor/autoload.php'; 
use enshrined\svgSanitize\Sanitizer;

class ITC_SVG_Upload_Svg {

    public function __construct() {
        
    }

    // Allow SVG uploads
    public function secure_svg_allow_uploads( $mime_types ) {
        $mime_types['svg'] = 'image/svg+xml';
        return $mime_types;
    }

    // Sanitize SVG during upload
    public function secure_svg_sanitize_upload( $upload ) {
        // Ensure user is authorized (e.g., editors and admins can upload SVG)
        if (!current_user_can('edit_posts')) { // Checks if user can edit posts (editors, admins)
            return new WP_Error('permission_error', __('You are not allowed to upload SVG files.'));
        }

        // Check the file type
        $filetype = wp_check_filetype( $upload['file'] );

        if ( 'svg' === $filetype['ext'] && 'image/svg+xml' === $filetype['type'] ) {
            // Get the raw SVG content
            $dirty_svg = file_get_contents( $upload['file'] );

            if ( $dirty_svg ) {
                $sanitizer = new Sanitizer();
                // Sanitize the SVG content
                $clean_svg = $sanitizer->sanitize( $dirty_svg );

                if ( $clean_svg ) {
                    // If sanitized, overwrite the original file with clean content
                    file_put_contents( $upload['file'], $clean_svg );
                    chmod($upload['file'], 0644); // Secure file permissions
                } else {
                    // If sanitization fails, delete the file and return an error
                    unlink( $upload['file'] );
                    // Log failed sanitization for tracking
                    error_log('Failed SVG sanitization: ' . $upload['file']);
                    return [
                        'error' => __('SVG sanitization failed. Upload aborted.', 'secure-svg-uploads'),
                    ];
                }
            }
        }

        // Return the upload data, whether sanitized or not
        return $upload;
    }
}
