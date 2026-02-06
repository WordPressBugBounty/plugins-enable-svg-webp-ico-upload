<?php
require_once __DIR__ . '/vendor/autoload.php';

use enshrined\svgSanitize\Sanitizer;

class ITC_SVG_Upload_Svg {

    protected $sanitizer;
    protected $max_file_size;

    public function __construct() {
        $this->sanitizer = new Sanitizer();
        $this->max_file_size = 5 * 1024 * 1024; // 5MB limit
        
        // Initialize all hooks
        $this->init_hooks();
    }

    // Initialize all WordPress hooks
    protected function init_hooks() {
        add_filter('upload_mimes', array($this, 'add_svg_support'));
        add_filter('wp_handle_upload_prefilter', array($this, 'sanitize_svg_upload'));
        add_filter('wp_check_filetype_and_ext', array($this, 'validate_svg_file'), 10, 4);
        add_filter('wp_generate_attachment_metadata', array($this, 'generate_svg_metadata'), 10, 2);
        add_filter('wp_prepare_attachment_for_js', array($this, 'display_svg_in_media_library'), 10, 3);
        add_action('admin_head', array($this, 'add_svg_styles'));
        
        // Add security headers when serving SVG files
        add_action('template_redirect', array($this, 'add_svg_security_headers'));
    }

    // Allow SVG uploads
    public function add_svg_support($mime_types) {
        $mime_types['svg'] = 'image/svg+xml';
        $mime_types['svgz'] = 'image/svg+xml';
        return $mime_types;
    }

    // Sanitize SVG during upload with comprehensive security checks
    public function sanitize_svg_upload($upload) {
        if ($this->is_svg_file($upload)) {
            // Check file size
            if (isset($upload['size']) && $upload['size'] > $this->max_file_size) {
				/* translators: %d: Maximum file size in megabytes */
                $upload['error'] = sprintf(__('SVG file exceeds maximum size of %dMB.', 'enable-svg-webp-ico-upload'), $this->max_file_size / 1024 / 1024);
                return $upload;
            }
            
            // Validate and sanitize the SVG file
            if (!isset($upload['tmp_name']) || !$this->check_and_sanitize_file($upload['tmp_name'])) {
                $upload['error'] = __('Sorry, this SVG file is not valid or could not be sanitized for security reasons.', 'enable-svg-webp-ico-upload');
            }
        }
        return $upload;
    }

    // Comprehensive SVG file detection
    protected function is_svg_file($upload) {
        if (!isset($upload['tmp_name']) || !file_exists($upload['tmp_name'])) {
            return false;
        }

        $file_name = isset($upload['name']) ? $upload['name'] : '';
        $file_ext = strtolower(pathinfo($file_name, PATHINFO_EXTENSION));
        $file_type = isset($upload['type']) ? $upload['type'] : '';
        
        // Check file size first (quick check)
        if (isset($upload['size']) && $upload['size'] > $this->max_file_size) {
            return false;
        }
        
        // Read and validate file content
        $file_content = file_get_contents($upload['tmp_name']);
        if ($file_content === false) {
            return false;
        }
        
        $is_svg_by_content = $this->is_svg_content($file_content);
        
        // STRICT validation: File must have SVG extension AND contain SVG content
        // OR have SVG MIME type AND contain SVG content
        return ($file_ext === 'svg' && $is_svg_by_content) || 
               ($file_ext === 'svgz' && $is_svg_by_content) ||
               ($file_type === 'image/svg+xml' && $is_svg_by_content);
    }

    // Robust SVG content detection
    protected function is_svg_content($content) {
        if (empty($content)) {
            return false;
        }
        
        // Remove comments and whitespace for better detection
        $cleaned_content = preg_replace('/<!--.*?-->/s', '', $content);
        $cleaned_content = preg_replace('/\s+/', ' ', $cleaned_content);
        $cleaned_content = trim($cleaned_content);
        
        if (empty($cleaned_content)) {
            return false;
        }
        
        // Check for SVG doctype or root element with namespace
        $has_svg_doctype = stripos($cleaned_content, '<!doctype svg') !== false;
        $has_svg_root = preg_match('/<svg[^>]*\sxmlns\s*=[^>]*>/i', $cleaned_content);
        $has_complete_svg = stripos($cleaned_content, '<svg') !== false && stripos($cleaned_content, '</svg>') !== false;
        
        // Also check for SVG markers
        $has_svg_markers = stripos($cleaned_content, 'viewbox') !== false || 
                          stripos($cleaned_content, 'svg') !== false;
        
        return $has_svg_doctype || $has_svg_root || ($has_complete_svg && $has_svg_markers);
    }

    // Comprehensive SVG sanitization
    protected function check_and_sanitize_file($file) {
        if (!file_exists($file) || !is_readable($file) || !is_writable($file)) {
            return false;
        }

        // Check file size again
        if (filesize($file) > $this->max_file_size) {
            return false;
        }

        $unclean = file_get_contents($file);
        if ($unclean === false) {
            return false;
        }

        // Validate it's actually SVG content
        if (!$this->is_svg_content($unclean)) {
            return false;
        }

        // Configure sanitizer with security settings
        $this->sanitizer->setAllowedTags(new class extends \enshrined\svgSanitize\data\AllowedTags {
            public static function getTags() {
                $allowed_tags = parent::getTags();
                return apply_filters('esw_svg_allowed_tags', $allowed_tags);
            }
        });

        $this->sanitizer->setAllowedAttrs(new class extends \enshrined\svgSanitize\data\AllowedAttributes {
            public static function getAttributes() {
                $allowed_attrs = parent::getAttributes();
                return apply_filters('esw_svg_allowed_attributes', $allowed_attrs);
            }
        });

        // Remove remote references for additional security
        $this->sanitizer->removeRemoteReferences(true);

        $clean = $this->sanitizer->sanitize($unclean);

        if ($clean === false) {
            return false;
        }

        // Validate the sanitized content is still SVG
        if (!$this->is_svg_content($clean)) {
            return false;
        }

        // Create backup of original file for audit purposes
        $backup_path = $file . '.backup';
        copy($file, $backup_path);

        // Save the sanitized SVG file
        if (file_put_contents($file, $clean) === false) {
            return false;
        }

        return true;
    }

    // Validate SVG files in WordPress
    public function validate_svg_file($checked, $file, $filename, $mimes) {
        if (!$checked['type']) {
            $file_info = wp_check_filetype($filename, $mimes);
            if ($file_info['ext'] === 'svg' && $file_info['type'] === 'image/svg+xml') {
                $checked = [
                    'ext' => $file_info['ext'],
                    'type' => $file_info['type'],
                    'proper_filename' => $filename,
                ];
            }
        }
        return $checked;
    }

    // Generate metadata for SVG files
    public function generate_svg_metadata($metadata, $attachment_id) {
        $mime_type = get_post_mime_type($attachment_id);
        
        if ($mime_type === 'image/svg+xml') {
            $file_path = get_attached_file($attachment_id);
            
            if ($file_path && file_exists($file_path)) {
                try {
                    $svg_content = file_get_contents($file_path);
                    $width = $height = 0;
                    
                    // Extract dimensions from SVG
                    if (preg_match('/width\s*=\s*["\']([^"\']+)["\']/i', $svg_content, $width_matches)) {
                        $width = $this->parse_svg_dimension($width_matches[1]);
                    }
                    
                    if (preg_match('/height\s*=\s*["\']([^"\']+)["\']/i', $svg_content, $height_matches)) {
                        $height = $this->parse_svg_dimension($height_matches[1]);
                    }
                    
                    // If no dimensions found, use viewBox
                    if (!$width || !$height) {
                        if (preg_match('/viewBox\s*=\s*["\']\s*([0-9\.\-]+)\s+([0-9\.\-]+)\s+([0-9\.\-]+)\s+([0-9\.\-]+)\s*["\']/i', $svg_content, $viewbox_matches)) {
                            $width = floatval($viewbox_matches[3]);
                            $height = floatval($viewbox_matches[4]);
                        }
                    }
                    
                    // Default dimensions if still not found
                    if (!$width || !$height) {
                        $width = 100;
                        $height = 100;
                    }
                    
                    $metadata['width'] = intval($width);
                    $metadata['height'] = intval($height);
                    $metadata['sizes'] = array();
                    
                } catch (Exception $e) {
                    // Silent catch - no error logging
                }
            }
        }
        
        return $metadata;
    }

    // Parse SVG dimensions (handles px, em, %, etc.)
    protected function parse_svg_dimension($dimension) {
        $dimension = trim($dimension);
        
        // Remove units and convert to float
        $value = floatval(preg_replace('/[^\d\.]/', '', $dimension));
        
        return $value > 0 ? $value : 0;
    }

    // Display SVG files in the WordPress Media Library
    public function display_svg_in_media_library($response, $attachment, $meta) {
        if ($response['type'] === 'image' && $response['subtype'] === 'svg+xml') {
            $path = get_attached_file($attachment->ID);
            
            if ($path && @file_exists($path)) {
                try {
                    $svg_content = @file_get_contents($path);
                    
                    if ($svg_content && $this->is_svg_content($svg_content)) {
                        $width = $height = 100; // Default dimensions
                        
                        // Extract dimensions
                        if (preg_match('/width\s*=\s*["\']([^"\']+)["\']/i', $svg_content, $width_matches)) {
                            $width = $this->parse_svg_dimension($width_matches[1]);
                        }
                        
                        if (preg_match('/height\s*=\s*["\']([^"\']+)["\']/i', $svg_content, $height_matches)) {
                            $height = $this->parse_svg_dimension($height_matches[1]);
                        }
                        
                        // Use viewBox if dimensions not found
                        if (!$width || !$height) {
                            if (preg_match('/viewBox\s*=\s*["\']\s*([0-9\.\-]+)\s+([0-9\.\-]+)\s+([0-9\.\-]+)\s+([0-9\.\-]+)\s*["\']/i', $svg_content, $viewbox_matches)) {
                                $width = floatval($viewbox_matches[3]);
                                $height = floatval($viewbox_matches[4]);
                            }
                        }
                        
                        $response['image'] = $response['thumb'] = array(
                            'src' => $response['url'],
                            'width' => max(1, intval($width)),
                            'height' => max(1, intval($height)),
                        );
                    }
                } catch (Exception $e) {
                    // Silent catch - no error logging
                }
            }
        }
        return $response;
    }

    // Add security headers when serving SVG files
    public function add_svg_security_headers() {
        if (is_attachment() && get_post_mime_type() === 'image/svg+xml') {
            // Security headers to prevent XSS and other attacks
            header("Content-Security-Policy: default-src 'none'; script-src 'none'; object-src 'none';");
            header("X-Content-Type-Options: nosniff");
            header("X-Frame-Options: DENY");
        }
    }

    // Add custom styles for SVGs in the WordPress admin interface
    public function add_svg_styles() {
        echo "<style>
            /* Media Library SVG styles */
            table.media .column-title .media-icon img[src*='.svg'],
            table.media .column-title .media-icon img[src*='.svgz'] {
                width: 100%;
                height: auto;
                max-width: 120px;
            }

            /* Gutenberg editor SVG styles */
            .components-responsive-wrapper__content[src*='.svg'],
            .components-responsive-wrapper__content[src*='.svgz'] {
                position: relative;
                width: 100%;
                height: auto;
            }
            
            /* Fix for SVG in media modals */
            .attachment-display-settings .thumbnail img[src*='.svg'],
            .attachment-display-settings .thumbnail img[src*='.svgz'] {
                max-width: 100%;
                height: auto;
            }
        </style>";
    }
}

// Initialize the class
new ITC_SVG_Upload_Svg();