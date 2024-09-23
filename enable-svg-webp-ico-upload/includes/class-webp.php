<?php
class ITC_SVG_Upload_Webp {

    /* This allows uploading webp files */
    function webp_file_ext( $types, $file, $filename, $mimes ) {
        if ( false !== strpos( $filename, '.webp' ) ) {
            $types['ext'] = 'webp';
            $types['type'] = 'image/webp';
        }
        return $types;
    }

    function webp_file_upload( $mimes ) {
        $mimes['webp'] = 'image/webp';
        return $mimes;
    }

    /* Preview Webp files */
    function preview_webp_thumbnail($result, $path) {
        if ($result === false) {
            $displayable_image_types = array( IMAGETYPE_WEBP );
            $info = @getimagesize( $path );

            if (empty($info)) {
                $result = false;
            } elseif (!in_array($info[2], $displayable_image_types)) {
                $result = false;
            } else {
                $result = true;
            }
        }

        return $result;
    }

    /* Sanitize the filename to prevent XSS */
    function sanitize_filename($filename) {
        return preg_replace('/[^a-zA-Z0-9_\-\.]/', '', $filename);
    }

    /* Validate the file type to prevent arbitrary uploads */
    function validate_file_type($file) {
        $allowed_types = array('image/webp');
        if (!in_array($file['type'], $allowed_types)) {
            return false; // Invalid file type
        }
        return true; // Valid file type
    }
}
