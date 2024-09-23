<?php
class ITC_SVG_Upload_Ico {

    public function upload_ico_files( $types, $file, $filename, $mimes ) {
        // Check if the filename has the correct extension and validate the file type
        if ( false !== strpos( $filename, '.ico' ) ) {
            $file_type = wp_check_filetype( $filename, null );

            // Ensure the file type is valid
            if ( $file_type['ext'] === 'ico' && $file_type['type'] === 'image/ico' ) {
                $types['ext'] = 'ico';
                $types['type'] = 'image/ico';
            }
        }
    
        return $types;
    } 

    public function ico_files( $mimes ) {
        // Allow only .ico files
        $mimes['ico'] = 'image/ico';
    
        return $mimes;
    }
}
