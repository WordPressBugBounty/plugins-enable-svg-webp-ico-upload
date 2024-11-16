<?php 
$availableTabs = array(
    'settings' => 'Settings',
	'youtube' => 'YouTube',
    'other_plugins' => 'Other Plugins',
    'about' => 'About',
);
$active_tab = 'settings'; // default tab
$plugin_slug_name = $this->get_plugin_slug();

if (isset($_GET['tab'])) {
    $input_tab = sanitize_key($_GET['tab']); 
    if (isset($input_tab) && in_array($input_tab, array_keys($availableTabs))) {
        $active_tab = $input_tab;
    }
}
?>

<div class="wrap">

<h1 id="itc_svg_upload_title" data-purl="<?php echo esc_url( ITC_SVG_UPLOAD_PLUGIN_DIR_URL ); ?>"><?php echo esc_html( get_admin_page_title() ); ?></h1>

<nav class="nav-tab-wrapper wp-clearfix">
    <?php 
    foreach ($availableTabs as $tabIndex => $tab) {
        // Escaping the $tabIndex when used in HTML attributes (like href and class)
    ?>
        <a href="?page=<?php echo esc_attr($plugin_slug_name); ?>&tab=<?php echo esc_attr($tabIndex); ?>" class="nav-tab <?php echo esc_attr($active_tab == $tabIndex ? 'nav-tab-active' : ''); ?>" title="<?php echo esc_attr($tab); ?>"><?php echo esc_html($tab); ?></a>
    <?php } ?>
</nav>

<?php 
foreach ($availableTabs as $tabIndex => $tab) {
    if ($active_tab === $tabIndex) {
        include_once '_'.esc_attr($tabIndex).'.php';  // Ensure $tabIndex is escaped here as well
    }
}
?>
</div>
