<?php
defined( 'ABSPATH' ) || exit( 1 );

function wpfg_test_assert( $condition, $message ) {
	if ( ! $condition ) {
		fwrite( STDERR, "TEST FAILED: {$message}\n" );
		exit( 1 );
	}
}

wp_set_current_user( 1 );

wpfg_test_assert(
	WPFG_Security_Intelligence::version_is_affected(
		'1.2.3',
		array(
			array(
				'from_version'   => '1.0.0',
				'from_inclusive' => true,
				'to_version'     => '1.2.3',
				'to_inclusive'   => true,
			),
		)
	),
	'inclusive affected range failed'
);

wpfg_test_assert(
	! WPFG_Security_Intelligence::version_is_affected(
		'1.2.4',
		array(
			array(
				'from_version'   => '1.0.0',
				'from_inclusive' => true,
				'to_version'     => '1.2.3',
				'to_inclusive'   => true,
			),
		)
	),
	'non-affected version matched incorrectly'
);

$secret = get_option( 'wpfg_wordfence_webhook_secret', '' );
wpfg_test_assert( is_string( $secret ) && strlen( $secret ) >= 32, 'webhook secret missing or weak' );

$product_plugin_dir = WP_PLUGIN_DIR . '/wpfg-test-vulnerable';
wp_mkdir_p( $product_plugin_dir );
file_put_contents(
	$product_plugin_dir . '/wpfg-test-vulnerable.php',
	"<?php\n/*\nPlugin Name: WPFG Test Vulnerable\nVersion: 1.2.3\n*/\n"
);

wp_clean_plugins_cache( true );

$payload = array(
	'vulnerabilities' => array(
		'created' => array(
			array(
				'id'    => '00000000-0000-0000-0000-000000000001',
				'title' => 'Synthetic CI vulnerability',
				'cvss'  => array(
					'score'  => 9.8,
					'rating' => 'critical',
				),
				'references' => array( 'https://example.test/advisory' ),
				'software'   => array(
					array(
						'type'              => 'plugin',
						'name'              => 'WPFG Test Vulnerable',
						'slug'              => 'wpfg-test-vulnerable',
						'affected_versions' => array(
							'1.0.0 - 1.2.3' => array(
								'from_version'   => '1.0.0',
								'from_inclusive' => true,
								'to_version'     => '1.2.3',
								'to_inclusive'   => true,
							),
						),
						'patched'           => true,
						'patched_versions'  => array( '1.2.4' ),
						'remediation'       => 'Update to 1.2.4 or later.',
					),
				),
			),
		),
		'replaced' => array(),
		'deleted'  => array(),
	),
);

$body      = wp_json_encode( $payload );
$signature = hash_hmac( 'sha256', $body, $secret );
$request   = new WP_REST_Request( 'POST', '/wp-fortress/v1/intelligence' );
$request->set_body( $body );
$request->set_header( 'X-Wordfence-Signature', $signature );

$response = WPFG_Security_Intelligence::receive_wordfence_webhook( $request );
wpfg_test_assert( $response instanceof WP_REST_Response, 'valid signed webhook was rejected' );
$data = $response->get_data();
wpfg_test_assert( ! empty( $data['ok'] ) && 1 === (int) $data['matched'], 'valid vulnerability was not matched' );

$findings = get_option( 'wpfg_intelligence_findings', array() );
wpfg_test_assert( is_array( $findings ) && 1 === count( $findings ), 'finding was not persisted' );

$bad = new WP_REST_Request( 'POST', '/wp-fortress/v1/intelligence' );
$bad->set_body( $body );
$bad->set_header( 'X-Wordfence-Signature', 'tampered' );
$bad_response = WPFG_Security_Intelligence::receive_wordfence_webhook( $bad );
wpfg_test_assert( is_wp_error( $bad_response ) && 403 === (int) $bad_response->get_error_data()['status'], 'tampered webhook signature was accepted' );

@unlink( $product_plugin_dir . '/wpfg-test-vulnerable.php' );
@rmdir( $product_plugin_dir );

echo "wpfg-security-intelligence-ok\n";
