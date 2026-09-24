<?php
/**
 * WP Fortress Guard Security Intelligence.
 *
 * Receives signed Wordfence Intelligence webhook notifications and matches them
 * locally against installed WordPress core/plugins/themes. It also watches the
 * official WordPress Security news feed and the normal WordPress update state.
 */

defined( 'ABSPATH' ) || exit;

final class WPFG_Security_Intelligence {

	const FINDINGS_OPTION = 'wpfg_intelligence_findings';
	const FEED_OPTION     = 'wpfg_security_feed';
	const SECRET_OPTION   = 'wpfg_wordfence_webhook_secret';
	const CRON_HOOK       = 'wpfg_daily_security_intelligence';
	const NONCE_ACTION    = 'wpfg_intelligence_admin';
	const REST_NAMESPACE  = 'wp-fortress/v1';
	const REST_ROUTE      = '/intelligence';
	const MAX_BODY_BYTES  = 2097152;
	const SECURITY_FEED   = 'https://wordpress.org/news/category/security/feed/';

	public static function init() {
		add_action( 'init', array( __CLASS__, 'ensure_schedule' ) );
		add_action( self::CRON_HOOK, array( __CLASS__, 'daily_scan' ) );
		add_action( 'rest_api_init', array( __CLASS__, 'register_rest_route' ) );
		add_action( 'admin_menu', array( __CLASS__, 'menu' ) );
		add_action( 'admin_notices', array( __CLASS__, 'admin_notice' ) );
		add_action( 'admin_post_wpfg_intelligence_refresh', array( __CLASS__, 'manual_refresh' ) );
		add_action( 'admin_post_wpfg_intelligence_rotate_secret', array( __CLASS__, 'rotate_secret' ) );
	}

	public static function activate() {
		self::ensure_secret();
		self::ensure_schedule();

		if ( ! wp_next_scheduled( self::CRON_HOOK ) ) {
			wp_schedule_single_event( time() + 60, self::CRON_HOOK );
		}
	}

	public static function deactivate() {
		wp_clear_scheduled_hook( self::CRON_HOOK );
	}

	public static function ensure_schedule() {
		self::ensure_secret();

		if ( ! wp_next_scheduled( self::CRON_HOOK ) ) {
			wp_schedule_event( time() + HOUR_IN_SECONDS, 'daily', self::CRON_HOOK );
		}
	}

	private static function ensure_secret() {
		$secret = get_option( self::SECRET_OPTION, '' );

		if ( ! is_string( $secret ) || strlen( $secret ) < 32 ) {
			try {
				$secret = bin2hex( random_bytes( 32 ) );
			} catch ( Exception $e ) {
				$secret = wp_generate_password( 64, true, true );
			}

			update_option( self::SECRET_OPTION, $secret, false );
		}

		return $secret;
	}

	public static function register_rest_route() {
		register_rest_route(
			self::REST_NAMESPACE,
			self::REST_ROUTE,
			array(
				'methods'             => WP_REST_Server::CREATABLE,
				'callback'            => array( __CLASS__, 'receive_wordfence_webhook' ),
				'permission_callback' => '__return_true',
			)
		);
	}

	public static function receive_wordfence_webhook( WP_REST_Request $request ) {
		$body = (string) $request->get_body();

		if ( '' === $body || strlen( $body ) > self::MAX_BODY_BYTES ) {
			return new WP_Error( 'wpfg_intel_bad_payload', 'Invalid webhook payload.', array( 'status' => 413 ) );
		}

		$secret    = self::ensure_secret();
		$signature = trim( (string) $request->get_header( 'x-wordfence-signature' ) );

		if ( '' === $signature ) {
			return new WP_Error( 'wpfg_intel_no_signature', 'Missing webhook signature.', array( 'status' => 401 ) );
		}

		$expected = hash_hmac( 'sha256', $body, $secret );

		if ( ! hash_equals( $expected, $signature ) ) {
			return new WP_Error( 'wpfg_intel_bad_signature', 'Invalid webhook signature.', array( 'status' => 403 ) );
		}

		$payload = json_decode( $body, true );

		if ( ! is_array( $payload ) || empty( $payload['vulnerabilities'] ) || ! is_array( $payload['vulnerabilities'] ) ) {
			return new WP_Error( 'wpfg_intel_bad_json', 'Invalid vulnerability payload.', array( 'status' => 400 ) );
		}

		$changed = self::process_vulnerability_payload( $payload['vulnerabilities'] );

		return new WP_REST_Response(
			array(
				'ok'      => true,
				'matched' => $changed,
			),
			200
		);
	}

	private static function process_vulnerability_payload( array $events ) {
		$findings = self::get_findings();
		$before   = $findings;

		foreach ( (array) ( $events['deleted'] ?? array() ) as $deleted_id ) {
			$deleted_id = sanitize_text_field( (string) $deleted_id );

			foreach ( array_keys( $findings ) as $key ) {
				if ( 0 === strpos( $key, $deleted_id . '|' ) ) {
					unset( $findings[ $key ] );
				}
			}
		}

		$incoming = array_merge(
			(array) ( $events['created'] ?? array() ),
			(array) ( $events['replaced'] ?? array() )
		);

		$new_alerts = array();

		foreach ( $incoming as $vulnerability ) {
			if ( ! is_array( $vulnerability ) ) {
				continue;
			}

			$id       = sanitize_text_field( (string) ( $vulnerability['id'] ?? '' ) );
			$title    = sanitize_text_field( (string) ( $vulnerability['title'] ?? 'WordPress vulnerability' ) );
			$cvss     = is_array( $vulnerability['cvss'] ?? null ) ? $vulnerability['cvss'] : array();
			$score    = isset( $cvss['score'] ) && is_numeric( $cvss['score'] ) ? (float) $cvss['score'] : null;
			$rating   = sanitize_key( (string) ( $cvss['rating'] ?? self::rating_from_score( $score ) ) );
			$refs     = array_values( array_filter( array_map( 'esc_url_raw', (array) ( $vulnerability['references'] ?? array() ) ) ) );
			$software = (array) ( $vulnerability['software'] ?? array() );

			if ( '' === $id ) {
				continue;
			}

			foreach ( $software as $component ) {
				if ( ! is_array( $component ) ) {
					continue;
				}

				$type    = sanitize_key( (string) ( $component['type'] ?? '' ) );
				$slug    = sanitize_key( (string) ( $component['slug'] ?? '' ) );
				$version = self::installed_version( $type, $slug );

				if ( '' === $version || ! self::version_is_affected( $version, (array) ( $component['affected_versions'] ?? array() ) ) ) {
					continue;
				}

				$key = $id . '|' . $type . '|' . $slug;

				$finding = array(
					'id'               => $id,
					'title'            => $title,
					'type'             => $type,
					'slug'             => $slug,
					'name'             => sanitize_text_field( (string) ( $component['name'] ?? $slug ) ),
					'installed_version'=> sanitize_text_field( $version ),
					'severity'         => in_array( $rating, array( 'low', 'medium', 'high', 'critical' ), true ) ? $rating : 'unknown',
					'cvss'             => $score,
					'patched'          => ! empty( $component['patched'] ),
					'patched_versions' => array_values( array_map( 'sanitize_text_field', (array) ( $component['patched_versions'] ?? array() ) ) ),
					'remediation'      => sanitize_textarea_field( (string) ( $component['remediation'] ?? '' ) ),
					'reference'        => isset( $refs[0] ) ? $refs[0] : '',
					'copyrights'       => self::copyright_notices( $vulnerability ),
					'updated_at'       => current_time( 'mysql' ),
				);

				$old_hash = isset( $findings[ $key ] ) ? md5( wp_json_encode( $findings[ $key ] ) ) : '';
				$new_hash = md5( wp_json_encode( $finding ) );

				$findings[ $key ] = $finding;

				if ( $old_hash !== $new_hash ) {
					$new_alerts[] = $finding;
				}
			}
		}

		$findings = array_slice( $findings, 0, 150, true );

		if ( $findings !== $before ) {
			update_option( self::FINDINGS_OPTION, $findings, false );
		}

		if ( ! empty( $new_alerts ) ) {
			self::email_vulnerability_alerts( $new_alerts );
		}

		return count( $new_alerts );
	}

	private static function rating_from_score( $score ) {
		if ( null === $score ) {
			return 'unknown';
		}
		if ( $score >= 9.0 ) {
			return 'critical';
		}
		if ( $score >= 7.0 ) {
			return 'high';
		}
		if ( $score >= 4.0 ) {
			return 'medium';
		}
		return 'low';
	}

	private static function copyright_notices( array $vulnerability ) {
		$out        = array();
		$copyrights = $vulnerability['copyrights'] ?? array();

		if ( ! is_array( $copyrights ) ) {
			return $out;
		}

		$items = isset( $copyrights['copyrights'] ) && is_array( $copyrights['copyrights'] )
			? $copyrights['copyrights']
			: $copyrights;

		foreach ( $items as $item ) {
			if ( ! is_array( $item ) ) {
				continue;
			}

			$notice = sanitize_text_field( (string) ( $item['notice'] ?? '' ) );
			$url    = esc_url_raw( (string) ( $item['license_url'] ?? '' ) );

			if ( $notice ) {
				$out[] = array(
					'notice' => $notice,
					'url'    => $url,
				);
			}

			if ( count( $out ) >= 5 ) {
				break;
			}
		}

		return $out;
	}

	public static function version_is_affected( $version, array $ranges ) {
		$version = trim( (string) $version );

		if ( '' === $version ) {
			return false;
		}

		foreach ( $ranges as $range ) {
			if ( ! is_array( $range ) ) {
				continue;
			}

			$from           = trim( (string) ( $range['from_version'] ?? '*' ) );
			$to             = trim( (string) ( $range['to_version'] ?? '*' ) );
			$from_inclusive = ! array_key_exists( 'from_inclusive', $range ) || ! empty( $range['from_inclusive'] );
			$to_inclusive   = ! array_key_exists( 'to_inclusive', $range ) || ! empty( $range['to_inclusive'] );

			$after_from = '*' === $from || '' === $from
				? true
				: version_compare( $version, $from, $from_inclusive ? '>=' : '>' );

			$before_to = '*' === $to || '' === $to
				? true
				: version_compare( $version, $to, $to_inclusive ? '<=' : '<' );

			if ( $after_from && $before_to ) {
				return true;
			}
		}

		return false;
	}

	private static function installed_version( $type, $slug ) {
		if ( 'wordpress' === $type || 'core' === $type ) {
			return isset( $GLOBALS['wp_version'] ) ? (string) $GLOBALS['wp_version'] : '';
		}

		if ( 'plugin' === $type ) {
			if ( ! function_exists( 'get_plugins' ) ) {
				require_once ABSPATH . 'wp-admin/includes/plugin.php';
			}

			foreach ( get_plugins() as $file => $data ) {
				$plugin_slug = '.' === dirname( $file ) ? basename( $file, '.php' ) : dirname( $file );

				if ( $plugin_slug === $slug ) {
					return (string) ( $data['Version'] ?? '' );
				}
			}

			return '';
		}

		if ( 'theme' === $type ) {
			$themes = wp_get_themes();

			if ( isset( $themes[ $slug ] ) ) {
				return (string) $themes[ $slug ]->get( 'Version' );
			}
		}

		return '';
	}

	private static function get_findings() {
		$findings = get_option( self::FINDINGS_OPTION, array() );
		return is_array( $findings ) ? $findings : array();
	}

	private static function email_vulnerability_alerts( array $alerts ) {
		$to = get_option( 'admin_email' );

		if ( ! is_email( $to ) ) {
			return;
		}

		$lines = array(
			'WP Fortress Guard detected vulnerability intelligence matching software installed on this site.',
			'',
		);

		foreach ( array_slice( $alerts, 0, 20 ) as $finding ) {
			$lines[] = sprintf(
				'[%s] %s — %s %s',
				strtoupper( (string) $finding['severity'] ),
				(string) $finding['title'],
				(string) $finding['name'],
				(string) $finding['installed_version']
			);

			if ( ! empty( $finding['reference'] ) ) {
				$lines[] = (string) $finding['reference'];
			}
		}

		$lines[] = '';
		$lines[] = 'Review Tools > Fortress Intelligence and update or remove affected components as appropriate.';

		wp_mail(
			$to,
			'[' . wp_specialchars_decode( get_bloginfo( 'name' ), ENT_QUOTES ) . '] WP Fortress vulnerability alert',
			implode( "\n", $lines )
		);
	}

	public static function daily_scan() {
		self::refresh_security_feed( true );

		if ( function_exists( 'wp_version_check' ) ) {
			wp_version_check();
		}
		if ( function_exists( 'wp_update_plugins' ) ) {
			wp_update_plugins();
		}
		if ( function_exists( 'wp_update_themes' ) ) {
			wp_update_themes();
		}
	}

	private static function refresh_security_feed( $notify = false ) {
		include_once ABSPATH . WPINC . '/feed.php';

		$feed = fetch_feed( self::SECURITY_FEED );

		if ( is_wp_error( $feed ) ) {
			return $feed;
		}

		$maxitems = $feed->get_item_quantity( 5 );
		$items    = $feed->get_items( 0, $maxitems );
		$news     = array();

		foreach ( $items as $item ) {
			$link = esc_url_raw( (string) $item->get_permalink() );

			$news[] = array(
				'id'    => hash( 'sha256', $link . '|' . (string) $item->get_title() ),
				'title' => sanitize_text_field( (string) $item->get_title() ),
				'link'  => $link,
				'date'  => sanitize_text_field( (string) $item->get_date( 'Y-m-d H:i:s' ) ),
			);
		}

		$old        = get_option( self::FEED_OPTION, array() );
		$old_latest = is_array( $old ) && ! empty( $old[0]['id'] ) ? (string) $old[0]['id'] : '';
		$new_latest = ! empty( $news[0]['id'] ) ? (string) $news[0]['id'] : '';

		update_option( self::FEED_OPTION, $news, false );

		if ( $notify && $old_latest && $new_latest && ! hash_equals( $old_latest, $new_latest ) ) {
			$to = get_option( 'admin_email' );

			if ( is_email( $to ) ) {
				wp_mail(
					$to,
					'[' . wp_specialchars_decode( get_bloginfo( 'name' ), ENT_QUOTES ) . '] New official WordPress security notice',
					"WordPress.org published a new security notice:\n\n" . $news[0]['title'] . "\n" . $news[0]['link'] . "\n\nReview available WordPress updates promptly."
				);
			}
		}

		return true;
	}

	public static function menu() {
		add_management_page(
			'Fortress Intelligence',
			'Fortress Intelligence',
			'manage_options',
			'wp-fortress-intelligence',
			array( __CLASS__, 'page' )
		);
	}

	public static function manual_refresh() {
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_die( 'Administrator permission required.' );
		}

		check_admin_referer( self::NONCE_ACTION );

		if ( function_exists( 'wp_version_check' ) ) {
			wp_version_check();
		}
		if ( function_exists( 'wp_update_plugins' ) ) {
			wp_update_plugins();
		}
		if ( function_exists( 'wp_update_themes' ) ) {
			wp_update_themes();
		}

		self::refresh_security_feed( false );

		wp_safe_redirect(
			add_query_arg(
				array(
					'page'      => 'wp-fortress-intelligence',
					'refreshed' => 1,
				),
				admin_url( 'tools.php' )
			)
		);
		exit;
	}

	public static function rotate_secret() {
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_die( 'Administrator permission required.' );
		}

		check_admin_referer( self::NONCE_ACTION );

		delete_option( self::SECRET_OPTION );
		self::ensure_secret();

		wp_safe_redirect(
			add_query_arg(
				array(
					'page'    => 'wp-fortress-intelligence',
					'rotated' => 1,
				),
				admin_url( 'tools.php' )
			)
		);
		exit;
	}

	private static function update_posture() {
		$core_updates = 0;
		$core         = get_site_transient( 'update_core' );

		if ( is_object( $core ) && ! empty( $core->updates ) && is_array( $core->updates ) ) {
			foreach ( $core->updates as $update ) {
				if ( is_object( $update ) && isset( $update->response ) && 'upgrade' === $update->response ) {
					$core_updates++;
				}
			}
		}

		$plugins = get_site_transient( 'update_plugins' );
		$themes  = get_site_transient( 'update_themes' );

		return array(
			'core'    => $core_updates,
			'plugins' => is_object( $plugins ) && is_array( $plugins->response ?? null ) ? count( $plugins->response ) : 0,
			'themes'  => is_object( $themes ) && is_array( $themes->response ?? null ) ? count( $themes->response ) : 0,
		);
	}

	public static function admin_notice() {
		if ( ! current_user_can( 'manage_options' ) ) {
			return;
		}

		$posture  = self::update_posture();
		$findings = self::get_findings();

		if ( empty( $findings ) && 0 === array_sum( $posture ) ) {
			return;
		}

		$url = admin_url( 'tools.php?page=wp-fortress-intelligence' );

		echo '<div class="notice notice-warning"><p><strong>WP Fortress Guard:</strong> ';
		echo esc_html(
			sprintf(
				'%d vulnerability finding(s), %d core update(s), %d plugin update(s), %d theme update(s) need review.',
				count( $findings ),
				$posture['core'],
				$posture['plugins'],
				$posture['themes']
			)
		);
		echo ' <a href="' . esc_url( $url ) . '">Review Fortress Intelligence</a></p></div>';
	}

	public static function page() {
		if ( ! current_user_can( 'manage_options' ) ) {
			return;
		}

		$findings = self::get_findings();
		$news     = get_option( self::FEED_OPTION, array() );
		$posture  = self::update_posture();
		$secret   = self::ensure_secret();
		$endpoint = rest_url( self::REST_NAMESPACE . self::REST_ROUTE );
		?>
		<div class="wrap">
			<h1>Fortress Intelligence</h1>
			<p>Real-time vulnerability matching plus official WordPress security-release monitoring. Intelligence data is advisory: WordPress, plugins and themes still need to be updated or removed when vulnerable.</p>

			<?php if ( isset( $_GET['refreshed'] ) ) : ?>
				<div class="notice notice-success inline"><p>Security intelligence status refreshed.</p></div>
			<?php endif; ?>
			<?php if ( isset( $_GET['rotated'] ) ) : ?>
				<div class="notice notice-success inline"><p>Webhook secret rotated. Update the secret in Wordfence Intelligence before re-enabling the webhook.</p></div>
			<?php endif; ?>

			<h2>Update posture</h2>
			<table class="widefat striped" style="max-width:760px">
				<tbody>
					<tr><th>WordPress core updates</th><td><?php echo esc_html( (string) $posture['core'] ); ?></td></tr>
					<tr><th>Plugin updates</th><td><?php echo esc_html( (string) $posture['plugins'] ); ?></td></tr>
					<tr><th>Theme updates</th><td><?php echo esc_html( (string) $posture['themes'] ); ?></td></tr>
				</tbody>
			</table>
			<p>
				<a class="button button-primary" href="<?php echo esc_url( wp_nonce_url( admin_url( 'admin-post.php?action=wpfg_intelligence_refresh' ), self::NONCE_ACTION ) ); ?>">Refresh security status</a>
			</p>

			<h2>Wordfence Intelligence real-time webhook</h2>
			<p>Configure a raw HTTP webhook in your Wordfence.com account. Wordfence sends vulnerability notifications to this endpoint; Fortress verifies the HMAC-SHA256 signature before processing anything. Your plugin/theme inventory is matched locally and is not sent by this feature.</p>
			<table class="form-table" role="presentation">
				<tr>
					<th>Webhook URL</th>
					<td><code id="wpfg-endpoint"><?php echo esc_html( $endpoint ); ?></code> <button type="button" class="button" onclick="navigator.clipboard.writeText(document.getElementById('wpfg-endpoint').textContent)">Copy</button></td>
				</tr>
				<tr>
					<th>Webhook secret</th>
					<td><code id="wpfg-secret"><?php echo esc_html( $secret ); ?></code> <button type="button" class="button" onclick="navigator.clipboard.writeText(document.getElementById('wpfg-secret').textContent)">Copy</button></td>
				</tr>
			</table>
			<p><a class="button" href="<?php echo esc_url( wp_nonce_url( admin_url( 'admin-post.php?action=wpfg_intelligence_rotate_secret' ), self::NONCE_ACTION ) ); ?>" onclick="return confirm('Rotate the webhook secret? Existing Wordfence webhook deliveries will fail until you update their secret.');">Rotate secret</a></p>

			<h2>Matching vulnerability findings</h2>
			<?php if ( empty( $findings ) ) : ?>
				<p>No matching vulnerability notifications have been recorded.</p>
			<?php else : ?>
				<table class="widefat striped">
					<thead><tr><th>Severity</th><th>Component</th><th>Vulnerability</th><th>Remediation</th><th>Updated</th></tr></thead>
					<tbody>
					<?php foreach ( $findings as $finding ) : ?>
						<tr>
							<td><strong><?php echo esc_html( strtoupper( (string) $finding['severity'] ) ); ?></strong><?php echo null !== $finding['cvss'] ? '<br>CVSS ' . esc_html( (string) $finding['cvss'] ) : ''; ?></td>
							<td><?php echo esc_html( (string) $finding['name'] ); ?><br><code><?php echo esc_html( (string) $finding['installed_version'] ); ?></code></td>
							<td>
								<?php if ( ! empty( $finding['reference'] ) ) : ?><a href="<?php echo esc_url( $finding['reference'] ); ?>" target="_blank" rel="noopener noreferrer"><?php echo esc_html( (string) $finding['title'] ); ?></a><?php else : echo esc_html( (string) $finding['title'] ); endif; ?>
								<?php foreach ( (array) ( $finding['copyrights'] ?? array() ) as $copyright ) : ?>
									<small style="display:block;margin-top:4px"><?php echo esc_html( (string) ( $copyright['notice'] ?? '' ) ); ?><?php if ( ! empty( $copyright['url'] ) ) : ?> — <a href="<?php echo esc_url( $copyright['url'] ); ?>" target="_blank" rel="noopener noreferrer">license</a><?php endif; ?></small>
								<?php endforeach; ?>
							</td>
							<td><?php echo esc_html( (string) ( $finding['remediation'] ?: ( $finding['patched'] ? 'Update to a patched version.' : 'No patch information supplied; review and consider disabling/removing the component.' ) ) ); ?></td>
							<td><?php echo esc_html( (string) $finding['updated_at'] ); ?></td>
						</tr>
					<?php endforeach; ?>
					</tbody>
				</table>
			<?php endif; ?>

			<h2>Official WordPress security notices</h2>
			<?php if ( empty( $news ) ) : ?>
				<p>No feed data cached yet. Use “Refresh security status”.</p>
			<?php else : ?>
				<ul>
					<?php foreach ( array_slice( (array) $news, 0, 5 ) as $item ) : ?>
						<li><a href="<?php echo esc_url( (string) $item['link'] ); ?>" target="_blank" rel="noopener noreferrer"><?php echo esc_html( (string) $item['title'] ); ?></a> — <?php echo esc_html( (string) $item['date'] ); ?></li>
					<?php endforeach; ?>
				</ul>
			<?php endif; ?>

			<p><small>External intelligence source: Wordfence Intelligence (Defiant, Inc.). Configure the webhook only after reviewing its terms and privacy policy. Official WordPress notices are read from WordPress.org.</small></p>
		</div>
		<?php
	}
}

WPFG_Security_Intelligence::init();
