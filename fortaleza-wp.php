<?php
/**
 * Plugin Name:       Fortaleza WP
 * Plugin URI:        https://github.com/
 * Description:       Hardening estrutural para WordPress. Em vez de detectar assinaturas de ataques conhecidos (que exigem atualização constante), bloqueia CLASSES de vetores de ataque: execução de PHP em uploads, enumeração de usuários, brute force, XML-RPC, fingerprinting da versão, e monitora a integridade dos arquivos do core/tema/plugins para detectar backdoors. Não substitui boas práticas (manter tudo atualizado continua sendo essencial), mas reduz drasticamente a frequência de manutenção necessária.
 * Version:           1.0.0
 * Requires at least: 5.5
 * Requires PHP:      7.4
 * Author:            Fortaleza WP
 * License:           GPLv2 or later
 * Text Domain:       fortaleza-wp
 *
 * ============================================================================
 * FILOSOFIA DESTE PLUGIN (leia antes de usar)
 * ============================================================================
 * A maioria dos plugins de segurança (Wordfence, Sucuri, etc.) depende de um
 * banco de dados de assinaturas de malware/vulnerabilidades que precisa ser
 * atualizado constantemente. Isso é poderoso, mas significa que você está
 * sempre numa corrida: se a assinatura de um ataque novo ainda não foi
 * adicionada ao banco, você fica exposto.
 *
 * Este plugin usa outra estratégia: em vez de tentar reconhecer ataques
 * específicos, ele FECHA ESTRUTURALMENTE as portas que a maioria dos ataques
 * usa, independente de qual vulnerabilidade específica está sendo explorada.
 * Por isso ele precisa de manutenção muito menos frequente — mas "menos
 * frequente" não é "nunca". WordPress evolui, novos vetores de ataque
 * aparecem. Nenhuma ferramenta de segurança é "configure e esqueça" para
 * sempre, e qualquer uma que prometa isso está sendo otimista demais.
 *
 * IMPORTANTE - Servidores Nginx:
 * As regras de bloqueio de PHP em /wp-content/uploads/ e proteção de
 * arquivos sensíveis usam .htaccess (Apache). Se seu servidor é Nginx,
 * essas regras específicas não terão efeito — você precisa adicionar o
 * equivalente no seu arquivo de configuração do site. Exemplo:
 *
 *   location ~* /wp-content/uploads/.*\.php$ { deny all; }
 *   location ~* /(wp-config\.php|\.htaccess|debug\.log)$ { deny all; }
 *
 * Todas as outras proteções (PHP-level: WAF, login, integridade, headers)
 * funcionam igual em Apache, Nginx, LiteSpeed, etc.
 * ============================================================================
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

define( 'FWP_VERSION', '1.0.0' );
define( 'FWP_OPTION_KEY', 'fwp_settings' );
define( 'FWP_HASHES_KEY', 'fwp_file_hashes' );
define( 'FWP_LOG_KEY', 'fwp_event_log' );
define( 'FWP_ATTEMPTS_PREFIX', 'fwp_attempts_' );

/* ============================================================================
 * 1. UTILITÁRIOS — settings, log de eventos, alertas por e-mail, IP do visitante
 * ========================================================================== */

function fwp_get_settings() {
	$defaults = array(
		'alerts_enabled'           => 1,
		'alert_email'              => get_option( 'admin_email' ),
		'waf_enabled'              => 1,
		'login_protection_enabled' => 1,
		'disable_user_enum'       => 1,
	);
	$saved = get_option( FWP_OPTION_KEY, array() );
	return wp_parse_args( $saved, $defaults );
}

function fwp_get_ip() {
	$candidates = array( 'HTTP_CF_CONNECTING_IP', 'HTTP_X_FORWARDED_FOR', 'REMOTE_ADDR' );
	foreach ( $candidates as $header ) {
		if ( ! empty( $_SERVER[ $header ] ) ) {
			$parts = explode( ',', $_SERVER[ $header ] );
			$ip    = trim( $parts[0] );
			if ( filter_var( $ip, FILTER_VALIDATE_IP ) ) {
				return $ip;
			}
		}
	}
	return '0.0.0.0';
}

function fwp_log_event( $type, $message ) {
	$logs = get_option( FWP_LOG_KEY, array() );
	array_unshift(
		$logs,
		array(
			'time'    => current_time( 'mysql' ),
			'type'    => $type,
			'message' => $message,
		)
	);
	$logs = array_slice( $logs, 0, 150 ); // mantém só os 150 eventos mais recentes (evita inchar o banco)
	update_option( FWP_LOG_KEY, $logs, false );
}

function fwp_maybe_send_alert( $message ) {
	$settings = fwp_get_settings();
	if ( empty( $settings['alerts_enabled'] ) ) {
		return;
	}
	$email = ! empty( $settings['alert_email'] ) ? $settings['alert_email'] : get_option( 'admin_email' );
	$subject = '[Fortaleza WP] Alerta de Seguranca - ' . wp_specialchars_decode( get_bloginfo( 'name' ) );
	wp_mail( $email, $subject, $message );
}

/* ============================================================================
 * 2. ATIVAÇÃO / DESATIVAÇÃO / DESINSTALAÇÃO
 * ========================================================================== */

function fwp_activate() {
	// cria a baseline inicial de hashes de arquivos para o monitor de integridade
	update_option( FWP_HASHES_KEY, fwp_scan_files(), false );

	if ( ! wp_next_scheduled( 'fwp_integrity_check' ) ) {
		wp_schedule_event( time() + 300, 'daily', 'fwp_integrity_check' );
	}

	fwp_harden_uploads_dir();
	fwp_harden_root_htaccess();

	fwp_log_event( 'sistema', 'Fortaleza WP ativado. Baseline de integridade criada.' );
}
register_activation_hook( __FILE__, 'fwp_activate' );

function fwp_deactivate() {
	wp_clear_scheduled_hook( 'fwp_integrity_check' );
}
register_deactivation_hook( __FILE__, 'fwp_deactivate' );

function fwp_uninstall() {
	delete_option( FWP_OPTION_KEY );
	delete_option( FWP_HASHES_KEY );
	delete_option( FWP_LOG_KEY );
	wp_clear_scheduled_hook( 'fwp_integrity_check' );
}
register_uninstall_hook( __FILE__, 'fwp_uninstall' );

/* ============================================================================
 * 3. HARDENING ESTRUTURAL (não depende de banco de assinaturas)
 * ========================================================================== */

// 3.1 — Cabeçalhos de segurança HTTP
add_action( 'send_headers', 'fwp_security_headers' );
function fwp_security_headers() {
	if ( headers_sent() ) {
		return;
	}
	header( 'X-Content-Type-Options: nosniff' );
	header( 'X-Frame-Options: SAMEORIGIN' );
	header( 'Referrer-Policy: strict-origin-when-cross-origin' );
	header( 'Permissions-Policy: geolocation=(), microphone=(), camera=()' );
}

// 3.2 — Impede edição de arquivos de plugins/temas pelo painel (vetor comum de persistência pós-invasão)
if ( ! defined( 'DISALLOW_FILE_EDIT' ) ) {
	define( 'DISALLOW_FILE_EDIT', true );
}

// 3.3 — Remove fingerprint de versão do WordPress (dificulta scanners automatizados)
remove_action( 'wp_head', 'wp_generator' );
add_filter( 'the_generator', '__return_empty_string' );
add_filter( 'style_loader_src', 'fwp_remove_version_query_arg', 9999 );
add_filter( 'script_loader_src', 'fwp_remove_version_query_arg', 9999 );
function fwp_remove_version_query_arg( $src ) {
	if ( strpos( $src, 'ver=' ) !== false ) {
		$src = remove_query_arg( 'ver', $src );
	}
	return $src;
}

// 3.4 — Desativa XML-RPC (amplificador clássico de brute force e DDoS via pingback)
add_filter( 'xmlrpc_enabled', '__return_false' );
add_action(
	'init',
	function() {
		remove_action( 'wp_head', 'rsd_link' );
		remove_action( 'wp_head', 'wlwmanifest_link' );
	}
);
add_filter(
	'wp_headers',
	function( $headers ) {
		unset( $headers['X-Pingback'] );
		return $headers;
	}
);

// 3.5 — Desativa enumeração de usuários via ?author=N e via REST API
add_action( 'init', 'fwp_block_author_enum' );
function fwp_block_author_enum() {
	$settings = fwp_get_settings();
	if ( empty( $settings['disable_user_enum'] ) ) {
		return;
	}
	if ( ! is_admin() && isset( $_REQUEST['author'] ) && is_numeric( $_REQUEST['author'] ) ) {
		wp_die( esc_html__( 'Acesso negado.', 'fortaleza-wp' ), esc_html__( 'Proibido', 'fortaleza-wp' ), array( 'response' => 403 ) );
	}
}
add_filter(
	'rest_endpoints',
	function( $endpoints ) {
		$settings = fwp_get_settings();
		if ( empty( $settings['disable_user_enum'] ) ) {
			return $endpoints;
		}
		if ( ! is_user_logged_in() ) {
			unset( $endpoints['/wp/v2/users'] );
			unset( $endpoints['/wp/v2/users/(?P<id>[\d]+)'] );
		}
		return $endpoints;
	}
);

// 3.6 — Bloqueia execução de PHP dentro de wp-content/uploads (Apache via .htaccess)
function fwp_harden_uploads_dir() {
	$upload_dir    = wp_upload_dir();
	$htaccess_path = trailingslashit( $upload_dir['basedir'] ) . '.htaccess';
	$marker        = '# BEGIN Fortaleza WP';
	$existing      = file_exists( $htaccess_path ) ? (string) @file_get_contents( $htaccess_path ) : '';

	if ( strpos( $existing, $marker ) !== false ) {
		return; // já aplicado
	}

	$rules  = "\n" . $marker . "\n";
	$rules .= "<FilesMatch \"\\.(php|php3|php4|php5|php7|phtml|pl|py|cgi|asp|aspx)$\">\n";
	$rules .= "  <IfModule mod_authz_core.c>\n    Require all denied\n  </IfModule>\n";
	$rules .= "  <IfModule !mod_authz_core.c>\n    Order Allow,Deny\n    Deny from all\n  </IfModule>\n";
	$rules .= "</FilesMatch>\n";
	$rules .= "# END Fortaleza WP\n";

	@file_put_contents( $htaccess_path, $existing . $rules );
}

// 3.7 — Protege arquivos sensíveis e desativa listagem de diretório (Apache, raiz do site)
function fwp_harden_root_htaccess() {
	if ( ! function_exists( 'insert_with_markers' ) ) {
		require_once ABSPATH . 'wp-admin/includes/misc.php';
	}
	$htaccess_path = ABSPATH . '.htaccess';

	$rules = array(
		'<FilesMatch "^(wp-config\.php|\.htaccess|debug\.log|readme\.html|license\.txt|wp-config-sample\.php)$">',
		'  <IfModule mod_authz_core.c>',
		'    Require all denied',
		'  </IfModule>',
		'  <IfModule !mod_authz_core.c>',
		'    Order Allow,Deny',
		'    Deny from all',
		'  </IfModule>',
		'</FilesMatch>',
		'Options -Indexes',
	);

	if ( wp_is_writable( ABSPATH ) || file_exists( $htaccess_path ) ) {
		@insert_with_markers( $htaccess_path, 'Fortaleza WP', $rules );
	}
}

/* ============================================================================
 * 4. WAF LEVE BASEADO EM PADRÕES ESTRUTURAIS (não em banco de assinaturas)
 *    Verifica apenas REQUEST_URI e $_GET — nunca o corpo de POST, para não
 *    quebrar o editor de conteúdo (Gutenberg envia HTML/scripts legítimos).
 * ========================================================================== */

add_action( 'init', 'fwp_basic_waf', 1 );
function fwp_basic_waf() {
	$settings = fwp_get_settings();
	if ( empty( $settings['waf_enabled'] ) ) {
		return;
	}

	// reduz falsos positivos: admins autenticados no painel não são verificados por este WAF leve
	if ( is_admin() && current_user_can( 'manage_options' ) ) {
		return;
	}

	$patterns = array(
		'/\bunion\b[\s\S]{1,150}\bselect\b/i',
		'/base64_(en|de)code\s*\(/i',
		'/<script[\s>\/]/i',
		'/\.\.\/\.\.\//',
		'/etc\/passwd/i',
		'/\beval\s*\(/i',
		'/document\.cookie/i',
		'/\b(exec|system|passthru|shell_exec)\s*\(/i',
		'/<\?php/i',
	);

	$pieces = array( isset( $_SERVER['REQUEST_URI'] ) ? $_SERVER['REQUEST_URI'] : '' );
	foreach ( $_GET as $value ) {
		if ( is_string( $value ) ) {
			$pieces[] = $value;
		}
	}
	$haystack = urldecode( implode( ' ', $pieces ) );

	foreach ( $patterns as $pattern ) {
		if ( preg_match( $pattern, $haystack ) ) {
			fwp_log_event(
				'waf_bloqueio',
				'Requisicao bloqueada. IP: ' . fwp_get_ip() . ' | URI: ' . sanitize_text_field( isset( $_SERVER['REQUEST_URI'] ) ? $_SERVER['REQUEST_URI'] : '' )
			);
			wp_die( esc_html__( 'Requisicao bloqueada por motivos de seguranca.', 'fortaleza-wp' ), esc_html__( 'Acesso Bloqueado', 'fortaleza-wp' ), array( 'response' => 403 ) );
		}
	}
}

/* ============================================================================
 * 5. PROTEÇÃO DE LOGIN — rate limiting com backoff exponencial, honeypot,
 *    mensagens de erro genéricas (não revelam se o usuário existe)
 * ========================================================================== */

add_filter( 'login_errors', 'fwp_generic_login_error' );
function fwp_generic_login_error() {
	return esc_html__( 'Usuario ou senha incorretos.', 'fortaleza-wp' );
}

// 5.1 — Honeypot: campo invisível que só bots preenchem
add_action( 'login_form', 'fwp_render_honeypot' );
function fwp_render_honeypot() {
	echo '<p style="position:absolute;left:-9999px;top:-9999px;" aria-hidden="true">';
	echo '<label>Nao preencha este campo<input type="text" name="fwp_hp" value="" tabindex="-1" autocomplete="off"></label>';
	echo '</p>';
}

add_filter( 'authenticate', 'fwp_check_honeypot', 1, 1 );
function fwp_check_honeypot( $user ) {
	if ( is_wp_error( $user ) ) {
		return $user;
	}
	if ( ! empty( $_POST['fwp_hp'] ) ) {
		fwp_log_event( 'honeypot', 'Bot detectado via honeypot. IP: ' . fwp_get_ip() );
		return new WP_Error( 'fwp_bot_detected', esc_html__( 'Erro ao processar requisicao.', 'fortaleza-wp' ) );
	}
	return $user;
}

// 5.2 — Limite de tentativas com bloqueio progressivo por IP
add_filter( 'authenticate', 'fwp_check_lockout', 1, 1 );
function fwp_check_lockout( $user ) {
	$settings = fwp_get_settings();
	if ( empty( $settings['login_protection_enabled'] ) ) {
		return $user;
	}
	if ( is_wp_error( $user ) ) {
		return $user;
	}
	$ip   = fwp_get_ip();
	$data = get_transient( FWP_ATTEMPTS_PREFIX . md5( $ip ) );
	if ( $data && isset( $data['count'] ) && $data['count'] >= 5 ) {
		return new WP_Error( 'fwp_locked_out', esc_html__( 'Muitas tentativas de login falharam. Tente novamente mais tarde.', 'fortaleza-wp' ) );
	}
	return $user;
}

function fwp_calculate_lockout_seconds( $count ) {
	if ( $count < 5 ) {
		return 5 * MINUTE_IN_SECONDS;
	} elseif ( $count < 10 ) {
		return 30 * MINUTE_IN_SECONDS;
	} elseif ( $count < 15 ) {
		return 4 * HOUR_IN_SECONDS;
	}
	return DAY_IN_SECONDS;
}

add_action( 'wp_login_failed', 'fwp_record_failed_login', 10, 1 );
function fwp_record_failed_login( $username ) {
	$settings = fwp_get_settings();
	if ( empty( $settings['login_protection_enabled'] ) ) {
		return;
	}
	$ip    = fwp_get_ip();
	$key   = FWP_ATTEMPTS_PREFIX . md5( $ip );
	$data  = get_transient( $key );
	$count = ( $data && isset( $data['count'] ) ) ? $data['count'] + 1 : 1;
	$ttl   = fwp_calculate_lockout_seconds( $count );
	set_transient( $key, array( 'count' => $count, 'last' => time() ), $ttl );

	if ( 5 === $count || 10 === $count || 15 === $count ) {
		$msg = sprintf(
			'Bloqueio de login ativado. IP: %s | Tentativas: %d | Usuario tentado: %s',
			$ip,
			$count,
			sanitize_text_field( $username )
		);
		fwp_log_event( 'lockout', $msg );
		fwp_maybe_send_alert( "Alerta de seguranca - Fortaleza WP\n\n" . $msg );
	}
}

add_action( 'wp_login', 'fwp_clear_failed_login', 10, 1 );
function fwp_clear_failed_login( $user_login ) {
	delete_transient( FWP_ATTEMPTS_PREFIX . md5( fwp_get_ip() ) );
}

/* ============================================================================
 * 6. MONITOR DE INTEGRIDADE DE ARQUIVOS
 *    Faz hash de todos os .php do core, tema ativo e TODOS os plugins
 *    instalados (ativos ou não, já que plugins desativados também podem
 *    abrigar um backdoor). Compara periodicamente e alerta sobre qualquer
 *    arquivo novo, removido ou alterado.
 *
 *    Importante: a baseline é atualizada automaticamente após updates
 *    legítimos feitos pelo painel (hook upgrader_process_complete). Isso
 *    significa que um alerta deste monitor indica uma mudança que NÃO
 *    veio de uma atualização normal — ou seja, é um sinal forte de
 *    comprometimento (ex: um backdoor sendo plantado via upload direto).
 * ========================================================================== */

function fwp_get_scan_dirs() {
	$dirs = array(
		ABSPATH . 'wp-admin',
		ABSPATH . WPINC,
		WP_PLUGIN_DIR,
	);
	$theme_dir = get_theme_root() . '/' . get_stylesheet();
	if ( is_dir( $theme_dir ) ) {
		$dirs[] = $theme_dir;
	}
	return $dirs;
}

function fwp_scan_files() {
	$hashes    = array();
	$max_files = 30000; // limite de seguranca para evitar timeout em instalacoes gigantes
	$count     = 0;
	$extensoes = array( 'php', 'phtml', 'php3', 'php4', 'php5' );

	foreach ( fwp_get_scan_dirs() as $dir ) {
		if ( ! is_dir( $dir ) ) {
			continue;
		}
		try {
			$iterator = new RecursiveIteratorIterator(
				new RecursiveDirectoryIterator( $dir, FilesystemIterator::SKIP_DOTS ),
				RecursiveIteratorIterator::CATCH_GET_CHILD
			);
		} catch ( Exception $e ) {
			continue;
		}

		foreach ( $iterator as $file ) {
			if ( $count >= $max_files ) {
				return $hashes;
			}
			if ( $file->isFile() && in_array( strtolower( $file->getExtension() ), $extensoes, true ) ) {
				$path = $file->getPathname();
				$hash = @md5_file( $path );
				if ( false !== $hash ) {
					$hashes[ $path ] = $hash;
					$count++;
				}
			}
		}
	}
	return $hashes;
}

add_action( 'fwp_integrity_check', 'fwp_run_integrity_check' );
function fwp_run_integrity_check() {
	$old = get_option( FWP_HASHES_KEY, array() );
	$new = fwp_scan_files();

	$added   = array_diff_key( $new, $old );
	$removed = array_diff_key( $old, $new );
	$changed = array();
	foreach ( $new as $path => $hash ) {
		if ( isset( $old[ $path ] ) && $old[ $path ] !== $hash ) {
			$changed[ $path ] = $hash;
		}
	}

	if ( ! empty( $added ) || ! empty( $removed ) || ! empty( $changed ) ) {
		$msg  = "ALERTA DE INTEGRIDADE - " . home_url() . "\n";
		$msg .= "Mudancas detectadas FORA do fluxo normal de atualizacao.\n\n";

		if ( ! empty( $added ) ) {
			$msg .= "ARQUIVOS NOVOS (possivel backdoor):\n - " . implode( "\n - ", array_keys( $added ) ) . "\n\n";
		}
		if ( ! empty( $changed ) ) {
			$msg .= "ARQUIVOS MODIFICADOS:\n - " . implode( "\n - ", array_keys( $changed ) ) . "\n\n";
		}
		if ( ! empty( $removed ) ) {
			$msg .= "ARQUIVOS REMOVIDOS:\n - " . implode( "\n - ", array_keys( $removed ) ) . "\n\n";
		}
		$msg .= "Se voce NAO fez alteracoes manuais nos arquivos recentemente, trate isso como um incidente de seguranca.\n";
		$msg .= "Se foi voce mesmo (ex: editou um arquivo via FTP), va em Fortaleza WP > Criar nova baseline.";

		fwp_log_event( 'integridade', $msg );
		fwp_maybe_send_alert( $msg );
	}

	update_option( FWP_HASHES_KEY, $new, false );
}

// Re-baseline automático após updates legítimos feitos pelo wp-admin (core, plugins, temas)
add_action( 'upgrader_process_complete', 'fwp_rebaseline_after_update', 10, 2 );
function fwp_rebaseline_after_update( $upgrader, $hook_extra ) {
	update_option( FWP_HASHES_KEY, fwp_scan_files(), false );
	fwp_log_event( 'rebaseline', 'Baseline de integridade atualizada automaticamente apos atualizacao legitima.' );
}

/* ============================================================================
 * 7. ALERTAS DE EVENTOS CRÍTICOS DE CONTA
 * ========================================================================== */

add_action( 'user_register', 'fwp_alert_new_user_if_admin', 10, 1 );
function fwp_alert_new_user_if_admin( $user_id ) {
	$user = get_userdata( $user_id );
	if ( $user && in_array( 'administrator', (array) $user->roles, true ) ) {
		$msg = sprintf(
			"Novo usuario ADMINISTRADOR criado.\nUsuario: %s\nE-mail: %s\nData: %s",
			$user->user_login,
			$user->user_email,
			current_time( 'mysql' )
		);
		fwp_log_event( 'novo_admin', $msg );
		fwp_maybe_send_alert( $msg );
	}
}

add_action( 'set_user_role', 'fwp_alert_role_promoted_to_admin', 10, 3 );
function fwp_alert_role_promoted_to_admin( $user_id, $role, $old_roles ) {
	if ( 'administrator' === $role && ! in_array( 'administrator', (array) $old_roles, true ) ) {
		$user = get_userdata( $user_id );
		if ( ! $user ) {
			return;
		}
		$msg = sprintf(
			"Usuario promovido a ADMINISTRADOR.\nUsuario: %s\nData: %s",
			$user->user_login,
			current_time( 'mysql' )
		);
		fwp_log_event( 'promocao_admin', $msg );
		fwp_maybe_send_alert( $msg );
	}
}

/* ============================================================================
 * 8. AVISOS DE SEGURANÇA NO PAINEL (checagens simples, sem custo de manutenção)
 * ========================================================================== */

add_action( 'admin_notices', 'fwp_show_security_notices' );
function fwp_show_security_notices() {
	if ( ! current_user_can( 'manage_options' ) ) {
		return;
	}
	$notices = array();

	if ( username_exists( 'admin' ) ) {
		$notices[] = __( 'Existe um usuario com login "admin" - alvo comum de ataques automatizados. Considere renomear ou remover.', 'fortaleza-wp' );
	}
	if ( defined( 'WP_DEBUG' ) && true === WP_DEBUG && ( ! defined( 'WP_DEBUG_DISPLAY' ) || WP_DEBUG_DISPLAY ) ) {
		$notices[] = __( 'WP_DEBUG esta ativo com exibicao de erros. Isso pode expor caminhos de arquivo e informacoes sensiveis publicamente.', 'fortaleza-wp' );
	}
	if ( version_compare( PHP_VERSION, '8.0', '<' ) ) {
		$notices[] = sprintf( __( 'Sua versao do PHP (%s) esta desatualizada e pode conter vulnerabilidades conhecidas sem correcao.', 'fortaleza-wp' ), PHP_VERSION );
	}

	foreach ( $notices as $notice ) {
		echo '<div class="notice notice-warning"><p><strong>Fortaleza WP:</strong> ' . esc_html( $notice ) . '</p></div>';
	}
}

/* ============================================================================
 * 9. PÁGINA DE CONFIGURAÇÕES
 * ========================================================================== */

add_action( 'admin_menu', 'fwp_add_admin_menu' );
function fwp_add_admin_menu() {
	add_menu_page(
		'Fortaleza WP',
		'Fortaleza WP',
		'manage_options',
		'fortaleza-wp',
		'fwp_render_settings_page',
		'dashicons-shield-alt',
		80
	);
}

function fwp_render_settings_page() {
	if ( ! current_user_can( 'manage_options' ) ) {
		return;
	}

	if ( isset( $_POST['fwp_save_settings'] ) && check_admin_referer( 'fwp_settings_nonce' ) ) {
		$settings = array(
			'alerts_enabled'           => isset( $_POST['alerts_enabled'] ) ? 1 : 0,
			'alert_email'              => sanitize_email( wp_unslash( $_POST['alert_email'] ) ),
			'waf_enabled'              => isset( $_POST['waf_enabled'] ) ? 1 : 0,
			'login_protection_enabled' => isset( $_POST['login_protection_enabled'] ) ? 1 : 0,
			'disable_user_enum'       => isset( $_POST['disable_user_enum'] ) ? 1 : 0,
		);
		update_option( FWP_OPTION_KEY, $settings );
		echo '<div class="updated"><p>Configuracoes salvas.</p></div>';
	}

	if ( isset( $_POST['fwp_rebaseline'] ) && check_admin_referer( 'fwp_settings_nonce' ) ) {
		update_option( FWP_HASHES_KEY, fwp_scan_files(), false );
		fwp_log_event( 'rebaseline', 'Baseline recriada manualmente pelo administrador.' );
		echo '<div class="updated"><p>Nova baseline de integridade criada com sucesso.</p></div>';
	}

	$settings = fwp_get_settings();
	$logs     = get_option( FWP_LOG_KEY, array() );
	$baseline = get_option( FWP_HASHES_KEY, array() );
	?>
	<div class="wrap">
		<h1>Fortaleza WP</h1>
		<p>Hardening estrutural — bloqueia classes de ataque em vez de depender de um banco de assinaturas para manter atualizado.</p>

		<form method="post">
			<?php wp_nonce_field( 'fwp_settings_nonce' ); ?>
			<table class="form-table">
				<tr>
					<th scope="row">Alertas por e-mail</th>
					<td><label><input type="checkbox" name="alerts_enabled" <?php checked( ! empty( $settings['alerts_enabled'] ) ); ?>> Ativar alertas de seguranca</label></td>
				</tr>
				<tr>
					<th scope="row">E-mail para alertas</th>
					<td><input type="email" name="alert_email" value="<?php echo esc_attr( $settings['alert_email'] ); ?>" class="regular-text"></td>
				</tr>
				<tr>
					<th scope="row">WAF leve</th>
					<td><label><input type="checkbox" name="waf_enabled" <?php checked( ! empty( $settings['waf_enabled'] ) ); ?>> Bloquear padroes de ataque em URLs (SQLi, XSS, path traversal)</label></td>
				</tr>
				<tr>
					<th scope="row">Protecao de login</th>
					<td><label><input type="checkbox" name="login_protection_enabled" <?php checked( ! empty( $settings['login_protection_enabled'] ) ); ?>> Limitar tentativas de login com bloqueio progressivo por IP</label></td>
				</tr>
				<tr>
					<th scope="row">Anti-enumeracao</th>
					<td><label><input type="checkbox" name="disable_user_enum" <?php checked( ! empty( $settings['disable_user_enum'] ) ); ?>> Bloquear descoberta de nomes de usuario via URL e REST API</label></td>
				</tr>
			</table>
			<p><button type="submit" name="fwp_save_settings" class="button button-primary">Salvar configuracoes</button></p>
		</form>

		<hr>
		<h2>Monitor de integridade de arquivos</h2>
		<p>Baseline atual: <strong><?php echo (int) count( $baseline ); ?></strong> arquivos PHP monitorados (core, plugins e tema ativo).</p>
		<p>Use o botao abaixo depois de fazer alteracoes manuais legitimas em arquivos (ex: editar functions.php via FTP). Caso contrario, o monitor vai alertar essa mudanca como suspeita na proxima verificacao.</p>
		<form method="post">
			<?php wp_nonce_field( 'fwp_settings_nonce' ); ?>
			<button type="submit" name="fwp_rebaseline" class="button">Criar nova baseline agora</button>
		</form>

		<hr>
		<h2>Log de eventos recentes</h2>
		<table class="widefat striped">
			<thead>
				<tr>
					<th style="width:160px;">Data</th>
					<th style="width:140px;">Tipo</th>
					<th>Mensagem</th>
				</tr>
			</thead>
			<tbody>
			<?php if ( empty( $logs ) ) : ?>
				<tr><td colspan="3">Nenhum evento registrado ainda.</td></tr>
			<?php else : ?>
				<?php foreach ( array_slice( $logs, 0, 40 ) as $log ) : ?>
					<tr>
						<td><?php echo esc_html( $log['time'] ); ?></td>
						<td><?php echo esc_html( $log['type'] ); ?></td>
						<td><?php echo esc_html( wp_trim_words( $log['message'], 40 ) ); ?></td>
					</tr>
				<?php endforeach; ?>
			<?php endif; ?>
			</tbody>
		</table>
	</div>
	<?php
}
