<?php
/*
 * wgclientexport.inc
 * 
 * WireGuard Quick Peer & Client Export for pfSense
 * Part of pfsense-wireguardclientexport
 */

require_once("config.inc");
require_once("functions.inc");
require_once("interfaces.inc");
require_once("util.inc");

// Ensure pfSense WireGuard package is loaded
if (file_exists("/usr/local/pkg/wireguard/includes/wg.inc")) {
    require_once("/usr/local/pkg/wireguard/includes/wg.inc");
    require_once("/usr/local/pkg/wireguard/includes/wg_api.inc");
    require_once("/usr/local/pkg/wireguard/includes/wg_guiconfig.inc");
    if (function_exists("wg_globals")) {
        wg_globals();
    }
}

const WG_KEY_VAULT_FILE = '/var/etc/wgclientexport_keys.json';
const WG_PEER_META_FILE = '/var/etc/wgclientexport_peers.json';

/**
 * Check if the official WireGuard package is installed on pfSense
 */
function wg_quick_is_pkg_installed() {
    return file_exists("/usr/local/pkg/wireguard/includes/wg.inc") && file_exists("/usr/bin/wg");
}

/**
 * Read the persistent client Private Key vault
 */
function wg_quick_get_key_vault() {
    $vault = [];
    if (file_exists(WG_KEY_VAULT_FILE)) {
        $data = @json_decode(file_get_contents(WG_KEY_VAULT_FILE), true);
        if (is_array($data)) {
            $vault = $data;
        }
    }

    // Also check config.xml
    $xml_keys = config_get_path('installedpackages/wgclientexport/keys') ?? [];
    if (is_array($xml_keys)) {
        foreach ($xml_keys as $pub => $priv) {
            if (!empty($pub) && !empty($priv) && empty($vault[$pub])) {
                $vault[$pub] = $priv;
            }
        }
    }

    return $vault;
}

/**
 * Save client Private Key into persistent vault
 */
function wg_quick_save_private_key($pubkey, $privkey) {
    if (empty($pubkey) || empty($privkey)) {
        return;
    }

    $vault = wg_quick_get_key_vault();
    $vault[$pubkey] = $privkey;

    @mkdir(dirname(WG_KEY_VAULT_FILE), 0755, true);
    @file_put_contents(WG_KEY_VAULT_FILE, json_encode($vault, JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE));

    // Also persist into config.xml
    $xml_keys = config_get_path('installedpackages/wgclientexport/keys') ?? [];
    $xml_keys[$pubkey] = $privkey;
    config_set_path('installedpackages/wgclientexport/keys', $xml_keys);
}

/**
 * Get the real Private Key for a given peer public key
 */
function wg_quick_get_peer_private_key($pubkey) {
    $vault = wg_quick_get_key_vault();
    if (!empty($vault[$pubkey])) {
        return $vault[$pubkey];
    }

    // If missing, generate a real keypair and associate
    $kp = wg_quick_gen_keys();
    if (!empty($kp['privkey'])) {
        wg_quick_save_private_key($pubkey, $kp['privkey']);
        return $kp['privkey'];
    }

    return '';
}

/**
 * Read the peer metadata store (associated AD username, etc.)
 */
function wg_quick_get_peers_meta() {
    $meta = [];
    if (file_exists(WG_PEER_META_FILE)) {
        $data = @json_decode(file_get_contents(WG_PEER_META_FILE), true);
        if (is_array($data)) {
            $meta = $data;
        }
    }

    $xml_meta = config_get_path('installedpackages/wgclientexport/peers_meta') ?? [];
    if (is_array($xml_meta)) {
        foreach ($xml_meta as $pub => $info) {
            if (!empty($pub) && !isset($meta[$pub])) {
                $meta[$pub] = $info;
            }
        }
    }

    return $meta;
}

/**
 * Save metadata for a peer (such as ad_username)
 */
function wg_quick_save_peer_meta($pubkey, $meta_data) {
    if (empty($pubkey) || !is_array($meta_data)) {
        return;
    }

    $meta = wg_quick_get_peers_meta();
    $meta[$pubkey] = array_merge($meta[$pubkey] ?? [], $meta_data);

    @mkdir(dirname(WG_PEER_META_FILE), 0755, true);
    @file_put_contents(WG_PEER_META_FILE, json_encode($meta, JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE));

    $xml_meta = config_get_path('installedpackages/wgclientexport/peers_meta') ?? [];
    $xml_meta[$pubkey] = $meta[$pubkey];
    config_set_path('installedpackages/wgclientexport/peers_meta', $xml_meta);
}

/**
 * Check if Posea AD SSO package is installed on pfSense
 */
function wg_quick_is_ad_sso_available() {
    return file_exists('/usr/local/pkg/posea_ad_sso.inc');
}

/**
 * Get Posea AD SSO status and configuration details
 */
function wg_quick_get_ad_sso_status() {
    if (!wg_quick_is_ad_sso_available()) {
        return [
            'available' => false,
            'enabled' => false,
            'reason' => 'posea_ad_sso paketi yüklü değil'
        ];
    }

    require_once('/usr/local/pkg/posea_ad_sso.inc');
    $cfg = posea_sso_get_config();
    $enabled = !empty($cfg['enabled']);
    $running = function_exists('posea_ad_sso_is_running') ? posea_ad_sso_is_running() : true;

    return [
        'available' => true,
        'enabled' => $enabled,
        'running' => $running,
        'domain_name' => $cfg['domain_name'] ?? '',
        'dc_host' => $cfg['dc_host'] ?? '',
        'dc_port' => intval($cfg['dc_port'] ?? 389),
        'base_dn' => $cfg['base_dn'] ?? '',
        'bind_user' => $cfg['bind_user'] ?? ''
    ];
}

/**
 * Fetch users from Active Directory LDAP with caching (TTL 300s)
 */
function wg_quick_get_ad_users($force_refresh = false) {
    if (!wg_quick_is_ad_sso_available()) {
        return [];
    }

    require_once('/usr/local/pkg/posea_ad_sso.inc');
    $cache_file = '/var/run/wg_ad_users_cache.json';

    if (!$force_refresh && file_exists($cache_file) && (time() - filemtime($cache_file) < 300)) {
        $cached = @json_decode(file_get_contents($cache_file), true);
        if (is_array($cached) && !empty($cached)) {
            return $cached;
        }
    }

    $cfg = posea_sso_get_config();
    $conn = posea_sso_ldap_connect($cfg);
    if (!$conn || !posea_sso_ldap_bind($conn, $cfg['bind_user'], $cfg['bind_password'])) {
        return [];
    }

    $filter = "(&(objectCategory=person)(objectClass=user))";
    $attrs = ["sAMAccountName", "displayName", "mail", "department", "userAccountControl", "memberOf"];
    $sr = @ldap_search($conn, $cfg['base_dn'], $filter, $attrs, 0, 500);
    if (!$sr) {
        return [];
    }

    $entries = @ldap_get_entries($conn, $sr);
    $users = [];
    for ($i = 0; $i < ($entries['count'] ?? 0); $i++) {
        $u = $entries[$i];
        $username = $u['samaccountname'][0] ?? '';
        if (empty($username)) continue;

        $uac = intval($u['useraccountcontrol'][0] ?? 0);
        $is_disabled = (($uac & 2) === 2);

        $groups = [];
        if (isset($u['memberof'])) {
            for ($g = 0; $g < $u['memberof']['count']; $g++) {
                if (preg_match('/^CN=([^,]+)/i', $u['memberof'][$g], $gm)) {
                    $groups[] = $gm[1];
                }
            }
        }

        $users[] = [
            'username' => $username,
            'display_name' => $u['displayname'][0] ?? $username,
            'mail' => $u['mail'][0] ?? '',
            'department' => $u['department'][0] ?? '',
            'groups' => $groups,
            'disabled' => $is_disabled
        ];
    }

    usort($users, function($a, $b) {
        return strcasecmp($a['display_name'], $b['display_name']);
    });

    @file_put_contents($cache_file, json_encode($users, JSON_UNESCAPED_UNICODE));
    return $users;
}

/**
 * Normalize Turkish & special characters to ASCII for smart matching
 */
function wg_quick_slug($str) {
    $str = str_replace(
        ['ı', 'ğ', 'ü', 'ş', 'ö', 'ç', 'İ', 'Ğ', 'Ü', 'Ş', 'Ö', 'Ç'],
        ['i', 'g', 'u', 's', 'o', 'c', 'i', 'g', 'u', 's', 'o', 'c'],
        (string)$str
    );
    return strtolower(trim(preg_replace('/[^a-zA-Z0-9]/', '', $str)));
}

/**
 * Synchronize online WireGuard peers into Posea AD SSO active sessions and PoseaFilter UTM
 */
function wg_quick_sync_ad_sessions() {
    if (!wg_quick_is_ad_sso_available()) {
        return ['success' => false, 'error' => 'Posea AD SSO modülü bulunamadı.'];
    }

    require_once('/usr/local/pkg/posea_ad_sso.inc');

    $status = wg_quick_get_status();
    $meta_all = wg_quick_get_peers_meta();
    $ad_users = wg_quick_get_ad_users();
    $ad_by_username = [];
    foreach ($ad_users as $u) {
        $ad_by_username[strtolower($u['username'])] = $u;
    }

    $sessions = posea_sso_get_sessions();
    $now = time();
    $synced_count = 0;

    foreach ($status['all_peers'] as $peer) {
        $pubkey = $peer['publickey'];
        $peer_ip = $peer['first_ip'];
        if (empty($peer_ip)) continue;

        $ad_user = null;
        $meta = $meta_all[$pubkey] ?? [];
        if (!empty($meta['ad_username'])) {
            $u_key = strtolower($meta['ad_username']);
            $ad_user = $ad_by_username[$u_key] ?? [
                'username' => $meta['ad_username'],
                'display_name' => $meta['ad_username'],
                'groups' => ['Domain Users', 'WireGuard-VPN'],
                'department' => 'VPN'
            ];
        } else {
            // Auto-match by description or name
            $clean_descr = wg_quick_slug($peer['descr']);
            foreach ($ad_by_username as $un => $u_info) {
                if ($un === $clean_descr || wg_quick_slug($u_info['display_name']) === $clean_descr) {
                    $ad_user = $u_info;
                    wg_quick_save_peer_meta($pubkey, ['ad_username' => $u_info['username']]);
                    break;
                }
            }
        }

        if (!$ad_user) continue;

        $latest_hs = intval($peer['latest_handshake'] ?? 0);
        $is_online = ($latest_hs > 0 && ($now - $latest_hs < 900));

        if ($is_online) {
            $sessions[$peer_ip] = [
                'ip' => $peer_ip,
                'mac' => 'wireguard',
                'hostname' => 'WG-' . strtoupper($ad_user['username']),
                'username' => $ad_user['username'],
                'display_name' => $ad_user['display_name'] ?? $ad_user['username'],
                'groups' => !empty($ad_user['groups']) ? $ad_user['groups'] : ['Domain Users', 'WireGuard-VPN'],
                'department' => $ad_user['department'] ?? 'VPN',
                'mail' => $ad_user['mail'] ?? '',
                'mode' => 'wireguard_vpn',
                'is_admin' => (in_array('Administrators', $ad_user['groups'] ?? []) || in_array('Domain Admins', $ad_user['groups'] ?? [])),
                'last_seen' => date('Y-m-d H:i:s', $latest_hs),
                'status' => 'authenticated'
            ];
            $synced_count++;
        }
    }

    posea_sso_save_sessions($sessions);

    return [
        'success' => true,
        'synced_count' => $synced_count,
        'total_sessions' => count($sessions)
    ];
}

/**
 * Detect the local network subnet and internal DNS dynamically
 */
function wg_quick_get_network_defaults() {
    $lan = config_get_path('interfaces/lan');
    $lan_ip = $lan['ipaddr'] ?? '192.168.1.1';
    $lan_subnet = (int)($lan['subnet'] ?? 24);

    // Calculate LAN network CIDR
    $lan_cidr = '';
    if (filter_var($lan_ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
        $ip_long = ip2long($lan_ip);
        $mask_long = ~((1 << (32 - $lan_subnet)) - 1);
        $net_long = $ip_long & $mask_long;
        $lan_cidr = long2ip($net_long) . "/{$lan_subnet}";
    }

    $allowed_ips_default = !empty($lan_cidr) ? "10.0.0.0/24, {$lan_cidr}" : "0.0.0.0/0, ::/0";

    // Detect internal DNS server (from unbound domain overrides matching system domain, or system DNS)
    $sys_domain = config_get_path('system/domain');
    $unbound_overrides = config_get_path('unbound/domainoverrides') ?? [];
    $default_dns = '';

    foreach ($unbound_overrides as $ov) {
        if (!empty($sys_domain) && ($ov['domain'] ?? '') === $sys_domain && !empty($ov['ip'])) {
            $default_dns = $ov['ip'];
            break;
        }
    }

    if (empty($default_dns)) {
        $sys_dns_arr = config_get_path('system/dnsserver') ?? [];
        $default_dns = !empty($sys_dns_arr[0]) ? $sys_dns_arr[0] : ($lan_ip ?: '1.1.1.1');
    }

    return [
        'lan_cidr' => $lan_cidr,
        'allowed_ips_default' => $allowed_ips_default,
        'default_dns' => $default_dns
    ];
}

/**
 * Detect the public / WAN endpoint IP dynamically for clients to connect
 */
function wg_quick_get_wan_endpoint() {
    $wan_ip = get_interface_ip("wan");
    if (!empty($wan_ip) && filter_var($wan_ip, FILTER_VALIDATE_IP)) {
        return $wan_ip;
    }

    $if_list = get_configured_interface_with_descr();
    foreach ($if_list as $if_name => $if_descr) {
        if (stripos($if_name, "wan") !== false || stripos($if_descr, "wan") !== false) {
            $ip = get_interface_ip($if_name);
            if (!empty($ip) && filter_var($ip, FILTER_VALIDATE_IP)) {
                return $ip;
            }
        }
    }

    $hostname = config_get_path("system/hostname");
    $domain = config_get_path("system/domain");
    if (!empty($hostname) && !empty($domain)) {
        return "{$hostname}.{$domain}";
    }

    return $_SERVER['SERVER_ADDR'] ?? "127.0.0.1";
}

/**
 * Get unified status of WireGuard tunnels and peers
 */
function wg_quick_get_status() {
    if (!wg_quick_is_pkg_installed()) {
        return [
            'installed' => false,
            'service_enabled' => false,
            'tunnels' => [],
            'all_peers' => [],
            'wan_endpoint' => wg_quick_get_wan_endpoint(),
            'network_defaults' => wg_quick_get_network_defaults()
        ];
    }

    $raw_status = function_exists('wg_get_status') ? wg_get_status(false) : [];
    $raw_tunnels = config_get_path('installedpackages/wireguard/tunnels/item') ?? [];
    $raw_peers = config_get_path('installedpackages/wireguard/peers/item') ?? [];
    $wg_config = config_get_path('installedpackages/wireguard/config/0') ?? [];
    $vault = wg_quick_get_key_vault();
    $peers_meta = wg_quick_get_peers_meta();
    $ad_status = wg_quick_get_ad_sso_status();
    $ad_users = $ad_status['available'] ? wg_quick_get_ad_users() : [];
    $ad_by_username = [];
    foreach ($ad_users as $u) {
        $ad_by_username[strtolower($u['username'])] = $u;
    }

    $service_enabled = (($wg_config['enable'] ?? 'off') === 'on');

    $tunnels = [];
    $all_peers = [];

    $peers_by_index = [];
    foreach ($raw_peers as $idx => $peer) {
        $peer['_idx'] = $idx;
        $peers_by_index[$idx] = $peer;
    }

    foreach ($raw_tunnels as $tun_idx => $tun) {
        $tun_name = $tun['name'] ?? "tun_wg{$tun_idx}";
        $running_tun = $raw_status[$tun_name] ?? [];

        $addr_row = $tun['addresses']['row'][0] ?? [];
        $tun_ip = $addr_row['address'] ?? '';
        $tun_mask = $addr_row['mask'] ?? '24';

        $tunnel_item = [
            'idx' => $tun_idx,
            'name' => $tun_name,
            'enabled' => ($tun['enabled'] ?? 'no') === 'yes',
            'descr' => $tun['descr'] ?? '',
            'listenport' => $tun['listenport'] ?? ($running_tun['listen_port'] ?? '51820'),
            'publickey' => $tun['publickey'] ?? ($running_tun['public_key'] ?? ''),
            'privatekey' => $tun['privatekey'] ?? '',
            'mtu' => $tun['mtu'] ?? ($running_tun['mtu'] ?? '1420'),
            'ip' => $tun_ip,
            'mask' => $tun_mask,
            'cidr' => (!empty($tun_ip) ? "{$tun_ip}/{$tun_mask}" : ''),
            'status' => $running_tun['status'] ?? 'down',
            'transfer_rx' => $running_tun['transfer_rx'] ?? 0,
            'transfer_tx' => $running_tun['transfer_tx'] ?? 0,
            'peers' => []
        ];

        foreach ($peers_by_index as $p_idx => $p) {
            if (($p['tun'] ?? '') === $tun_name) {
                $pub_key = $p['publickey'] ?? '';
                $running_peer = $running_tun['peers'][$pub_key] ?? [];

                $aips = [];
                if (!empty($p['allowedips']['row'])) {
                    foreach ((array)$p['allowedips']['row'] as $arow) {
                        if (!empty($arow['address'])) {
                            $mask = $arow['mask'] ?? '32';
                            $aips[] = "{$arow['address']}/{$mask}";
                        }
                    }
                }
                $allowed_ips_str = !empty($aips) ? implode(", ", $aips) : ($running_peer['allowed_ips'] ?? '');
                $first_ip = !empty($aips[0]) ? explode('/', $aips[0])[0] : '';

                $meta = $peers_meta[$pub_key] ?? [];
                $ad_username = $meta['ad_username'] ?? ($p['ad_username'] ?? '');

                if (empty($ad_username) && !empty($ad_users)) {
                    $clean_descr = wg_quick_slug($p['descr'] ?? '');
                    foreach ($ad_users as $au) {
                        if (wg_quick_slug($au['username']) === $clean_descr || wg_quick_slug($au['display_name']) === $clean_descr) {
                            $ad_username = $au['username'];
                            wg_quick_save_peer_meta($pub_key, ['ad_username' => $ad_username]);
                            break;
                        }
                    }
                }

                $ad_info = null;
                if (!empty($ad_username)) {
                    $ad_info = $ad_by_username[strtolower($ad_username)] ?? null;
                }

                $peer_item = [
                    'idx' => $p_idx,
                    'tun' => $tun_name,
                    'descr' => $p['descr'] ?? '',
                    'ad_username' => $ad_username,
                    'ad_info' => $ad_info,
                    'enabled' => ($p['enabled'] ?? 'no') === 'yes',
                    'publickey' => $pub_key,
                    'privatekey' => $vault[$pub_key] ?? '',
                    'presharedkey' => $p['presharedkey'] ?? '',
                    'endpoint' => $running_peer['endpoint'] ?? ($p['endpoint'] ?? ''),
                    'allowed_ips' => $allowed_ips_str,
                    'first_ip' => $first_ip,
                    'persistentkeepalive' => $p['persistentkeepalive'] ?? ($running_peer['persistent_keepalive'] ?? ''),
                    'latest_handshake' => $running_peer['latest_handshake'] ?? 0,
                    'transfer_rx' => $running_peer['transfer_rx'] ?? 0,
                    'transfer_tx' => $running_peer['transfer_tx'] ?? 0
                ];

                $tunnel_item['peers'][] = $peer_item;
                $all_peers[] = $peer_item;
            }
        }

        $tunnels[$tun_name] = $tunnel_item;
    }

    return [
        'installed' => true,
        'service_enabled' => $service_enabled,
        'tunnels' => $tunnels,
        'all_peers' => $all_peers,
        'wan_endpoint' => wg_quick_get_wan_endpoint(),
        'network_defaults' => wg_quick_get_network_defaults(),
        'ad_sso' => $ad_status
    ];
}

/**
 * Calculate the next available IP address for a tunnel subnet
 */
function wg_quick_get_next_available_ip($tun_name) {
    $status = wg_quick_get_status();
    $tunnel = $status['tunnels'][$tun_name] ?? null;

    if (!$tunnel || empty($tunnel['ip']) || empty($tunnel['mask'])) {
        return ['suggested' => '10.0.0.2', 'used' => [], 'subnet' => '10.0.0.0/24'];
    }

    $tun_ip = $tunnel['ip'];
    $tun_mask = (int)$tunnel['mask'];

    $used_ips = [];
    $used_ips[$tun_ip] = true;

    $max_used_long = ip2long($tun_ip);

    foreach ($tunnel['peers'] as $peer) {
        $ips = explode(',', $peer['allowed_ips']);
        foreach ($ips as $ip_str) {
            $clean = explode('/', trim($ip_str))[0];
            if (filter_var($clean, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
                $used_ips[$clean] = true;
                $l = ip2long($clean);
                if ($l > $max_used_long) {
                    $max_used_long = $l;
                }
            }
        }
    }

    $ip_long = ip2long($tun_ip);
    $mask_long = ~((1 << (32 - $tun_mask)) - 1);
    $net_long = $ip_long & $mask_long;
    $bcast_long = $net_long | (~$mask_long);
    $subnet_str = long2ip($net_long) . "/{$tun_mask}";

    $sequential_candidate = $max_used_long + 1;
    $suggested = null;
    if ($sequential_candidate > $net_long && $sequential_candidate < $bcast_long && !isset($used_ips[long2ip($sequential_candidate)])) {
        $suggested = long2ip($sequential_candidate);
    }

    if (!$suggested) {
        for ($l = $net_long + 2; $l < $bcast_long; $l++) {
            $cand = long2ip($l);
            if (!isset($used_ips[$cand])) {
                $suggested = $cand;
                break;
            }
        }
    }

    if (!$suggested) {
        $suggested = '10.0.0.254';
    }

    return [
        'suggested' => $suggested,
        'used' => array_keys($used_ips),
        'subnet' => $subnet_str,
        'tun_ip' => $tun_ip
    ];
}

/**
 * Add a new WireGuard Peer quickly
 */
function wg_quick_add_peer($data) {
    if (!wg_quick_is_pkg_installed()) {
        return ['success' => false, 'error' => 'WireGuard paketi kurulu değil.'];
    }

    $net_defaults = wg_quick_get_network_defaults();

    $tun = trim($data['tun'] ?? '');
    $descr = trim($data['descr'] ?? '');
    $client_ip = trim($data['client_ip'] ?? '');
    $client_privkey = trim($data['client_privkey'] ?? '');
    $publickey = trim($data['publickey'] ?? '');
    $dns = trim($data['dns'] ?? $net_defaults['default_dns']);
    $allowed_ips_client = trim($data['allowed_ips_client'] ?? $net_defaults['allowed_ips_default']);
    $endpoint_override = trim($data['endpoint_override'] ?? '');
    $ad_username = trim($data['ad_username'] ?? '');

    // Validation
    if (empty($tun)) {
        return ['success' => false, 'error' => 'Geçerli bir tünel seçilmelidir.'];
    }
    if (empty($descr)) {
        return ['success' => false, 'error' => 'Lütfen bir Peer adı / açıklaması belirtin.'];
    }

    // Handle Keys
    if (!empty($client_privkey)) {
        if (function_exists('wg_is_valid_key') && !wg_is_valid_key($client_privkey)) {
            return ['success' => false, 'error' => 'Girilen Private Key geçerli bir WireGuard anahtarı değildir (32 bayt Base64 formatında olmalı).'];
        }
        $derived = wg_quick_derive_pubkey($client_privkey);
        if (!empty($derived)) {
            $publickey = $derived;
        }
    }

    if (empty($publickey)) {
        $kp = wg_quick_gen_keys();
        $client_privkey = $kp['privkey'];
        $publickey = $kp['pubkey'];
    }

    if (empty($client_privkey)) {
        $client_privkey = wg_quick_get_peer_private_key($publickey);
    }

    if (function_exists('wg_is_valid_key') && !wg_is_valid_key($publickey)) {
        return ['success' => false, 'error' => 'Geçerli bir Public Key belirlenemedi.'];
    }

    if (empty($client_ip)) {
        return ['success' => false, 'error' => 'Atanacak IP adresi boş olamaz.'];
    }

    $clean_ip = explode('/', $client_ip)[0];
    if (!filter_var($clean_ip, FILTER_VALIDATE_IP)) {
        return ['success' => false, 'error' => "Geçersiz IP adresi formatı: {$client_ip}"];
    }

    $status = wg_quick_get_status();
    $tunnel = $status['tunnels'][$tun] ?? null;
    if (!$tunnel) {
        return ['success' => false, 'error' => "Belirtilen tünel ({$tun}) bulunamadı."];
    }

    foreach ($tunnel['peers'] as $existing_peer) {
        if ($existing_peer['publickey'] === $publickey) {
            return ['success' => false, 'error' => "Bu Public Key zaten '{$existing_peer['descr']}' adlı peer tarafından kullanılıyor!"];
        }
        $existing_ips = explode(',', $existing_peer['allowed_ips']);
        foreach ($existing_ips as $e_ip) {
            if (explode('/', trim($e_ip))[0] === $clean_ip) {
                return ['success' => false, 'error' => "{$clean_ip} IP adresi zaten '{$existing_peer['descr']}' adlı peer'a atanmış!"];
            }
        }
    }

    // Save Private Key to persistent vault
    wg_quick_save_private_key($publickey, $client_privkey);

    // Save peer to pfSense config
    $raw_peers = config_get_path('installedpackages/wireguard/peers/item') ?? [];
    $peer_idx = count($raw_peers);

    $peer_record = [
        'enabled' => 'yes',
        'tun' => $tun,
        'descr' => $descr,
        'endpoint' => '',
        'port' => '',
        'persistentkeepalive' => '',
        'publickey' => $publickey,
        'presharedkey' => '',
        'allowedips' => [
            'row' => [
                [
                    'address' => $clean_ip,
                    'mask' => '32',
                    'descr' => $descr
                ]
            ]
        ]
    ];

    config_set_path("installedpackages/wireguard/peers/item/{$peer_idx}", $peer_record);
    if (!empty($ad_username)) {
        wg_quick_save_peer_meta($publickey, ['ad_username' => $ad_username]);
    }

    if (function_exists('wg_write_config')) {
        wg_write_config("Added peer {$descr} ({$publickey}) to {$tun}", true);
    } else {
        write_config("Added peer {$descr} to {$tun}");
    }

    if (function_exists('wg_resync')) {
        wg_resync();
    }
    if (function_exists('wg_tunnel_sync')) {
        wg_tunnel_sync($tun, true, true);
    }

    // Sync to Posea AD SSO active sessions and PoseaFilter
    if (wg_quick_is_ad_sso_available()) {
        wg_quick_sync_ad_sessions();
    }

    $conf_text = wg_quick_generate_config(
        $tun,
        $clean_ip,
        $client_privkey,
        $endpoint_override,
        $dns,
        $allowed_ips_client
    );

    return [
        'success' => true,
        'peer_idx' => $peer_idx,
        'peer' => $peer_record,
        'config' => $conf_text,
        'descr' => $descr,
        'ad_username' => $ad_username,
        'client_ip' => $clean_ip,
        'client_privkey' => $client_privkey,
        'publickey' => $publickey,
        'tun' => $tun
    ];
}

/**
 * Toggle peer enabled / disabled
 */
function wg_quick_toggle_peer($peer_idx) {
    if (!wg_quick_is_pkg_installed()) {
        return ['success' => false, 'error' => 'WireGuard paketi kurulu değil.'];
    }

    if (function_exists('wg_toggle_peer')) {
        $res = wg_toggle_peer($peer_idx);
        if (!empty($res['input_errors'])) {
            return ['success' => false, 'error' => implode(" ", $res['input_errors'])];
        }
        if (!empty($res['tuns_to_sync']) && function_exists('wg_tunnel_sync')) {
            wg_tunnel_sync($res['tuns_to_sync'], true, true);
        }
        return ['success' => true];
    }

    return ['success' => false, 'error' => 'Fonksiyon bulunamadı.'];
}

/**
 * Delete a peer
 */
function wg_quick_delete_peer($peer_idx) {
    if (!wg_quick_is_pkg_installed()) {
        return ['success' => false, 'error' => 'WireGuard paketi kurulu değil.'];
    }

    if (function_exists('wg_delete_peer')) {
        $res = wg_delete_peer($peer_idx);
        if (!empty($res['input_errors'])) {
            return ['success' => false, 'error' => implode(" ", $res['input_errors'])];
        }
        if (!empty($res['tuns_to_sync']) && function_exists('wg_tunnel_sync')) {
            wg_tunnel_sync($res['tuns_to_sync'], true, true);
        }
        return ['success' => true];
    }

    return ['success' => false, 'error' => 'Fonksiyon bulunamadı.'];
}

/**
 * Create a new tunnel
 */
function wg_quick_create_tunnel($data) {
    if (!wg_quick_is_pkg_installed()) {
        return ['success' => false, 'error' => 'WireGuard paketi kurulu değil.'];
    }

    $raw_tunnels = config_get_path('installedpackages/wireguard/tunnels/item') ?? [];
    
    $name = trim($data['name'] ?? '');
    if (empty($name)) {
        $name = function_exists('next_wg_if') ? next_wg_if() : 'tun_wg' . count($raw_tunnels);
    }

    $port = trim($data['listenport'] ?? '');
    if (empty($port)) {
        $port = function_exists('next_wg_port') ? (string)next_wg_port() : (string)(51820 + count($raw_tunnels));
    }

    $address = trim($data['address'] ?? '');
    if (empty($address)) {
        $offset = count($raw_tunnels);
        $address = "10.0.{$offset}.1";
    }

    $mask = trim($data['mask'] ?? '24');
    $descr = trim($data['descr'] ?? "WireGuard {$name}");
    $mtu = trim($data['mtu'] ?? '1420');

    $keypair = function_exists('wg_gen_keypair') ? wg_gen_keypair() : [];
    if (empty($keypair['privkey']) || empty($keypair['pubkey'])) {
        return ['success' => false, 'error' => 'Sunucu için WireGuard anahtar çifti oluşturulamadı.'];
    }

    $tunnel_record = [
        'name' => $name,
        'enabled' => 'yes',
        'descr' => $descr,
        'listenport' => (string)$port,
        'privatekey' => $keypair['privkey'],
        'publickey' => $keypair['pubkey'],
        'mtu' => (string)$mtu,
        'addresses' => [
            'row' => [
                [
                    'address' => $address,
                    'mask' => (string)$mask,
                    'descr' => $descr
                ]
            ]
        ]
    ];

    config_set_path('installedpackages/wireguard/config/0/enable', 'on');
    config_set_path('installedpackages/wireguard/config/0/keep_conf', 'yes');
    if (!config_get_path('installedpackages/wireguard/config/0/interface_group')) {
        config_set_path('installedpackages/wireguard/config/0/interface_group', 'all');
    }

    $ifgroups = config_get_path('ifgroups/ifgroupentry') ?? [];
    $has_wg_group = false;
    foreach ($ifgroups as $grp) {
        if (($grp['ifname'] ?? '') === 'WireGuard') {
            $has_wg_group = true;
            break;
        }
    }
    if (!$has_wg_group) {
        $ifgroups[] = [
            'ifname' => 'WireGuard',
            'descr' => 'WireGuard Interface Group',
            'members' => ''
        ];
        config_set_path('ifgroups/ifgroupentry', $ifgroups);
    }

    $tun_idx = count($raw_tunnels);
    config_set_path("installedpackages/wireguard/tunnels/item/{$tun_idx}", $tunnel_record);

    if (function_exists('wg_write_config')) {
        wg_write_config("Created tunnel {$name}", true);
    } else {
        write_config("Created tunnel {$name}");
    }

    if (function_exists('wg_resync')) {
        wg_resync();
    }
    if (function_exists('wg_tunnel_sync')) {
        wg_tunnel_sync($name, true, true);
    }

    return [
        'success' => true,
        'tunnel' => $tunnel_record,
        'name' => $name
    ];
}

/**
 * Generate standard WireGuard client configuration file
 */
function wg_quick_generate_config($tun_name, $client_ip, $client_privkey = '', $endpoint_host = '', $dns = '', $allowed_ips = '') {
    $status = wg_quick_get_status();
    $tunnel = $status['tunnels'][$tun_name] ?? null;

    $server_pubkey = $tunnel['publickey'] ?? '';
    $server_port = $tunnel['listenport'] ?? '51820';
    $tun_mask = $tunnel['mask'] ?? '24';

    if (empty($endpoint_host)) {
        $endpoint_host = $status['wan_endpoint'];
    }

    $net_def = wg_quick_get_network_defaults();

    if (empty($dns)) {
        $dns = $net_def['default_dns'];
    }

    if (empty($allowed_ips)) {
        $allowed_ips = $net_def['allowed_ips_default'];
    }

    $clean_client_ip = explode('/', $client_ip)[0];

    // Fetch from vault or generate
    if (empty($client_privkey)) {
        foreach ($tunnel['peers'] as $peer) {
            if ($peer['first_ip'] === $clean_client_ip) {
                $client_privkey = wg_quick_get_peer_private_key($peer['publickey']);
                break;
            }
        }
    }

    if (empty($client_privkey)) {
        $kp = wg_quick_gen_keys();
        $client_privkey = $kp['privkey'];
    }

    $lines = [];
    $lines[] = "[Interface]";
    $lines[] = "PrivateKey = {$client_privkey}";
    $lines[] = "ListenPort = {$server_port}";
    $lines[] = "Address = {$clean_client_ip}/{$tun_mask}";
    $lines[] = "DNS = {$dns}";
    $lines[] = "";
    $lines[] = "[Peer]";
    $lines[] = "PublicKey = {$server_pubkey}";
    $lines[] = "AllowedIPs = {$allowed_ips}";
    $lines[] = "Endpoint = {$endpoint_host}:{$server_port}";

    return implode("\n", $lines) . "\n";
}

/**
 * Helper to derive Public Key from Private Key
 */
function wg_quick_derive_pubkey($privkey) {
    if (function_exists('wg_gen_publickey')) {
        $res = wg_gen_publickey($privkey);
        return $res['pubkey'] ?? '';
    }
    $pub = trim(shell_exec("echo '{$privkey}' | /usr/bin/wg pubkey 2>/dev/null"));
    return $pub;
}

/**
 * Helper to generate a new keypair
 */
function wg_quick_gen_keys() {
    if (function_exists('wg_gen_keypair')) {
        $kp = wg_gen_keypair();
        return [
            'privkey' => $kp['privkey'] ?? '',
            'pubkey' => $kp['pubkey'] ?? ''
        ];
    }
    $priv = trim(shell_exec('/usr/bin/wg genkey 2>/dev/null'));
    $pub = '';
    if (!empty($priv)) {
        $pub = trim(shell_exec("echo '{$priv}' | /usr/bin/wg pubkey 2>/dev/null"));
    }
    return ['privkey' => $priv, 'pubkey' => $pub];
}
