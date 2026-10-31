<?php
/*
 * wg_quick_peer.php
 *
 * WireGuard Quick Peer & Client Export for pfSense
 * Part of pfsense-wireguardclientexport
 */

##|+PRIV
##|*IDENT=page-vpn-quick-wireguard
##|*NAME=VPN: WireGuard Hızlı Yönetici
##|*DESCR=WireGuard Hızlı Peer Ekleme ve İstemci İhracı sayfasına erişim.
##|*MATCH=wg_quick_peer.php*
##|-PRIV

require_once("guiconfig.inc");
require_once("/usr/local/pkg/wgclientexport.inc");

$savemsg = "";
$errormsg = "";
$new_config_modal = null;

// ==========================================
// AJAX Handlers
// ==========================================

// 1. AJAX Status
if (isset($_GET['ajax_status'])) {
    session_write_close();
    header('Content-Type: application/json; charset=utf-8');
    echo json_encode(wg_quick_get_status(), JSON_UNESCAPED_UNICODE);
    exit;
}

// 2. AJAX Next Available IP
if (isset($_GET['ajax_next_ip'])) {
    session_write_close();
    header('Content-Type: application/json; charset=utf-8');
    $tun = trim($_GET['tun'] ?? 'tun_wg0');
    echo json_encode(wg_quick_get_next_available_ip($tun), JSON_UNESCAPED_UNICODE);
    exit;
}

// 3. AJAX Generate Keys
if (isset($_GET['ajax_gen_keys'])) {
    session_write_close();
    header('Content-Type: application/json; charset=utf-8');
    echo json_encode(wg_quick_gen_keys(), JSON_UNESCAPED_UNICODE);
    exit;
}

// 4. AJAX Derive Public Key from Private Key
if (isset($_GET['ajax_derive_pub'])) {
    session_write_close();
    header('Content-Type: application/json; charset=utf-8');
    $priv = trim($_GET['privkey'] ?? '');
    $pub = wg_quick_derive_pubkey($priv);
    echo json_encode(['pubkey' => $pub], JSON_UNESCAPED_UNICODE);
    exit;
}

// 5. AJAX Save Private Key for a peer
if (isset($_REQUEST['ajax_save_privkey'])) {
    session_write_close();
    header('Content-Type: application/json; charset=utf-8');
    $pub = trim($_REQUEST['pubkey'] ?? '');
    $priv = trim($_REQUEST['privkey'] ?? '');
    if (!empty($pub) && !empty($priv)) {
        wg_quick_save_private_key($pub, $priv);
        echo json_encode(['success' => true]);
    } else {
        echo json_encode(['success' => false, 'error' => 'Geçersiz anahtar.']);
    }
    exit;
}

// 5b. AJAX Save AD User Mapping for a peer
if (isset($_REQUEST['ajax_save_peer_ad'])) {
    session_write_close();
    header('Content-Type: application/json; charset=utf-8');
    $pub = trim($_REQUEST['pubkey'] ?? '');
    $ad_user = trim($_REQUEST['ad_username'] ?? '');
    if (!empty($pub)) {
        wg_quick_save_peer_meta($pub, ['ad_username' => $ad_user]);
        if (wg_quick_is_ad_sso_available()) {
            wg_quick_sync_ad_sessions();
        }
        echo json_encode(['success' => true]);
    } else {
        echo json_encode(['success' => false, 'error' => 'Geçersiz peer.']);
    }
    exit;
}

// 6. AJAX Get Existing Peer Config
if (isset($_GET['ajax_get_config'])) {
    session_write_close();
    header('Content-Type: application/json; charset=utf-8');
    $tun = trim($_GET['tun'] ?? 'tun_wg0');
    $client_ip = trim($_GET['ip'] ?? '');
    $client_privkey = trim($_GET['privkey'] ?? '');
    $pubkey = trim($_GET['pubkey'] ?? '');
    $descr = trim($_GET['descr'] ?? 'wireguard-client');
    $dns = trim($_GET['dns'] ?? '');
    $allowed_ips = trim($_GET['allowed_ips'] ?? '');

    $conf = wg_quick_generate_config($tun, $client_ip, $client_privkey, '', $dns, $allowed_ips);
    
    // Extract real private key used
    $used_priv = '';
    if (preg_match('/PrivateKey\s*=\s*([^\r\n]+)/', $conf, $m)) {
        $used_priv = trim($m[1]);
    }

    $peers_meta = wg_quick_get_peers_meta();
    $peer_ad = $peers_meta[$pubkey]['ad_username'] ?? '';

    echo json_encode([
        'success' => true,
        'config' => $conf,
        'descr' => $descr,
        'client_ip' => $client_ip,
        'client_privkey' => $used_priv,
        'ad_username' => $peer_ad,
        'pubkey' => $pubkey,
        'tun' => $tun
    ], JSON_UNESCAPED_UNICODE);
    exit;
}

// 7. AJAX Active Directory Users
if (isset($_GET['ajax_ad_users'])) {
    session_write_close();
    header('Content-Type: application/json; charset=utf-8');
    $refresh = !empty($_GET['refresh']);
    echo json_encode(wg_quick_get_ad_users($refresh), JSON_UNESCAPED_UNICODE);
    exit;
}

// 8. AJAX Sync Active Sessions to Posea AD SSO & PoseaFilter
if (isset($_POST['ajax_sync_ad_sessions']) || isset($_GET['ajax_sync_ad_sessions'])) {
    session_write_close();
    header('Content-Type: application/json; charset=utf-8');
    echo json_encode(wg_quick_sync_ad_sessions(), JSON_UNESCAPED_UNICODE);
    exit;
}

// 9. Direct Download .conf
if (isset($_GET['download_conf'])) {
    $tun = trim($_GET['tun'] ?? 'tun_wg0');
    $client_ip = trim($_GET['ip'] ?? '10.0.0.2');
    $descr = trim($_GET['descr'] ?? 'client');
    $privkey = trim($_GET['privkey'] ?? '');
    $dns = trim($_GET['dns'] ?? '');
    $allowed_ips = trim($_GET['allowed_ips'] ?? '');

    $conf = wg_quick_generate_config($tun, $client_ip, $privkey, '', $dns, $allowed_ips);
    $filename = preg_replace('/[^a-zA-Z0-9_-]/', '_', $descr) ?: "wg_{$tun}_client";

    header('Content-Type: text/plain; charset=utf-8');
    header('Content-Disposition: attachment; filename="' . $filename . '.conf"');
    header('Content-Length: ' . strlen($conf));
    echo $conf;
    exit;
}

// ==========================================
// Form Submissions
// ==========================================

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $act = $_POST['act'] ?? '';

    // Quick Add Peer
    if ($act === 'add_peer') {
        $res = wg_quick_add_peer($_POST);
        if (isset($_GET['ajax'])) {
            session_write_close();
            header('Content-Type: application/json; charset=utf-8');
            echo json_encode($res, JSON_UNESCAPED_UNICODE);
            exit;
        }

        if ($res['success']) {
            $savemsg = "Yeni WireGuard Peer <strong>" . htmlspecialchars($res['descr']) . "</strong> (" . htmlspecialchars($res['client_ip']) . ") başarıyla eklendi ve WireGuard servisi güncellendi.";
            $new_config_modal = $res;
        } else {
            $errormsg = $res['error'] ?? 'Peer eklenirken bilinmeyen bir hata oluştu.';
        }
    }

    // Toggle Peer
    elseif ($act === 'toggle_peer') {
        $p_idx = intval($_POST['peer_idx'] ?? -1);
        $res = wg_quick_toggle_peer($p_idx);
        if (isset($_GET['ajax'])) {
            session_write_close();
            header('Content-Type: application/json; charset=utf-8');
            echo json_encode($res, JSON_UNESCAPED_UNICODE);
            exit;
        }
        if ($res['success']) {
            $savemsg = "Peer durumu başarıyla güncellendi.";
        } else {
            $errormsg = $res['error'] ?? 'Peer durumu güncellenirken hata oluştu.';
        }
    }

    // Delete Peer
    elseif ($act === 'delete_peer') {
        $p_idx = intval($_POST['peer_idx'] ?? -1);
        $res = wg_quick_delete_peer($p_idx);
        if (isset($_GET['ajax'])) {
            session_write_close();
            header('Content-Type: application/json; charset=utf-8');
            echo json_encode($res, JSON_UNESCAPED_UNICODE);
            exit;
        }
        if ($res['success']) {
            $savemsg = "Peer başarıyla silindi.";
        } else {
            $errormsg = $res['error'] ?? 'Peer silinirken hata oluştu.';
        }
    }

    // Create Tunnel
    elseif ($act === 'create_tunnel') {
        $res = wg_quick_create_tunnel($_POST);
        if (isset($_GET['ajax'])) {
            session_write_close();
            header('Content-Type: application/json; charset=utf-8');
            echo json_encode($res, JSON_UNESCAPED_UNICODE);
            exit;
        }
        if ($res['success']) {
            $savemsg = "WireGuard Tüneli <strong>" . htmlspecialchars($res['name']) . "</strong> başarıyla oluşturuldu ve servis başlatıldı!";
        } else {
            $errormsg = $res['error'] ?? 'Tünel oluşturulurken hata oluştu.';
        }
    }
}

// Read status
$wg_data = wg_quick_get_status();
$ad_sso = $wg_data['ad_sso'] ?? wg_quick_get_ad_sso_status();
$ad_users = ($ad_sso['available'] && $ad_sso['enabled']) ? wg_quick_get_ad_users() : [];
$has_tunnels = !empty($wg_data['tunnels']);
$active_tunnel_name = $_GET['tun'] ?? array_key_first($wg_data['tunnels']) ?? 'tun_wg0';
$current_tunnel = $wg_data['tunnels'][$active_tunnel_name] ?? null;

// IP recommendation
$next_ip_info = $has_tunnels ? wg_quick_get_next_available_ip($active_tunnel_name) : ['suggested' => '10.0.0.2', 'subnet' => '10.0.0.0/24'];
$net_defaults = $wg_data['network_defaults'] ?? ['default_dns' => '1.1.1.1', 'allowed_ips_default' => '0.0.0.0/0, ::/0'];

$pgtitle = array(gettext("VPN"), gettext("WireGuard Hızlı Yönetici (Quick Peer & Export)"));
include("head.inc");

$tab_array = array();
$tab_array[] = array(gettext("Hızlı Peer & Yönetim"), true, "/wg_quick_peer.php");
$tab_array[] = array(gettext("Tüneller (pfSense)"), false, "/wg/vpn_wg_tunnels.php");
$tab_array[] = array(gettext("Peer'lar (pfSense)"), false, "/wg/vpn_wg_peers.php");
$tab_array[] = array(gettext("WireGuard Durumu"), false, "/wg/status_wireguard.php");
display_top_tabs($tab_array);

function format_bytes_human($bytes, $precision = 2) {
    $units = array('B', 'KB', 'MB', 'GB', 'TB');
    $bytes = max($bytes, 0);
    $pow = floor(($bytes ? log($bytes) : 0) / log(1024));
    $pow = min($pow, count($units) - 1);
    $bytes /= (1 << (10 * $pow));
    return round($bytes, $precision) . ' ' . $units[$pow];
}

function format_handshake_human($timestamp) {
    if (empty($timestamp) || $timestamp == 0) {
        return '<span class="text-muted"><i class="fa fa-times-circle"></i> Henüz bağlanmadı</span>';
    }
    $diff = time() - $timestamp;
    if ($diff < 0) $diff = 0;
    if ($diff < 60) return "<span class=\"text-success font-weight-bold\"><i class=\"fa fa-check-circle\"></i> {$diff} sn önce</span>";
    if ($diff < 3600) return "<span class=\"text-success font-weight-bold\"><i class=\"fa fa-check-circle\"></i> " . floor($diff / 60) . " dk önce</span>";
    if ($diff < 86400) return "<span class=\"text-info\"><i class=\"fa fa-clock-o\"></i> " . floor($diff / 3600) . " saat önce</span>";
    return "<span class=\"text-muted\"><i class=\"fa fa-calendar\"></i> " . floor($diff / 86400) . " gün önce</span>";
}
?>

<script src="/wg_quick_peer_qr.js"></script>

<style>
/* Modern Theme Adaptive Styling */
.wg-badge-card {
    background: rgba(255, 255, 255, 0.05);
    border: 1px solid rgba(255, 255, 255, 0.12);
    border-radius: 8px;
    padding: 15px;
    box-shadow: 0 2px 4px rgba(0, 0, 0, 0.15);
    margin-bottom: 15px;
}
.wg-stat-label {
    font-size: 11px;
    text-transform: uppercase;
    font-weight: 700;
    opacity: 0.8;
    letter-spacing: 0.5px;
    margin-bottom: 5px;
}
.wg-stat-val {
    font-size: 17px;
    font-weight: 700;
    word-break: break-all;
}
.wg-tunnel-bar {
    background: rgba(255, 255, 255, 0.04);
    border: 1px solid rgba(255, 255, 255, 0.12);
    border-radius: 8px;
    padding: 12px 18px;
    display: flex;
    justify-content: space-between;
    align-items: center;
    flex-wrap: wrap;
    gap: 10px;
}
.wg-pubkey-well {
    background: rgba(0, 0, 0, 0.25);
    border: 1px solid rgba(255, 255, 255, 0.12);
    border-radius: 6px;
    padding: 10px 15px;
    margin-bottom: 0;
    display: flex;
    align-items: center;
    justify-content: space-between;
    flex-wrap: wrap;
    gap: 10px;
}
.key-preview {
    font-family: 'Consolas', 'Monaco', monospace;
    font-size: 12px;
    background: rgba(0, 0, 0, 0.35);
    color: #38bdf8;
    padding: 4px 8px;
    border-radius: 4px;
    border: 1px solid rgba(56, 189, 248, 0.3);
    word-break: break-all;
    display: inline-block;
}
.wg-advanced-box {
    background: rgba(0, 0, 0, 0.25);
    border: 1px solid rgba(255, 255, 255, 0.12);
    border-radius: 8px;
    padding: 18px;
    margin-top: 10px;
}
.wg-advanced-box label,
.wg-advanced-box strong {
    color: inherit;
}
.wg-config-box {
    font-family: 'Consolas', 'Monaco', monospace;
    font-size: 12px;
    background-color: #0f172a;
    color: #38bdf8;
    padding: 15px;
    border-radius: 6px;
    border: 1px solid #334155;
    line-height: 1.5;
    white-space: pre;
    overflow-x: auto;
    max-height: 380px;
}
.qr-container {
    background: #ffffff !important;
    padding: 16px;
    border: 2px solid #38bdf8;
    border-radius: 8px;
    display: inline-block;
    box-shadow: 0 4px 6px rgba(0,0,0,0.3);
}
#peerTable thead th {
    background: rgba(0, 0, 0, 0.35) !important;
    color: #38bdf8 !important;
    font-size: 12px;
    font-weight: 700;
    text-transform: uppercase;
    letter-spacing: 0.5px;
    border-bottom: 2px solid #0284c7 !important;
    border-top: none !important;
    padding: 11px 12px;
    vertical-align: middle;
}
#peerTable tbody tr:hover {
    background: rgba(255, 255, 255, 0.05);
}
.modal-content {
    background-color: #1e293b;
    color: #f8fafc;
    border: 1px solid #334155;
}
.modal-header {
    background-color: #0f172a;
    border-bottom: 1px solid #334155;
}
.modal-footer {
    background-color: #0f172a;
    border-top: 1px solid #334155;
}
</style>

<div class="panel panel-default">
    <div class="panel-heading" style="display:flex; justify-content:space-between; align-items:center;">
        <h2 class="panel-title" style="font-size:17px; margin:0; font-weight:bold;">
            <i class="fa fa-shield text-primary"></i> WireGuard Hızlı Peer Yönetimi &amp; İstemci İhracı
        </h2>
        <div>
            <?php if ($has_tunnels): ?>
                <button type="button" class="btn btn-sm btn-info" data-toggle="modal" data-target="#newTunnelModal">
                    <i class="fa fa-plus-circle"></i> Ek Tünel Oluştur
                </button>
            <?php endif; ?>
        </div>
    </div>
    <div class="panel-body">
        <p class="text-muted" style="margin-bottom: 20px;">
            Atanacak IP, Peer Adı ve Private Key girerek (veya 1-tıkla üreterek) saniyeler içinde WireGuard ağına yeni bir istemci ekleyebilir; 
            hazır <strong>.conf</strong> dosyasını indirebilir veya mobil cihazlar için <strong>QR kod</strong> alabilirsiniz.
        </p>

        <?php if (!empty($savemsg)): ?>
            <div class="alert alert-success alert-dismissible" role="alert">
                <button type="button" class="close" data-dismiss="alert"><span>&times;</span></button>
                <i class="fa fa-check-circle"></i> <?= $savemsg ?>
            </div>
        <?php endif; ?>

        <?php if (!empty($errormsg)): ?>
            <div class="alert alert-danger alert-dismissible" role="alert">
                <button type="button" class="close" data-dismiss="alert"><span>&times;</span></button>
                <i class="fa fa-exclamation-triangle"></i> <?= htmlspecialchars($errormsg) ?>
            </div>
        <?php endif; ?>

        <?php if (!$has_tunnels): ?>
            <!-- KURULUM SİHİRBAZI -->
            <div class="alert alert-warning" style="padding:25px; border-left: 6px solid #f59e0b; background:rgba(245, 158, 11, 0.1);">
                <div class="row">
                    <div class="col-md-8">
                        <h3 style="margin-top:0; color:#f59e0b;"><i class="fa fa-magic"></i> WireGuard Tüneli Bulunamadı - Hızlı Kurulum Sihirbazı</h3>
                        <p style="font-size:14px;">
                            Sisteminizde tanımlı herhangi bir WireGuard tüneli bulunmuyor. 
                            Aşağıdaki hazır değerleri kullanarak tek tıkla <strong>tun_wg0</strong> tünelini ve WireGuard servisini kurabilirsiniz.
                        </p>
                    </div>
                </div>
                <hr style="border-top: 1px solid rgba(245, 158, 11, 0.3);">
                <form method="post" action="wg_quick_peer.php" class="form-inline">
                    <input type="hidden" name="act" value="create_tunnel">
                    <div class="form-group" style="margin-right:12px;">
                        <label>Tünel Arayüzü: &nbsp;</label>
                        <input type="text" name="name" class="form-control" value="tun_wg0" style="width:110px;" required>
                    </div>
                    <div class="form-group" style="margin-right:12px;">
                        <label>Sunucu IP / Maske: &nbsp;</label>
                        <input type="text" name="address" class="form-control" value="10.0.0.1" style="width:120px;" required>
                        <input type="number" name="mask" class="form-control" value="24" style="width:65px;" required>
                    </div>
                    <div class="form-group" style="margin-right:12px;">
                        <label>Dinleme Portu: &nbsp;</label>
                        <input type="number" name="listenport" class="form-control" value="51820" style="width:90px;" required>
                    </div>
                    <div class="form-group" style="margin-right:12px;">
                        <label>Açıklama: &nbsp;</label>
                        <input type="text" name="descr" class="form-control" value="Ana WireGuard VPN Sunucusu" style="width:200px;">
                    </div>
                    <button type="submit" class="btn btn-success" style="font-weight:bold;">
                        <i class="fa fa-play-circle"></i> tun_wg0 Tünelini Oluştur ve Başlat
                    </button>
                </form>
            </div>

        <?php else: ?>

            <?php if (!empty($ad_sso['available']) && !empty($ad_sso['enabled'])): ?>
                <!-- POSEA AD SSO & 5651 DURUM BARI -->
                <div class="row" style="margin-bottom:15px;">
                    <div class="col-md-12">
                        <div style="display:flex; justify-content:space-between; align-items:center; background:rgba(56, 189, 248, 0.08); border:1px solid rgba(56, 189, 248, 0.25); border-radius:8px; padding:10px 16px; flex-wrap:wrap; gap:10px;">
                            <div style="display:flex; align-items:center; flex-wrap:wrap; gap:8px;">
                                <i class="fa fa-windows" style="color:#38bdf8; font-size:18px;"></i>
                                <strong style="color:#38bdf8;">Posea AD SSO Entegrasyonu Aktif:</strong>
                                <span class="label label-primary" style="font-size:12px;"><?= htmlspecialchars($ad_sso['domain_name']) ?></span>
                                <span class="text-muted" style="font-size:12px;">(DC: <?= htmlspecialchars($ad_sso['dc_host']) ?>) &bull; <?= count($ad_users) ?> AD Kullanıcısı &bull; PoseaFilter UTM &amp; 5651 Log Senkron</span>
                            </div>
                            <div>
                                <button type="button" class="btn btn-xs btn-info" id="btnSyncAd" style="background:rgba(56, 189, 248, 0.2); border:1px solid #38bdf8; color:#38bdf8; font-weight:bold; padding:4px 10px;" onclick="syncAdSessions(this)">
                                    <i class="fa fa-refresh"></i> <span>AD &amp; 5651 Senkronize Et</span>
                                </button>
                            </div>
                        </div>
                    </div>
                </div>
            <?php endif; ?>

            <!-- AKTİF TÜNEL BİLGİ KARTLARI -->
            <div class="row" style="margin-bottom:15px;">
                <div class="col-md-12">
                    <div class="wg-tunnel-bar">
                        <div class="form-inline">
                            <label style="font-weight:bold; margin-right:8px;"><i class="fa fa-random text-primary"></i> Aktif Tünel:</label>
                            <select id="tunnelSelect" class="form-control" style="font-weight:bold; min-width:260px;" onchange="location.href='wg_quick_peer.php?tun=' + this.value;">
                                <?php foreach ($wg_data['tunnels'] as $t_name => $t_info): ?>
                                    <option value="<?= htmlspecialchars($t_name) ?>" <?= ($t_name === $active_tunnel_name) ? 'selected' : '' ?>>
                                        <?= htmlspecialchars($t_name) ?> (<?= htmlspecialchars($t_info['cidr'] ?: 'Ağ Belirsiz') ?>) - <?= count($t_info['peers']) ?> Peer
                                    </option>
                                <?php endforeach; ?>
                            </select>
                        </div>
                        <div>
                            <span class="label label-<?= ($current_tunnel['status'] === 'up') ? 'success' : 'warning' ?>" style="font-size:12px; padding:6px 12px;">
                                <i class="fa fa-circle"></i> Tünel <?= strtoupper($current_tunnel['status']) ?>
                            </span>
                            <span class="label label-info" style="font-size:12px; padding:6px 12px; margin-left:6px;">
                                <i class="fa fa-globe"></i> Endpoint: <?= htmlspecialchars($wg_data['wan_endpoint']) ?>:<?= htmlspecialchars($current_tunnel['listenport']) ?>
                            </span>
                        </div>
                    </div>
                </div>
            </div>

            <!-- Tünel Detay İstatistikleri -->
            <div class="row">
                <div class="col-sm-6 col-md-3">
                    <div class="wg-badge-card">
                        <div class="wg-stat-label"><i class="fa fa-sitemap text-primary"></i> Tünel IP &amp; Alt Ağ</div>
                        <div class="wg-stat-val text-primary"><?= htmlspecialchars($current_tunnel['cidr'] ?: '10.0.0.1/24') ?></div>
                    </div>
                </div>
                <div class="col-sm-6 col-md-3">
                    <div class="wg-badge-card">
                        <div class="wg-stat-label"><i class="fa fa-plug text-info"></i> UDP Dinleme Portu</div>
                        <div class="wg-stat-val text-info"><?= htmlspecialchars($current_tunnel['listenport']) ?></div>
                    </div>
                </div>
                <div class="col-sm-6 col-md-3">
                    <div class="wg-badge-card">
                        <div class="wg-stat-label"><i class="fa fa-users text-success"></i> Kayıtlı Peer Sayısı</div>
                        <div class="wg-stat-val text-success"><?= count($current_tunnel['peers']) ?> Adet</div>
                    </div>
                </div>
                <div class="col-sm-6 col-md-3">
                    <div class="wg-badge-card">
                        <div class="wg-stat-label"><i class="fa fa-exchange text-warning"></i> Toplam Veri Transferi</div>
                        <div class="wg-stat-val">
                            <span class="text-success">&darr; <?= format_bytes_human($current_tunnel['transfer_rx']) ?></span> &nbsp;
                            <span class="text-info">&uarr; <?= format_bytes_human($current_tunnel['transfer_tx']) ?></span>
                        </div>
                    </div>
                </div>
            </div>

            <div class="row" style="margin-bottom:20px;">
                <div class="col-md-12">
                    <div class="wg-pubkey-well">
                        <div>
                            <strong style="margin-right:6px;"><i class="fa fa-key text-warning"></i> Sunucu Public Key:</strong>
                            <span class="key-preview" id="serverPubKeyText"><?= htmlspecialchars($current_tunnel['publickey']) ?></span>
                        </div>
                        <button type="button" class="btn btn-xs btn-default" onclick="copyTextToClipboard('<?= htmlspecialchars($current_tunnel['publickey']) ?>', this)">
                            <i class="fa fa-copy"></i> Kopyala
                        </button>
                    </div>
                </div>
            </div>

            <!-- ============================================================== -->
            <!-- HIZLI PEER OLUŞTURMA FORMU                                     -->
            <!-- ============================================================== -->
            <div class="panel panel-info" style="border: 2px solid #0284c7; box-shadow: 0 4px 10px rgba(2, 132, 199, 0.15);">
                <div class="panel-heading" style="background:#0284c7; color:#fff; border-bottom: 2px solid #0369a1;">
                    <h3 class="panel-title" style="font-weight:bold; font-size:15px;">
                        <i class="fa fa-user-plus"></i> Hızlı Peer Oluştur &bull; <?= htmlspecialchars($active_tunnel_name) ?>
                    </h3>
                </div>
                <div class="panel-body">
                    <form id="addPeerForm" method="post" action="wg_quick_peer.php?tun=<?= urlencode($active_tunnel_name) ?>">
                        <input type="hidden" name="act" value="add_peer">
                        <input type="hidden" name="tun" value="<?= htmlspecialchars($active_tunnel_name) ?>">

                        <?php if (!empty($ad_sso['available']) && !empty($ad_sso['enabled'])): ?>
                            <!-- AD Kullanıcısı Seçim Alanı -->
                            <div class="row" style="margin-bottom:12px;">
                                <div class="col-md-12">
                                    <div style="background:rgba(56, 189, 248, 0.05); border:1px solid rgba(56, 189, 248, 0.25); border-radius:6px; padding:10px 14px;">
                                        <label for="ad_user_select" style="font-weight:bold; color:#38bdf8; margin-bottom:5px;">
                                            <i class="fa fa-windows"></i> Active Directory Kullanıcısı Seç (SSO / 5651 Entegrasyonu):
                                        </label>
                                        <div class="input-group">
                                            <span class="input-group-addon" style="background:rgba(0,0,0,0.25); border-color:rgba(56,189,248,0.3); color:#38bdf8;">
                                                <i class="fa fa-user"></i>
                                            </span>
                                            <select id="ad_user_select" class="form-control input-md" onchange="onAdUserSelected(this)" style="font-weight:bold;">
                                                <option value="">-- Serbest Cihaz / AD Eşlemesi Yok (Manuel İsim Girin) --</option>
                                                <?php foreach ($ad_users as $u): ?>
                                                    <option value="<?= htmlspecialchars($u['username']) ?>"
                                                            data-display="<?= htmlspecialchars($u['display_name']) ?>"
                                                            data-dept="<?= htmlspecialchars($u['department']) ?>"
                                                            data-disabled="<?= $u['disabled'] ? '1' : '0' ?>"
                                                            <?= $u['disabled'] ? 'style="color:#f87171;"' : '' ?>>
                                                        <?= htmlspecialchars($u['display_name']) ?> (<?= htmlspecialchars($u['username']) ?>) <?= !empty($u['department']) ? ' &bull; ' . htmlspecialchars($u['department']) : '' ?><?= $u['disabled'] ? ' [AD PASİF]' : '' ?>
                                                    </option>
                                                <?php endforeach; ?>
                                            </select>
                                        </div>
                                        <input type="hidden" name="ad_username" id="ad_username" value="">
                                        <p class="help-block text-muted" style="margin-top:4px; margin-bottom:0; font-size:11px;">
                                            Kullanıcı seçildiğinde profil adı otomatik dolar ve anahtarlar hazırlanır. Bağlandığında oturum PoseaFilter UTM ve 5651 loglarına AD kimliğiyle işlenir.
                                        </p>
                                    </div>
                                </div>
                            </div>
                        <?php endif; ?>

                        <div class="row">
                            <!-- Peer Adı -->
                            <div class="col-md-4">
                                <div class="form-group">
                                    <label for="peer_descr" style="font-weight:bold;">
                                        <i class="fa fa-tag text-primary"></i> Peer Adı / Profil Adı <span class="text-danger">*</span>
                                    </label>
                                    <input type="text" class="form-control input-lg" id="peer_descr" name="descr" placeholder="Örn: sener veya Ahmet-Laptop" required autofocus>
                                    <p class="help-block text-muted" style="margin-bottom:0; font-size:12px;">Cihaz veya kullanıcıyı tanımlayacak isim.</p>
                                </div>
                            </div>

                            <!-- Atanacak IP -->
                            <div class="col-md-4">
                                <div class="form-group">
                                    <label for="peer_ip" style="font-weight:bold;">
                                        <i class="fa fa-sitemap text-primary"></i> Atanacak Tünel IP <span class="text-danger">*</span>
                                    </label>
                                    <div class="input-group">
                                        <input type="text" class="form-control input-lg" id="peer_ip" name="client_ip" value="<?= htmlspecialchars($next_ip_info['suggested']) ?>" required>
                                        <span class="input-group-btn">
                                            <button type="button" class="btn btn-lg btn-default" title="Boş IP adresini yeniden sorgula" onclick="refreshNextIp('<?= htmlspecialchars($active_tunnel_name) ?>')">
                                                <i class="fa fa-refresh" id="ipRefreshIcon"></i>
                                            </button>
                                        </span>
                                    </div>
                                    <p class="help-block text-success" style="margin-bottom:0; font-size:12px;">
                                        <i class="fa fa-check-circle"></i> Sıradaki önerilen boş IP.
                                    </p>
                                </div>
                            </div>

                            <!-- Endpoint / Harici IP -->
                            <div class="col-md-4">
                                <div class="form-group">
                                    <label for="endpoint_override" style="font-weight:bold;">
                                        <i class="fa fa-globe text-primary"></i> Dış Ağ Endpoint (IP / Port)
                                    </label>
                                    <input type="text" class="form-control input-lg" id="endpoint_override" name="endpoint_override" value="<?= htmlspecialchars($wg_data['wan_endpoint']) ?>">
                                    <p class="help-block text-muted" style="margin-bottom:0; font-size:12px;">İstemcilerin bağlanacağı pfSense dış IP'si.</p>
                                </div>
                            </div>
                        </div>

                        <!-- Private Key & Otomatik Public Key Alanı -->
                        <div class="row" style="margin-top:10px;">
                            <div class="col-md-12">
                                <div class="form-group">
                                    <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:5px;">
                                        <label for="client_privkey" style="font-weight:bold; margin:0;">
                                            <i class="fa fa-lock text-warning"></i> İstemci Private Key (Özel Anahtar) <span class="text-danger">*</span>
                                        </label>
                                        <button type="button" class="btn btn-sm btn-warning" onclick="generateKeypair();" style="font-weight:bold;">
                                            <i class="fa fa-magic"></i> 🔑 Otomatik Anahtar Çifti Üret (1-Tık)
                                        </button>
                                    </div>
                                    <input type="text" class="form-control" id="client_privkey" name="client_privkey" placeholder="İstemcinin Private Key'ini buraya yapıştırın (Veya yukarıdaki butona basarak otomatik üretin)" style="font-family:monospace; font-size:13px; font-weight:bold; color:#38bdf8;" oninput="onPrivateKeyInput(this.value)" required>
                                    <p class="help-block text-muted" style="font-size:12px; margin-bottom:5px;">
                                        Bu anahtar üretilecek <strong>.conf</strong> dosyası ve <strong>QR kod</strong> içerisine gerçek PrivateKey olarak otomatik yazılacaktır.
                                    </p>
                                </div>
                            </div>
                        </div>

                        <!-- Derived Public Key (Otomatik türetilir) -->
                        <div class="row">
                            <div class="col-md-12">
                                <div class="form-group" style="margin-bottom:10px;">
                                    <label for="peer_pubkey" style="font-weight:bold; font-size:12px; opacity:0.9;">
                                        <i class="fa fa-key text-info"></i> Açık Anahtar (Public Key) &mdash; <span class="text-info">Sunucu yöneticisine verilecek</span>:
                                    </label>
                                    <input type="text" class="form-control" id="peer_pubkey" name="publickey" placeholder="Private Key girildiğinde Public Key otomatik olarak türetilir..." style="font-family:monospace; font-size:13px; background:rgba(0,0,0,0.3); color:#38bdf8;" readonly>
                                </div>
                            </div>
                        </div>

                        <!-- İsteğe Bağlı Gelişmiş Ayarlar (Rotalama & DNS) -->
                        <div style="margin-top:10px; margin-bottom:15px;">
                            <a href="#advancedSettings" data-toggle="collapse" class="text-primary" style="font-weight:bold; font-size:13px; text-decoration:none;">
                                <i class="fa fa-cog"></i> Gelişmiş Ayarlar (Rotalama, DNS) &darr;
                            </a>
                            <div id="advancedSettings" class="collapse wg-advanced-box in">
                                <div class="row">
                                    <div class="col-md-6">
                                        <div class="form-group">
                                            <label for="allowed_ips_client" style="font-weight:bold;"><i class="fa fa-random text-primary"></i> İstemci AllowedIPs (Rotalama):</label>
                                            <input type="text" class="form-control" id="allowed_ips_client" name="allowed_ips_client" value="<?= htmlspecialchars($net_defaults['allowed_ips_default']) ?>" style="font-family:monospace;">
                                            <p class="help-block text-muted" style="font-size:11px;">
                                                Varsayılan: <code><?= htmlspecialchars($net_defaults['allowed_ips_default']) ?></code> (Tüm internet için <code>0.0.0.0/0, ::/0</code> yazabilirsiniz).
                                            </p>
                                        </div>
                                    </div>
                                    <div class="col-md-6">
                                        <div class="form-group">
                                            <label for="dns_servers" style="font-weight:bold;"><i class="fa fa-server text-info"></i> DNS Sunucuları:</label>
                                            <input type="text" class="form-control" id="dns_servers" name="dns" value="<?= htmlspecialchars($net_defaults['default_dns']) ?>" style="font-family:monospace;">
                                            <p class="help-block text-muted" style="font-size:11px;">
                                                Varsayılan kurumsal DNS: <code><?= htmlspecialchars($net_defaults['default_dns']) ?></code>
                                            </p>
                                        </div>
                                    </div>
                                </div>
                            </div>
                        </div>

                        <div style="text-align:right;">
                            <button type="submit" class="btn btn-success btn-lg" style="padding-left:35px; padding-right:35px; font-weight:bold; font-size:16px;">
                                <i class="fa fa-rocket"></i> Peer Ekle ve Hazır Config Al
                            </button>
                        </div>
                    </form>
                </div>
            </div>

            <!-- ============================================================== -->
            <!-- MEVCUT PEER'LAR LİSTESİ TABLOSU                                -->
            <!-- ============================================================== -->
            <div class="panel panel-default" style="margin-top:25px;">
                <div class="panel-heading" style="display:flex; justify-content:space-between; align-items:center;">
                    <h3 class="panel-title" style="font-weight:bold;">
                        <i class="fa fa-list text-primary"></i> <?= htmlspecialchars($active_tunnel_name) ?> Üzerindeki Kayıtlı Peer'lar (<?= count($current_tunnel['peers']) ?>)
                    </h3>
                    <div style="width:250px;">
                        <input type="text" id="peerSearch" class="form-control input-sm" placeholder="Peer adı veya IP ara..." onkeyup="filterPeerTable()">
                    </div>
                </div>
                <div class="table-responsive">
                    <table class="table table-striped table-hover" id="peerTable" style="margin-bottom:0; font-size:13px;">
                        <thead>
                            <tr>
                                <th style="width:50px; text-align:center;">Durum</th>
                                <th>Peer Adı / Açıklama</th>
                                <th>Atanan IP (Allowed IPs)</th>
                                <th>Public Key</th>
                                <th>Son El Sıkışma</th>
                                <th>Transfer (Rx / Tx)</th>
                                <th style="width:170px; text-align:right;">İşlemler</th>
                            </tr>
                        </thead>
                        <tbody>
                            <?php if (empty($current_tunnel['peers'])): ?>
                                <tr>
                                    <td colspan="7" class="text-center text-muted" style="padding:25px;">
                                        <i class="fa fa-info-circle"></i> Bu tünelde henüz kayıtlı peer bulunmuyor. Yukarıdaki formu kullanarak hemen ekleyebilirsiniz.
                                    </td>
                                </tr>
                            <?php else: ?>
                                <?php foreach ($current_tunnel['peers'] as $p): ?>
                                    <tr class="peer-row" data-descr="<?= htmlspecialchars(strtolower($p['descr'])) ?>" data-ip="<?= htmlspecialchars($p['allowed_ips']) ?>">
                                        <td style="text-align:center; vertical-align:middle;">
                                            <button type="button" class="btn btn-xs btn-<?= $p['enabled'] ? 'success' : 'default' ?>" title="<?= $p['enabled'] ? 'Devre Dışı Bırak' : 'Etkinleştir' ?>" onclick="togglePeer(<?= $p['idx'] ?>)">
                                                <i class="fa fa-<?= $p['enabled'] ? 'check' : 'pause' ?>"></i>
                                            </button>
                                        </td>
                                        <td style="vertical-align:middle; font-weight:bold;">
                                            <?= htmlspecialchars($p['descr'] ?: 'İsimsiz Peer') ?>
                                            <?php if (!empty($p['ad_username'])): ?>
                                                <br>
                                                <span class="badge" style="background:rgba(56,189,248,0.15); color:#38bdf8; border:1px solid rgba(56,189,248,0.35); font-size:10px; font-weight:normal; margin-top:3px; display:inline-block;">
                                                    <i class="fa fa-windows"></i> <?= htmlspecialchars($p['ad_username']) ?>
                                                </span>
                                                <?php if (!empty($p['ad_info']['disabled'])): ?>
                                                    <span class="badge badge-danger" style="background-color:#ef4444; color:#fff; font-size:10px; margin-top:3px; display:inline-block;" title="Active Directory'de bu kullanıcı hesabı devre dışı bırakılmıştır!">
                                                        <i class="fa fa-ban"></i> AD Pasif
                                                    </span>
                                                <?php endif; ?>
                                            <?php endif; ?>
                                        </td>
                                        <td style="vertical-align:middle;">
                                            <span class="label label-primary" style="font-size:12px; font-family:monospace; padding:4px 8px;">
                                                <?= htmlspecialchars($p['allowed_ips']) ?>
                                            </span>
                                        </td>
                                        <td style="vertical-align:middle;">
                                            <span class="key-preview" title="<?= htmlspecialchars($p['publickey']) ?>">
                                                <?= htmlspecialchars(substr($p['publickey'], 0, 14)) ?>...
                                            </span>
                                            <button type="button" class="btn btn-xs btn-link" onclick="copyTextToClipboard('<?= htmlspecialchars($p['publickey']) ?>', this)">
                                                <i class="fa fa-copy"></i>
                                            </button>
                                        </td>
                                        <td style="vertical-align:middle;">
                                            <?= format_handshake_human($p['latest_handshake']) ?>
                                        </td>
                                        <td style="vertical-align:middle;">
                                            <span class="text-success">&darr; <?= format_bytes_human($p['transfer_rx']) ?></span><br>
                                            <span class="text-info">&uarr; <?= format_bytes_human($p['transfer_tx']) ?></span>
                                        </td>
                                        <td style="text-align:right; vertical-align:middle;">
                                            <?php if (!empty($p['ad_info']['disabled']) && $p['enabled']): ?>
                                                <button type="button" class="btn btn-xs btn-warning" title="Kullanıcının AD hesabı kapalı! VPN bağlantısını devre dışı bırakmak için tıklayın" onclick="togglePeer(<?= $p['idx'] ?>)" style="margin-right:3px;">
                                                    <i class="fa fa-lock"></i> Pasife Al
                                                </button>
                                            <?php endif; ?>
                                            <button type="button" class="btn btn-xs btn-info" title="Config ve QR Kod Görüntüle" onclick="showExistingPeerModal('<?= htmlspecialchars($active_tunnel_name) ?>', '<?= htmlspecialchars($p['first_ip'] ?: '10.0.0.2') ?>', '<?= htmlspecialchars($p['descr']) ?>', '<?= htmlspecialchars($p['publickey']) ?>', '<?= htmlspecialchars($p['privatekey']) ?>')">
                                                <i class="fa fa-qrcode"></i> Config &amp; QR
                                            </button>
                                            <button type="button" class="btn btn-xs btn-danger" title="Peer'ı Sil" onclick="deletePeer(<?= $p['idx'] ?>, '<?= htmlspecialchars(addslashes($p['descr'])) ?>')">
                                                <i class="fa fa-trash"></i>
                                            </button>
                                        </td>
                                    </tr>
                                <?php endforeach; ?>
                            <?php endif; ?>
                        </tbody>
                    </table>
                </div>
            </div>

        <?php endif; ?>

    </div>
</div>

<!-- ============================================================== -->
<!-- CONFIG & QR KOD GÖSTERİM MODALI                                -->
<!-- ============================================================== -->
<div class="modal fade" id="configExportModal" tabindex="-1" role="dialog">
    <div class="modal-dialog modal-lg" role="document">
        <div class="modal-content">
            <div class="modal-header">
                <button type="button" class="close" data-dismiss="modal" style="color:#fff; opacity:0.9;">&times;</button>
                <h4 class="modal-title" style="font-weight:bold;">
                    <i class="fa fa-qrcode text-info"></i> WireGuard İstemci Yapılandırması &bull; <span id="modalPeerTitle"></span>
                </h4>
            </div>
            <div class="modal-body">
                <div class="row">
                    <!-- Config Dosyası Metni -->
                    <div class="col-md-7">
                        <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:8px;">
                            <label style="margin:0; font-weight:bold;"><i class="fa fa-file-text-o text-primary"></i> Yapılandırma (.conf):</label>
                            <div>
                                <button type="button" class="btn btn-xs btn-default" onclick="copyModalConfig()">
                                    <i class="fa fa-copy"></i> Kopyala
                                </button>
                                <button type="button" class="btn btn-xs btn-success" onclick="downloadModalConfig()">
                                    <i class="fa fa-download"></i> .conf İndir
                                </button>
                            </div>
                        </div>
                        <pre class="wg-config-box" id="modalConfigContent"></pre>

                        <!-- Private Key Düzenleme / Güncelleme Kutusu -->
                        <div style="margin-top:10px; background:rgba(0,0,0,0.3); padding:10px; border-radius:6px; border:1px solid rgba(255,255,255,0.1);">
                            <label style="font-size:12px; font-weight:bold; margin-bottom:4px;">
                                <i class="fa fa-lock text-warning"></i> İstemci Private Key:
                            </label>
                            <div class="input-group">
                                <input type="text" class="form-control input-sm" id="modalPrivKeyInput" style="font-family:monospace; font-weight:bold; color:#38bdf8;">
                                <span class="input-group-btn">
                                    <button type="button" class="btn btn-sm btn-info" onclick="saveModalPrivateKey()">
                                        <i class="fa fa-save"></i> Güncelle
                                    </button>
                                </span>
                            </div>
                        </div>

                        <?php if (!empty($ad_sso['available']) && !empty($ad_sso['enabled'])): ?>
                            <!-- Active Directory Kullanıcı Eşleme Kutusu -->
                            <div style="margin-top:10px; background:rgba(0,0,0,0.3); padding:10px; border-radius:6px; border:1px solid rgba(255,255,255,0.1);">
                                <label style="font-size:12px; font-weight:bold; margin-bottom:4px;">
                                    <i class="fa fa-windows text-info"></i> Active Directory Kullanıcı Eşlemesi (SSO / 5651):
                                </label>
                                <div class="input-group">
                                    <select id="modalAdUserSelect" class="form-control input-sm" style="font-weight:bold;">
                                        <option value="">-- Serbest Cihaz / AD Eşlemesi Yok --</option>
                                        <?php foreach ($ad_users as $u): ?>
                                            <option value="<?= htmlspecialchars($u['username']) ?>">
                                                <?= htmlspecialchars($u['display_name']) ?> (<?= htmlspecialchars($u['username']) ?>)
                                            </option>
                                        <?php endforeach; ?>
                                    </select>
                                    <span class="input-group-btn">
                                        <button type="button" class="btn btn-sm btn-info" onclick="saveModalAdUser()">
                                            <i class="fa fa-save"></i> Kaydet
                                        </button>
                                    </span>
                                </div>
                            </div>
                        <?php endif; ?>
                    </div>

                    <!-- QR Kodu & Mobil Bilgi -->
                    <div class="col-md-5 text-center">
                        <label style="font-weight:bold;"><i class="fa fa-mobile text-success"></i> Mobil WireGuard QR Kodu</label>
                        <div style="margin:10px 0;">
                            <div class="qr-container">
                                <div id="modalQrcode"></div>
                            </div>
                        </div>
                        <p class="text-muted" style="font-size:12px; line-height:1.4; padding:0 10px;">
                            <i class="fa fa-camera text-primary"></i> <strong>WireGuard</strong> mobil uygulamasını açın, <strong>+</strong> butonuna basıp <strong>QR Kodu Tara</strong> seçeneği ile kameranızı okutun.
                        </p>
                    </div>
                </div>
            </div>
            <div class="modal-footer">
                <button type="button" class="btn btn-success" onclick="downloadModalConfig()"><i class="fa fa-download"></i> .conf Dosyasını İndir</button>
                <button type="button" class="btn btn-primary" onclick="copyModalConfig()"><i class="fa fa-copy"></i> Panoya Kopyala</button>
                <button type="button" class="btn btn-default" data-dismiss="modal">Kapat</button>
            </div>
        </div>
    </div>
</div>

<!-- ============================================================== -->
<!-- YENİ TÜNEL EKLEME MODALI                                       -->
<!-- ============================================================== -->
<div class="modal fade" id="newTunnelModal" tabindex="-1" role="dialog">
    <div class="modal-dialog" role="document">
        <div class="modal-content">
            <form method="post" action="wg_quick_peer.php">
                <input type="hidden" name="act" value="create_tunnel">
                <div class="modal-header">
                    <button type="button" class="close" data-dismiss="modal" style="color:#fff; opacity:0.9;">&times;</button>
                    <h4 class="modal-title"><i class="fa fa-plus-circle text-info"></i> Yeni WireGuard Tüneli Ekle</h4>
                </div>
                <div class="modal-body">
                    <p class="text-muted">pfSense üzerinde ek bir WireGuard sunucu tüneli oluşturabilirsiniz.</p>
                    <div class="form-group">
                        <label>Tünel Arayüzü:</label>
                        <input type="text" name="name" class="form-control" value="tun_wg<?= count($wg_data['tunnels']) ?>" required>
                    </div>
                    <div class="row">
                        <div class="col-md-8">
                            <div class="form-group">
                                <label>Sunucu IP / Alt Ağ:</label>
                                <input type="text" name="address" class="form-control" value="10.0.<?= count($wg_data['tunnels']) ?>.1" required>
                            </div>
                        </div>
                        <div class="col-md-4">
                            <div class="form-group">
                                <label>Alt Ağ Maskesi:</label>
                                <input type="number" name="mask" class="form-control" value="24" required>
                            </div>
                        </div>
                    </div>
                    <div class="row">
                        <div class="col-md-6">
                            <div class="form-group">
                                <label>Dinleme Portu (UDP):</label>
                                <input type="number" name="listenport" class="form-control" value="<?= 51820 + count($wg_data['tunnels']) ?>" required>
                            </div>
                        </div>
                        <div class="col-md-6">
                            <div class="form-group">
                                <label>MTU:</label>
                                <input type="number" name="mtu" class="form-control" value="1420" required>
                            </div>
                        </div>
                    </div>
                    <div class="form-group">
                        <label>Açıklama:</label>
                        <input type="text" name="descr" class="form-control" placeholder="Örn: 2. Sube VPN Tuneli">
                    </div>
                </div>
                <div class="modal-footer">
                    <button type="button" class="btn btn-default" data-dismiss="modal">İptal</button>
                    <button type="submit" class="btn btn-success font-weight-bold"><i class="fa fa-check"></i> Tüneli Oluştur</button>
                </div>
            </form>
        </div>
    </div>
</div>

<script>
var currentExportConfig = "";
var currentExportName = "client";
var currentModalPubkey = "";
var currentModalTun = "tun_wg0";
var currentModalIp = "";

function copyTextToClipboard(text, btnElem) {
    if (navigator.clipboard && window.isSecureContext) {
        navigator.clipboard.writeText(text).then(function() {
            showCopiedTooltip(btnElem);
        });
    } else {
        var textArea = document.createElement("textarea");
        textArea.value = text;
        textArea.style.position = "fixed";
        textArea.style.left = "-999999px";
        document.body.appendChild(textArea);
        textArea.focus();
        textArea.select();
        try {
            document.execCommand('copy');
            showCopiedTooltip(btnElem);
        } catch (err) {}
        document.body.removeChild(textArea);
    }
}

function showCopiedTooltip(btnElem) {
    if (!btnElem) return;
    var origHtml = btnElem.innerHTML;
    btnElem.innerHTML = '<i class="fa fa-check text-success"></i> Kopyalandı!';
    setTimeout(function() {
        btnElem.innerHTML = origHtml;
    }, 1500);
}

function copyModalConfig() {
    copyTextToClipboard(currentExportConfig, event ? event.target : null);
}

function downloadModalConfig() {
    var blob = new Blob([currentExportConfig], { type: "text/plain;charset=utf-8" });
    var url = URL.createObjectURL(blob);
    var a = document.createElement("a");
    a.href = url;
    a.download = (currentExportName.replace(/[^a-zA-Z0-9_-]/g, "_") || "wireguard_client") + ".conf";
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
}

function getCleanConfigForQR(configText) {
    var lines = (configText || "").split('\n');
    var cleanLines = [];
    for (var i = 0; i < lines.length; i++) {
        var line = lines[i].trim();
        if (line.length === 0 || line.indexOf('#') === 0 || line.indexOf(';') === 0) {
            continue;
        }
        cleanLines.push(line);
    }
    return cleanLines.join('\n');
}

function renderQRCode(text) {
    var container = document.getElementById("modalQrcode");
    if (!container) return;
    container.innerHTML = "";

    var qrText = getCleanConfigForQR(text);

    if (typeof QRCode !== 'undefined') {
        try {
            new QRCode(container, {
                text: qrText,
                width: 200,
                height: 200,
                colorDark: "#000000",
                colorLight: "#ffffff",
                correctLevel: QRCode.CorrectLevel.L
            });
        } catch (err) {
            console.error('QR Render Error:', err);
            container.innerHTML = "<div class='text-danger' style='font-size:12px; padding:10px;'><i class='fa fa-exclamation-triangle'></i> QR Kod oluşturulamadı.<br><small>" + err.message + "</small></div>";
        }
    } else {
        container.innerHTML = "<span class='text-muted'>QR kütüphanesi yüklenemedi.</span>";
    }
}

function openConfigModal(title, configText, name, pubkey, privkey, tun, ip, adUser) {
    currentExportConfig = configText;
    currentExportName = name;
    currentModalPubkey = pubkey || "";
    currentModalTun = tun || "tun_wg0";
    currentModalIp = ip || "";

    document.getElementById("modalPeerTitle").innerText = title;
    document.getElementById("modalConfigContent").innerText = configText;
    document.getElementById("modalPrivKeyInput").value = privkey || "";

    var adSel = document.getElementById("modalAdUserSelect");
    if (adSel) {
        adSel.value = adUser || "";
    }

    renderQRCode(configText);
    $('#configExportModal').modal('show');
}

function getCsrfToken() {
    if (typeof csrfMagicToken !== 'undefined' && csrfMagicToken) {
        return csrfMagicToken;
    }
    var csrfInput = document.querySelector('input[name="__csrf_magic"]');
    if (csrfInput && csrfInput.value) {
        return csrfInput.value;
    }
    return '';
}

function saveModalPrivateKey() {
    var newPriv = document.getElementById("modalPrivKeyInput").value.trim();
    if (!newPriv) {
        alert("Lütfen geçerli bir Private Key girin.");
        return;
    }

    var params = new URLSearchParams();
    params.append("ajax_save_privkey", "1");
    params.append("pubkey", currentModalPubkey);
    params.append("privkey", newPriv);

    var csrfToken = getCsrfToken();
    if (csrfToken) {
        params.append("__csrf_magic", csrfToken);
    }

    fetch("wg_quick_peer.php?" + params.toString())
    .then(function(res) { return res.json(); })
    .then(function(data) {
        if (data && data.success) {
            // Re-fetch config with new private key
            showExistingPeerModal(currentModalTun, currentModalIp, currentExportName, currentModalPubkey, newPriv);
        } else {
            alert("Anahtar kaydedilemedi: " + ((data && data.error) ? data.error : "Bilinmeyen hata"));
        }
    })
    .catch(function(err) {
        console.error(err);
        alert("Sunucu ile iletişim hatası.");
    });
}

function saveModalAdUser() {
    var adSel = document.getElementById("modalAdUserSelect");
    if (!adSel || !currentModalPubkey) return;

    var newAdUser = adSel.value;
    var params = new URLSearchParams();
    params.append('ajax_save_peer_ad', '1');
    params.append('pubkey', currentModalPubkey);
    params.append('ad_username', newAdUser);

    var csrfToken = getCsrfToken();
    if (csrfToken) {
        params.append('__csrf_magic', csrfToken);
    }

    fetch('wg_quick_peer.php?' + params.toString())
        .then(function(res) { return res.json(); })
        .then(function(data) {
            if (data && data.success) {
                alert("Active Directory kullanıcı eşlemesi başarıyla kaydedildi!");
                location.reload();
            } else {
                alert("Hata: " + ((data && data.error) ? data.error : "Eşleme kaydedilemedi."));
            }
        })
        .catch(function(err) {
            console.error(err);
            alert("Sunucu ile iletişim hatası.");
        });
}

function onAdUserSelected(sel) {
    var val = sel.value;
    var adInput = document.getElementById('ad_username');
    if (adInput) adInput.value = val;

    if (val) {
        var opt = sel.options[sel.selectedIndex];
        var disp = opt.getAttribute('data-display') || val;
        var dept = opt.getAttribute('data-dept') || '';
        var isDisabled = opt.getAttribute('data-disabled') === '1';

        var nameText = disp;
        if (disp.toLowerCase() !== val.toLowerCase()) {
            nameText += ' (' + val + ')';
        }
        var descrInput = document.getElementById('peer_descr');
        if (descrInput) descrInput.value = nameText;

        if (isDisabled) {
            alert('DİKKAT: Seçilen kullanıcının (' + val + ') Active Directory hesabı PASİF / KAPALIDIR!');
        }

        var privInput = document.getElementById('client_privkey');
        if (privInput && !privInput.value) {
            generateKeypair();
        }
    }
}

function syncAdSessions(btn) {
    var origHtml = btn ? btn.innerHTML : '';
    if (btn) {
        btn.disabled = true;
        btn.innerHTML = '<i class="fa fa-spinner fa-spin"></i> Senkronize ediliyor...';
    }

    fetch('wg_quick_peer.php?ajax_sync_ad_sessions=1')
        .then(function(res) { return res.json(); })
        .then(function(data) {
            if (btn) {
                btn.disabled = false;
                btn.innerHTML = origHtml;
            }
            if (data && data.success) {
                alert('Senkronizasyon Başarılı!\n' + (data.synced_count || 0) + ' aktif WireGuard VPN oturumu Posea AD SSO ve PoseaFilter UTM sistemine aktarıldı.');
            } else {
                alert('Hata: ' + ((data && data.error) ? data.error : 'Senkronizasyon başarısız oldu.'));
            }
        })
        .catch(function(err) {
            if (btn) {
                btn.disabled = false;
                btn.innerHTML = origHtml;
            }
            console.error(err);
            alert('Sunucu ile iletişim kurulurken hata oluştu.');
        });
}

function onPrivateKeyInput(privVal) {
    privVal = privVal.trim();
    if (privVal.length >= 40) {
        fetch('wg_quick_peer.php?ajax_derive_pub=1&privkey=' + encodeURIComponent(privVal))
            .then(function(res) { return res.json(); })
            .then(function(data) {
                if (data.pubkey) {
                    document.getElementById('peer_pubkey').value = data.pubkey;
                }
            });
    }
}

function generateKeypair() {
    fetch('wg_quick_peer.php?ajax_gen_keys=1')
        .then(function(res) { return res.json(); })
        .then(function(data) {
            if (data.pubkey && data.privkey) {
                document.getElementById('client_privkey').value = data.privkey;
                document.getElementById('peer_pubkey').value = data.pubkey;
            }
        });
}

function refreshNextIp(tunName) {
    var icon = document.getElementById('ipRefreshIcon');
    if (icon) icon.className = "fa fa-spin fa-refresh";

    fetch('wg_quick_peer.php?ajax_next_ip=1&tun=' + encodeURIComponent(tunName))
        .then(function(res) { return res.json(); })
        .then(function(data) {
            if (icon) icon.className = "fa fa-refresh";
            if (data.suggested) {
                document.getElementById('peer_ip').value = data.suggested;
            }
        })
        .catch(function() {
            if (icon) icon.className = "fa fa-refresh";
        });
}

function showExistingPeerModal(tunName, clientIp, descr, pubkey, privkey) {
    fetch('wg_quick_peer.php?ajax_get_config=1&tun=' + encodeURIComponent(tunName) + '&ip=' + encodeURIComponent(clientIp) + '&descr=' + encodeURIComponent(descr) + '&pubkey=' + encodeURIComponent(pubkey || '') + '&privkey=' + encodeURIComponent(privkey || ''))
        .then(function(res) { return res.json(); })
        .then(function(data) {
            if (data.success && data.config) {
                openConfigModal(descr + " (" + clientIp + ")", data.config, descr, pubkey, data.client_privkey || privkey, tunName, clientIp, data.ad_username || '');
            }
        });
}

function togglePeer(peerIdx) {
    var form = document.createElement('form');
    form.method = 'POST';
    form.action = 'wg_quick_peer.php?tun=<?= urlencode($active_tunnel_name) ?>';
    form.innerHTML = '<input type="hidden" name="act" value="toggle_peer"><input type="hidden" name="peer_idx" value="' + peerIdx + '">';
    document.body.appendChild(form);
    form.submit();
}

function deletePeer(peerIdx, descr) {
    if (!confirm('"' + descr + '" adlı WireGuard peer\'ını silmek istediğinizden emin misiniz?')) {
        return;
    }
    var form = document.createElement('form');
    form.method = 'POST';
    form.action = 'wg_quick_peer.php?tun=<?= urlencode($active_tunnel_name) ?>';
    form.innerHTML = '<input type="hidden" name="act" value="delete_peer"><input type="hidden" name="peer_idx" value="' + peerIdx + '">';
    document.body.appendChild(form);
    form.submit();
}

function filterPeerTable() {
    var input = document.getElementById("peerSearch");
    var filter = input.value.toLowerCase();
    var rows = document.getElementsByClassName("peer-row");

    for (var i = 0; i < rows.length; i++) {
        var descr = rows[i].getAttribute("data-descr") || "";
        var ip = rows[i].getAttribute("data-ip") || "";
        if (descr.indexOf(filter) > -1 || ip.indexOf(filter) > -1) {
            rows[i].style.display = "";
        } else {
            rows[i].style.display = "none";
        }
    }
}

<?php if (!empty($new_config_modal)): ?>
$(document).ready(function() {
    openConfigModal(
        <?= json_encode($new_config_modal['descr'] . " (" . $new_config_modal['client_ip'] . ")") ?>,
        <?= json_encode($new_config_modal['config']) ?>,
        <?= json_encode($new_config_modal['descr']) ?>,
        <?= json_encode($new_config_modal['publickey'] ?? '') ?>,
        <?= json_encode($new_config_modal['client_privkey'] ?? '') ?>,
        <?= json_encode($new_config_modal['tun'] ?? 'tun_wg0') ?>,
        <?= json_encode($new_config_modal['client_ip'] ?? '') ?>
    );
});
<?php endif; ?>
</script>

<?php include("foot.inc"); ?>
