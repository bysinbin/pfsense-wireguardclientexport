#!/bin/sh
# ==============================================================================
# WireGuard Hızlı Peer & İstemci İhracı (Quick Peer & Client Export) for pfSense
# ==============================================================================
set -e

echo "=== pfSense WireGuard Hızlı Peer Eklentisi Kurulumu ==="

if [ "$(id -u)" -ne 0 ]; then
    echo "[!] Hata: Bu betik root yetkisiyle çalıştırılmalıdır."
    exit 1
fi

SCRIPT_DIR="$(cd "$(dirname "$0")/.." 2>/dev/null && pwd)"

if [ ! -d "${SCRIPT_DIR}/pfsense-pkg" ]; then
    TMP_DIR="/tmp/wg_quick_install"
    rm -rf "${TMP_DIR}"
    mkdir -p "${TMP_DIR}"
    echo "[*] Kaynak dosyalar indiriliyor..."
    fetch -q -o "${TMP_DIR}/main.tar.gz" "https://github.com/bysinbin/pfsense-wireguardclientexport/archive/refs/heads/main.tar.gz"
    tar -xzf "${TMP_DIR}/main.tar.gz" -C "${TMP_DIR}"
    SCRIPT_DIR="${TMP_DIR}/pfsense-wireguardclientexport-main"
fi

echo "[*] Dosyalar kopyalanıyor..."
mkdir -p /usr/local/pkg /usr/local/www

cp "${SCRIPT_DIR}/pfsense-pkg/usr/local/pkg/wgclientexport.xml" /usr/local/pkg/wgclientexport.xml
cp "${SCRIPT_DIR}/pfsense-pkg/usr/local/pkg/wgclientexport.inc" /usr/local/pkg/wgclientexport.inc
cp "${SCRIPT_DIR}/pfsense-pkg/usr/local/www/wg_quick_peer.php" /usr/local/www/wg_quick_peer.php
cp "${SCRIPT_DIR}/pfsense-pkg/usr/local/www/wg_quick_peer_qr.js" /usr/local/www/wg_quick_peer_qr.js

chmod 644 /usr/local/pkg/wgclientexport.xml
chmod 644 /usr/local/pkg/wgclientexport.inc
chmod 644 /usr/local/www/wg_quick_peer.php
chmod 644 /usr/local/www/wg_quick_peer_qr.js

echo "[*] Sözdizimi (PHP Lint) kontrol ediliyor..."
php -l /usr/local/pkg/wgclientexport.inc
php -l /usr/local/www/wg_quick_peer.php

echo "[*] pfSense menüsüne ve paket sistemine kaydediliyor..."
php -r '
require_once("/etc/inc/config.inc");
global $config;

$pkg_found = false;
foreach ($config["installedpackages"]["package"] ?? [] as $p) {
    if (($p["name"] ?? "") === "wgclientexport") { $pkg_found = true; break; }
}
if (!$pkg_found) {
    $config["installedpackages"]["package"][] = [
        "name" => "wgclientexport",
        "descr" => "WireGuard Quick Peer & Client Export Manager for pfSense",
        "website" => "https://github.com/bysinbin/pfsense-wireguardclientexport",
        "version" => "1.0.0",
        "status" => "Stable",
        "configurationfile" => "wgclientexport.xml"
    ];
}

$menu_found = false;
foreach ($config["installedpackages"]["menu"] ?? [] as $m) {
    if (($m["name"] ?? "") === "WireGuard Hızlı Peer" || ($m["url"] ?? "") === "/wg_quick_peer.php") {
        $menu_found = true;
        break;
    }
}
if (!$menu_found) {
    $config["installedpackages"]["menu"][] = [
        "name" => "WireGuard Hızlı Peer",
        "section" => "VPN",
        "configfile" => "wgclientexport.xml",
        "url" => "/wg_quick_peer.php"
    ];
}

write_config("Installed WireGuard Quick Peer package");
'

echo "[+] Kurulum başarıyla tamamlandı!"
echo "[i] pfSense Web Arayüzü -> 'VPN' menüsü altında 'WireGuard Hızlı Peer' seçeneğine tıklayabilirsiniz."
echo "[i] Doğrudan bağlantı: https://<pfsense-ip>:<webgui-port>/wg_quick_peer.php"
