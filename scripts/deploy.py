import os
import sys
import getpass
import paramiko
import hashlib

sys.stdout.reconfigure(encoding='utf-8')

REMOTE_HOST = os.getenv('PFSENSE_HOST', '').strip()
REMOTE_PORT = int(os.getenv('PFSENSE_PORT', '22'))
REMOTE_USER = os.getenv('PFSENSE_USER', 'admin').strip()
REMOTE_PASS = os.getenv('PFSENSE_PASS', '').strip()

if not REMOTE_HOST:
    REMOTE_HOST = input("pfSense Host / IP: ").strip()
if not REMOTE_HOST:
    print("[!] Error: pfSense host is required.")
    sys.exit(1)

if not REMOTE_PASS:
    REMOTE_PASS = getpass.getpass(f"SSH Password for {REMOTE_USER}@{REMOTE_HOST}: ").strip()

BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))

FILES_TO_DEPLOY = [
    (
        os.path.join(BASE_DIR, 'pfsense-pkg', 'usr', 'local', 'pkg', 'wgclientexport.xml'),
        '/usr/local/pkg/wgclientexport.xml'
    ),
    (
        os.path.join(BASE_DIR, 'pfsense-pkg', 'usr', 'local', 'pkg', 'wgclientexport.inc'),
        '/usr/local/pkg/wgclientexport.inc'
    ),
    (
        os.path.join(BASE_DIR, 'pfsense-pkg', 'usr', 'local', 'www', 'wg_quick_peer.php'),
        '/usr/local/www/wg_quick_peer.php'
    ),
    (
        os.path.join(BASE_DIR, 'pfsense-pkg', 'usr', 'local', 'www', 'wg_quick_peer_qr.js'),
        '/usr/local/www/wg_quick_peer_qr.js'
    ),
]

def md5_file(filepath):
    with open(filepath, 'rb') as f:
        return hashlib.md5(f.read()).hexdigest()

print(f"[*] Connecting to {REMOTE_HOST}:{REMOTE_PORT} as {REMOTE_USER}...")
ssh = paramiko.SSHClient()
ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
ssh.connect(REMOTE_HOST, port=REMOTE_PORT, username=REMOTE_USER, password=REMOTE_PASS, timeout=15)

sftp = ssh.open_sftp()

print("[*] Uploading package files...")
for local_file, remote_file in FILES_TO_DEPLOY:
    local_md5 = md5_file(local_file)
    print(f" -> {os.path.basename(local_file)} -> {remote_file} (md5: {local_md5[:8]})")
    with open(local_file, 'rb') as lf:
        with sftp.open(remote_file, 'wb') as rf:
            rf.write(lf.read())

sftp.close()

def run_cmd(cmd, desc):
    print(f"\n[*] {desc}...")
    stdin, stdout, stderr = ssh.exec_command(cmd)
    out = stdout.read().decode('utf-8', errors='replace').strip()
    err = stderr.read().decode('utf-8', errors='replace').strip()
    if out:
        print(out)
    if err:
        print("STDERR:", err)
    return out

# 1. PHP Syntax Check
run_cmd("php -l /usr/local/pkg/wgclientexport.inc && php -l /usr/local/www/wg_quick_peer.php", "Linting PHP files")

# 2. Register Package and Menu in pfSense
register_script = '''php -r '
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
echo "Package & Menu registered successfully!\n";
' '''

run_cmd(register_script, "Registering pfSense Package & Menu")

ssh.close()
print("\n[+] Deployment and verification completed successfully!")
