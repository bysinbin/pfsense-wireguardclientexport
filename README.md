# pfSense WireGuard Hızlı Peer Yönetimi & İstemci İhracı (Quick Peer & Client Export)

pfSense üzerinde karmaşık WireGuard menüleri arasında dolaşmadan, **tek bir sade ekrandan** hızlıca yeni WireGuard istemcileri (peer) oluşturmanızı, hazır `.conf` dosyası indirmenizi ve mobil cihazlar için anında **QR Kod** almanızı sağlayan pfSense eklentisi.

---

## 🚀 Öne Çıkan Özellikler

1. **Süper Hızlı Peer Ekleme:**
   - **Atanacak IP:** Tünel subnetindeki boş IP adreslerini otomatik tespit eder ve sıradaki IP'yi (örn: `10.0.0.14`) formda otomatik önerir.
   - **Peer Adı / Açıklama:** İstemci veya kullanıcı adı (örn: `Ahmet-Telefon`, `Ofis-Laptop`).
   - **Public Key (Açık Anahtar):** Kullanıcı doğrudan istemcisinde ürettiği Public Key'i yapıştırabilir.
   - **🔑 Otomatik Anahtar Çifti Üret (1-Tık):** Eğer istemcide henüz anahtar üretilmediyse, tek tıkla Private Key + Public Key üretilir. Public Key alana yerleşir, üretilen Private Key ise indirilecek config dosyasına ve QR koda otomatik eklenir!

2. **Hazır İstemci Konfigürasyonu (`.conf`) & İndirme:**
   - pfSense sunucusunun WAN dış IP'sini, dinleme portunu ve sunucu Public Key'ini otomatik alarak istemci için tam hazır konfigürasyon üretir.
   - **📋 Panoya Kopyala** ve **💾 .conf İndir** butonları.

3. **Mobil Cihazlar İçin Yerleşik QR Kod:**
   - Tamamen yerel (`wg_quick_peer_qr.js`) çalışan, dış internete veya CDN'lere bağımlı olmayan QR kod motoru.
   - WireGuard iOS ve Android uygulamalarından tek saniyede kamerayla taranıp kurulabilir.

4. **Tünel Kurulum Sihirbazı (Wizard):**
   - Sistemde hiç WireGuard tüneli yoksa `tun_wg0` tünelini örnek alarak 1-tıkla sunucuyu, IP bloklarını ve servisleri kurar.
   - Mevcut tünel varsa, istenildiğinde **"+ Ek Tünel Oluştur"** modalı ile `tun_wg1`, `tun_wg2` gibi yeni tüneller oluşturulabilir.

5. **Mevcut Peer'ları Canlı İzleme & Yönetim:**
   - Kayıtlı tüm peer'lar için son el sıkışma (handshake) süresi ve gelen/giden (Rx/Tx) veri transferi canlı gösterilir.
   - Her peer için tek tıkla **Config & QR Kod** açılabilir.
   - Peer'lar tek tıkla geçici olarak durdurulabilir (disable) veya silinebilir.

---

## 📂 Dosya Yapısı

```
pfsense-wireguardclientexport/
├── pfsense-pkg/
│   └── usr/
│       └── local/
│           ├── pkg/
│           │   ├── wgclientexport.xml       # pfSense paket ve menü tanımı
│           │   └── wgclientexport.inc       # Arka plan API ve WireGuard yönetim fonksiyonları
│           └── www/
│               ├── wg_quick_peer.php        # pfSense GUI sayfası (Yönetim, Hızlı Form, Tablo)
│               └── wg_quick_peer_qr.js      # Bağımsız yerel QR kod kütüphanesi
├── scripts/
│   ├── deploy.py                            # SSH/SFTP ile uzaktan pfSense'e yükleme scripti
│   └── install.sh                           # pfSense konsolunda doğrudan kurulum scripti
└── README.md
```

---

## 🛠️ Kurulum

### Yöntem 1: SSH ile Uzaktan Otomatik Dağıtım (Deploy Scripti)
`scripts/deploy.py` dosyasını çalıştırarak hedef pfSense sunucunuza tüm dosyaları aktarabilir ve paketi kaydedebilirsiniz:

```bash
python scripts/deploy.py
```

### Yöntem 2: pfSense Üzerinde Doğrudan Kurulum (Shell)
pfSense SSH / Konsoluna bağlanarak:

```sh
sh scripts/install.sh
```

---

## 🌐 pfSense Web Arayüzünden Erişim

Kurulum tamamlandıktan sonra pfSense WebGUI üzerinde:
- **Menü:** `VPN` -> `WireGuard Hızlı Peer`
- **Doğrudan Bağlantı:** `https://<pfsense-ip>:<webgui-port>/wg_quick_peer.php`

---

## 💡 Nasıl Kullanılır?

1. **VPN -> WireGuard Hızlı Peer** sayfasına gidin.
2. Peer Adı yazın (Örn: `Mustafa-PC`).
3. Atanacak IP adresini kontrol edin (Sistem sıradaki boş IP'yi otomatik doldurur).
4. İstemcinizin **Public Key**'ini kutuya yapıştırın (Veya **🔑 Otomatik Key Çifti Üret** butonuna basarak sistemin sizin için üretmesini sağlayın).
5. **🚀 Peer Ekle ve Hazır Config Al** butonuna tıklayın.
6. Açılan pencereden:
   - Mobil için: WireGuard uygulamasından QR kodu taratın.
   - Bilgisayar için: **.conf İndir** butonuna basıp istemciye aktarın.
