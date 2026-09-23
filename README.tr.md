# Mole

DPI ile yapılan site engellerini kendi bilgisayarında aşan, bağlantının hangi
yönteme ihtiyacı olduğunu da kendisi bulan bir Windows aracı.

[English](README.md)

![Mole penceresi](docs/img/gui-dark-tr.png)

GoodbyeDPI ve zapret gibi araçlar numaraları zaten biliyor. Sana bıraktıkları
iş, doğru olanı seçmek: bir klasör dolusu `.bat`, biri tutana kadar sırayla
denenir, operatör filtresini değiştirince de her şey baştan. Mole bu kısmı
yapar. Bağlantını test eder, geçen yöntemi bulur, arka planda servis olarak
çalıştırır, çalışmaz olursa da kendi kendine yeniden test eder.

VPN değildir. Trafiğin yine doğrudan siteye gider; Mole sadece her bağlantının
ilk paketini, filtre hangi siteyi istediğini okuyamayacak şekilde yeniden
biçimlendirir. Mole herhangi bir sebeple durursa internetin normal çalışmaya
devam eder.

## Kurulum

1. [Releases](../../releases) sayfasından son zip'i indir ve aç.
2. **`install.cmd`**'ye çift tıkla (ya da **`mole-gui.exe`**'yi açıp *Korumayı
   kur*'a bas). Mole bir ağ sürücüsü kullandığı için Windows yönetici izni
   ister.
3. Bu kadar. Mole bağlantını ölçer (birkaç saniye), kendini
   `C:\Program Files\Mole` altına kurar ve bundan sonra Windows ile birlikte
   başlar. Açtığın klasörü silebilirsin.

Kaldırmak için: **Ayarlar › Uygulamalar › Mole › Kaldır**, ya da
`uninstall.cmd`. Servisi durdurur, sürücüyü kapatır ve dosyalarını siler.

Arkadaşına gönderirken zip'in tamamını at — ya da sadece `mole.exe`,
`install.cmd` ve `uninstall.cmd` (pencere de istersen `mole-gui.exe`). Sürücü
`mole.exe`'nin içinde.

## Nasıl çalışır

1. **Ölçer.** Mole engelli siteyi şifreli DNS (DoH) ile çözer, sonra ona gerçek
   bir TLS bağlantısı açar: önce hiçbir yardım olmadan, engeli doğrulamak için,
   sonra her yöntemle bir kez. Bir yöntem ancak el sıkışma baştan sona
   tamamlanırsa sayılır — sunucunun yanıt verip bağlantının ardından kopması
   başarı değil, başarısızlıktır. Çalışan ilk yöntem seçilir; denemeler paralel
   yapıldığı için tüm ölçüm 1–2 saniye sürer.
2. **Uygular.** Bir Windows servisi bu yöntemi makinedeki her giden TLS el
   sıkışmasına uygular — tarayıcı, oyun, uygulama fark etmez. Geri kalan her şey
   olduğu gibi geçer.
3. **İzler.** Servis birkaç dakikada bir, ölçümün yapıldığı siteyi kontrol eder.
   Site yeniden engellenmişse operatör bir şey değiştirmiştir: servis yeniden
   ölçer ve o an çalışan yönteme geçer.
4. **Açıklar.** Hiçbir şey geçmezse Mole sebebini söyler: site adı görüldüğü
   anda gelen bir sıfırlama (DPI engeli), yanıtsız kalan bir istek, engellenmiş
   bir IP adresi (bunu hiçbir yerel araç aşamaz) ya da başarısız bir DNS
   sorgusu.

Yöntemler bilinen yöntemler; küçük ve test edilmiş paket dönüşümleri olarak
yazıldı: ClientHello'yu site adının ortasından bölmek (iki ya da daha fazla
parçaya, sıralı ya da ters sırada), ve gerçeğinden hemen önce zararsız bir site
için sahte ClientHello göndermek — filtreye ulaşıp sunucuya ulaşmayacak kadar
düşük TTL ile, yanlış sıra numarasıyla ya da bozuk checksum ile — tek başına ya
da bölme ile birlikte. IPv4 ve IPv6'nın ikisi de destekleniyor.

Ölçümlerin gerçek bir hatta ne gösterdiği [docs/findings.md](docs/findings.md)
dosyasında.

## Komut satırı

Pencerenin yaptığı her şeyi, fazlasıyla, `mole.exe` yapar. Çoğu komut yönetici
olarak açılmış bir komut istemi ister.

| Komut | Ne yapar |
|---|---|
| `mole install --auto` | Ölç, yöntemi seç, servisi kur ve başlat |
| `mole uninstall` | Her şeyi durdur ve kaldır |
| `mole status` | Servisin durumu, kullanılan yöntem, son servis kayıtları |
| `mole test <site>` | Bu site şu an engelli mi? (yönetici gerekmez) |
| `mole probe [site …]` | Hangi yöntemlerin çalıştığını, diğerlerinin neden çalışmadığını ölç |
| `mole apply --auto` | Servis kurmadan ölç ve Ctrl+C'ye kadar uygula |
| `mole doctor` | Yönetici hakkını, sürücüyü ve paket yakalamayı kontrol et |
| `mole report` | Her şeyi ölç, anonim bir JSON raporu yaz |
| `mole dns <site>` | Bir adı DoH ile çöz |

## Çalışmıyorsa

- **Antivirüs.** Ağ kalkanları (Avast, AVG, Kaspersky, ESET…) WinDivert
  sürücüsünü engelleyebilir. Mole yaygın olanları tanır ve söyler; WinDivert
  için bir istisna ekle ya da kalkanı durdurup kurulumu tekrar çalıştır.
- **Başka bir DPI aracı.** GoodbyeDPI, zapret ve Mole aynı paketleri değiştirir
  ve birbirini bozar. Birini tut.
- **Adresten engel.** Sitenin IP adresi doğrudan engellenmişse bilgisayarındaki
  hiçbir şey bunu aşamaz. Durum buysa Mole bunu söyler.
- **QUIC.** Tarayıcılar bazı sitelere QUIC (UDP) üzerinden de bağlanır; Mole
  bunu biçimlendirmez. `mole install --auto --block-quic` QUIC'i engeller,
  tarayıcı Mole'un çalıştığı TCP'ye döner.

## Derleme

Windows'ta Rust (MSVC araç zinciri) ile:

```
cargo build --release
```

Çıktı: `target/release/mole.exe` ve `mole-gui.exe`. İmzalı WinDivert 2.x
sürücüsü ve DLL'i `vendor/windivert` altında; `mole.exe`'nin içine gömülür.

| Crate | |
|---|---|
| `mole-core` | WinDivert sarmalayıcı, paket ayrıştırma, yöntemler, canlı filtre motoru, Windows servisi |
| `mole-dns` | DNS-over-HTTPS istemcisi |
| `mole-probe` | Ölçüm ve site kontrolü |
| `mole-cli` | `mole` komutu ve servisin gövdesi |
| `mole-gui` | Pencere ve tepsi ikonu |

## Lisans

Mole MIT lisanslıdır. [WinDivert](https://reqrypt.org/windivert.html)'i
değiştirmeden, LGPL v3 altında içerir (bkz. `vendor/windivert/LICENSE`).

Mole kim olduğunu ya da internette ne yaptığını gizlemez. Bulunduğun yerde
kullanımının serbest olup olmadığını kontrol etmek sana kalmış.
