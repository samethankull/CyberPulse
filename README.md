# CyberPulse


## Genel Bakış
**CyberPulse**, bir hedef web sitesinin güvenlik durumunu, kullanılan teknolojileri ve olası güvenlik açıklarını analiz etmek için tasarlanmış Python tabanlı bir güvenlik tarama aracıdır. Web Uygulama Güvenlik Duvarları (WAF), teknoloji yığını, HTTP başlıkları, güvenlik başlıkları, alt alan adları (subdomain) ve SSL/TLS sertifika detayları gibi çeşitli özellikleri tarayarak kapsamlı bilgiler sağlar. Araç, asenkron programlama ile verimli tarama yapar ve sonuçları `rich` kütüphanesi ile görsel olarak çekici bir şekilde sunar. Ayrıca, sonuçlar JSON formatında bir dosyaya kaydedilir ve ileride kullanılmak üzere saklanabilir.

Bu araç, güvenlik araştırmacıları, sızma testi uzmanları ve sistem yöneticileri için web uygulamalarının güvenlik ve yapılandırma durumunu değerlendirmek amacıyla geliştirilmiştir.

## Özellikler
CyberPulse, aşağıdaki temel analizleri gerçekleştirir:
1. **WAF Tespiti**: Hedef web sitesinin bir Web Uygulama Güvenlik Duvarı (WAF) tarafından korunup korunmadığını birden fazla yöntemle (WAFW00F, HTTP başlıkları ve içerik analizi) tespit eder.
2. **Teknoloji Yığını Tespiti**: Web sitesinde kullanılan programlama dilleri, veritabanları, çerçeveler (frameworks) ve içerik yönetim sistemlerini (CMS) belirler.
3. **HTTP Başlık Analizi**: `Server` ve `X-Powered-By` gibi genel HTTP başlıklarını analiz ederek web sunucusu hakkında bilgi toplar.
4. **Güvenlik Başlık Analizi**: Web sitesinin güvenlik yapılandırmalarını değerlendirmek için güvenlik başlıklarını (ör. `Content-Security-Policy`, `Strict-Transport-Security`) inceler.
5. **Alt Alan Adı Tespiti**: DNS çözümlemesi ve sertifika şeffaflık günlükleri (crt.sh) aracılığıyla hedef alan adının alt alan adlarını keşfeder.
6. **SSL/TLS Sertifika Analizi**: HTTPS kullanan web siteleri için sertifika detaylarını (yayıncı, konu, geçerlilik tarihleri) alır ve görüntüler.
7. **JSON Çıktısı**: Tüm tarama sonuçlarını `web_scanner_output.json` dosyasına kaydeder.
8. **Rich Konsol Çıktısı**: Sonuçları, `rich` kütüphanesi ile tablolar ve paneller kullanarak düzenli ve görsel bir formatta konsolda gösterir.

## Nasıl Çalışır?
CyberPulse, Python'un `asyncio` ve `aiohttp` kütüphanelerini kullanarak HTTP isteklerini asenkron bir şekilde gerçekleştirir. Hedef web sitesi hakkında kapsamlı bilgi toplamak için birden fazla tarama tekniğini birleştirir. Ana iş akışı şu şekildedir:
1. Kullanıcı, hedef URL’yi girer (ör. `https://example.com`).
2. Araç, URL’yi doğrular ve protokol belirtilmemişse varsayılan olarak HTTPS kullanır.
3. Aşağıdaki taramaları gerçekleştirmek için asenkron görevler çalıştırır:
   - **WAF Tespiti**: WAFW00F (API ve komut satırı), HTTP başlıkları ve içerik analizi ile Cloudflare, AWS WAF veya Akamai gibi WAF’leri tespit eder.
   - **Teknoloji Tespiti**: `builtwith` kütüphanesi ve özel başlık/içerik analizi ile programlama dilleri (PHP, Python), veritabanları (MySQL, MongoDB), çerçeveler (Django, Laravel) ve CMS’ler (WordPress, Drupal) gibi teknolojileri belirler.
   - **HTTP Başlık Analizi**: `Server` ve `X-Powered-By` gibi başlıkları inceleyerek web sunucusu ve arka plan teknolojilerini tespit eder.
   - **Güvenlik Başlık Analizi**: `Content-Security-Policy`, `X-Frame-Options` gibi güvenlik başlıklarını kontrol eder.
   - **Alt Alan Adı Tespiti**: Yaygın alt alan adlarını (ör. `www`, `api`, `mail`) DNS ile sorgular ve crt.sh üzerinden ek alt alan adları toplar.
   - **SSL/TLS Sertifika Analizi**: HTTPS siteleri için Python’un `ssl` ve `cryptography` kütüphaneleriyle sertifika detaylarını alır.
4. Sonuçlar, `web_scanner.log` dosyasına kaydedilir ve `rich` kütüphanesi ile konsolda düzenli bir şekilde görüntülenir.
5. Tüm sonuçlar, `web_scanner_output.json` dosyasına JSON formatında kaydedilir.

## Gereksinimler
CyberPulse’u çalıştırmak için aşağıdaki Python kütüphaneleri ve harici araçlar gereklidir:
- **Python Kütüphaneleri**:
  - `aiohttp`: Asenkron HTTP istekleri için.
  - `builtwith`: Teknoloji yığını tespiti için.
  - `wafw00f`: WAF tespiti için.
  - `dnspython`: DNS tabanlı alt alan adı tespiti için.
  - `cryptography`: SSL/TLS sertifika analizi için.
  - `rich`: Biçimlendirilmiş konsol çıktısı için.
  - Bunları yüklemek için:
    ```bash
    pip install aiohttp builtwith wafw00f dnspython cryptography rich
    ```
- **Harici Araçlar**:
  - `wafw00f`: WAFW00F komut satırı aracı, sistem PATH’inde erişilebilir olmalıdır. Yüklemek için:
    ```bash
    pip install wafw00f
    ```
- **Sistem Gereksinimleri**:
  - Python 3.7 veya üstü.
  - HTTP istekleri, DNS sorguları ve crt.sh erişimi için internet bağlantısı.
  - SSL/TLS sertifika analizi için OpenSSL.

## Kurulum
1. Script’in bulunduğu depoyu klonlayın veya indirin.
2. Gerekli Python kütüphanelerini yükleyin:
   ```bash
   pip install -r requirements.txt
   ```
   Alternatif olarak, yukarıdaki kütüphaneleri tek tek yükleyin.
3. `wafw00f` komut satırı aracının yüklü ve sistem PATH’inde erişilebilir olduğundan emin olun.
4. Script’i `CyberPulse.py` olarak kaydedin.

## Kullanım
1. Script’i Python ile çalıştırın:
   ```bash
   python CyberPulse.py
   ```
2. İstenildiğinde hedef URL’yi girin (ör. `https://example.com` veya `example.com`).
3. Araç, taramaları gerçekleştirir ve sonuçları konsolda biçimlendirilmiş tablolar ve panellerle gösterir.
4. Sonuçlar, geçerli dizinde `web_scanner_output.json` dosyasına kaydedilir.
5. Hata ayıklama ve kayıt için loglar `web_scanner.log` dosyasına kaydedilir.

### Örnek
```bash
$ python CyberPulse.py
Hedef URL'yi girin (örneğin, https://example.com): https://example.com
```

Araç, aşağıdaki işlemleri yapar:
- Her görev (WAF tespiti, teknoloji tespiti vb.) için bir ilerleme çubuğu gösterir.
- WAF detayları, teknoloji yığını, başlıklar, güvenlik başlıkları, alt alan adları ve SSL/TLS sertifika bilgileri dahil ayrıntılı sonuçları konsolda gösterir.
- Sonuçları `web_scanner_output.json` dosyasına kaydeder.

## Çıktı Formatı
### Konsol Çıktısı
Konsol çıktısı, `rich` kütüphanesi ile biçimlendirilir ve sonuçlar, her bölüm (WAF, teknoloji, başlıklar vb.) için ayrı paneller ve tablolarla düzenli bir şekilde gösterilir.

### JSON Çıktısı
Sonuçlar, `web_scanner_output.json` dosyasına aşağıdaki yapıda kaydedilir:
```json
{
  "target_url": "https://example.com",
  "timestamp": "2025-06-07 17:01:23 UTC",
  "waf": "Cloudflare",
  "technology": {
    "programming_languages": ["PHP", "JavaScript"],
    "databases": ["MySQL"],
    "frameworks": ["Laravel"],
    "cms": ["WordPress"]
  },
  "headers": {
    "server": "Apache",
    "x_powered_by": "PHP/7.4.33"
  },
  "security_headers": {
    "Content-Security-Policy": "default-src 'self'",
    "X-Frame-Options": "DENY",
    "X-Content-Type-Options": "nosniff",
    "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
    "Referrer-Policy": "strict-origin",
    "Permissions-Policy": "geolocation=(), microphone=()"
  },
  "subdomains": ["www.example.com", "api.example.com"],
  "ssl_tls": {
    "issuer": "C=US,O=Let's Encrypt,CN=R3",
    "subject": "CN=example.com",
    "valid_from": "2025-01-01 00:00:00 UTC",
    "valid_until": "2025-12-31 23:59:59 UTC"
  }
}
```

## Loglama
Araç, tüm aktiviteleri zaman damgaları, log seviyeleri (INFO, WARNING, ERROR) ve ayrıntılı mesajlarla `web_scanner.log` dosyasına kaydeder. Bu, hata ayıklama ve tarama sürecini takip etmek için kullanışlıdır.

## Sınırlamalar
- **WAF Tespiti**: Özelleştirilmiş veya az bilinen WAF’leri tespit edemeyebilir. WAFW00F ve imza tabanlı tespit yöntemlerine dayanır.
- **Alt Alan Adı Tespiti**: Yaygın alt alan adları ve crt.sh sonuçlarıyla sınırlıdır; özel veya listelenmemiş alt alan adlarını kaçırabilir.
- **SSL/TLS Analizi**: Yalnızca HTTPS etkin sitelerde çalışır ve katı SSL yapılandırmalarına sahip sunucularda başarısız olabilir.
- **Ağ Bağımlılığı**: HTTP istekleri, DNS sorguları ve crt.sh erişimi için sabit bir internet bağlantısı gerektirir.
- **Hata İşleme**: Sağlam olsa da, bazı hatalar (ör. ağ zaman aşımı, DNS hataları) sonuçların tamlığını etkileyebilir.

## Güvenlik Hususları
- **Sorumlu Kullanım**: Bu aracı yalnızca tarama izniniz olan web sitelerinde kullanın. Yetkisiz tarama, yasaları veya hizmet şartlarını ihlal edebilir.
- **Hız Sınırlaması**: Araç, agresif hız sınırlaması uygulamaz; bu nedenle hedef sunucuları aşırı yüklememek için dikkatli kullanın.
- **Log ve Çıktı Dosyaları**: `web_scanner.log` ve `web_scanner_output.json` dosyalarının güvenli bir şekilde saklandığından emin olun, çünkü bunlar hedef web sitesi hakkında hassas bilgiler içerebilir.

## Gelecekteki İyileştirmeler
- Özel alt alan adı listeleri için destek ekleme.
- Daha gelişmiş WAF tespit teknikleri uygulama.
- Yaygın yapılandırma hataları için güvenlik açığı taraması ekleme.
- Tek bir çalışmada birden fazla URL tarama desteği.
- Kenar durumlar için hata işleme ve yeniden deneme mekanizmalarını geliştirme.

## Lisans
Bu proje MIT Lisansı altında lisanslanmıştır. Ayrıntılar için `LICENSE` dosyasına bakın.

## Katkıda Bulunma
Katkılar memnuniyetle karşılanır! İyileştirme önerileri veya hata bildirimleri için lütfen projenin deposunda bir pull request gönderin veya bir sorun (issue) açın.

## İletişim
Sorular veya geri bildirim için proje sorumlusuyla [samethankull@gmail.com] üzerinden iletişime geçin veya depoda bir sorun açın.
