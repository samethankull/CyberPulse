# testphp.vulnweb.com için Web Sitesi Tarama Raporu

Bu rapor, `http://testphp.vulnweb.com/` web sitesine 17 Haziran 2025 tarihinde gerçekleştirilen güvenlik taramasının sonuçlarını detaylandırmaktadır. Tarama, sitenin teknoloji yığını, sunucu yapılandırması, güvenlik başlıkları, alt alan adları ve SSL/TLS durumu hakkında bilgiler sunmaktadır. Aşağıda her bölümün açıklaması ve güvenliği artırmak için öneriler yer almaktadır.

## Orijinal Tarama Sonuçları (JSON)

Aşağıda tarama aracının ürettiği ham JSON çıktısı yer almaktadır:

```json
{
    "target_url": "http://testphp.vulnweb.com/",
    "timestamp": "2025-06-17 16:18:24 UTC",
    "waf": "Bilinmiyor",
    "technology": {
        "programming_languages": [
            "Java",
            "PHP",
            "Go"
        ],
        "databases": [
            "Bilinmiyor"
        ],
        "frameworks": [
            "Bilinmiyor"
        ],
        "cms": [
            "Bilinmiyor"
        ]
    },
    "headers": {
        "server": "nginx/1.19.0",
        "x_powered_by": "PHP/5.6.40-38+ubuntu20.04.1+deb.sury.org+1"
    },
    "security_headers": {
        "Content-Security-Policy": "Yok",
        "X-Frame-Options": "Yok",
        "X-Content-Type-Options": "Yok",
        "Strict-Transport-Security": "Yok",
        "Referrer-Policy": "Yok",
        "Permissions-Policy": "Yok"
    },
    "subdomains": [
        "testphp.vulnweb.com"
    ],
    "ssl_tls": {
        "status": "HTTPS kullanılmıyor"
    }
}
```

## Tarama Sonuçlarının Açıklaması

### 1. Genel Bilgiler
- **Hedef URL**: `http://testphp.vulnweb.com/`
  - Site HTTP üzerinden erişilebilir, yani HTTPS kullanılmamaktadır.
- **Zaman Damgası**: `2025-06-17 16:18:24 UTC`
  - Tarama, 17 Haziran 2025 tarihinde saat 16:18 UTC'de gerçekleştirilmiştir.
- **WAF (Web Uygulama Güvenlik Duvarı)**: `Bilinmiyor`
  - Web uygulama güvenlik duvarı tespit edilmemiştir. WAF, SQL enjeksiyonu ve XSS gibi yaygın web saldırılarına karşı koruma sağlar. WAF'ın olmaması sitenin güvenlik açıklarına karşı savunmasızlığını artırabilir.

### 2. Teknoloji Yığını
- **Programlama Dilleri**:
  - Java, PHP, Go
  - Site, birden fazla programlama dili kullanıyor; PHP, `X-Powered-By` başlığı ile doğrulanmıştır. Java ve Go'nun varlığı karmaşık bir arka uç yapısını işaret ediyor, ancak kullanılan çerçeveler veya sürümler belirlenememiştir.
- **Veritabanları**: `Bilinmiyor`
  - Spesifik bir veritabanı teknolojisi tespit edilememiştir. Bu, veritabanının açıkta olmaması veya tarama aracının bunu tespit edememesi anlamına gelebilir.
- **Çerçeveler**: `Bilinmiyor`
  - Laravel, Spring gibi web çerçeveleri tespit edilmemiştir.
- **CMS (İçerik Yönetim Sistemi)**: `Bilinmiyor`
  - WordPress, Drupal gibi bir CMS tespit edilmemiştir; bu, sitenin özel olarak geliştirilmiş olabileceğini gösterir.

### 3. Sunucu Başlıkları
- **Server**: `nginx/1.19.0`
  - Web sunucusu olarak Nginx 1.19.0 sürümü kullanılmaktadır. Bu sürüm 2020 yılında yayınlanmış olup güncel değildir ve bilinen güvenlik açıkları içerebilir. Güncel bir sürüme yükseltme yapılması önerilir.
- **X-Powered-By**: `PHP/5.6.40-38+ubuntu20.04.1+deb.sury.org+1`
  - Site, PHP 5.6.40 sürümünü kullanıyor. Bu sürüm, Ocak 2019'dan beri desteklenmeyen (EOL) bir sürümdür ve güncellenmeyen güvenlik açıkları nedeniyle ciddi riskler taşır. Ayrıca, bu başlık PHP sürümünü ifşa ederek saldırganların bu bilgiyi kötüye kullanmasına olanak tanır.

### 4. Güvenlik Başlıkları
Tüm güvenlik başlıkları `Yok` olarak işaretlenmiştir, yani kritik HTTP güvenlik başlıkları mevcut değildir:
- **Content-Security-Policy (CSP)**: Yok
  - CSP olmadan site, kaynak yükleme kısıtlamaları olmadığı için XSS (çapraz site betik çalıştırma) saldırılarına karşı savunmasızdır.
- **X-Frame-Options**: Yok
  - Bu başlığın olmaması, sitenin iframe'lere gömülmesine izin verir ve clickjacking saldırılarına karşı savunmasız hale getirir.
- **X-Content-Type-Options**: Yok
  - `nosniff` olmadan, tarayıcılar içerik türlerini yanlış yorumlayabilir ve MIME tipi koklama güvenlik açıklarına yol açabilir.
- **Strict-Transport-Security (HSTS)**: Yok
  - HSTS, HTTPS bağlantılarını zorlar, ancak site HTTPS kullanmadığı için bu başlığın olmaması beklenen bir durumdur.
- **Referrer-Policy**: Yok
  - Bu başlık olmadan, kullanıcılar harici sitelere yönlendirildiğinde Referer başlığı aracılığıyla hassas bilgiler sızdırılabilir.
- **Permissions-Policy**: Yok
  - Bu başlık, tarayıcı özelliklerine (ör. kamera, konum) erişimi kısıtlar; yokluğu varsayılan izinlerin sınırsız olmasına neden olur.

### 5. Alt Alan Adları
- **Alt Alan Adları**: `testphp.vulnweb.com`
  - Yalnızca taranan alt alan adı tespit edilmiştir. Başka alt alan adları mevcut olabilir, ancak tarama bunları bulamamıştır.

### 6. SSL/TLS
- **Durum**: `HTTPS kullanılmıyor`
  - Site HTTP üzerinden çalışmaktadır, HTTPS kullanılmamaktadır. Bu, verilerin ortada bir adam (man-in-the-middle) saldırılarıyla ele geçirilmesine olanak tanır ve modern standartlara göre güvensizdir. Geçerli bir SSL/TLS sertifikası uygulanması kritik önemdedir.

## Güvenlik Önerileri
Tarama sonuçlarına dayanarak, web sitesinin güvenliğini artırmak için aşağıdaki adımlar önerilmektedir:
1. **HTTPS'yi Etkinleştirin**:
   - Geçerli bir SSL/TLS sertifikası edinin (ör. Let's Encrypt).
   - Tüm HTTP trafiğini HTTPS'ye yönlendirin.
   - HTTPS bağlantılarını zorlamak için HSTS başlığını uygulayın.
2. **Yazılımları Güncelleyin**:
   - Nginx'i en son kararlı sürüme yükseltin.
   - PHP'yi desteklenen bir sürüme (ör. PHP 8.2 veya üstü) güncelleyin.
   - `X-Powered-By` başlığını kaldırarak PHP sürüm bilgisinin ifşa edilmesini önleyin.
3. **Güvenlik Başlıkları Ekleyin**:
   - XSS risklerini azaltmak için kapsamlı bir CSP başlığı uygulayın.
   - Clickjacking saldırılarını önlemek için `X-Frame-Options: DENY` veya `SAMEORIGIN` ayarını ekleyin.
   - MIME tipi koklama açıklarını önlemek için `X-Content-Type-Options: nosniff` başlığını ayarlayın.
   - Referer bilgisi sızıntısını azaltmak için `Referrer-Policy` (ör. `strict-origin-when-cross-origin`) kullanın.
   - Hassas tarayıcı özelliklerine erişimi kısıtlamak için `Permissions-Policy` başlığını ekleyin.
4. **WAF Kullanımını Araştırın**:
   - Yaygın web saldırılarına karşı koruma sağlamak için bir WAF (ör. Cloudflare, ModSecurity) kullanmayı değerlendirin.
5. **Teknoloji Yığınını Gözden Geçirin**:
   - Tüm programlama dilleri ve bağımlılıkların güncel olduğundan emin olun.
   - Eğer bir veritabanı veya çerçeve kullanılıyorsa, SQL enjeksiyonu gibi yaygın güvenlik açıklarına karşı koruma sağlayın.
6. **Alt Alan Adı Tespiti**:
   - Ek alt alan adlarını tespit etmek ve güvenli hale getirmek için kapsamlı bir alt alan adı taraması gerçekleştirin.

## Sonuç
Tarama, HTTPS eksikliği, güncel olmayan yazılımlar, güvenlik başlıklarının bulunmaması ve WAF'ın tespit edilememesi gibi ciddi güvenlik açıklarını ortaya koymaktadır. Bu sorunlar, siteyi çeşitli saldırılara karşı oldukça savunmasız hale getirmektedir. HTTPS'nin uygulanması, yazılımların güncellenmesi ve güvenlik başlıklarının eklenmesi için acil önlem alınması önerilir.
