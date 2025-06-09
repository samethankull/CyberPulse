import asyncio
import aiohttp
import builtwith
from wafw00f.main import WAFW00F
import subprocess
from urllib.parse import urlparse
import dns.resolver
import dns.asyncresolver
import re
import json
from cryptography import x509
from cryptography.hazmat.backends import default_backend
import ssl
import logging
from datetime import datetime
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.progress import Progress, BarColumn, TextColumn, TimeElapsedColumn

# Loglama yapılandırması
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(name)s - %(message)s',
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler('web_scanner.log')
    ]
)
logger = logging.getLogger(__name__)

# Rich konsol nesnesi
console = Console()

# Yaygın subdomain'ler için liste
COMMON_SUBDOMAINS = [
    'www', 'api', 'mail', 'ftp', 'test', 'dev', 'staging', 'blog', 'shop', 'admin',
    'login', 'secure', 'app', 'portal', 'dashboard', 'cdn', 'auth', 'web', 'demo', 'beta',
    'forum', 'news', 'support', 'docs', 'staging1', 'staging2', 'api2', 'cpanel', 'webmail'
]

async def detect_waf(url, session):
    try:
        logger.info(f"WAF tespiti başlatılıyor: {url}")

        # 1. WAFW00F API ile tespit
        try:
            waf_detector = WAFW00F(url)
            results = waf_detector.identwaf()
            if results:
                waf = ", ".join(results)
                logger.info(f"WAF tespit edildi (API): {waf}")
                return waf
            else:
                logger.info("WAFW00F API ile WAF tespit edilmedi.")
        except Exception as e:
            logger.warning(f"WAFW00F API hatası: {str(e)}")

        # 2. WAFW00F komut satırı ile tespit
        try:
            logger.info("WAFW00F komut satırı deneniyor.")
            result = subprocess.run(['wafw00f', url], capture_output=True, text=True, timeout=30)
            output = result.stdout
            if "is behind" in output:
                waf = re.search(r'is behind\s+([^\n]+)', output)
                if waf:
                    waf_name = waf.group(1).strip()
                    logger.info(f"WAF tespit edildi (komut satırı): {waf_name}")
                    return waf_name
            logger.info("WAFW00F komut satırı ile WAF tespit edilmedi.")
        except (subprocess.SubprocessError, FileNotFoundError) as e:
            logger.warning(f"WAFW00F komut satırı hatası: {str(e)}")

        # 3. HTTP başlıkları ve içerik analizi ile WAF tespiti
        try:
            logger.info("HTTP başlıkları ve içerik ile WAF tespiti başlatılıyor.")
            async with session.get(url, timeout=8, allow_redirects=True) as response:
                headers = response.headers
                html_content = (await response.text()).lower()

                # Yaygın WAF izleri
                waf_signatures = {
                    'cloudflare': ['cf-ray', 'cloudflare', '__cfduid'],
                    'aws waf': ['x-amzn-waf', 'aws-waf'],
                    'akamai': ['akamai', 'x-akamai'],
                    'f5 big-ip': ['bigip', 'f5'],
                    'incapsula': ['incap_ses', 'visid_incap'],
                    'sucuri': ['sucuri', 'x-sucuri'],
                    'fortiweb': ['fortiweb'],
                    'imperva': ['x-imperva'],
                    'barracuda': ['barracuda'],
                    'cloudfront': ['x-amz-cf'],
                }

                detected_waf = []
                for waf_name, signatures in waf_signatures.items():
                    for signature in signatures:
                        if signature in headers or signature in html_content:
                            detected_waf.append(waf_name.title())
                            break

                if detected_waf:
                    waf = ", ".join(detected_waf)
                    logger.info(f"WAF tespit edildi (başlık/içerik): {waf}")
                    return waf
                else:
                    logger.info("HTTP başlıkları ve içerik ile WAF tespit edilmedi.")
        except Exception as e:
            logger.warning(f"HTTP başlık/içerik WAF tespiti hatası: {str(e)}")

        logger.info("Hiçbir WAF tespit edilmedi.")
        return "Bilinmiyor"
    except Exception as e:
        logger.error(f"WAF Tespit Hatası: {str(e)}")
        return f"Hata: {str(e)}"

async def detect_tech(url, session):
    try:
        logger.info(f"Teknoloji tespiti başlatılıyor: {url}")
        tech_info = builtwith.builtwith(url)
        programming_languages = tech_info.get('programming-languages', [])
        databases = tech_info.get('databases', [])
        frameworks = tech_info.get('frameworks', [])
        cms = tech_info.get('cms', [])

        async with session.get(url, timeout=8, allow_redirects=True) as response:
            headers = response.headers
            html_content = (await response.text()).lower()

        extra_lang = []
        if 'x-powered-by' in headers:
            powered_by = headers['x-powered-by'].lower()
            if 'php' in powered_by:
                extra_lang.append('PHP')
            if 'asp' in powered_by:
                extra_lang.append('ASP.NET')
        if 'x-aspnet-version' in headers or 'asp.net' in html_content:
            extra_lang.append('ASP.NET')
        if 'django' in html_content or 'python' in headers.get('server', '').lower():
            extra_lang.append('Python')
        if 'rails' in html_content or 'ruby' in headers.get('server', '').lower():
            extra_lang.append('Ruby')
        if 'node' in html_content or 'express' in headers.get('server', '').lower():
            extra_lang.append('Node.js')
        if 'java' in html_content or 'jsp' in html_content or 'servlet' in html_content:
            extra_lang.append('Java')
        if 'go' in html_content or 'golang' in headers.get('server', '').lower():
            extra_lang.append('Go')

        extra_db = []
        if 'mysql' in html_content or 'mysqli' in html_content:
            extra_db.append('MySQL')
        if 'postgresql' in html_content or 'psql' in html_content:
            extra_db.append('PostgreSQL')
        if 'mongodb' in html_content:
            extra_db.append('MongoDB')
        if 'redis' in html_content:
            extra_db.append('Redis')
        if 'sqlite' in html_content:
            extra_db.append('SQLite')

        extra_frameworks = []
        extra_cms = []
        if 'wp-content' in html_content or 'wordpress' in html_content:
            extra_cms.append('WordPress')
        if 'joomla' in html_content:
            extra_cms.append('Joomla')
        if 'drupal' in html_content:
            extra_cms.append('Drupal')
        if 'magento' in html_content:
            extra_cms.append('Magento')
        if 'laravel' in html_content:
            extra_frameworks.append('Laravel')
        if 'django' in html_content:
            extra_frameworks.append('Django')
        if 'rails' in html_content:
            extra_frameworks.append('Ruby on Rails')
        if 'spring' in html_content or 'springframework' in html_content:
            extra_frameworks.append('Spring')
        if 'express' in html_content:
            extra_frameworks.append('Express')

        programming_languages = list(set(programming_languages + extra_lang))
        databases = list(set(databases + extra_db))
        frameworks = list(set(frameworks + extra_frameworks))
        cms = list(set(cms + extra_cms))

        result = {
            'programming_languages': programming_languages if programming_languages else ["Bilinmiyor"],
            'databases': databases if databases else ["Bilinmiyor"],
            'frameworks': frameworks if frameworks else ["Bilinmiyor"],
            'cms': cms if cms else ["Bilinmiyor"]
        }
        logger.info(f"Teknoloji tespiti sonuçları: {result}")
        return result
    except Exception as e:
        logger.error(f"Teknoloji Tespit Hatası: {str(e)}")
        return {
            'programming_languages': ["Hata"],
            'databases': [f"Hata: {str(e)}"],
            'frameworks': ["Hata"],
            'cms': ["Hata"]
        }

async def analyze_headers(url, session):
    try:
        logger.info(f"Başlık analizi başlatılıyor: {url}")
        async with session.get(url, timeout=8, allow_redirects=True) as response:
            headers = response.headers
            server = headers.get('Server', 'Bilinmiyor')
            powered_by = headers.get('X-Powered-By', 'Bilinmiyor')
            logger.info(f"Sunucu: {server}, X-Powered-By: {powered_by}")
            return {
                'server': server,
                'x_powered_by': powered_by
            }
    except Exception as e:
        logger.error(f"Başlık Analizi Hatası: {str(e)}")
        return {'server': 'Hata', 'x_powered_by': f"Hata: {str(e)}"}

async def analyze_security_headers(url, session):
    try:
        logger.info(f"Güvenlik başlıkları analizi başlatılıyor: {url}")
        async with session.get(url, timeout=8, allow_redirects=True) as response:
            headers = response.headers
            security_headers = {
                "Content-Security-Policy": headers.get("Content-Security-Policy", "Yok"),
                "X-Frame-Options": headers.get("X-Frame-Options", "Yok"),
                "X-Content-Type-Options": headers.get("X-Content-Type-Options", "Yok"),
                "Strict-Transport-Security": headers.get("Strict-Transport-Security", "Yok"),
                "Referrer-Policy": headers.get("Referrer-Policy", "Yok"),
                "Permissions-Policy": headers.get("Permissions-Policy", "Yok")
            }
            logger.info(f"Güvenlik başlıkları: {security_headers}")
            return security_headers
    except Exception as e:
        logger.error(f"Güvenlik Başlıkları Analizi Hatası: {str(e)}")
        return {"error": f"Hata: {str(e)}"}

async def enumerate_subdomains(url):
    parsed_url = urlparse(url)
    domain = parsed_url.netloc
    subdomains = set()

    async def check_subdomain(subdomain):
        try:
            full_domain = f"{subdomain}.{domain}"
            resolver = dns.asyncresolver.Resolver()
            resolver.timeout = 8
            resolver.lifetime = 8
            answers = await resolver.resolve(full_domain, 'A')
            for _ in answers:
                subdomains.add(full_domain)
                logger.info(f"Subdomain bulundu (DNS): {full_domain}")
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.Timeout):
            pass
        except Exception as e:
            logger.warning(f"Subdomain tarama hatası (DNS, {subdomain}): {str(e)}")

    try:
        logger.info(f"DNS tabanlı subdomain tespiti başlatılıyor: {domain}")
        tasks = [check_subdomain(subdomain) for subdomain in COMMON_SUBDOMAINS]
        await asyncio.gather(*tasks)
    except Exception as e:
        logger.error(f"DNS Subdomain tespiti hatası: {str(e)}")

    try:
        logger.info(f"crt.sh tabanlı subdomain tespiti başlatılıyor: {domain}")
        async with aiohttp.ClientSession() as session:
            async with session.get(f"https://crt.sh/?q=.{domain}", timeout=20) as response:
                crt_subdomains = re.findall(r'(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9][a-z0-9-]{0,61}[a-z0-9]', await response.text())
                tld = '.' + domain.partition('.')[2]
                crt_subdomains = [sd for sd in crt_subdomains if tld in sd]
                subdomains.update(crt_subdomains)
                logger.info(f"Subdomain'ler bulundu (crt.sh): {crt_subdomains}")
    except Exception as e:
        logger.error(f"crt.sh Subdomain tespiti hatası: {str(e)}")

    subdomains = sorted(list(subdomains))
    return subdomains if subdomains else ["Hiçbir subdomain bulunamadı"]

def get_certificate_details(url):
    parsed_url = urlparse(url)
    if parsed_url.scheme != 'https':
        logger.warning(f"HTTPS kullanılmıyor: {url}")
        return {"status": "HTTPS kullanılmıyor"}
    host = parsed_url.hostname
    port = parsed_url.port or 443
    try:
        logger.info(f"SSL/TLS sertifika analizi başlatılıyor: {host}:{port}")
        context = ssl.create_default_context()
        context.check_hostname = True
        context.verify_mode = ssl.CERT_REQUIRED
        with ssl.create_connection((host, port), timeout=10) as sock:
            with context.wrap_socket(sock, server_hostname=host) as ssock:
                cert_pem = ssock.getpeercert(True)
                cert = x509.load_der_x509_certificate(cert_pem, default_backend())
                issuer = cert.issuer.rfc4514_string()
                subject = cert.subject.rfc4514_string()
                not_valid_before = cert.not_valid_before.strftime('%Y-%m-%d %H:%M:%S UTC')
                not_valid_after = cert.not_valid_after.strftime('%Y-%m-%d %H:%M:%S UTC')
                logger.info(f"Sertifika detayları: issuer={issuer}, subject={subject}")
                return {
                    "issuer": issuer,
                    "subject": subject,
                    "valid_from": not_valid_before,
                    "valid_until": not_valid_after
                }
    except ssl.SSLError as e:
        logger.error(f"SSL Hatası: {str(e)}")
        return {"status": f"SSL Hatası: {str(e)}"}
    except Exception as e:
        logger.error(f"SSL Tespit Hatası: {str(e)}")
        return {"status": f"Hata: {str(e)}"}

def save_to_json(url, results):
    output = {
        "target_url": url,
        "timestamp": datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC'),
        "waf": results["waf"],
        "technology": results["technology"],
        "headers": results["headers"],
        "security_headers": results["security_headers"],
        "subdomains": results["subdomains"],
        "ssl_tls": results["ssl_tls"]
    }
    try:
        with open('web_scanner_output.json', 'w', encoding='utf-8') as f:
            json.dump(output, f, indent=4, ensure_ascii=False)
        logger.info("Sonuçlar web_scanner_output.json dosyasına kaydedildi.")
    except Exception as e:
        logger.error(f"JSON kaydetme hatası: {str(e)}")
        output["error"] = f"JSON kaydetme hatası: {str(e)}"
    return output

def print_results(url, results):
    console.print(Panel(f"[bold cyan]Web Tarayıcı Sonuçları - {url}[/bold cyan]", style="bold green", expand=False))

    console.print(Panel("[bold blue][1] WAF Tespiti[/bold blue]\n[yellow]WAF:[/yellow] " + results['waf'], style="blue", expand=False))

    console.print(Panel("[bold blue][2] Teknoloji Tespiti[/bold blue]", style="blue", expand=False))
    tech_table = Table(show_header=True, header_style="bold magenta")
    tech_table.add_column("Kategori", style="cyan")
    tech_table.add_column("Değer", style="green")
    tech_table.add_row("Programlama Dilleri", ", ".join(results['technology']['programming_languages']))
    tech_table.add_row("Veritabanları", ", ".join(results['technology']['databases']))
    tech_table.add_row("Framework'ler", ", ".join(results['technology']['frameworks']))
    tech_table.add_row("CMS", ", ".join(results['technology']['cms']))
    console.print(tech_table)

    console.print(Panel("[bold blue][3] Başlık Analizi[/bold blue]", style="blue", expand=False))
    headers_table = Table(show_header=True, header_style="bold magenta")
    headers_table.add_column("Başlık", style="cyan")
    headers_table.add_column("Değer", style="green")
    headers_table.add_row("Sunucu", results['headers']['server'])
    headers_table.add_row("X-Powered-By", results['headers']['x_powered_by'])
    console.print(headers_table)

    console.print(Panel("[bold blue][4] Güvenlik Başlıkları Analizi[/bold blue]", style="blue", expand=False))
    if "error" in results['security_headers']:
        console.print(f"[red]Hata: {results['security_headers']['error']}[/red]")
    else:
        sec_table = Table(show_header=True, header_style="bold magenta")
        sec_table.add_column("Başlık", style="cyan")
        sec_table.add_column("Değer", style="green")
        for header, value in results['security_headers'].items():
            sec_table.add_row(header, value)
        console.print(sec_table)

    console.print(Panel("[bold blue][5] Subdomain Tespiti[/bold blue]", style="blue", expand=False))
    if results['subdomains'] == ["Hiçbir subdomain bulunamadı"]:
        console.print(f"[red]{results['subdomains'][0]}[/red]")
    else:
        sub_table = Table(show_header=True, header_style="bold magenta")
        sub_table.add_column("No", style="cyan")
        sub_table.add_column("Subdomain", style="green")
        for i, sd in enumerate(results['subdomains'], 1):
            sub_table.add_row(str(i), sd)
        console.print(sub_table)

    console.print(Panel("[bold blue][6] SSL/TLS Sertifika Detayları[/bold blue]", style="blue", expand=False))
    if "status" in results['ssl_tls']:
        console.print(f"[red]Durum: {results['ssl_tls']['status']}[/red]")
    else:
        ssl_table = Table(show_header=True, header_style="bold magenta")
        ssl_table.add_column("Özellik", style="cyan")
        ssl_table.add_column("Değer", style="green")
        ssl_table.add_row("Yayıncı", results['ssl_tls']['issuer'])
        ssl_table.add_row("Konu", results['ssl_tls']['subject'])
        ssl_table.add_row("Geçerlilik Başlangıcı", results['ssl_tls']['valid_from'])
        ssl_table.add_row("Geçerlilik Bitişi", results['ssl_tls']['valid_until'])
        console.print(ssl_table)

    console.print(Panel("[bold blue][7] JSON Çıktısı[/bold blue]\n[green]Sonuçlar 'web_scanner_output.json' dosyasına kaydedildi.[/green]" +
                        (f"\n[red]JSON Kaydetme Hatası: {results['json_output']['error']}[/red]" if "error" in results.get('json_output', {}) else ""),
                        style="blue", expand=False))

async def main():
    url = input("Hedef URL'yi girin (örneğin, https://example.com): ").strip()
    if not url.startswith(('http://', 'https://')):
        url = 'https://' + url
        logger.info(f"URL'ye HTTPS protokolü eklendi: {url}")
    else:
        logger.info(f"Hedef URL: {url}")

    tasks = [
        ("WAF Tespiti", detect_waf(url, None)),
        ("Teknoloji Tespiti", None),
        ("Başlık Analizi", None),
        ("Güvenlik Başlıkları Analizi", None),
        ("Subdomain Tespiti", enumerate_subdomains(url)),
        ("SSL/TLS Sertifika Analizi", get_certificate_details(url)),
    ]

    results = {
        "waf": None,
        "technology": None,
        "headers": None,
        "security_headers": None,
        "subdomains": None,
        "ssl_tls": None
    }

    async with aiohttp.ClientSession() as session:
        with Progress(
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TimeElapsedColumn(),
            console=console
        ) as progress:
            for task_name, task_func in tasks:
                task = progress.add_task(f"[cyan]{task_name}[/cyan]", total=100)
                if task_name == "Teknoloji Tespiti":
                    results["technology"] = await detect_tech(url, session)
                elif task_name == "Başlık Analizi":
                    results["headers"] = await analyze_headers(url, session)
                elif task_name == "Güvenlik Başlıkları Analizi":
                    results["security_headers"] = await analyze_security_headers(url, session)
                elif task_name == "WAF Tespiti":
                    results["waf"] = await task_func
                elif task_name == "Subdomain Tespiti":
                    results["subdomains"] = await task_func
                elif task_name == "SSL/TLS Sertifika Analizi":
                    results["ssl_tls"] = task_func
                progress.update(task, advance=100)

    json_output = save_to_json(url, results)
    results["json_output"] = json_output

    print_results(url, results)

if __name__ == "__main__":
    asyncio.run(main())