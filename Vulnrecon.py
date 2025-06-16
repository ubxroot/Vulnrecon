#!/usr/bin/env python3

import requests
import socket
import re
import threading
from urllib.parse import urlparse, quote_plus
from queue import Queue
import json
import sys
from typing import Optional

import pyfiglet
import typer
from rich.console import Console
from rich.table import Table
from rich.text import Text
from rich.markup import escape

# --- Initialize Typer and Rich Console ---
app = typer.Typer(help="Vulnrecon - Comprehensive Web Vulnerability & Reconnaissance Tool")
console = Console()

# --- ASCII Banners ---
# Vulnrecon Main Banner (Larger)
VULNRECON_BANNER_PART = pyfiglet.figlet_format("Vulnrecon", font="smslant")

# UBXROOT GitHub Repo Banner (Smaller)
UBXROOT_BANNER_PART = pyfiglet.figlet_format("UBXROOT", font="mini")

# Combined Banner
# Using rich.Text objects for robust multi-line banner with colors
MAIN_BANNER = Text()
MAIN_BANNER.append(VULNRECON_BANNER_PART, style="red")
MAIN_BANNER.append("\n") # Add a newline between the two figlet banners
MAIN_BANNER.append(UBXROOT_BANNER_PART, style="yellow")
MAIN_BANNER.append("\n")
MAIN_BANNER.append("Comprehensive Web Vulnerability & Reconnaissance Tool\n", style="bright_blue")
MAIN_BANNER.append("github.com/ubxroot | Scripted in Python3\n", style="bright_black")

# --- Global Data Structures ---
all_findings = []
http_check_queue = Queue()
findings_lock = threading.Lock() # Lock for thread-safe access to all_findings

# --- Configuration for Common Scans ---
COMMON_PORTS = [21, 22, 23, 25, 53, 80, 110, 139, 143, 443, 445, 3306, 8080, 8443]
COMMON_PATHS = [
    '/admin/', '/login.php', '/wp-admin/', '/config.php', '/.env',
    '/phpinfo.php', '/test.php', '/backup.zip', '/sitemap.xml', '/robots.txt',
    '/.git/config', '/.svn/entries', '/etc/passwd', '/proc/self/cmdline' # Add common Linux path traversal attempts
]

# --- Vulnerability Check Definitions (Extensible "Templates") ---
# Each dictionary defines a check. The 'check_function' field will be dynamically
# resolved to the actual Python function that performs the check.
VULNERABILITY_CHECKS = [
    # HTTP Security Header Checks
    {"type": "security_header_missing_hsts", "severity": "Medium", "description": "Missing Strict-Transport-Security (HSTS) header. HTTPS might not be enforced.", "remediation": "Implement HSTS header to enforce HTTPS-only connections: `Strict-Transport-Security: max-age=31536000; includeSubDomains`."},
    {"type": "security_header_missing_xfo", "severity": "Medium", "description": "Missing X-Frame-Options header. Site might be vulnerable to Clickjacking.", "remediation": "Implement X-Frame-Options header to prevent embedding: `X-Frame-Options: DENY` or `SAMEORIGIN`."},
    {"type": "security_header_missing_xcto", "severity": "Medium", "description": "Missing X-Content-Type-Options header. Browser might perform MIME sniffing, leading to XSS.", "remediation": "Implement X-Content-Type-Options header: `X-Content-Type-Options: nosniff`."},
    {"type": "security_header_missing_csp", "severity": "High", "description": "Missing Content-Security-Policy (CSP) header. Site might be vulnerable to various attacks like XSS, data injection.", "remediation": "Implement a strong Content-Security-Policy header to restrict content sources."},
    {"type": "security_header_missing_rp", "severity": "Medium", "description": "Missing Referrer-Policy header. May leak sensitive information during navigation.", "remediation": "Implement `Referrer-Policy: no-referrer-when-downgrade` or stricter."},

    # Information Disclosure & Misconfigurations
    {"type": "server_info_disclosure", "severity": "Low", "description": "Server header discloses detailed server software and version, aiding attackers.", "remediation": "Configure web server to suppress or generalize the 'Server' header information."},
    {"type": "directory_listing_enabled", "severity": "Medium", "description": "Directory listing is enabled, potentially exposing sensitive files.", "remediation": "Disable directory listing on the web server (e.g., Options -Indexes in Apache, autoindex off in Nginx)."},
    {"type": "sensitive_file_exposure", "severity": "High", "description": "Sensitive configuration or info file (e.g., .git, phpinfo.php, .env) is exposed.", "remediation": "Remove or properly restrict access to sensitive files and directories."},
    {"type": "robots_txt_disallowed_paths", "severity": "Low", "description": "Robots.txt lists disallowed paths, potentially indicating sensitive directories.", "remediation": "Review sensitive disallowed paths. Ensure they are properly secured and not publicly accessible. Use robots.txt for crawl control, not security."},
    {"type": "insecure_ssl_tls", "severity": "Medium", "description": "Target uses HTTP instead of HTTPS, or has basic SSL/TLS issues (e.g., invalid cert).", "remediation": "Force HTTPS. Ensure valid, up-to-date SSL/TLS certificates are installed and configured correctly."},
    {"type": "cors_misconfiguration", "severity": "Medium", "description": "Cross-Origin Resource Sharing (CORS) is overly permissive, potentially allowing unauthorized cross-domain requests.", "remediation": "Strictly whitelist allowed origins for CORS. Avoid `Access-Control-Allow-Origin: *` in production unless absolutely necessary."},

    # Web Application Vulnerabilities
    {"type": "reflected_xss_potential", "severity": "High", "description": "Potential reflected XSS detected. Input from URL parameter is echoed without proper sanitization.", "remediation": "Implement rigorous input validation and output encoding for all user-supplied data. Consider a strong CSP."},
    {"type": "open_redirect_potential", "severity": "Medium", "description": "Potential open redirect vulnerability. User input can redirect to arbitrary URLs.", "remediation": "Validate and whitelist all redirection targets. Avoid using untrusted input in redirection logic. Use safe redirect mechanisms."},
]


# --- Helper Functions ---

def fetch_url(url: str, timeout: int = 7, allow_redirects: bool = False) -> Optional[requests.Response]:
    """Helper to fetch a URL and return response or None on error."""
    try:
        response = requests.get(url, timeout=timeout, allow_redirects=allow_redirects)
        response.raise_for_status() # Raise HTTPError for bad responses (4xx or 5xx)
        return response
    except requests.exceptions.RequestException as e:
        # Use Text object for error message
        error_text = Text(f"[!] Network error fetching {url}: ", style="red")
        error_text.append(escape(str(e)), style="red dim")
        console.print(error_text)
        return None
    except Exception as e:
        error_text = Text(f"[!] An unexpected error occurred while fetching {url}: ", style="red")
        error_text.append(escape(str(e)), style="red dim")
        console.print(error_text)
        return None

def add_finding(finding_type: str, severity: str, target_url: str, description: str, remediation: str):
    """Thread-safe way to add a new finding to the global list."""
    with findings_lock:
        all_findings.append({
            "type": finding_type,
            "severity": severity,
            "target_url": target_url,
            "description": description,
            "remediation": remediation
        })

# --- Scan Modules (Functions) ---

def check_security_headers_and_disclosure(target_url: str, response: requests.Response):
    """Checks for common missing security headers and server info disclosure."""
    headers = {k.lower(): v for k, v in response.headers.items()}
    
    # HSTS
    if "strict-transport-security" not in headers:
        add_finding("security_header_missing_hsts", "Medium", target_url, 
                    "Missing Strict-Transport-Security (HSTS) header. HTTPS might not be enforced.", 
                    "Implement HSTS header to enforce HTTPS-only connections: `Strict-Transport-Security: max-age=31536000; includeSubDomains`.")
            
    # X-Frame-Options
    if "x-frame-options" not in headers:
        add_finding("security_header_missing_xfo", "Medium", target_url,
                    "Missing X-Frame-Options header. Site might be vulnerable to Clickjacking.",
                    "Implement X-Frame-Options header to prevent embedding: `X-Frame-Options: DENY` or `SAMEORIGIN`.")
            
    # X-Content-Type-Options
    if "x-content-type-options" not in headers:
        add_finding("security_header_missing_xcto", "Medium", target_url,
                    "Missing X-Content-Type-Options header. Browser might perform MIME sniffing, leading to XSS.",
                    "Implement X-Content-Type-Options header: `X-Content-Type-Options: nosniff`.")

    # Content-Security-Policy
    if "content-security-policy" not in headers:
        add_finding("security_header_missing_csp", "High", target_url,
                    "Missing Content-Security-Policy (CSP) header. Site might be vulnerable to various attacks like XSS, data injection.",
                    "Implement a strong Content-Security-Policy header to restrict content sources.")
    
    # Referrer-Policy
    if "referrer-policy" not in headers:
        add_finding("security_header_missing_rp", "Medium", target_url,
                    "Missing Referrer-Policy header. May leak sensitive information during navigation.",
                    "Implement `Referrer-Policy: no-referrer-when-downgrade` or stricter.")

    # Server Information Disclosure
    server = headers.get("server", "")
    if server:
        add_finding("server_info_disclosure", "Low", target_url, 
                    f"Server header discloses detailed server software and version: {server}",
                    "Configure web server to suppress or generalize the 'Server' header information.")

    # Directory Listing (root)
    if "Index of /" in response.text and response.status_code == 200:
        add_finding("directory_listing_enabled", "Medium", target_url,
                    "Directory listing is enabled on the root, potentially exposing sensitive files.",
                    "Disable directory listing on the web server (e.g., Options -Indexes in Apache, autoindex off in Nginx).")

def check_sensitive_paths_scan(base_url: str):
    """Scans for commonly exposed sensitive paths."""
    for path in COMMON_PATHS:
        full_url = base_url.rstrip("/") + path
        response = fetch_url(full_url)
        if response and response.status_code == 200:
            description = f"Path '{path}' found."
            if "Index of" in response.text:
                description = f"Exposed directory '{path}' found."
            add_finding("sensitive_file_exposure", "High", full_url, description,
                        "Remove or properly restrict access to sensitive files and directories.")

def check_robots_txt(base_url: str):
    """Fetches and parses robots.txt for disallowed paths."""
    robots_url = base_url.rstrip('/') + '/robots.txt'
    response = fetch_url(robots_url)
    if response and response.status_code == 200:
        disallowed_paths = re.findall(r"Disallow:\s*(.*)", response.text, re.IGNORECASE)
        for path in disallowed_paths:
            if path.strip() and path.strip() != '/':
                full_path_url = base_url.rstrip('/') + path.strip()
                add_finding("robots_txt_disallowed_paths", "Low", full_path_url,
                            f"Robots.txt indicates disallowed path: '{path.strip()}'. This might be a sensitive area.",
                            "Ensure all disallowed paths are properly secured and not publicly accessible. Use robots.txt for crawl control, not security.")

def check_reflected_xss(base_url: str):
    """A very basic check for reflected XSS in URL parameters."""
    test_payload = "<script>alert('XSS')</script>" # Simpler payload
    test_url = f"{base_url}?q={quote_plus(test_payload)}"
    
    response = fetch_url(test_url)
    if response and test_payload in response.text:
        # This is a very basic reflection. A real XSS requires more sophisticated checks.
        add_finding("reflected_xss_potential", "High", test_url,
                    f"Potential reflected XSS detected. Payload '{escape(test_payload)}' reflected in response body.",
                    "Implement rigorous input validation and output encoding for all user-supplied data. Consider a strong Content-Security-Policy (CSP).")

def check_open_redirect(base_url: str):
    """A basic check for open redirect vulnerability."""
    redirect_target = "http://evil.com/redirected" # A specific target to look for in Location header
    redirect_params = ["next", "redirect", "url", "continue", "target", "dest"]
    
    for param in redirect_params:
        test_url = f"{base_url}?{param}={quote_plus(redirect_target)}"
        response = fetch_url(test_url)
        if response and response.status_code in [301, 302, 303, 307, 308]:
            location_header = response.headers.get("Location")
            if location_header and redirect_target in location_header:
                add_finding("open_redirect_potential", "Medium", test_url,
                            f"Potential Open Redirect via parameter '{param}'. Redirects to {escape(location_header)}.",
                            "Validate and whitelist all redirection targets. Avoid using untrusted input in redirection logic. Use safe redirect mechanisms.")
                return # Found one, no need to check other params

def check_cors_misconfiguration(base_url: str):
    """Checks for overly permissive CORS headers."""
    # Attempt to trigger CORS check from an arbitrary origin
    headers = {"Origin": "http://malicious.com"}
    try:
        response = requests.get(base_url, headers=headers, timeout=5)
        if response and response.headers.get("Access-Control-Allow-Origin") == "*":
            add_finding("cors_misconfiguration", "Medium", base_url,
                        "CORS header `Access-Control-Allow-Origin: *` found. Allows all origins.",
                        "Strictly whitelist allowed origins for CORS. Avoid `Access-Control-Allow-Origin: *` in production unless absolutely necessary.")
        elif response and response.headers.get("Access-Control-Allow-Origin") == "http://malicious.com":
             add_finding("cors_misconfiguration", "Medium", base_url,
                        "CORS header `Access-Control-Allow-Origin` reflects origin. Potentially vulnerable if combined with other issues.",
                        "Ensure `Access-Control-Allow-Origin` only allows trusted domains. Avoid reflecting user-supplied origins.")
    except requests.exceptions.RequestException as e:
        # Ignore network errors for CORS check
        error_text = Text(f"[!] Could not perform CORS check on {base_url}: ", style="dim red")
        error_text.append(escape(str(e)), style="dim red")
        console.print(error_text)


def check_ssl_tls_basic(target_url: str):
    """Basic SSL/TLS check: verifies if HTTPS is used and if certificate is valid."""
    if not target_url.startswith("https://"):
        add_finding("insecure_ssl_tls", "Medium", target_url,
                    "Site is using HTTP, not HTTPS.",
                    "Configure site to exclusively use HTTPS with a valid SSL/TLS certificate. Implement HSTS.")
        return

    try:
        # This will verify SSL certificate automatically
        requests.get(target_url, timeout=7)
        # If no exception, basic SSL is likely fine (certificate valid)
        # More advanced checks would need cert parsing libraries
    except requests.exceptions.SSLError as e:
        add_finding("insecure_ssl_tls", "High", target_url,
                    f"SSL/TLS Certificate Error: {escape(str(e))}",
                    "Ensure your SSL/TLS certificate is valid, not expired, and correctly configured. Check certificate chain.")
    except requests.exceptions.RequestException as e:
        error_text = Text(f"[!] Could not perform SSL/TLS check on {target_url}: ", style="dim red")
        error_text.append(escape(str(e)), style="dim red")
        console.print(error_text)


def passive_subdomain_discovery(domain: str):
    """Performs passive subdomain discovery using crt.sh certificate transparency logs."""
    console.print(f"\n[cyan][+] Performing passive subdomain discovery for {domain}...[/cyan]")
    crtsh_url = f"https://crt.sh/?q=%25.{domain}&output=json"
    
    try:
        response = requests.get(crtsh_url, timeout=15) # Increased timeout for external API
        response.raise_for_status()
        certs = response.json()
        
        found_subdomains = set()
        for entry in certs:
            if 'common_name' in entry:
                found_subdomains.add(entry['common_name'].lower())
            if 'name_value' in entry:
                for name in entry['name_value'].split(','):
                    name = name.strip().lower()
                    if name.endswith(domain) and name != domain and not name.startswith("*."):
                        found_subdomains.add(name)
        
        if found_subdomains:
            console.print(f"[green][+] Found {len(found_subdomains)} potential subdomains:[/green]")
            for sd in sorted(list(found_subdomains)):
                console.print(f"    - {sd}")
        else:
            console.print("[green][+] No additional subdomains found via crt.sh for this target.[/green]")

    except requests.exceptions.RequestException as e:
        error_text = Text(f"[!] Error during subdomain discovery (crt.sh): ", style="red")
        error_text.append(escape(str(e)), style="red")
        console.print(error_text)
    except json.JSONDecodeError:
        console.print(f"[red][!] Error parsing crt.sh response. Invalid JSON received (might be no results or API error).[/red]")
    except Exception as e:
        error_text = Text(f"[!] An unexpected error occurred during subdomain discovery: ", style="red")
        error_text.append(escape(str(e)), style="red")
        console.print(error_text)

def port_scan_single_port(ip: str, port: int):
    """Scans a single port and adds to global results if open."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(0.5)
            s.connect((ip, port))
            # No direct finding added, just add to results list for a summary
            with findings_lock:
                port_scan_results.append(port)
    except (socket.timeout, ConnectionRefusedError, OSError):
        pass # Port is closed or filtered
    except Exception as e:
        # Changed from sys.stderr.write to console.print for rich consistency
        error_text = Text(f"[!] Error scanning port {port}: ", style="red")
        error_text.append(escape(str(e)), style="red")
        console.print(error_text)


# --- Main Orchestration Command ---

@app.command(name="scan", help="Perform a comprehensive vulnerability scan on a target URL or domain.")
def scan_command(
    target: str = typer.Argument(..., help="Target URL (e.g., https://example.com) or domain (e.g., example.com)"),
    threads: int = typer.Option(5, "--threads", "-t", help="Number of concurrent threads for HTTP checks.")
):
    """
    Orchestrates the various reconnaissance and vulnerability scanning modules.
    """
    console.print(MAIN_BANNER) # Display the combined banner at the start

    # --- Initial Target Processing ---
    target_url_input = target
    # Ensure URL has a scheme for requests library
    if not target_url_input.startswith("http://") and not target_url_input.startswith("https://"):
        target_url = "http://" + target_url_input
    else:
        target_url = target_url_input

    domain_or_ip_for_recon = urlparse(target_url).netloc # Extract domain from URL
    if not domain_or_ip_for_recon: # Fallback if direct IP or malformed URL
        domain_or_ip_for_recon = target_url_input

    # Resolve IP for port scanning
    ip_address = None
    try:
        ip_address = socket.gethostbyname(domain_or_ip_for_recon)
        # Using rich.Text for precise styling and concatenation
        resolved_text = Text("[+] Target resolved: ", style="cyan")
        resolved_text.append("Domain=", style="cyan")
        resolved_text.append(domain_or_ip_for_recon, style="white")
        resolved_text.append(", IP=", style="cyan")
        resolved_text.append(ip_address, style="white")
        console.print(resolved_text)
    except socket.gaierror:
        console.print(f"[red][!] Could not resolve {domain_or_ip_for_recon}. Please ensure it's correct and reachable.[/red]")
        return
    except Exception as e:
        error_text = Text(f"[!] An unexpected error occurred during domain resolution: ", style="red")
        error_text.append(escape(str(e)), style="red")
        console.print(error_text)
        return

    # --- Step 1: Initial HTTP Response & Header Checks ---
    console.print(f"\n[cyan][+] Initial HTTP connection and header analysis to {target_url}...[/cyan]")
    initial_response = fetch_url(target_url)
    if initial_response:
        console.print(f"[green][+] HTTP Status: {initial_response.status_code}[/green]")
        check_security_headers_and_disclosure(target_url, initial_response)
        check_ssl_tls_basic(target_url) # Check SSL/TLS only if HTTPS is used or fetchable
    else:
        console.print(f"[red][!] Could not get initial HTTP response from {target_url}. Skipping most web checks.[/red]")
        # If we can't even connect to the initial URL, many web checks will fail.
        # Still proceed with port scan and subdomain discovery.

    # --- Step 2: HTTP-based Vulnerability Checks (Threaded) ---
    console.print(f"\n[cyan][+] Starting concurrent HTTP-based vulnerability checks (Threads: {threads})...[/cyan]")
    http_workers = []
    for _ in range(threads):
        worker = threading.Thread(target=http_worker, args=(http_check_queue,))
        worker.daemon = True
        worker.start()
        http_workers.append(worker)

    # Populate HTTP check queue with tasks
    http_check_queue.put(("common_paths", (target_url,), {}))
    http_check_queue.put(("robots.txt", (target_url,), {}))
    http_check_queue.put(("xss", (target_url,), {}))
    http_check_queue.put(("open_redirect", (target_url,), {}))
    http_check_queue.put(("cors_misconfiguration", (target_url,), {}))
    
    # Wait for all HTTP checks to complete
    http_check_queue.join()
    for _ in range(threads):
        http_check_queue.put(None) # Sentinel to terminate workers
    for worker in http_workers:
        worker.join()

    # --- Step 3: Port Scan (Threaded) ---
    console.print(f"\n[cyan][+] Starting port scan on {ip_address}...[/cyan]")
    port_scan_threads = []
    for port in COMMON_PORTS:
        t = threading.Thread(target=port_scan_single_port, args=(ip_address, port))
        t.start()
        port_scan_threads.append(t)
    for t in port_scan_threads:
        t.join()

    if port_scan_results:
        # Add port scan results as a general finding for comprehensive table
        port_description = f"Found {len(port_scan_results)} common open ports: {', '.join(map(str, sorted(port_scan_results)))}"
        add_finding("open_ports_detected", "Informational", ip_address, port_description, "Review open ports and ensure only necessary services are exposed.")
        console.print(f"[green][+] {len(port_scan_results)} common ports found open.[/green]")
    else:
        console.print("[green][+] No common ports found open.[/green]")


    # --- Step 4: Passive Reconnaissance ---
    passive_subdomain_discovery(domain_or_ip_for_recon)


    # --- Display All Findings in a Table ---
    console.print(f"\n[yellow]--- Consolidated Scan Results ---[/yellow]")
    if all_findings:
        table = Table(title="Vulnerability Findings", show_header=True, header_style="bold magenta", expand=True)
        table.add_column("Type", style="bold green", min_width=15, justify="left")
        table.add_column("Severity", style="bold blue", min_width=10, justify="center")
        table.add_column("Target/URL", style="cyan", min_width=20, justify="left")
        table.add_column("Description", style="white", min_width=30, justify="left")
        table.add_column("Remediation", style="yellow", min_width=40, justify="left")

        # Sort findings by severity (High > Medium > Low > Informational)
        severity_order = {"High": 4, "Medium": 3, "Low": 2, "Informational": 1, "N/A": 0}
        sorted_findings = sorted(all_findings, key=lambda x: severity_order.get(x.get("severity"), 0), reverse=True)

        for finding in sorted_findings:
            # Map severity to a specific rich color for better visual distinction
            severity_style = {
                "High": "bold red",
                "Medium": "bold yellow",
                "Low": "bold blue",
                "Informational": "bold green"
            }.get(finding.get("severity", "N/A"), "white")

            table.add_row(
                Text(finding.get("type", "N/A").replace('_', ' ').title(), style="bold white"), # Type text is always white, category color comes from severity
                Text(finding.get("severity", "N/A"), style=severity_style),
                Text(finding.get("target_url", "N/A"), style="cyan"),
                Text(finding.get("description", "N/A"), style="white"),
                Text(finding.get("remediation", "No specific remedy provided."), style="yellow")
            )
        console.print(table)
    else:
        console.print(f"[green][+] No specific web vulnerabilities or sensitive paths identified. Good job![/green]")

    console.print(f"\n[green][+] Vulnrecon scan complete. Review results above.[/green]")


if __name__ == "__main__":
    try:
        app()
    except Exception as e:
        # Final fallback for any uncaught top-level errors, printed with rich.Text
        console.print(f"\n[bold red]FATAL ERROR: An unhandled exception occurred:[/bold red]")
        error_message = Text(escape(str(e)), style="red")
        console.print(error_message)
        sys.exit(1)

