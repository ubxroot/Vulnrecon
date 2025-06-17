#!/usr/bin/env python3
"""
Vulnrecon - Professional Vulnerability Assessment Tool
Combining capabilities of nuclei, magicrecon, and other professional VA tools
"""

import os
import sys
import argparse
import subprocess
import time
import json
import requests
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import urlparse

# ASCII Banner
BANNER = """
\033[1;31m
██╗   ██╗██╗   ██╗██╗     ██╗  ██╗██████╗ ███████╗ ██████╗ ██████╗ ███████╗ ██████╗ 
██║   ██║██║   ██║██║     ██║ ██╔╝██╔══██╗██╔════╝██╔═══██╗██╔══██╗██╔════╝██╔═══██╗
██║   ██║██║   ██║██║     █████╔╝ ██████╔╝█████╗  ██║   ██║██████╔╝█████╗  ██║   ██║
╚██╗ ██╔╝██║   ██║██║     ██╔═██╗ ██╔══██╗██╔══╝  ██║   ██║██╔══██╗██╔══╝  ██║   ██║
 ╚████╔╝ ╚██████╔╝███████╗██║  ██╗██║  ██║███████╗╚██████╔╝██║  ██║███████╗╚██████╔╝
  ╚═══╝   ╚═════╝ ╚══════╝╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═╝  ╚═╝╚══════╝ ╚═════╝ 
                                                                                    
████████╗██╗  ██╗███████╗    ██████╗  ██████╗  ██████╗ ████████╗                    
╚══██╔══╝██║  ██║██╔════╝    ██╔══██╗██╔═══██╗██╔═══██╗╚══██╔══╝                    
   ██║   ███████║█████╗      ██████╔╝██║   ██║██║   ██║   ██║                       
   ██║   ██╔══██║██╔══╝      ██╔══██╗██║   ██║██║   ██║   ██║                       
   ██║   ██║  ██║███████╗    ██║  ██║╚██████╔╝╚██████╔╝   ██║                       
   ╚═╝   ╚═╝  ╚═╝╚══════╝    ╚═╝  ╚═╝ ╚═════╝  ╚═════╝    ╚═╝                       
\033[0m
"""

class Vulnrecon:
    def __init__(self):
        self.tools_installed = False
        self.check_tools()
        self.recon_results = {}
        self.vulnerabilities = []
        
    def check_tools(self):
        """Check if required tools are installed"""
        required_tools = {
            'nuclei': 'nuclei -version',
            'subfinder': 'subfinder -version',
            'httpx': 'httpx -version',
            'naabu': 'naabu -version',
            'waybackurls': 'waybackurls -h',
            'gf': 'gf -h',
            'dalfox': 'dalfox -h'
        }
        
        missing_tools = []
        for tool, cmd in required_tools.items():
            try:
                subprocess.run(cmd.split(), stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            except:
                missing_tools.append(tool)
                
        if missing_tools:
            print(f"\033[1;31m[!] Missing tools: {', '.join(missing_tools)}\033[0m")
            print("[*] Please install them before running Vulnrecon")
            sys.exit(1)
            
        self.tools_installed = True
        
    def run_command(self, command, timeout=600):
        """Execute shell command with timeout"""
        try:
            result = subprocess.run(command, shell=True, check=True, 
                                  stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                  text=True, timeout=timeout)
            return result.stdout
        except subprocess.TimeoutExpired:
            print(f"\033[1;33m[!] Command timed out: {command}\033[0m")
            return ""
        except subprocess.CalledProcessError as e:
            print(f"\033[1;31m[!] Error executing command: {command}\n{e.stderr}\033[0m")
            return ""
            
    def passive_recon(self, domain):
        """Perform passive reconnaissance"""
        print(f"\n\033[1;34m[*] Starting passive reconnaissance on {domain}\033[0m")
        
        # Subdomain enumeration
        print("[*] Enumerating subdomains with subfinder...")
        subdomains = self.run_command(f"subfinder -d {domain} -silent")
        subdomains = list(set(subdomains.splitlines()))
        self.recon_results['subdomains'] = subdomains
        print(f"[+] Found {len(subdomains)} unique subdomains")
        
        # HTTP probing
        print("[*] Probing for live HTTP/HTTPS services...")
        alive_hosts = self.run_command(f"echo '{'\\n'.join(subdomains)}' | httpx -silent")
        alive_hosts = alive_hosts.splitlines()
        self.recon_results['alive_hosts'] = alive_hosts
        print(f"[+] Found {len(alive_hosts)} alive hosts")
        
        # Wayback machine URLs
        print("[*] Gathering historical URLs from Wayback Machine...")
        wayback_urls = self.run_command(f"echo '{domain}' | waybackurls")
        wayback_urls = wayback_urls.splitlines()
        self.recon_results['wayback_urls'] = wayback_urls
        print(f"[+] Found {len(wayback_urls)} historical URLs")
        
        # Port scanning for top ports
        print("[*] Scanning for open ports on alive hosts...")
        ports_data = {}
        with ThreadPoolExecutor(max_workers=10) as executor:
            futures = []
            for host in alive_hosts:
                parsed = urlparse(host)
                if parsed.hostname:
                    futures.append(executor.submit(self.scan_ports, parsed.hostname))
            
            for future in futures:
                host, ports = future.result()
                if ports:
                    ports_data[host] = ports
                    
        self.recon_results['open_ports'] = ports_data
        print(f"[+] Port scanning completed for {len(ports_data)} hosts")
        
    def scan_ports(self, host):
        """Scan top ports on a host"""
        ports = self.run_command(f"naabu -host {host} -top-ports 100 -silent")
        return host, ports.splitlines()
        
    def active_scanning(self, domain):
        """Perform active vulnerability scanning"""
        print(f"\n\033[1;34m[*] Starting active vulnerability scanning on {domain}\033[0m")
        
        # Nuclei scanning with all templates
        print("[*] Running nuclei with all templates...")
        nuclei_results = self.run_command(f"echo '{'\\n'.join(self.recon_results['alive_hosts'])}' | nuclei -t ~/nuclei-templates -severity low,medium,high,critical -json")
        
        if nuclei_results:
            vulns = [json.loads(line) for line in nuclei_results.splitlines() if line.strip()]
            self.vulnerabilities.extend(vulns)
            print(f"[+] Nuclei found {len(vulns)} vulnerabilities")
            
        # XSS scanning with dalfox
        print("[*] Scanning for XSS vulnerabilities...")
        xss_results = []
        for url in self.recon_results['wayback_urls']:
            if any(ext in url.lower() for ext in ['php', 'asp', 'aspx', 'jsp', 'html', 'htm', 'js']):
                result = self.run_command(f"echo '{url}' | dalfox pipe --silence --only-poc r")
                if result:
                    xss_results.append({
                        'url': url,
                        'result': result
                    })
                    
        if xss_results:
            self.vulnerabilities.extend(xss_results)
            print(f"[+] Found {len(xss_results)} potential XSS vulnerabilities")
            
        # GF pattern scanning
        print("[*] Scanning for interesting patterns...")
        gf_patterns = [
            'gf sqli',
            'gf lfi',
            'gf ssrf',
            'gf redirect',
            'gf rce',
            'gf idor'
        ]
        
        pattern_results = []
        for pattern in gf_patterns:
            result = self.run_command(f"echo '{'\\n'.join(self.recon_results['wayback_urls'])}' | {pattern}")
            if result:
                pattern_results.append({
                    'pattern': pattern,
                    'results': result.splitlines()
                })
                
        if pattern_results:
            self.vulnerabilities.extend(pattern_results)
            print(f"[+] Found {sum(len(r['results']) for r in pattern_results)} interesting patterns")
            
    def generate_report(self, domain, output_format='json'):
        """Generate vulnerability report"""
        print(f"\n\033[1;34m[*] Generating {output_format} report for {domain}\033[0m")
        
        report = {
            'target': domain,
            'timestamp': int(time.time()),
            'recon_data': self.recon_results,
            'vulnerabilities': self.vulnerabilities
        }
        
        filename = f"vulnrecon_{domain}_{int(time.time())}"
        
        if output_format == 'json':
            with open(f"{filename}.json", 'w') as f:
                json.dump(report, f, indent=4)
        elif output_format == 'html':
            self.generate_html_report(report, filename)
        else:
            print("\033[1;31m[!] Unsupported report format\033[0m")
            return
            
        print(f"[+] Report saved to {filename}.{output_format}")
        
    def generate_html_report(self, report, filename):
        """Generate HTML report"""
        html_template = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <title>Vulnrecon Report - {report['target']}</title>
            <style>
                body {{ font-family: Arial, sans-serif; margin: 0; padding: 20px; color: #333; }}
                .header {{ background-color: #f44336; color: white; padding: 20px; text-align: center; }}
                .section {{ margin-bottom: 30px; border-bottom: 1px solid #eee; padding-bottom: 20px; }}
                .vuln {{ background-color: #f9f9f9; padding: 15px; margin-bottom: 10px; border-radius: 5px; }}
                .critical {{ border-left: 5px solid #f44336; }}
                .high {{ border-left: 5px solid #ff9800; }}
                .medium {{ border-left: 5px solid #ffc107; }}
                .low {{ border-left: 5px solid #4caf50; }}
                table {{ width: 100%; border-collapse: collapse; }}
                th, td {{ padding: 12px; text-align: left; border-bottom: 1px solid #ddd; }}
                tr:hover {{ background-color: #f5f5f5; }}
            </style>
        </head>
        <body>
            <div class="header">
                <h1>Vulnrecon Report</h1>
                <h2>{report['target']}</h2>
                <p>Generated on {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(report['timestamp']))}</p>
            </div>
            
            <div class="section">
                <h2>Reconnaissance Summary</h2>
                <p><strong>Subdomains found:</strong> {len(report['recon_data'].get('subdomains', []))}</p>
                <p><strong>Alive hosts:</strong> {len(report['recon_data'].get('alive_hosts', []))}</p>
                <p><strong>Historical URLs:</strong> {len(report['recon_data'].get('wayback_urls', []))}</p>
            </div>
            
            <div class="section">
                <h2>Vulnerabilities Found ({len(report['vulnerabilities'])})</h2>
        """
        
        for vuln in report['vulnerabilities']:
            if isinstance(vuln, dict) and 'template' in vuln:
                severity = vuln.get('info', {}).get('severity', 'unknown').lower()
                html_template += f"""
                <div class="vuln {severity}">
                    <h3>{vuln.get('template-id', 'Unknown')}</h3>
                    <p><strong>Severity:</strong> <span class="{severity}">{severity.upper()}</span></p>
                    <p><strong>URL:</strong> {vuln.get('host', 'N/A')}</p>
                    <p><strong>Description:</strong> {vuln.get('info', {}).get('description', 'N/A')}</p>
                    <pre>{json.dumps(vuln, indent=2)}</pre>
                </div>
                """
            elif isinstance(vuln, dict) and 'pattern' in vuln:
                html_template += f"""
                <div class="vuln">
                    <h3>Pattern: {vuln['pattern']}</h3>
                    <p><strong>Matches found:</strong> {len(vuln['results'])}</p>
                    <pre>{'\\n'.join(vuln['results'])}</pre>
                </div>
                """
                
        html_template += """
            </div>
        </body>
        </html>
        """
        
        with open(f"{filename}.html", 'w') as f:
            f.write(html_template)
            
    def run(self, domain, output_format='json'):
        """Run complete Vulnrecon assessment"""
        print(BANNER)
        print(f"\033[1;32m[+] Starting Vulnrecon assessment for {domain}\033[0m")
        
        start_time = time.time()
        
        # Phase 1: Passive reconnaissance
        self.passive_recon(domain)
        
        # Phase 2: Active vulnerability scanning
        self.active_scanning(domain)
        
        # Phase 3: Reporting
        self.generate_report(domain, output_format)
        
        duration = time.time() - start_time
        print(f"\n\033[1;32m[+] Assessment completed in {duration:.2f} seconds\033[0m")
        
        # Print summary
        print("\n\033[1;34m[+] Vulnerability Summary:\033[0m")
        severities = {}
        for vuln in self.vulnerabilities:
            if isinstance(vuln, dict) and 'info' in vuln:
                severity = vuln['info'].get('severity', 'unknown').lower()
                severities[severity] = severities.get(severity, 0) + 1
                
        for severity, count in severities.items():
            print(f"  {severity.upper()}: {count}")

def main():
    parser = argparse.ArgumentParser(description="Vulnrecon - Professional Vulnerability Assessment Tool")
    parser.add_argument("-d", "--domain", help="Target domain to scan", required=True)
    parser.add_argument("-o", "--output", help="Output format (json/html)", default="json", choices=['json', 'html'])
    parser.add_argument("-q", "--quiet", help="Run in quiet mode", action="store_true")
    
    args = parser.parse_args()
    
    if args.quiet:
        sys.stdout = open(os.devnull, 'w')
    
    vulnrecon = Vulnrecon()
    vulnrecon.run(args.domain, args.output)

if __name__ == "__main__":
    main()
