#!/usr/bin/env python3
"""
TurboVulnScanner - Custom vulnerability scanner with RustScan-like speed and Nmap integration
Author: artemis37
"""

import asyncio
import subprocess
import xml.etree.ElementTree as ET
from typing import List, Dict, Optional
import argparse
import sys
from dataclasses import dataclass
import requests
from colorama import Fore, Style, init

# Initialize colorama
init(autoreset=True)

@dataclass
class ScanConfig:
    target: str
    ports: str = "1-1000"
    timeout: float = 1.0
    rate_limit: int = 1000
    nmap_args: str = "-sV --script vulners,vuln"
    nvd_api_key: Optional[str] = None

class TurboPortScanner:
    """Asynchronous high-speed port scanner with RustScan-like features"""
    def __init__(self, config: ScanConfig):
        self.config = config
        self.open_ports: List[int] = []
    
    async def _scan_port(self, port: int):
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(self.config.target, port),
                timeout=self.config.timeout
            )
            self.open_ports.append(port)
            writer.close()
            await writer.wait_closed()
        except:
            pass

    async def _batch_scan(self, ports: List[int]):
        semaphore = asyncio.Semaphore(self.config.rate_limit)
        async def limited_scan(port):
            async with semaphore:
                await self._scan_port(port)
        
        await asyncio.gather(*[limited_scan(port) for port in ports])

    async def run_scan(self) -> List[int]:
        ports = self._parse_ports()
        chunk_size = self.config.rate_limit
        for i in range(0, len(ports), chunk_size):
            chunk = ports[i:i + chunk_size]
            await self._batch_scan(chunk)
        return sorted(self.open_ports)

    def _parse_ports(self) -> List[int]:
        ports = []
        for part in self.config.ports.split(','):
            if '-' in part:
                start, end = map(int, part.split('-'))
                ports.extend(range(start, end + 1))
            else:
                ports.append(int(part))
        return ports

class NmapIntegration:
    """Handles Nmap scanning and XML output parsing"""
    def __init__(self, config: ScanConfig):
        self.config = config
        self.services: List[Dict] = []

    def run_scan(self, open_ports: List[int]) -> List[Dict]:
        port_list = ','.join(map(str, open_ports))
        command = [
            "nmap",
            "-p", port_list,
            *self.config.nmap_args.split(),
            "-oX", "-",
            self.config.target
        ]
        
        try:
            result = subprocess.run(
                command,
                capture_output=True,
                text=True,
                check=True
            )
            return self._parse_xml(result.stdout)
        except subprocess.CalledProcessError as e:
            print(f"{Fore.RED}Nmap error: {e.stderr}")
            return []

    def _parse_xml(self, xml_data: str) -> List[Dict]:
        root = ET.fromstring(xml_data)
        services = []
        
        for port in root.findall(".//port"):
            service = {
                "port": port.get("portid"),
                "protocol": port.get("protocol"),
                "service": port.find("service").get("name") if port.find("service") is not None else "unknown",
                "version": port.find("service").get("version", ""),
                "cpes": [cpe.text for cpe in port.findall(".//cpe")],
                "vulnerabilities": []
            }

            for script in port.findall(".//script"):
                if script.get("id") == "vulners":
                    service["vulnerabilities"].extend(
                        self._parse_vulners_script(script)
                    )
            
            services.append(service)
        return services

    def _parse_vulners_script(self, script) -> List[Dict]:
        vulns = []
        for table in script.findall(".//table"):
            vuln = {
                "id": table.find(".//elem[@key='id']").text,
                "cvss": float(table.find(".//elem[@key='cvss']").text),
                "type": table.find(".//elem[@key='type']").text
            }
            vulns.append(vuln)
        return vulns

class VulnerabilityAnalyzer:
    """Handles CVE lookups with proper NVD API v2 integration"""
    def __init__(self, config: ScanConfig):
        self.config = config
        self.nvd_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
        self.headers = {"apiKey": config.nvd_api_key} if config.nvd_api_key else {}

    def _convert_to_cpe23(self, cpe: str) -> str:
        """Convert any CPE format to CPE 2.3 standard"""
        try:
            parts = cpe.split(":")
            if parts[0] == "cpe" and len(parts) < 13:
                # Pad with wildcards for missing components
                return ":".join(parts + ["*"]*(13 - len(parts)))[:13]
            return cpe
        except:
            return cpe

    def check_cves(self, service: Dict) -> List[Dict]:
        cves = []
        
        for cpe in service["cpes"]:
            try:
                # Convert to CPE 2.3 format
                cpe23 = self._convert_to_cpe23(cpe)
                
                params = {
                    "cpeName": cpe23,
                    "resultsPerPage": 5,
                    "startIndex": 0
                }

                response = requests.get(
                    self.nvd_url,
                    params=params,
                    headers=self.headers,
                    timeout=15
                )
                response.raise_for_status()

                data = response.json()
                vulnerabilities = data.get("vulnerabilities", [])

                for vuln in vulnerabilities:
                    cve_data = vuln.get("cve", {})
                    cve_id = cve_data.get("id", "")
                    
                    # Extract description
                    descriptions = cpe_data.get("descriptions", [])
                    description = next(
                        (desc["value"] for desc in descriptions if desc["lang"] == "en"),
                        "No description available"
                    )
                    
                    # Extract CVSS score
                    metrics = cve_data.get("metrics", {})
                    cvss_score = None
                    
                    for version in ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]:
                        if version in metrics:
                            cvss_score = metrics[version][0]["cvssData"]["baseScore"]
                            break

                    cves.append({
                        "id": cve_id,
                        "description": description,
                        "cvss": cvss_score
                    })

            except requests.exceptions.HTTPError as e:
                if e.response.status_code == 403:
                    msg = "403 Forbidden - Invalid or missing API key" if self.config.nvd_api_key \
                        else "403 Forbidden - API key required (get one from https://nvd.nist.gov/developers/request-an-api-key)"
                    print(f"{Fore.YELLOW}NVD API Error: {msg}")
                elif e.response.status_code == 404:
                    print(f"{Fore.YELLOW}Invalid CPE format: {cpe} (converted to {cpe23})")
                else:
                    print(f"{Fore.YELLOW}NVD API Error: {str(e)}")
            except Exception as e:
                print(f"{Fore.YELLOW}Error processing {cpe}: {str(e)}")
        
        return sorted(
            [cve for cve in cves if cve["cvss"] is not None],
            key=lambda x: x["cvss"],
            reverse=True
        )

def print_results(services: List[Dict], config: ScanConfig):
    """Display scan results with colored output"""
    print(f"\n{Fore.CYAN}=== Scan Results for {config.target} ==={Style.RESET_ALL}")
    
    for service in services:
        port = service["port"]
        print(f"\n{Fore.GREEN}Port {port}: {service['service']} {service['version']}")
        
        if service["vulnerabilities"]:
            print(f"{Fore.RED}  [!] Found {len(service['vulnerabilities'])} vulnerabilities:")
            for vuln in service["vulnerabilities"]:
                print(f"    - {vuln['id']} (CVSS: {vuln['cvss']})")
        
        cves = VulnerabilityAnalyzer(config).check_cves(service)
        if cves:
            print(f"{Fore.MAGENTA}  [!] Top related CVEs:")
            for cve in cves:
                cve_id = cve["cve"]["CVE_data_meta"]["ID"]
                desc = cve["cve"]["description"]["description_data"][0]["value"]
                print(f"    - {cve_id}: {desc[:80]}...")

async def main(config: ScanConfig):
    print(f"{Fore.BLUE}Starting scan against {config.target}...")
    
    # Phase 1: Rapid Port Scanning
    print(f"{Fore.CYAN}Phase 1: Port scanning ({config.ports})...")
    port_scanner = TurboPortScanner(config)
    open_ports = await port_scanner.run_scan()
    print(f"{Fore.GREEN}Found {len(open_ports)} open ports")
    
    if not open_ports:
        print(f"{Fore.YELLOW}No open ports found. Exiting.")
        return
    
    # Phase 2: Nmap Service Scanning
    print(f"{Fore.CYAN}Phase 2: Service and vulnerability detection...")
    nmap = NmapIntegration(config)
    services = nmap.run_scan(open_ports)
    
    # Phase 3: Vulnerability Analysis
    print(f"{Fore.CYAN}Phase 3: Vulnerability assessment...")
    print_results(services, config)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="TurboVulnScanner - Advanced vulnerability scanner",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter
    )
    parser.add_argument("target", help="Target IP address or hostname")
    parser.add_argument("-p", "--ports", default="1-1000",
                      help="Ports/ranges to scan (e.g., '80,443,8000-9000')")
    parser.add_argument("-t", "--timeout", type=float, default=1.0,
                      help="Connection timeout in seconds")
    parser.add_argument("-r", "--rate-limit", type=int, default=1000,
                      help="Maximum concurrent connections")
    parser.add_argument("--nmap-args", default="-sV --script vulners,vuln",
                      help="Additional Nmap arguments")
    parser.add_argument("--nvd-api-key", help="NVD API key for CVE lookups")
    
    args = parser.parse_args()
    
    config = ScanConfig(
        target=args.target,
        ports=args.ports,
        timeout=args.timeout,
        rate_limit=args.rate_limit,
        nmap_args=args.nmap_args,
        nvd_api_key=args.nvd_api_key
    )
    
    try:
        asyncio.run(main(config))
    except KeyboardInterrupt:
        print(f"\n{Fore.RED}Scan interrupted by user. Exiting.")
        sys.exit(1)
