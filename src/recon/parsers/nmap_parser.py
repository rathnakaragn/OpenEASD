"""
OpenEASD Recon Layer - Nmap Output Parser
6-Layer Architecture - Recon Layer

Dedicated parser for Nmap output with enhanced service analysis capabilities.

Author: Rathnakara G N
Company: Cybersecify
Created: January 2025
"""

import xml.etree.ElementTree as ET
import re
from typing import Dict, List, Optional, Any, Tuple
from datetime import datetime


class NmapParser:
    """
    Advanced parser for Nmap XML output with comprehensive service analysis.
    
    Features:
    - XML and text output parsing
    - Service fingerprinting analysis
    - Vulnerability detection from scripts
    - OS fingerprinting interpretation
    - Security risk assessment
    - Performance metrics extraction
    """
    
    def __init__(self):
        """Initialize the Nmap parser."""
        # Service risk scoring
        self.service_risks = {
            'telnet': {'risk': 'high', 'reason': 'Unencrypted remote access'},
            'ftp': {'risk': 'medium', 'reason': 'Unencrypted file transfer'},
            'ssh': {'risk': 'low', 'reason': 'Encrypted remote access'},
            'http': {'risk': 'medium', 'reason': 'Unencrypted web service'},
            'https': {'risk': 'low', 'reason': 'Encrypted web service'},
            'smtp': {'risk': 'low', 'reason': 'Email service'},
            'pop3': {'risk': 'medium', 'reason': 'Unencrypted email retrieval'},
            'imap': {'risk': 'medium', 'reason': 'Unencrypted email access'},
            'mysql': {'risk': 'high', 'reason': 'Database service exposed'},
            'postgresql': {'risk': 'high', 'reason': 'Database service exposed'},
            'mongodb': {'risk': 'high', 'reason': 'Database service exposed'},
            'redis': {'risk': 'high', 'reason': 'In-memory database exposed'},
            'elasticsearch': {'risk': 'high', 'reason': 'Search engine database exposed'},
            'rdp': {'risk': 'high', 'reason': 'Windows remote desktop'},
            'vnc': {'risk': 'high', 'reason': 'VNC remote desktop'},
            'snmp': {'risk': 'medium', 'reason': 'Network management protocol'},
        }
        
        # Vulnerability script patterns
        self.vuln_script_patterns = [
            r'vuln-.*',
            r'.*-vuln',
            r'.*-exploit',
            r'.*-dos',
            r'ssl-.*-vuln',
            r'http-.*-vuln'
        ]

    def parse(self, raw_output: str, target: str) -> Dict[str, Any]:
        """
        Parse Nmap output with enhanced analysis.
        
        Args:
            raw_output: Raw output from Nmap
            target: Target being scanned
            
        Returns:
            Comprehensive parsed data structure
        """
        parsed_data = {
            "target": target,
            "scan_info": {},
            "hosts": [],
            "service_summary": {},
            "security_analysis": {
                "risks": [],
                "vulnerabilities": [],
                "recommendations": []
            },
            "statistics": {
                "total_hosts": 0,
                "up_hosts": 0,
                "total_ports": 0,
                "open_ports": 0,
                "services_detected": 0
            },
            "parsing_metadata": {
                "parsed_at": datetime.utcnow().isoformat(),
                "parsing_errors": [],
                "warnings": []
            }
        }
        
        if not raw_output.strip():
            return parsed_data
        
        try:
            # Try XML parsing first
            if raw_output.strip().startswith('<?xml') or '<nmaprun' in raw_output:
                self._parse_xml_output(raw_output, parsed_data)
            else:
                # Fallback to text parsing
                self._parse_text_output(raw_output, parsed_data)
                
        except Exception as e:
            parsed_data["parsing_metadata"]["parsing_errors"].append({
                "type": "general_parsing_error",
                "error": str(e)
            })
            # Try text parsing as fallback
            try:
                self._parse_text_output(raw_output, parsed_data)
            except:
                pass
        
        # Post-process analysis
        self._analyze_services(parsed_data)
        self._assess_security_risks(parsed_data)
        self._update_statistics(parsed_data)
        
        return parsed_data

    def _parse_xml_output(self, xml_output: str, parsed_data: Dict[str, Any]) -> None:
        """
        Parse Nmap XML output.
        
        Args:
            xml_output: XML output string
            parsed_data: Data structure to populate
        """
        try:
            root = ET.fromstring(xml_output)
            
            # Parse scan information
            self._parse_scan_info(root, parsed_data)
            
            # Parse hosts
            for host_elem in root.findall('host'):
                host_data = self._parse_xml_host(host_elem)
                if host_data:
                    parsed_data["hosts"].append(host_data)
                    
        except ET.ParseError as e:
            parsed_data["parsing_metadata"]["parsing_errors"].append({
                "type": "xml_parse_error",
                "error": str(e)
            })
            raise

    def _parse_scan_info(self, root: ET.Element, parsed_data: Dict[str, Any]) -> None:
        """
        Parse scan information from XML root.
        
        Args:
            root: XML root element
            parsed_data: Data structure to populate
        """
        # Scan info
        scaninfo = root.find('scaninfo')
        if scaninfo is not None:
            parsed_data["scan_info"] = {
                "type": scaninfo.get('type'),
                "protocol": scaninfo.get('protocol'),
                "numservices": int(scaninfo.get('numservices', 0)),
                "services": scaninfo.get('services')
            }
        
        # Runtime statistics
        runstats = root.find('runstats')
        if runstats is not None:
            finished = runstats.find('finished')
            if finished is not None:
                parsed_data["scan_info"]["elapsed_time"] = float(finished.get('elapsed', 0))
                parsed_data["scan_info"]["exit_status"] = finished.get('exit')
                
            hosts_summary = runstats.find('hosts')
            if hosts_summary is not None:
                parsed_data["statistics"]["total_hosts"] = int(hosts_summary.get('total', 0))
                parsed_data["statistics"]["up_hosts"] = int(hosts_summary.get('up', 0))

    def _parse_xml_host(self, host_elem: ET.Element) -> Optional[Dict[str, Any]]:
        """
        Parse individual host from XML.
        
        Args:
            host_elem: Host XML element
            
        Returns:
            Parsed host data or None
        """
        try:
            host_data = {
                "addresses": [],
                "hostnames": [],
                "status": {},
                "ports": [],
                "os": {},
                "uptime": {},
                "distance": None,
                "tcp_sequence": {},
                "ip_id_sequence": {}
            }
            
            # Parse addresses
            for addr in host_elem.findall('address'):
                host_data["addresses"].append({
                    "addr": addr.get('addr'),
                    "addrtype": addr.get('addrtype'),
                    "vendor": addr.get('vendor')
                })
            
            # Parse hostnames
            hostnames_elem = host_elem.find('hostnames')
            if hostnames_elem is not None:
                for hostname in hostnames_elem.findall('hostname'):
                    host_data["hostnames"].append({
                        "name": hostname.get('name'),
                        "type": hostname.get('type')
                    })
            
            # Parse status
            status_elem = host_elem.find('status')
            if status_elem is not None:
                host_data["status"] = {
                    "state": status_elem.get('state'),
                    "reason": status_elem.get('reason'),
                    "reason_ttl": status_elem.get('reason_ttl')
                }
            
            # Parse ports
            ports_elem = host_elem.find('ports')
            if ports_elem is not None:
                for port_elem in ports_elem.findall('port'):
                    port_data = self._parse_xml_port(port_elem)
                    if port_data:
                        host_data["ports"].append(port_data)
            
            # Parse OS information
            os_elem = host_elem.find('os')
            if os_elem is not None:
                host_data["os"] = self._parse_xml_os(os_elem)
                
            # Parse uptime
            uptime_elem = host_elem.find('uptime')
            if uptime_elem is not None:
                host_data["uptime"] = {
                    "seconds": int(uptime_elem.get('seconds', 0)),
                    "lastboot": uptime_elem.get('lastboot')
                }
                
            # Parse distance
            distance_elem = host_elem.find('distance')
            if distance_elem is not None:
                host_data["distance"] = int(distance_elem.get('value', 0))
            
            return host_data
            
        except Exception as e:
            return None

    def _parse_xml_port(self, port_elem: ET.Element) -> Optional[Dict[str, Any]]:
        """
        Parse individual port from XML with enhanced analysis.
        
        Args:
            port_elem: Port XML element
            
        Returns:
            Parsed port data with security analysis
        """
        try:
            port_data = {
                "portid": int(port_elem.get('portid')),
                "protocol": port_elem.get('protocol'),
                "state": {},
                "service": {},
                "scripts": [],
                "security_analysis": {
                    "risk_level": "unknown",
                    "vulnerabilities": [],
                    "recommendations": []
                }
            }
            
            # Parse state
            state_elem = port_elem.find('state')
            if state_elem is not None:
                port_data["state"] = {
                    "state": state_elem.get('state'),
                    "reason": state_elem.get('reason'),
                    "reason_ttl": state_elem.get('reason_ttl')
                }
            
            # Parse service with enhanced analysis
            service_elem = port_elem.find('service')
            if service_elem is not None:
                service_data = {
                    "name": service_elem.get('name'),
                    "product": service_elem.get('product'),
                    "version": service_elem.get('version'),
                    "extrainfo": service_elem.get('extrainfo'),
                    "method": service_elem.get('method'),
                    "conf": int(service_elem.get('conf', 0)),
                    "cpe": []
                }
                
                # Parse CPE entries
                for cpe_elem in service_elem.findall('cpe'):
                    service_data["cpe"].append(cpe_elem.text)
                    
                port_data["service"] = service_data
                
                # Analyze service security
                self._analyze_service_security(port_data)
            
            # Parse scripts with vulnerability detection
            for script_elem in port_elem.findall('script'):
                script_data = self._parse_xml_script(script_elem)
                port_data["scripts"].append(script_data)
                
                # Check for vulnerability indicators
                self._analyze_script_vulnerabilities(script_data, port_data)
            
            return port_data
            
        except Exception as e:
            return None

    def _parse_xml_script(self, script_elem: ET.Element) -> Dict[str, Any]:
        """
        Parse NSE script results with enhanced analysis.
        
        Args:
            script_elem: Script XML element
            
        Returns:
            Parsed script data
        """
        script_data = {
            "id": script_elem.get('id'),
            "output": script_elem.get('output'),
            "elements": [],
            "tables": []
        }
        
        # Parse elements
        for elem in script_elem.findall('.//elem'):
            script_data["elements"].append({
                "key": elem.get('key'),
                "value": elem.text
            })
        
        # Parse tables
        for table in script_elem.findall('.//table'):
            table_data = {"key": table.get('key'), "elements": []}
            for elem in table.findall('elem'):
                table_data["elements"].append({
                    "key": elem.get('key'),
                    "value": elem.text
                })
            script_data["tables"].append(table_data)
        
        return script_data

    def _parse_xml_os(self, os_elem: ET.Element) -> Dict[str, Any]:
        """
        Parse OS detection information with enhanced analysis.
        
        Args:
            os_elem: OS XML element
            
        Returns:
            Parsed OS data
        """
        os_data = {
            "portused": [],
            "osmatch": [],
            "osfingerprint": [],
            "best_guess": None
        }
        
        # Parse ports used for OS detection
        for portused in os_elem.findall('portused'):
            os_data["portused"].append({
                "state": portused.get('state'),
                "proto": portused.get('proto'),
                "portid": int(portused.get('portid', 0))
            })
        
        # Parse OS matches
        best_accuracy = 0
        for osmatch in os_elem.findall('osmatch'):
            accuracy = int(osmatch.get('accuracy', 0))
            match_data = {
                "name": osmatch.get('name'),
                "accuracy": accuracy,
                "line": osmatch.get('line'),
                "osclass": []
            }
            
            # Track best guess
            if accuracy > best_accuracy:
                best_accuracy = accuracy
                os_data["best_guess"] = match_data["name"]
            
            # Parse OS classes
            for osclass in osmatch.findall('osclass'):
                match_data["osclass"].append({
                    "type": osclass.get('type'),
                    "vendor": osclass.get('vendor'),
                    "osfamily": osclass.get('osfamily'),
                    "osgen": osclass.get('osgen'),
                    "accuracy": int(osclass.get('accuracy', 0))
                })
            
            os_data["osmatch"].append(match_data)
        
        return os_data

    def _parse_text_output(self, text_output: str, parsed_data: Dict[str, Any]) -> None:
        """
        Parse Nmap text output as fallback.
        
        Args:
            text_output: Text output string
            parsed_data: Data structure to populate
        """
        lines = text_output.split('\n')
        current_host = None
        
        for line in lines:
            line = line.strip()
            
            # Match host headers
            host_match = re.search(r'Nmap scan report for (.+)', line)
            if host_match:
                if current_host:
                    parsed_data["hosts"].append(current_host)
                    
                host_addr = host_match.group(1)
                current_host = {
                    "addresses": [{"addr": host_addr, "addrtype": "ipv4"}],
                    "hostnames": [],
                    "status": {"state": "up"},
                    "ports": [],
                    "os": {}
                }
                continue
            
            # Match port information
            port_match = re.search(r'(\d+)/(tcp|udp)\s+(open|closed|filtered)\s+(.*)', line)
            if port_match and current_host:
                port_data = {
                    "portid": int(port_match.group(1)),
                    "protocol": port_match.group(2),
                    "state": {"state": port_match.group(3)},
                    "service": {"name": port_match.group(4).split()[0] if port_match.group(4) else "unknown"},
                    "scripts": [],
                    "security_analysis": {"risk_level": "unknown", "vulnerabilities": []}
                }
                
                # Analyze service security
                self._analyze_service_security(port_data)
                current_host["ports"].append(port_data)
        
        # Add last host
        if current_host:
            parsed_data["hosts"].append(current_host)

    def _analyze_service_security(self, port_data: Dict[str, Any]) -> None:
        """
        Analyze security implications of detected service.
        
        Args:
            port_data: Port data to analyze
        """
        service_name = port_data.get("service", {}).get("name", "").lower()
        port_num = port_data.get("portid", 0)
        
        # Default risk assessment
        risk_info = self.service_risks.get(service_name, {"risk": "unknown", "reason": "Unknown service"})
        port_data["security_analysis"]["risk_level"] = risk_info["risk"]
        port_data["security_analysis"]["risk_reason"] = risk_info["reason"]
        
        # Additional risk factors
        recommendations = []
        vulnerabilities = []
        
        # Version-specific vulnerabilities
        version = port_data.get("service", {}).get("version", "")
        if version:
            # Check for old/vulnerable versions (this could be enhanced with CVE database)
            if any(old_version in version.lower() for old_version in ['1.0', '2.0', '6.0', '7.0']):
                vulnerabilities.append({
                    "type": "outdated_version",
                    "description": f"Service version {version} may be outdated",
                    "severity": "medium"
                })
                recommendations.append("Update service to latest version")
        
        # Port-specific risks
        if port_num in [23, 21, 80, 110, 143]:  # Unencrypted services
            vulnerabilities.append({
                "type": "unencrypted_service",
                "description": f"Service on port {port_num} transmits data in clear text",
                "severity": "medium"
            })
            recommendations.append("Use encrypted alternative if available")
        
        # Database exposure
        if port_num in [3306, 5432, 27017, 6379, 9200, 1433]:
            vulnerabilities.append({
                "type": "database_exposure",
                "description": f"Database service exposed on port {port_num}",
                "severity": "high"
            })
            recommendations.append("Restrict database access to trusted networks only")
        
        port_data["security_analysis"]["vulnerabilities"] = vulnerabilities
        port_data["security_analysis"]["recommendations"] = recommendations

    def _analyze_script_vulnerabilities(self, script_data: Dict[str, Any], port_data: Dict[str, Any]) -> None:
        """
        Analyze NSE script output for vulnerabilities.
        
        Args:
            script_data: Script data to analyze
            port_data: Port data to update
        """
        script_id = script_data.get("id", "")
        script_output = script_data.get("output", "").lower()
        
        # Check if script is vulnerability-related
        is_vuln_script = any(re.match(pattern, script_id) for pattern in self.vuln_script_patterns)
        
        if is_vuln_script:
            # Analyze vulnerability script output
            vuln_indicators = [
                "vulnerable", "exploit", "cve-", "ms-", "critical", "high risk",
                "backdoor", "weak", "default", "anonymous"
            ]
            
            severity = "low"
            if any(indicator in script_output for indicator in ["critical", "exploit", "backdoor"]):
                severity = "critical"
            elif any(indicator in script_output for indicator in ["vulnerable", "high risk"]):
                severity = "high"
            elif any(indicator in script_output for indicator in ["weak", "default"]):
                severity = "medium"
            
            # Extract CVE references
            cve_matches = re.findall(r'cve-\d{4}-\d+', script_output)
            
            vulnerability = {
                "type": "nse_detected",
                "script": script_id,
                "description": f"NSE script {script_id} detected potential vulnerability",
                "severity": severity,
                "details": script_output[:500],  # Truncate long output
                "cves": list(set(cve_matches)) if cve_matches else []
            }
            
            port_data["security_analysis"]["vulnerabilities"].append(vulnerability)
            
            # Update risk level if higher severity found
            current_risk = port_data["security_analysis"]["risk_level"]
            if severity in ["critical", "high"] and current_risk in ["unknown", "low", "medium"]:
                port_data["security_analysis"]["risk_level"] = severity

    def _analyze_services(self, parsed_data: Dict[str, Any]) -> None:
        """
        Analyze services across all hosts and generate summary.
        
        Args:
            parsed_data: Parsed data to analyze
        """
        service_summary = {}
        
        for host in parsed_data.get("hosts", []):
            for port in host.get("ports", []):
                if port.get("state", {}).get("state") != "open":
                    continue
                    
                service_name = port.get("service", {}).get("name", "unknown")
                port_num = port.get("portid", 0)
                protocol = port.get("protocol", "tcp")
                
                service_key = f"{service_name}_{protocol}"
                
                if service_key not in service_summary:
                    service_summary[service_key] = {
                        "service": service_name,
                        "protocol": protocol,
                        "ports": [],
                        "hosts": [],
                        "risk_levels": {},
                        "vulnerabilities": []
                    }
                
                service_info = service_summary[service_key]
                
                if port_num not in service_info["ports"]:
                    service_info["ports"].append(port_num)
                    
                host_addr = self._get_host_primary_address(host)
                if host_addr and host_addr not in service_info["hosts"]:
                    service_info["hosts"].append(host_addr)
                
                # Aggregate risk levels
                risk_level = port.get("security_analysis", {}).get("risk_level", "unknown")
                service_info["risk_levels"][risk_level] = service_info["risk_levels"].get(risk_level, 0) + 1
                
                # Aggregate vulnerabilities
                vulns = port.get("security_analysis", {}).get("vulnerabilities", [])
                service_info["vulnerabilities"].extend(vulns)
        
        parsed_data["service_summary"] = service_summary

    def _assess_security_risks(self, parsed_data: Dict[str, Any]) -> None:
        """
        Assess overall security risks and generate recommendations.
        
        Args:
            parsed_data: Parsed data to analyze
        """
        risks = []
        vulnerabilities = []
        recommendations = set()
        
        # Analyze each host
        for host in parsed_data.get("hosts", []):
            host_addr = self._get_host_primary_address(host)
            
            # Count open ports
            open_ports = [p for p in host.get("ports", []) if p.get("state", {}).get("state") == "open"]
            
            if len(open_ports) > 10:
                risks.append({
                    "type": "excessive_open_ports",
                    "host": host_addr,
                    "severity": "medium",
                    "description": f"Host has {len(open_ports)} open ports",
                    "recommendation": "Review and close unnecessary services"
                })
            
            # Analyze each port
            for port in open_ports:
                port_vulns = port.get("security_analysis", {}).get("vulnerabilities", [])
                for vuln in port_vulns:
                    vulnerability = {
                        "host": host_addr,
                        "port": port.get("portid"),
                        "service": port.get("service", {}).get("name", "unknown"),
                        **vuln
                    }
                    vulnerabilities.append(vulnerability)
                
                # Add port-specific recommendations
                port_recs = port.get("security_analysis", {}).get("recommendations", [])
                recommendations.update(port_recs)
        
        parsed_data["security_analysis"]["risks"] = risks
        parsed_data["security_analysis"]["vulnerabilities"] = vulnerabilities
        parsed_data["security_analysis"]["recommendations"] = list(recommendations)

    def _update_statistics(self, parsed_data: Dict[str, Any]) -> None:
        """
        Update scan statistics.
        
        Args:
            parsed_data: Parsed data to update
        """
        stats = parsed_data["statistics"]
        hosts = parsed_data.get("hosts", [])
        
        stats["total_hosts"] = len(hosts)
        stats["up_hosts"] = len([h for h in hosts if h.get("status", {}).get("state") == "up"])
        
        total_ports = 0
        open_ports = 0
        services = set()
        
        for host in hosts:
            host_ports = host.get("ports", [])
            total_ports += len(host_ports)
            
            for port in host_ports:
                if port.get("state", {}).get("state") == "open":
                    open_ports += 1
                    service_name = port.get("service", {}).get("name")
                    if service_name:
                        services.add(service_name)
        
        stats["total_ports"] = total_ports
        stats["open_ports"] = open_ports
        stats["services_detected"] = len(services)

    def _get_host_primary_address(self, host: Dict[str, Any]) -> Optional[str]:
        """
        Get primary IP address for a host.
        
        Args:
            host: Host data
            
        Returns:
            Primary IP address or None
        """
        addresses = host.get("addresses", [])
        for addr in addresses:
            if addr.get("addrtype") in ["ipv4", "ipv6"]:
                return addr.get("addr")
        return None

    def extract_critical_findings(self, parsed_data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Extract critical security findings for immediate attention.
        
        Args:
            parsed_data: Parsed Nmap data
            
        Returns:
            List of critical findings
        """
        critical_findings = []
        
        # High-risk services
        high_risk_services = ['telnet', 'ftp', 'mysql', 'postgresql', 'mongodb', 'redis', 'rdp']
        
        for host in parsed_data.get("hosts", []):
            host_addr = self._get_host_primary_address(host)
            
            for port in host.get("ports", []):
                if port.get("state", {}).get("state") != "open":
                    continue
                    
                service_name = port.get("service", {}).get("name", "").lower()
                port_num = port.get("portid", 0)
                risk_level = port.get("security_analysis", {}).get("risk_level", "unknown")
                
                # Critical service exposure
                if service_name in high_risk_services:
                    critical_findings.append({
                        "type": "high_risk_service",
                        "host": host_addr,
                        "port": port_num,
                        "service": service_name,
                        "severity": "high",
                        "description": f"High-risk service {service_name} exposed on port {port_num}",
                        "recommendation": f"Secure or disable {service_name} service"
                    })
                
                # Critical vulnerabilities
                vulnerabilities = port.get("security_analysis", {}).get("vulnerabilities", [])
                for vuln in vulnerabilities:
                    if vuln.get("severity") == "critical":
                        critical_findings.append({
                            "type": "critical_vulnerability",
                            "host": host_addr,
                            "port": port_num,
                            "service": service_name,
                            "severity": "critical",
                            "description": vuln.get("description", "Critical vulnerability detected"),
                            "details": vuln,
                            "recommendation": "Apply security patches immediately"
                        })
        
        # Sort by severity
        severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
        critical_findings.sort(key=lambda x: severity_order.get(x["severity"], 4))
        
        return critical_findings