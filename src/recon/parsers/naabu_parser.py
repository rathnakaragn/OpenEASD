"""
OpenEASD Recon Layer - Naabu Output Parser
6-Layer Architecture - Recon Layer

Dedicated parser for Naabu output with enhanced port analysis capabilities.

Author: Rathnakara G N
Company: Cybersecify
Created: January 2025
"""

import json
import re
from typing import Dict, List, Optional, Any, Tuple
from datetime import datetime


class NaabuParser:
    """
    Advanced parser for Naabu JSON output with comprehensive port analysis.
    
    Features:
    - JSON and text output parsing
    - Port service inference
    - Security risk assessment
    - Performance metrics analysis
    - Host categorization
    - Attack surface mapping
    """
    
    def __init__(self):
        """Initialize the Naabu parser."""
        # Port categorization and risk assessment
        self.port_categories = {
            'web': {
                'ports': [80, 443, 8080, 8443, 8000, 8888, 9000, 3000],
                'risk': 'medium',
                'description': 'Web services'
            },
            'database': {
                'ports': [3306, 5432, 1433, 1521, 27017, 6379, 5984, 9200, 11211],
                'risk': 'critical',
                'description': 'Database services'
            },
            'remote_access': {
                'ports': [22, 23, 3389, 5900, 5901, 5902],
                'risk': 'high',
                'description': 'Remote access services'
            },
            'file_transfer': {
                'ports': [21, 69, 115, 119],
                'risk': 'medium',
                'description': 'File transfer services'
            },
            'email': {
                'ports': [25, 110, 143, 993, 995, 587],
                'risk': 'low',
                'description': 'Email services'
            },
            'dns': {
                'ports': [53],
                'risk': 'low',
                'description': 'DNS services'
            },
            'management': {
                'ports': [161, 162, 623, 664, 7001],
                'risk': 'high',
                'description': 'Network management services'
            },
            'development': {
                'ports': [4000, 5000, 8001, 8002, 8003, 8004, 9001],
                'risk': 'medium',
                'description': 'Development services'
            }
        }
        
        # Service name mappings for common ports
        self.port_services = {
            21: 'ftp', 22: 'ssh', 23: 'telnet', 25: 'smtp', 53: 'dns',
            80: 'http', 110: 'pop3', 111: 'rpcbind', 135: 'msrpc',
            139: 'netbios-ssn', 143: 'imap', 443: 'https', 445: 'microsoft-ds',
            993: 'imaps', 995: 'pop3s', 1433: 'ms-sql-s', 1521: 'oracle',
            3306: 'mysql', 3389: 'rdp', 5432: 'postgresql', 5900: 'vnc',
            6379: 'redis', 8080: 'http-alt', 9200: 'elasticsearch',
            27017: 'mongodb'
        }

    def parse(self, raw_output: str, target: str) -> Dict[str, Any]:
        """
        Parse Naabu output with enhanced analysis.
        
        Args:
            raw_output: Raw output from Naabu
            target: Target being scanned
            
        Returns:
            Comprehensive parsed data structure
        """
        parsed_data = {
            "target": target,
            "hosts": [],
            "port_summary": {},
            "service_analysis": {},
            "security_analysis": {
                "attack_surface": {},
                "risk_assessment": {},
                "recommendations": []
            },
            "statistics": {
                "total_hosts": 0,
                "responsive_hosts": 0,
                "total_ports": 0,
                "unique_ports": set(),
                "scan_speed": 0
            },
            "parsing_metadata": {
                "parsed_at": datetime.utcnow().isoformat(),
                "parsing_errors": [],
                "warnings": []
            }
        }
        
        if not raw_output.strip():
            return parsed_data
        
        # Parse raw data
        raw_entries = []
        for line_num, line in enumerate(raw_output.strip().split('\n'), 1):
            line = line.strip()
            if not line:
                continue
                
            try:
                entry = self._parse_line(line)
                if entry:
                    raw_entries.append(entry)
                    
            except Exception as e:
                parsed_data["parsing_metadata"]["parsing_errors"].append({
                    "line": line_num,
                    "content": line,
                    "error": str(e)
                })
        
        # Process and analyze data
        self._process_hosts(raw_entries, parsed_data)
        self._analyze_ports(parsed_data)
        self._assess_security_risks(parsed_data)
        self._update_statistics(parsed_data)
        
        return parsed_data

    def _parse_line(self, line: str) -> Optional[Dict[str, Any]]:
        """
        Parse individual line from Naabu output.
        
        Args:
            line: Single line from output
            
        Returns:
            Parsed entry data or None
        """
        try:
            # Try JSON parsing first
            if line.startswith('{'):
                data = json.loads(line)
                return {
                    "host": data.get('host', '').strip(),
                    "ip": data.get('ip', '').strip(),
                    "port": int(data.get('port', 0)),
                    "protocol": data.get('protocol', 'tcp').lower(),
                    "timestamp": data.get('timestamp'),
                    "source": "json"
                }
            else:
                # Handle text format: host:port
                match = re.match(r'^([^\s:]+):(\d+)(?:/(\w+))?', line)
                if match:
                    host = match.group(1)
                    port = int(match.group(2))
                    protocol = match.group(3) or 'tcp'
                    
                    return {
                        "host": host,
                        "ip": host,  # Assume host is IP for text format
                        "port": port,
                        "protocol": protocol.lower(),
                        "timestamp": None,
                        "source": "text"
                    }
                    
        except (json.JSONDecodeError, ValueError) as e:
            # Try alternative text patterns
            patterns = [
                r'^(\S+)\s+(\d+)/(tcp|udp)\s+open',  # Standard format
                r'^(\S+):(\d+)\s+open',              # Host:port format
                r'^(\d+)\s+(tcp|udp)\s+(\S+)',       # Port protocol host
            ]
            
            for pattern in patterns:
                match = re.search(pattern, line, re.IGNORECASE)
                if match:
                    if len(match.groups()) == 3 and match.group(3) != 'open':
                        # Port protocol host format
                        return {
                            "host": match.group(3),
                            "ip": match.group(3),
                            "port": int(match.group(1)),
                            "protocol": match.group(2).lower(),
                            "timestamp": None,
                            "source": "text"
                        }
                    else:
                        # Other formats
                        return {
                            "host": match.group(1),
                            "ip": match.group(1),
                            "port": int(match.group(2)),
                            "protocol": match.group(3).lower() if len(match.groups()) > 2 else 'tcp',
                            "timestamp": None,
                            "source": "text"
                        }
                        
        return None

    def _process_hosts(self, raw_entries: List[Dict[str, Any]], parsed_data: Dict[str, Any]) -> None:
        """
        Process raw entries into organized host data.
        
        Args:
            raw_entries: Raw parsed entries
            parsed_data: Data structure to populate
        """
        hosts_data = {}
        
        for entry in raw_entries:
            host = entry.get("host")
            if not host:
                continue
                
            if host not in hosts_data:
                hosts_data[host] = {
                    "host": host,
                    "ip": entry.get("ip", host),
                    "ports": [],
                    "port_count": 0,
                    "protocols": set(),
                    "categories": set(),
                    "risk_level": "low"
                }
            
            host_data = hosts_data[host]
            
            # Add port information
            port_info = {
                "port": entry["port"],
                "protocol": entry["protocol"],
                "service": self._infer_service(entry["port"], entry["protocol"]),
                "category": self._categorize_port(entry["port"]),
                "risk_level": self._assess_port_risk(entry["port"], entry["protocol"]),
                "timestamp": entry.get("timestamp")
            }
            
            host_data["ports"].append(port_info)
            host_data["port_count"] += 1
            host_data["protocols"].add(entry["protocol"])
            
            if port_info["category"]:
                host_data["categories"].add(port_info["category"])
            
            # Update host risk level
            if port_info["risk_level"] == "critical" or host_data["risk_level"] != "critical":
                if self._risk_level_priority(port_info["risk_level"]) > self._risk_level_priority(host_data["risk_level"]):
                    host_data["risk_level"] = port_info["risk_level"]
        
        # Convert sets to lists and sort ports
        for host_data in hosts_data.values():
            host_data["protocols"] = list(host_data["protocols"])
            host_data["categories"] = list(host_data["categories"])
            host_data["ports"].sort(key=lambda x: x["port"])
        
        parsed_data["hosts"] = list(hosts_data.values())

    def _infer_service(self, port: int, protocol: str) -> str:
        """
        Infer service name from port and protocol.
        
        Args:
            port: Port number
            protocol: Protocol (tcp/udp)
            
        Returns:
            Inferred service name
        """
        if protocol == "tcp":
            return self.port_services.get(port, "unknown")
        elif protocol == "udp":
            # UDP-specific services
            udp_services = {
                53: 'dns', 67: 'dhcps', 68: 'dhcpc', 69: 'tftp',
                123: 'ntp', 161: 'snmp', 162: 'snmptrap', 514: 'syslog'
            }
            return udp_services.get(port, "unknown")
        
        return "unknown"

    def _categorize_port(self, port: int) -> Optional[str]:
        """
        Categorize port based on service type.
        
        Args:
            port: Port number
            
        Returns:
            Category name or None
        """
        for category, info in self.port_categories.items():
            if port in info['ports']:
                return category
        return None

    def _assess_port_risk(self, port: int, protocol: str) -> str:
        """
        Assess risk level of a port.
        
        Args:
            port: Port number
            protocol: Protocol
            
        Returns:
            Risk level string
        """
        # Check category-based risk
        category = self._categorize_port(port)
        if category and category in self.port_categories:
            return self.port_categories[category]['risk']
        
        # Protocol-based risk assessment
        if protocol == "udp" and port in [161, 69, 514]:  # SNMP, TFTP, Syslog
            return "medium"
        
        # High ports might be custom services
        if port > 10000:
            return "medium"
        
        return "low"

    def _risk_level_priority(self, risk_level: str) -> int:
        """
        Get numeric priority for risk level.
        
        Args:
            risk_level: Risk level string
            
        Returns:
            Numeric priority (higher = more severe)
        """
        priorities = {"low": 1, "medium": 2, "high": 3, "critical": 4}
        return priorities.get(risk_level, 0)

    def _analyze_ports(self, parsed_data: Dict[str, Any]) -> None:
        """
        Analyze port distribution and generate summary.
        
        Args:
            parsed_data: Parsed data to analyze
        """
        port_summary = {}
        service_analysis = {}
        all_ports = []
        
        for host in parsed_data.get("hosts", []):
            for port_info in host.get("ports", []):
                port = port_info["port"]
                service = port_info["service"]
                category = port_info["category"]
                protocol = port_info["protocol"]
                
                all_ports.append(port)
                
                # Port frequency analysis
                if port not in port_summary:
                    port_summary[port] = {
                        "port": port,
                        "protocol": protocol,
                        "service": service,
                        "category": category,
                        "hosts": [],
                        "frequency": 0,
                        "risk_level": port_info["risk_level"]
                    }
                
                port_summary[port]["frequency"] += 1
                if host["host"] not in port_summary[port]["hosts"]:
                    port_summary[port]["hosts"].append(host["host"])
                
                # Service analysis
                if service != "unknown":
                    if service not in service_analysis:
                        service_analysis[service] = {
                            "service": service,
                            "category": category,
                            "ports": set(),
                            "hosts": set(),
                            "risk_level": port_info["risk_level"]
                        }
                    
                    service_analysis[service]["ports"].add(port)
                    service_analysis[service]["hosts"].add(host["host"])
        
        # Convert sets to lists and sort by frequency
        port_list = list(port_summary.values())
        port_list.sort(key=lambda x: x["frequency"], reverse=True)
        
        for service_info in service_analysis.values():
            service_info["ports"] = list(service_info["ports"])
            service_info["hosts"] = list(service_info["hosts"])
        
        parsed_data["port_summary"] = {
            "most_common_ports": port_list[:10],  # Top 10 most common
            "all_ports": port_summary,
            "port_distribution": self._calculate_port_distribution(all_ports)
        }
        parsed_data["service_analysis"] = service_analysis

    def _calculate_port_distribution(self, ports: List[int]) -> Dict[str, Any]:
        """
        Calculate port range distribution statistics.
        
        Args:
            ports: List of all ports found
            
        Returns:
            Distribution statistics
        """
        if not ports:
            return {}
        
        distribution = {
            "well_known": len([p for p in ports if p <= 1023]),      # 0-1023
            "registered": len([p for p in ports if 1024 <= p <= 49151]),  # 1024-49151
            "dynamic": len([p for p in ports if p >= 49152]),        # 49152-65535
            "total_unique": len(set(ports)),
            "range_stats": {
                "min": min(ports),
                "max": max(ports),
                "median": sorted(ports)[len(ports) // 2]
            }
        }
        
        return distribution

    def _assess_security_risks(self, parsed_data: Dict[str, Any]) -> None:
        """
        Assess security risks and generate recommendations.
        
        Args:
            parsed_data: Parsed data to analyze
        """
        attack_surface = {}
        risk_assessment = {
            "critical_hosts": [],
            "high_risk_services": [],
            "exposed_databases": [],
            "management_interfaces": [],
            "development_services": []
        }
        recommendations = []
        
        # Analyze each host
        for host in parsed_data.get("hosts", []):
            host_addr = host["host"]
            open_ports = len(host["ports"])
            categories = host.get("categories", [])
            risk_level = host.get("risk_level", "low")
            
            # Attack surface analysis
            attack_surface[host_addr] = {
                "open_ports": open_ports,
                "categories": categories,
                "risk_level": risk_level,
                "critical_services": []
            }
            
            # Identify critical exposures
            for port_info in host["ports"]:
                port = port_info["port"]
                service = port_info["service"]
                category = port_info["category"]
                port_risk = port_info["risk_level"]
                
                if port_risk in ["critical", "high"]:
                    attack_surface[host_addr]["critical_services"].append({
                        "port": port,
                        "service": service,
                        "risk": port_risk
                    })
                
                # Specific risk categorization
                if category == "database":
                    risk_assessment["exposed_databases"].append({
                        "host": host_addr,
                        "port": port,
                        "service": service
                    })
                    
                elif category == "management":
                    risk_assessment["management_interfaces"].append({
                        "host": host_addr,
                        "port": port,
                        "service": service
                    })
                    
                elif category == "development":
                    risk_assessment["development_services"].append({
                        "host": host_addr,
                        "port": port,
                        "service": service
                    })
                    
                elif service in ["ftp", "telnet"] or port in [21, 23]:
                    risk_assessment["high_risk_services"].append({
                        "host": host_addr,
                        "port": port,
                        "service": service,
                        "reason": "Unencrypted protocol"
                    })
            
            # Mark critical hosts
            if risk_level == "critical" or len(attack_surface[host_addr]["critical_services"]) > 0:
                risk_assessment["critical_hosts"].append({
                    "host": host_addr,
                    "risk_level": risk_level,
                    "open_ports": open_ports,
                    "critical_services": len(attack_surface[host_addr]["critical_services"])
                })
        
        # Generate recommendations
        if risk_assessment["exposed_databases"]:
            recommendations.append("Secure or restrict access to exposed database services")
            
        if risk_assessment["management_interfaces"]:
            recommendations.append("Limit access to network management interfaces")
            
        if risk_assessment["high_risk_services"]:
            recommendations.append("Replace unencrypted services with secure alternatives")
            
        if risk_assessment["development_services"]:
            recommendations.append("Remove or secure development services in production")
        
        # General recommendations based on port count
        avg_ports = sum(len(h["ports"]) for h in parsed_data["hosts"]) / len(parsed_data["hosts"]) if parsed_data["hosts"] else 0
        if avg_ports > 10:
            recommendations.append("Review and reduce the number of exposed services per host")
        
        parsed_data["security_analysis"]["attack_surface"] = attack_surface
        parsed_data["security_analysis"]["risk_assessment"] = risk_assessment
        parsed_data["security_analysis"]["recommendations"] = recommendations

    def _update_statistics(self, parsed_data: Dict[str, Any]) -> None:
        """
        Update scan statistics.
        
        Args:
            parsed_data: Parsed data to update
        """
        stats = parsed_data["statistics"]
        hosts = parsed_data.get("hosts", [])
        
        stats["total_hosts"] = len(hosts)
        stats["responsive_hosts"] = len([h for h in hosts if h.get("port_count", 0) > 0])
        
        all_ports = []
        for host in hosts:
            all_ports.extend([p["port"] for p in host.get("ports", [])])
        
        stats["total_ports"] = len(all_ports)
        stats["unique_ports"] = len(set(all_ports))
        
        # Calculate scan speed if timing info available
        # This would need timing information from the scan process
        stats["scan_speed"] = 0  # Placeholder

    def extract_priority_targets(self, parsed_data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Extract priority targets for further investigation.
        
        Args:
            parsed_data: Parsed Naabu data
            
        Returns:
            List of priority targets
        """
        priority_targets = []
        
        # High-value port combinations
        valuable_combinations = [
            {"ports": [80, 443], "reason": "Web services with HTTP/HTTPS"},
            {"ports": [22, 80, 443], "reason": "Server with SSH and web services"},
            {"ports": [3306, 80], "reason": "Web application with MySQL"},
            {"ports": [5432, 80], "reason": "Web application with PostgreSQL"},
            {"ports": [21, 22, 80], "reason": "Server with multiple services"},
        ]
        
        for host in parsed_data.get("hosts", []):
            host_addr = host["host"]
            host_ports = set(p["port"] for p in host["ports"])
            risk_level = host.get("risk_level", "low")
            categories = host.get("categories", [])
            
            priority_score = 0
            reasons = []
            
            # Risk-based scoring
            if risk_level == "critical":
                priority_score += 50
                reasons.append("Critical risk level")
            elif risk_level == "high":
                priority_score += 30
                reasons.append("High risk level")
            
            # Port count scoring
            port_count = len(host_ports)
            if port_count > 10:
                priority_score += 25
                reasons.append(f"Many open ports ({port_count})")
            elif port_count > 5:
                priority_score += 15
                reasons.append(f"Multiple open ports ({port_count})")
            
            # Category-based scoring
            if "database" in categories:
                priority_score += 40
                reasons.append("Database services exposed")
            if "web" in categories:
                priority_score += 20
                reasons.append("Web services available")
            if "remote_access" in categories:
                priority_score += 25
                reasons.append("Remote access services")
            
            # Combination scoring
            for combo in valuable_combinations:
                if set(combo["ports"]).issubset(host_ports):
                    priority_score += 20
                    reasons.append(combo["reason"])
            
            # Administrative services
            admin_ports = [22, 23, 3389, 5900, 161]  # SSH, Telnet, RDP, VNC, SNMP
            admin_open = host_ports.intersection(set(admin_ports))
            if admin_open:
                priority_score += 15 * len(admin_open)
                reasons.append(f"Administrative services: {list(admin_open)}")
            
            if priority_score >= 30:  # Threshold for priority
                priority_targets.append({
                    "host": host_addr,
                    "priority_score": priority_score,
                    "reasons": reasons,
                    "open_ports": sorted(list(host_ports)),
                    "port_count": port_count,
                    "categories": categories,
                    "risk_level": risk_level
                })
        
        # Sort by priority score
        priority_targets.sort(key=lambda x: x["priority_score"], reverse=True)
        
        return priority_targets

    def generate_scan_report(self, parsed_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Generate a comprehensive scan report.
        
        Args:
            parsed_data: Parsed Naabu data
            
        Returns:
            Comprehensive report
        """
        report = {
            "executive_summary": {},
            "technical_findings": {},
            "risk_matrix": {},
            "action_items": []
        }
        
        stats = parsed_data.get("statistics", {})
        security_analysis = parsed_data.get("security_analysis", {})
        
        # Executive summary
        report["executive_summary"] = {
            "total_hosts_scanned": stats.get("total_hosts", 0),
            "responsive_hosts": stats.get("responsive_hosts", 0),
            "total_open_ports": stats.get("total_ports", 0),
            "unique_services": len(parsed_data.get("service_analysis", {})),
            "critical_findings": len(security_analysis.get("risk_assessment", {}).get("critical_hosts", [])),
            "overall_risk": self._calculate_overall_risk(parsed_data)
        }
        
        # Technical findings
        report["technical_findings"] = {
            "port_distribution": parsed_data.get("port_summary", {}).get("port_distribution", {}),
            "service_breakdown": {k: len(v.get("hosts", [])) for k, v in parsed_data.get("service_analysis", {}).items()},
            "most_common_ports": parsed_data.get("port_summary", {}).get("most_common_ports", [])[:5]
        }
        
        # Risk matrix
        risk_counts = {"low": 0, "medium": 0, "high": 0, "critical": 0}
        for host in parsed_data.get("hosts", []):
            risk_level = host.get("risk_level", "low")
            risk_counts[risk_level] += 1
        
        report["risk_matrix"] = risk_counts
        
        # Action items
        recommendations = security_analysis.get("recommendations", [])
        priority_targets = self.extract_priority_targets(parsed_data)
        
        action_items = []
        if priority_targets:
            action_items.append(f"Investigate {len(priority_targets)} high-priority hosts")
        
        action_items.extend(recommendations[:5])  # Top 5 recommendations
        report["action_items"] = action_items
        
        return report

    def _calculate_overall_risk(self, parsed_data: Dict[str, Any]) -> str:
        """
        Calculate overall risk level for the scan.
        
        Args:
            parsed_data: Parsed data
            
        Returns:
            Overall risk level
        """
        risk_assessment = parsed_data.get("security_analysis", {}).get("risk_assessment", {})
        
        if risk_assessment.get("exposed_databases") or risk_assessment.get("critical_hosts"):
            return "critical"
        elif risk_assessment.get("management_interfaces") or risk_assessment.get("high_risk_services"):
            return "high"
        elif len(parsed_data.get("hosts", [])) > 0:
            return "medium"
        else:
            return "low"