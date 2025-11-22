"""
OpenEASD Recon Layer - WHOIS Output Parser
6-Layer Architecture - Recon Layer

Dedicated parser for WHOIS output with enhanced domain intelligence capabilities.

Author: Rathnakara G N
Company: Cybersecify
Created: January 2025
"""

import re
from typing import Dict, List, Optional, Any, Tuple
from datetime import datetime, timezone
import calendar


class WhoisParser:
    """
    Advanced parser for WHOIS text output with comprehensive domain analysis.
    
    Features:
    - Multi-format date parsing
    - Registrar and contact extraction
    - Security posture assessment
    - Domain lifecycle analysis
    - Brand protection insights
    - Compliance checking
    """
    
    def __init__(self):
        """Initialize the WHOIS parser."""
        # Domain status risk assessment
        self.status_risks = {
            'clientTransferProhibited': {'risk': 'low', 'description': 'Transfer protection enabled'},
            'clientUpdateProhibited': {'risk': 'low', 'description': 'Update protection enabled'},
            'clientDeleteProhibited': {'risk': 'low', 'description': 'Delete protection enabled'},
            'serverTransferProhibited': {'risk': 'low', 'description': 'Registry transfer lock'},
            'serverUpdateProhibited': {'risk': 'low', 'description': 'Registry update lock'},
            'serverDeleteProhibited': {'risk': 'low', 'description': 'Registry delete lock'},
            'clientHold': {'risk': 'high', 'description': 'Domain on hold - resolution disabled'},
            'serverHold': {'risk': 'high', 'description': 'Registry hold - resolution disabled'},
            'redemptionPeriod': {'risk': 'critical', 'description': 'Domain in redemption period'},
            'pendingDelete': {'risk': 'critical', 'description': 'Domain pending deletion'},
            'inactive': {'risk': 'medium', 'description': 'Domain inactive'},
            'ok': {'risk': 'low', 'description': 'No restrictions'}
        }
        
        # Privacy service indicators
        self.privacy_indicators = [
            'domains by proxy', 'whoisguard', 'privacy protection', 'private registrant',
            'redacted for privacy', 'data protected', 'contact privacy', 'whois privacy',
            'domain privacy', 'registrant protected', 'proxy protection'
        ]
        
        # Suspicious registrar patterns
        self.suspicious_patterns = [
            'privacy', 'proxy', 'guard', 'protect', 'anonymous', 'hidden',
            'private', 'redacted', 'masked', 'shielded'
        ]

    def parse(self, raw_output: str, domain: str) -> Dict[str, Any]:
        """
        Parse WHOIS output with enhanced domain intelligence.
        
        Args:
            raw_output: Raw WHOIS output
            domain: Domain being queried
            
        Returns:
            Comprehensive parsed data structure
        """
        parsed_data = {
            "domain": domain,
            "registration_info": {},
            "contacts": {
                "registrant": {},
                "admin": {},
                "tech": {},
                "billing": {}
            },
            "technical_info": {
                "nameservers": [],
                "dnssec": None,
                "status": []
            },
            "security_analysis": {
                "risk_factors": [],
                "security_posture": "unknown",
                "recommendations": [],
                "privacy_protected": False
            },
            "lifecycle_analysis": {
                "domain_age_days": None,
                "days_until_expiry": None,
                "renewal_urgency": "unknown",
                "registration_period": None
            },
            "intelligence": {
                "registrar_reputation": "unknown",
                "hosting_insights": {},
                "brand_protection": {}
            },
            "parsing_metadata": {
                "parsed_at": datetime.utcnow().isoformat(),
                "parsing_errors": [],
                "warnings": [],
                "data_completeness": 0.0
            }
        }
        
        if not raw_output.strip():
            parsed_data["parsing_metadata"]["warnings"].append("No WHOIS data received")
            return parsed_data
        
        # Parse raw WHOIS data
        self._parse_whois_fields(raw_output, parsed_data)
        
        # Perform advanced analysis
        self._analyze_security_posture(parsed_data)
        self._analyze_lifecycle(parsed_data)
        self._analyze_intelligence(parsed_data)
        self._assess_data_completeness(parsed_data)
        
        return parsed_data

    def _parse_whois_fields(self, raw_output: str, parsed_data: Dict[str, Any]) -> None:
        """
        Parse WHOIS fields from raw output.
        
        Args:
            raw_output: Raw WHOIS output
            parsed_data: Data structure to populate
        """
        lines = raw_output.strip().split('\n')
        
        for line_num, line in enumerate(lines, 1):
            line = line.strip()
            if not line or line.startswith('%') or line.startswith('#') or line.startswith(';'):
                continue
            
            try:
                self._parse_whois_line(line, parsed_data)
            except Exception as e:
                parsed_data["parsing_metadata"]["parsing_errors"].append({
                    "line": line_num,
                    "content": line,
                    "error": str(e)
                })

    def _parse_whois_line(self, line: str, parsed_data: Dict[str, Any]) -> None:
        """
        Parse individual WHOIS line using comprehensive field patterns.
        
        Args:
            line: WHOIS line to parse
            parsed_data: Data structure to populate
        """
        # Define comprehensive field patterns
        field_mappings = {
            # Domain information
            r'domain name?:?\s*(.+)': ('registration_info', 'domain_name'),
            r'domain:?\s*(.+)': ('registration_info', 'domain_name'),
            
            # Registrar information
            r'registrar:?\s*(.+)': ('registration_info', 'registrar_name'),
            r'registrar name:?\s*(.+)': ('registration_info', 'registrar_name'),
            r'sponsoring registrar:?\s*(.+)': ('registration_info', 'registrar_name'),
            r'registrar url:?\s*(.+)': ('registration_info', 'registrar_url'),
            r'registrar iana id:?\s*(.+)': ('registration_info', 'registrar_iana_id'),
            r'registrar abuse contact email:?\s*(.+)': ('registration_info', 'registrar_abuse_email'),
            r'registrar abuse contact phone:?\s*(.+)': ('registration_info', 'registrar_abuse_phone'),
            
            # Registration dates
            r'creation date:?\s*(.+)': ('registration_info', 'created_date'),
            r'created on:?\s*(.+)': ('registration_info', 'created_date'),
            r'registered on:?\s*(.+)': ('registration_info', 'created_date'),
            r'registration time:?\s*(.+)': ('registration_info', 'created_date'),
            r'updated date:?\s*(.+)': ('registration_info', 'updated_date'),
            r'last updated:?\s*(.+)': ('registration_info', 'updated_date'),
            r'modified:?\s*(.+)': ('registration_info', 'updated_date'),
            r'registry expiry date:?\s*(.+)': ('registration_info', 'expiry_date'),
            r'registrar registration expiration date:?\s*(.+)': ('registration_info', 'expiry_date'),
            r'expir[ey] date?.*:?\s*(.+)': ('registration_info', 'expiry_date'),
            r'expires on:?\s*(.+)': ('registration_info', 'expiry_date'),
            
            # Domain status
            r'domain status:?\s*(.+)': ('technical_info', 'status'),
            r'status:?\s*(.+)': ('technical_info', 'status'),
            
            # Nameservers
            r'name server:?\s*(.+)': ('technical_info', 'nameservers'),
            r'nserver:?\s*(.+)': ('technical_info', 'nameservers'),
            r'dns:?\s*(.+)': ('technical_info', 'nameservers'),
            
            # DNSSEC
            r'dnssec:?\s*(.+)': ('technical_info', 'dnssec'),
            r'dnssec delegation signed:?\s*(.+)': ('technical_info', 'dnssec'),
            
            # Contact information patterns
            r'registrant name:?\s*(.+)': ('contacts', 'registrant', 'name'),
            r'registrant organization:?\s*(.+)': ('contacts', 'registrant', 'organization'),
            r'registrant email:?\s*(.+)': ('contacts', 'registrant', 'email'),
            r'registrant phone:?\s*(.+)': ('contacts', 'registrant', 'phone'),
            r'registrant country:?\s*(.+)': ('contacts', 'registrant', 'country'),
            r'registrant street:?\s*(.+)': ('contacts', 'registrant', 'street'),
            r'registrant city:?\s*(.+)': ('contacts', 'registrant', 'city'),
            r'registrant postal code:?\s*(.+)': ('contacts', 'registrant', 'postal_code'),
            
            # Admin contact
            r'admin name:?\s*(.+)': ('contacts', 'admin', 'name'),
            r'administrative contact name:?\s*(.+)': ('contacts', 'admin', 'name'),
            r'admin organization:?\s*(.+)': ('contacts', 'admin', 'organization'),
            r'admin email:?\s*(.+)': ('contacts', 'admin', 'email'),
            r'admin phone:?\s*(.+)': ('contacts', 'admin', 'phone'),
            r'admin country:?\s*(.+)': ('contacts', 'admin', 'country'),
            
            # Tech contact
            r'tech name:?\s*(.+)': ('contacts', 'tech', 'name'),
            r'technical contact name:?\s*(.+)': ('contacts', 'tech', 'name'),
            r'tech organization:?\s*(.+)': ('contacts', 'tech', 'organization'),
            r'tech email:?\s*(.+)': ('contacts', 'tech', 'email'),
            r'tech phone:?\s*(.+)': ('contacts', 'tech', 'phone'),
            r'tech country:?\s*(.+)': ('contacts', 'tech', 'country'),
        }
        
        # Try to match line against patterns
        for pattern, path in field_mappings.items():
            match = re.search(pattern, line, re.IGNORECASE)
            if match:
                value = match.group(1).strip()
                self._set_nested_value(parsed_data, path, value)
                break

    def _set_nested_value(self, data: Dict[str, Any], path: Tuple[str, ...], value: str) -> None:
        """
        Set value in nested dictionary structure.
        
        Args:
            data: Dictionary to update
            path: Tuple representing nested path
            value: Value to set
        """
        current = data
        
        # Navigate to the correct nested level
        for key in path[:-1]:
            if key not in current:
                current[key] = {}
            current = current[key]
        
        final_key = path[-1]
        
        # Handle special cases for list fields
        if final_key in ['status', 'nameservers']:
            if final_key not in current:
                current[final_key] = []
            
            # Clean and add value if not already present
            clean_value = self._clean_field_value(final_key, value)
            if clean_value and clean_value not in current[final_key]:
                current[final_key].append(clean_value)
        else:
            # Handle single value fields
            if final_key not in current or not current[final_key]:
                current[final_key] = self._clean_field_value(final_key, value)

    def _clean_field_value(self, field_name: str, value: str) -> str:
        """
        Clean and normalize field values.
        
        Args:
            field_name: Name of the field
            value: Raw value to clean
            
        Returns:
            Cleaned value
        """
        if not value:
            return value
            
        # Remove extra whitespace
        value = ' '.join(value.split())
        
        # Field-specific cleaning
        if field_name == 'domain_name':
            return value.lower()
        elif field_name in ['created_date', 'updated_date', 'expiry_date']:
            return self._normalize_date(value)
        elif field_name == 'status':
            # Remove URLs and extra info from status
            return value.split('(')[0].split('https://')[0].strip()
        elif field_name == 'nameservers':
            # Extract just the nameserver name, remove IPs
            return value.split()[0].lower().rstrip('.')
        elif field_name == 'dnssec':
            value_lower = value.lower()
            if 'yes' in value_lower or 'signed' in value_lower:
                return 'enabled'
            elif 'no' in value_lower or 'unsigned' in value_lower:
                return 'disabled'
            return 'unknown'
        
        return value

    def _normalize_date(self, date_str: str) -> Optional[str]:
        """
        Normalize various date formats to ISO format.
        
        Args:
            date_str: Date string to normalize
            
        Returns:
            ISO format date string or original if parsing fails
        """
        if not date_str:
            return None
        
        # Remove common suffixes and normalize
        date_str = re.sub(r'\s*\(.*\)$', '', date_str)  # Remove parenthetical info
        date_str = re.sub(r'\s*UTC.*$', '', date_str, re.IGNORECASE)  # Remove timezone info
        date_str = date_str.strip()
        
        # Try various date patterns
        date_patterns = [
            (r'(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})Z?', '%Y-%m-%dT%H:%M:%S'),
            (r'(\d{4}-\d{2}-\d{2})\s+\d{2}:\d{2}:\d{2}', '%Y-%m-%d'),
            (r'(\d{4}-\d{2}-\d{2})', '%Y-%m-%d'),
            (r'(\d{2})-(\d{2})-(\d{4})', None),  # MM-DD-YYYY, needs special handling
            (r'(\d{2})\.(\d{2})\.(\d{4})', None),  # DD.MM.YYYY, needs special handling
            (r'(\d{2})/(\d{2})/(\d{4})', None),  # MM/DD/YYYY, needs special handling
            (r'(\d{1,2})\s+(Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\s+(\d{4})', None),  # DD Mon YYYY
        ]
        
        for pattern, fmt in date_patterns:
            match = re.search(pattern, date_str, re.IGNORECASE)
            if match:
                try:
                    if fmt:
                        # Direct parsing with strptime
                        date_obj = datetime.strptime(match.group(1), fmt)
                        return date_obj.strftime('%Y-%m-%d')
                    else:
                        # Custom parsing for specific formats
                        groups = match.groups()
                        if len(groups) == 3:
                            if groups[1].isalpha():  # Month name format
                                day, month_name, year = groups
                                month_map = {
                                    'jan': 1, 'feb': 2, 'mar': 3, 'apr': 4, 'may': 5, 'jun': 6,
                                    'jul': 7, 'aug': 8, 'sep': 9, 'oct': 10, 'nov': 11, 'dec': 12
                                }
                                month = month_map.get(month_name.lower()[:3])
                                if month:
                                    return f"{year}-{month:02d}-{int(day):02d}"
                            else:
                                # Numeric format - determine order
                                if '.' in date_str:  # DD.MM.YYYY
                                    day, month, year = groups
                                    return f"{year}-{int(month):02d}-{int(day):02d}"
                                else:  # MM-DD-YYYY or MM/DD/YYYY
                                    month, day, year = groups
                                    return f"{year}-{int(month):02d}-{int(day):02d}"
                except (ValueError, KeyError):
                    continue
        
        return date_str  # Return original if no pattern matched

    def _analyze_security_posture(self, parsed_data: Dict[str, Any]) -> None:
        """
        Analyze domain security posture and identify risks.
        
        Args:
            parsed_data: Parsed data to analyze
        """
        security_analysis = parsed_data["security_analysis"]
        risk_factors = []
        recommendations = []
        
        # Analyze domain status
        status_list = parsed_data.get("technical_info", {}).get("status", [])
        security_score = 0
        
        for status in status_list:
            if status in self.status_risks:
                risk_info = self.status_risks[status]
                risk_factors.append({
                    "type": "domain_status",
                    "status": status,
                    "risk_level": risk_info["risk"],
                    "description": risk_info["description"]
                })
                
                if risk_info["risk"] == "low":
                    security_score += 10
                elif risk_info["risk"] == "high":
                    security_score -= 20
                elif risk_info["risk"] == "critical":
                    security_score -= 50
        
        # Check privacy protection
        contacts = parsed_data.get("contacts", {})
        privacy_protected = False
        
        for contact_type, contact_info in contacts.items():
            if contact_info:
                for field, value in contact_info.items():
                    if value and any(indicator in value.lower() for indicator in self.privacy_indicators):
                        privacy_protected = True
                        break
                if privacy_protected:
                    break
        
        security_analysis["privacy_protected"] = privacy_protected
        
        if privacy_protected:
            risk_factors.append({
                "type": "privacy_protection",
                "risk_level": "low",
                "description": "Domain uses privacy protection service"
            })
            security_score += 5
        else:
            risk_factors.append({
                "type": "exposed_contacts",
                "risk_level": "medium",
                "description": "Contact information exposed in WHOIS"
            })
            recommendations.append("Consider enabling WHOIS privacy protection")
        
        # DNSSEC analysis
        dnssec = parsed_data.get("technical_info", {}).get("dnssec")
        if dnssec == "enabled":
            security_score += 15
            risk_factors.append({
                "type": "dnssec_enabled",
                "risk_level": "low",
                "description": "DNSSEC is properly configured"
            })
        elif dnssec == "disabled":
            risk_factors.append({
                "type": "dnssec_disabled",
                "risk_level": "medium",
                "description": "DNSSEC is not enabled"
            })
            recommendations.append("Enable DNSSEC for improved DNS security")
        
        # Registrar analysis
        registrar_name = parsed_data.get("registration_info", {}).get("registrar_name", "").lower()
        if any(pattern in registrar_name for pattern in self.suspicious_patterns):
            risk_factors.append({
                "type": "suspicious_registrar",
                "risk_level": "medium",
                "description": "Registrar associated with privacy services"
            })
        
        # Determine overall security posture
        if security_score >= 20:
            security_posture = "strong"
        elif security_score >= 0:
            security_posture = "moderate"
        elif security_score >= -20:
            security_posture = "weak"
        else:
            security_posture = "poor"
        
        security_analysis["risk_factors"] = risk_factors
        security_analysis["security_posture"] = security_posture
        security_analysis["recommendations"] = recommendations
        security_analysis["security_score"] = security_score

    def _analyze_lifecycle(self, parsed_data: Dict[str, Any]) -> None:
        """
        Analyze domain lifecycle and expiration risks.
        
        Args:
            parsed_data: Parsed data to analyze
        """
        lifecycle_analysis = parsed_data["lifecycle_analysis"]
        reg_info = parsed_data.get("registration_info", {})
        
        now = datetime.now(timezone.utc)
        
        # Parse dates
        created_date = self._parse_iso_date(reg_info.get("created_date"))
        expiry_date = self._parse_iso_date(reg_info.get("expiry_date"))
        updated_date = self._parse_iso_date(reg_info.get("updated_date"))
        
        # Calculate domain age
        if created_date:
            domain_age = (now - created_date).days
            lifecycle_analysis["domain_age_days"] = domain_age
            
            if domain_age < 30:
                parsed_data["security_analysis"]["risk_factors"].append({
                    "type": "new_domain",
                    "risk_level": "medium",
                    "description": f"Domain registered only {domain_age} days ago"
                })
        
        # Calculate expiry information
        if expiry_date:
            days_until_expiry = (expiry_date - now).days
            lifecycle_analysis["days_until_expiry"] = days_until_expiry
            
            # Determine renewal urgency
            if days_until_expiry < 30:
                lifecycle_analysis["renewal_urgency"] = "critical"
                parsed_data["security_analysis"]["risk_factors"].append({
                    "type": "expiring_soon",
                    "risk_level": "high",
                    "description": f"Domain expires in {days_until_expiry} days"
                })
                parsed_data["security_analysis"]["recommendations"].append("Renew domain immediately")
            elif days_until_expiry < 90:
                lifecycle_analysis["renewal_urgency"] = "high"
                parsed_data["security_analysis"]["risk_factors"].append({
                    "type": "expiring_within_90_days",
                    "risk_level": "medium", 
                    "description": f"Domain expires in {days_until_expiry} days"
                })
                parsed_data["security_analysis"]["recommendations"].append("Plan domain renewal")
            elif days_until_expiry < 365:
                lifecycle_analysis["renewal_urgency"] = "medium"
            else:
                lifecycle_analysis["renewal_urgency"] = "low"
        
        # Calculate registration period
        if created_date and expiry_date:
            total_period = (expiry_date - created_date).days
            lifecycle_analysis["registration_period"] = total_period

    def _parse_iso_date(self, date_str: Optional[str]) -> Optional[datetime]:
        """
        Parse ISO date string to datetime object.
        
        Args:
            date_str: ISO date string
            
        Returns:
            Datetime object or None
        """
        if not date_str:
            return None
            
        try:
            # Try parsing different formats
            formats = ['%Y-%m-%d', '%Y-%m-%dT%H:%M:%S', '%Y-%m-%dT%H:%M:%SZ']
            for fmt in formats:
                try:
                    dt = datetime.strptime(date_str, fmt)
                    return dt.replace(tzinfo=timezone.utc)
                except ValueError:
                    continue
        except:
            pass
            
        return None

    def _analyze_intelligence(self, parsed_data: Dict[str, Any]) -> None:
        """
        Perform domain intelligence analysis.
        
        Args:
            parsed_data: Parsed data to analyze
        """
        intelligence = parsed_data["intelligence"]
        reg_info = parsed_data.get("registration_info", {})
        
        # Registrar reputation analysis
        registrar_name = reg_info.get("registrar_name", "").lower()
        
        # Well-known reputable registrars
        reputable_registrars = [
            'godaddy', 'namecheap', 'google', 'cloudflare', 'amazon',
            'verisign', 'network solutions', 'tucows', 'enom'
        ]
        
        if any(rep_reg in registrar_name for rep_reg in reputable_registrars):
            intelligence["registrar_reputation"] = "high"
        elif any(susp_pattern in registrar_name for susp_pattern in self.suspicious_patterns):
            intelligence["registrar_reputation"] = "low"
        else:
            intelligence["registrar_reputation"] = "unknown"
        
        # Nameserver analysis
        nameservers = parsed_data.get("technical_info", {}).get("nameservers", [])
        if nameservers:
            # Analyze hosting patterns
            hosting_providers = {}
            for ns in nameservers:
                if 'cloudflare' in ns:
                    hosting_providers['cloudflare'] = 'CDN/Security'
                elif 'amazon' in ns or 'aws' in ns:
                    hosting_providers['aws'] = 'Cloud Hosting'
                elif 'google' in ns:
                    hosting_providers['google'] = 'Cloud Hosting'
                elif 'godaddy' in ns:
                    hosting_providers['godaddy'] = 'Domain Registrar'
                elif 'namecheap' in ns:
                    hosting_providers['namecheap'] = 'Domain Registrar'
            
            intelligence["hosting_insights"] = {
                "nameserver_count": len(nameservers),
                "hosting_providers": hosting_providers,
                "uses_major_provider": len(hosting_providers) > 0
            }
        
        # Brand protection analysis
        domain = parsed_data.get("domain", "").lower()
        brand_indicators = []
        
        # Check for trademark indicators
        if any(indicator in domain for indicator in ['-tm', 'trademark', 'brand']):
            brand_indicators.append("trademark_related")
        
        # Check for corporate indicators  
        if any(indicator in domain for indicator in ['corp', 'inc', 'ltd', 'llc', 'company']):
            brand_indicators.append("corporate_entity")
        
        intelligence["brand_protection"] = {
            "brand_indicators": brand_indicators,
            "likely_commercial": len(brand_indicators) > 0
        }

    def _assess_data_completeness(self, parsed_data: Dict[str, Any]) -> None:
        """
        Assess completeness of parsed WHOIS data.
        
        Args:
            parsed_data: Parsed data to assess
        """
        # Define expected fields and their weights
        expected_fields = {
            ("registration_info", "registrar_name"): 10,
            ("registration_info", "created_date"): 15,
            ("registration_info", "expiry_date"): 15,
            ("registration_info", "updated_date"): 10,
            ("technical_info", "nameservers"): 15,
            ("technical_info", "status"): 10,
            ("technical_info", "dnssec"): 5,
            ("contacts", "registrant", "name"): 10,
            ("contacts", "admin", "email"): 5,
            ("contacts", "tech", "email"): 5
        }
        
        total_weight = sum(expected_fields.values())
        found_weight = 0
        
        for field_path, weight in expected_fields.items():
            current = parsed_data
            try:
                for key in field_path:
                    current = current.get(key, {})
                
                if current:  # Field has data
                    if isinstance(current, list) and len(current) > 0:
                        found_weight += weight
                    elif isinstance(current, str) and current.strip():
                        found_weight += weight
                    elif isinstance(current, dict) and current:
                        found_weight += weight
                        
            except (AttributeError, TypeError):
                continue
        
        completeness = (found_weight / total_weight) * 100 if total_weight > 0 else 0
        parsed_data["parsing_metadata"]["data_completeness"] = round(completeness, 1)

    def extract_threat_indicators(self, parsed_data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Extract potential threat indicators from WHOIS data.
        
        Args:
            parsed_data: Parsed WHOIS data
            
        Returns:
            List of threat indicators
        """
        indicators = []
        
        # Recent registration (potentially suspicious)
        domain_age = parsed_data.get("lifecycle_analysis", {}).get("domain_age_days")
        if domain_age is not None and domain_age < 30:
            indicators.append({
                "type": "recent_registration",
                "severity": "medium",
                "description": f"Domain registered {domain_age} days ago",
                "value": domain_age
            })
        
        # Privacy protection (could hide malicious actors)
        if parsed_data.get("security_analysis", {}).get("privacy_protected"):
            indicators.append({
                "type": "privacy_protected",
                "severity": "low",
                "description": "Domain uses privacy protection service",
                "value": True
            })
        
        # Domain holds or restrictions
        status_list = parsed_data.get("technical_info", {}).get("status", [])
        critical_statuses = ["clientHold", "serverHold", "redemptionPeriod", "pendingDelete"]
        
        for status in status_list:
            if any(critical in status for critical in critical_statuses):
                indicators.append({
                    "type": "domain_hold",
                    "severity": "high",
                    "description": f"Domain has status: {status}",
                    "value": status
                })
        
        # Missing DNSSEC
        dnssec = parsed_data.get("technical_info", {}).get("dnssec")
        if dnssec == "disabled":
            indicators.append({
                "type": "no_dnssec",
                "severity": "medium",
                "description": "DNSSEC not enabled",
                "value": False
            })
        
        # Suspicious registrar
        registrar_rep = parsed_data.get("intelligence", {}).get("registrar_reputation")
        if registrar_rep == "low":
            indicators.append({
                "type": "suspicious_registrar",
                "severity": "medium",
                "description": "Registrar associated with privacy/proxy services",
                "value": parsed_data.get("registration_info", {}).get("registrar_name")
            })
        
        return indicators

    def generate_domain_profile(self, parsed_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Generate comprehensive domain profile for intelligence purposes.
        
        Args:
            parsed_data: Parsed WHOIS data
            
        Returns:
            Domain profile summary
        """
        profile = {
            "domain_summary": {},
            "security_summary": {},
            "operational_summary": {},
            "risk_summary": {}
        }
        
        # Domain summary
        reg_info = parsed_data.get("registration_info", {})
        lifecycle = parsed_data.get("lifecycle_analysis", {})
        
        profile["domain_summary"] = {
            "domain": parsed_data.get("domain"),
            "registrar": reg_info.get("registrar_name"),
            "age_days": lifecycle.get("domain_age_days"),
            "expires_in_days": lifecycle.get("days_until_expiry"),
            "privacy_protected": parsed_data.get("security_analysis", {}).get("privacy_protected"),
            "data_completeness": parsed_data.get("parsing_metadata", {}).get("data_completeness")
        }
        
        # Security summary
        security = parsed_data.get("security_analysis", {})
        profile["security_summary"] = {
            "security_posture": security.get("security_posture"),
            "dnssec_enabled": parsed_data.get("technical_info", {}).get("dnssec") == "enabled",
            "risk_factors_count": len(security.get("risk_factors", [])),
            "high_risk_factors": [r for r in security.get("risk_factors", []) if r.get("risk_level") in ["high", "critical"]]
        }
        
        # Operational summary
        tech_info = parsed_data.get("technical_info", {})
        intelligence = parsed_data.get("intelligence", {})
        
        profile["operational_summary"] = {
            "nameserver_count": len(tech_info.get("nameservers", [])),
            "status_count": len(tech_info.get("status", [])),
            "registrar_reputation": intelligence.get("registrar_reputation"),
            "uses_major_hosting": intelligence.get("hosting_insights", {}).get("uses_major_provider", False)
        }
        
        # Risk summary
        threat_indicators = self.extract_threat_indicators(parsed_data)
        profile["risk_summary"] = {
            "overall_risk": self._calculate_overall_risk_level(parsed_data),
            "threat_indicators": len(threat_indicators),
            "critical_issues": len([t for t in threat_indicators if t["severity"] == "high"]),
            "renewal_urgency": lifecycle.get("renewal_urgency", "unknown")
        }
        
        return profile

    def _calculate_overall_risk_level(self, parsed_data: Dict[str, Any]) -> str:
        """
        Calculate overall risk level for the domain.
        
        Args:
            parsed_data: Parsed WHOIS data
            
        Returns:
            Overall risk level
        """
        risk_factors = parsed_data.get("security_analysis", {}).get("risk_factors", [])
        
        critical_count = len([r for r in risk_factors if r.get("risk_level") == "critical"])
        high_count = len([r for r in risk_factors if r.get("risk_level") == "high"])
        
        if critical_count > 0:
            return "critical"
        elif high_count > 2:
            return "high"
        elif high_count > 0:
            return "medium"
        else:
            return "low"