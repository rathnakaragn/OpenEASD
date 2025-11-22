"""
OpenEASD Recon Layer - Subfinder Output Parser
6-Layer Architecture - Recon Layer

Dedicated parser for Subfinder output with enhanced processing capabilities.

Author: Rathnakara G N
Company: Cybersecify
Created: January 2025
"""

import json
import re
from typing import Dict, List, Optional, Any, Tuple
from datetime import datetime


class SubfinderParser:
    """
    Advanced parser for Subfinder output with comprehensive subdomain analysis.
    
    Features:
    - JSON and text output parsing
    - Subdomain validation and categorization
    - Source attribution and confidence scoring
    - Wildcard detection
    - Duplicate removal and normalization
    """
    
    def __init__(self):
        """Initialize the Subfinder parser."""
        # Subdomain categorization patterns
        self.subdomain_patterns = {
            'api': [r'^api\.', r'api\d*\.', r'.*api.*\.'],
            'admin': [r'^admin\.', r'^administrator\.', r'^manage\.', r'^control\.'],
            'dev': [r'^dev\.', r'^development\.', r'^test\.', r'^staging\.', r'^beta\.'],
            'mail': [r'^mail\.', r'^email\.', r'^smtp\.', r'^imap\.', r'^pop\.'],
            'web': [r'^www\.', r'^web\.', r'^portal\.', r'^site\.'],
            'cdn': [r'^cdn\.', r'^static\.', r'^assets\.', r'^img\.', r'^images\.'],
            'database': [r'^db\.', r'^database\.', r'^mysql\.', r'^postgres\.'],
            'monitoring': [r'^monitor\.', r'^stats\.', r'^metrics\.', r'^health\.'],
            'security': [r'^vpn\.', r'^security\.', r'^auth\.', r'^sso\.'],
            'backup': [r'^backup\.', r'^bak\.', r'^archive\.'],
            'internal': [r'^internal\.', r'^intranet\.', r'^private\.']
        }
        
        # Common false positive patterns
        self.false_positive_patterns = [
            r'^\*\..*',  # Wildcard domains
            r'.*\*.*',   # Contains asterisk
            r'^_.*',     # Starts with underscore (SRV records)
            r'.*localhost.*',  # Contains localhost
            r'.*example\.com.*',  # Example domains
            r'.*test\..*invalid.*'  # Test/invalid domains
        ]

    def parse(self, raw_output: str, target_domain: str) -> Dict[str, Any]:
        """
        Parse Subfinder output with enhanced processing.
        
        Args:
            raw_output: Raw output from Subfinder
            target_domain: Target domain being scanned
            
        Returns:
            Comprehensive parsed data structure
        """
        parsed_data = {
            "target_domain": target_domain,
            "subdomains": [],
            "subdomain_categories": {},
            "sources": {},
            "statistics": {
                "total_found": 0,
                "unique_subdomains": 0,
                "valid_subdomains": 0,
                "false_positives": 0,
                "wildcards_detected": 0
            },
            "parsing_metadata": {
                "parsed_at": datetime.utcnow().isoformat(),
                "parsing_errors": [],
                "warnings": []
            }
        }
        
        if not raw_output.strip():
            return parsed_data
        
        # Process each line
        raw_subdomains = []
        for line_num, line in enumerate(raw_output.strip().split('\n'), 1):
            line = line.strip()
            if not line:
                continue
                
            try:
                subdomain_data = self._parse_line(line, target_domain)
                if subdomain_data:
                    raw_subdomains.append(subdomain_data)
                    
            except Exception as e:
                parsed_data["parsing_metadata"]["parsing_errors"].append({
                    "line": line_num,
                    "content": line,
                    "error": str(e)
                })
        
        # Process and validate subdomains
        processed_subdomains = self._process_subdomains(raw_subdomains, target_domain)
        
        # Populate final data structure
        parsed_data["subdomains"] = processed_subdomains
        self._update_statistics(parsed_data)
        self._categorize_subdomains(parsed_data)
        self._analyze_sources(parsed_data)
        
        return parsed_data

    def _parse_line(self, line: str, target_domain: str) -> Optional[Dict[str, Any]]:
        """
        Parse individual line from Subfinder output.
        
        Args:
            line: Single line from output
            target_domain: Target domain
            
        Returns:
            Parsed subdomain data or None
        """
        try:
            # Try JSON parsing first
            if line.startswith('{'):
                data = json.loads(line)
                return {
                    "subdomain": data.get('host', '').strip().lower(),
                    "source": data.get('source', 'unknown'),
                    "ip": data.get('ip'),
                    "response_code": data.get('status_code'),
                    "title": data.get('title'),
                    "content_length": data.get('content_length'),
                    "is_wildcard": data.get('is_wildcard', False),
                    "timestamp": data.get('timestamp')
                }
            else:
                # Handle plain text output
                subdomain = self._extract_subdomain_from_text(line)
                if subdomain and self._is_valid_subdomain(subdomain, target_domain):
                    return {
                        "subdomain": subdomain,
                        "source": "unknown",
                        "ip": None,
                        "response_code": None,
                        "title": None,
                        "content_length": None,
                        "is_wildcard": False,
                        "timestamp": None
                    }
                    
        except json.JSONDecodeError:
            # Try text extraction as fallback
            subdomain = self._extract_subdomain_from_text(line)
            if subdomain and self._is_valid_subdomain(subdomain, target_domain):
                return {
                    "subdomain": subdomain,
                    "source": "unknown",
                    "ip": None,
                    "response_code": None,
                    "title": None,
                    "content_length": None,
                    "is_wildcard": False,
                    "timestamp": None
                }
                
        return None

    def _extract_subdomain_from_text(self, text: str) -> Optional[str]:
        """
        Extract subdomain from text using regex patterns.
        
        Args:
            text: Text potentially containing subdomain
            
        Returns:
            Extracted subdomain or None
        """
        # Domain pattern matching
        domain_patterns = [
            r'^([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$',  # Full domain
            r'https?://([a-zA-Z0-9\-\.]+)',  # From URLs
            r'([a-zA-Z0-9\-\.]+\.[a-zA-Z]{2,})',  # Domain in text
        ]
        
        for pattern in domain_patterns:
            match = re.search(pattern, text.strip())
            if match:
                domain = match.group(1) if pattern.startswith('https?') else match.group(0)
                return domain.lower().strip()
                
        return None

    def _is_valid_subdomain(self, subdomain: str, target_domain: str) -> bool:
        """
        Validate if subdomain is legitimate and related to target domain.
        
        Args:
            subdomain: Subdomain to validate
            target_domain: Target domain being scanned
            
        Returns:
            True if valid subdomain
        """
        if not subdomain:
            return False
            
        # Check if it's a subdomain of target domain
        if not subdomain.endswith('.' + target_domain) and subdomain != target_domain:
            return False
            
        # Check against false positive patterns
        for pattern in self.false_positive_patterns:
            if re.match(pattern, subdomain, re.IGNORECASE):
                return False
                
        # Basic format validation
        if len(subdomain) > 253:  # Max domain length
            return False
            
        # Check for invalid characters
        if not re.match(r'^[a-zA-Z0-9\-\.]+$', subdomain):
            return False
            
        # Check for consecutive dots or hyphens
        if '..' in subdomain or '--' in subdomain:
            return False
            
        return True

    def _process_subdomains(self, raw_subdomains: List[Dict[str, Any]], target_domain: str) -> List[Dict[str, Any]]:
        """
        Process and deduplicate subdomains with enhanced metadata.
        
        Args:
            raw_subdomains: Raw subdomain data
            target_domain: Target domain
            
        Returns:
            Processed and deduplicated subdomain list
        """
        processed = {}
        
        for subdomain_data in raw_subdomains:
            subdomain = subdomain_data.get("subdomain")
            if not subdomain or not self._is_valid_subdomain(subdomain, target_domain):
                continue
                
            if subdomain in processed:
                # Merge data for duplicate subdomains
                existing = processed[subdomain]
                
                # Update sources
                existing_sources = existing.setdefault("sources", [])
                new_source = subdomain_data.get("source", "unknown")
                if new_source not in existing_sources:
                    existing_sources.append(new_source)
                    
                # Update IP if not present
                if not existing.get("ip") and subdomain_data.get("ip"):
                    existing["ip"] = subdomain_data["ip"]
                    
                # Update response code if not present
                if not existing.get("response_code") and subdomain_data.get("response_code"):
                    existing["response_code"] = subdomain_data["response_code"]
                    
                # Update wildcard status
                if subdomain_data.get("is_wildcard"):
                    existing["is_wildcard"] = True
                    
            else:
                # New subdomain
                processed_data = {
                    "subdomain": subdomain,
                    "sources": [subdomain_data.get("source", "unknown")],
                    "ip": subdomain_data.get("ip"),
                    "response_code": subdomain_data.get("response_code"),
                    "title": subdomain_data.get("title"),
                    "content_length": subdomain_data.get("content_length"),
                    "is_wildcard": subdomain_data.get("is_wildcard", False),
                    "timestamp": subdomain_data.get("timestamp"),
                    "metadata": self._generate_subdomain_metadata(subdomain, target_domain)
                }
                
                processed[subdomain] = processed_data
        
        return list(processed.values())

    def _generate_subdomain_metadata(self, subdomain: str, target_domain: str) -> Dict[str, Any]:
        """
        Generate comprehensive metadata for a subdomain.
        
        Args:
            subdomain: Subdomain to analyze
            target_domain: Target domain
            
        Returns:
            Metadata dictionary
        """
        metadata = {
            "level": self._get_subdomain_level(subdomain, target_domain),
            "category": self._categorize_single_subdomain(subdomain),
            "is_numeric": self._contains_numbers(subdomain),
            "length": len(subdomain),
            "has_hyphen": '-' in subdomain,
            "suspicious_patterns": self._check_suspicious_patterns(subdomain)
        }
        
        return metadata

    def _get_subdomain_level(self, subdomain: str, target_domain: str) -> int:
        """
        Determine the level of the subdomain.
        
        Args:
            subdomain: Subdomain to analyze
            target_domain: Target domain
            
        Returns:
            Subdomain level (1 = direct subdomain)
        """
        if subdomain == target_domain:
            return 0
            
        # Remove target domain and count remaining levels
        if subdomain.endswith('.' + target_domain):
            prefix = subdomain[:-len('.' + target_domain)]
            return len(prefix.split('.'))
            
        return 0

    def _categorize_single_subdomain(self, subdomain: str) -> str:
        """
        Categorize a single subdomain based on its name.
        
        Args:
            subdomain: Subdomain to categorize
            
        Returns:
            Category name
        """
        for category, patterns in self.subdomain_patterns.items():
            for pattern in patterns:
                if re.search(pattern, subdomain, re.IGNORECASE):
                    return category
                    
        return 'unknown'

    def _contains_numbers(self, subdomain: str) -> bool:
        """Check if subdomain contains numeric characters."""
        return bool(re.search(r'\d', subdomain))

    def _check_suspicious_patterns(self, subdomain: str) -> List[str]:
        """
        Check for suspicious patterns in subdomain names.
        
        Args:
            subdomain: Subdomain to check
            
        Returns:
            List of suspicious patterns found
        """
        suspicious = []
        
        suspicious_patterns = {
            'long_random': r'^[a-f0-9]{16,}',  # Long hex strings
            'base64_like': r'^[A-Za-z0-9+/]{20,}={0,2}',  # Base64-like
            'excessive_hyphens': r'.*-.*-.*-.*',  # Many hyphens
            'numeric_only': r'^\d+\.',  # Only numbers
            'mixed_case_random': r'^[a-zA-Z0-9]{1}[a-zA-Z0-9]*[A-Z][a-z][A-Z]',  # Mixed case
        }
        
        for pattern_name, pattern in suspicious_patterns.items():
            if re.search(pattern, subdomain):
                suspicious.append(pattern_name)
                
        return suspicious

    def _update_statistics(self, parsed_data: Dict[str, Any]) -> None:
        """
        Update statistics in parsed data.
        
        Args:
            parsed_data: Parsed data to update
        """
        subdomains = parsed_data["subdomains"]
        stats = parsed_data["statistics"]
        
        stats["total_found"] = len(subdomains)
        stats["unique_subdomains"] = len(set(s["subdomain"] for s in subdomains))
        stats["valid_subdomains"] = len([s for s in subdomains if not s.get("is_wildcard")])
        stats["wildcards_detected"] = len([s for s in subdomains if s.get("is_wildcard")])
        
        # Calculate response statistics
        responded = len([s for s in subdomains if s.get("response_code")])
        stats["response_rate"] = (responded / len(subdomains)) * 100 if subdomains else 0

    def _categorize_subdomains(self, parsed_data: Dict[str, Any]) -> None:
        """
        Categorize subdomains and update category statistics.
        
        Args:
            parsed_data: Parsed data to update
        """
        categories = {}
        
        for subdomain_data in parsed_data["subdomains"]:
            category = subdomain_data.get("metadata", {}).get("category", "unknown")
            
            if category not in categories:
                categories[category] = {
                    "count": 0,
                    "subdomains": []
                }
                
            categories[category]["count"] += 1
            categories[category]["subdomains"].append(subdomain_data["subdomain"])
            
        parsed_data["subdomain_categories"] = categories

    def _analyze_sources(self, parsed_data: Dict[str, Any]) -> None:
        """
        Analyze and aggregate source information.
        
        Args:
            parsed_data: Parsed data to update
        """
        sources = {}
        
        for subdomain_data in parsed_data["subdomains"]:
            for source in subdomain_data.get("sources", []):
                if source not in sources:
                    sources[source] = {
                        "count": 0,
                        "percentage": 0.0
                    }
                    
                sources[source]["count"] += 1
        
        # Calculate percentages
        total = len(parsed_data["subdomains"])
        if total > 0:
            for source_data in sources.values():
                source_data["percentage"] = (source_data["count"] / total) * 100
                
        parsed_data["sources"] = sources

    def extract_high_value_targets(self, parsed_data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Extract high-value subdomains for prioritized scanning.
        
        Args:
            parsed_data: Parsed Subfinder data
            
        Returns:
            List of high-value subdomain targets
        """
        high_value = []
        
        # Priority categories
        priority_categories = ['admin', 'api', 'dev', 'database', 'security']
        
        for subdomain_data in parsed_data.get("subdomains", []):
            metadata = subdomain_data.get("metadata", {})
            category = metadata.get("category", "unknown")
            
            priority_score = 0
            reasons = []
            
            # Category-based scoring
            if category in priority_categories:
                priority_score += 30
                reasons.append(f"High-value category: {category}")
                
            # Response code indicates active service
            if subdomain_data.get("response_code"):
                priority_score += 20
                reasons.append("Active HTTP response")
                
            # Has IP address
            if subdomain_data.get("ip"):
                priority_score += 15
                reasons.append("Has IP resolution")
                
            # Multiple sources found it
            source_count = len(subdomain_data.get("sources", []))
            if source_count > 1:
                priority_score += 10 * source_count
                reasons.append(f"Found by {source_count} sources")
                
            # Suspicious patterns might indicate hidden services
            suspicious = metadata.get("suspicious_patterns", [])
            if suspicious:
                priority_score += 25
                reasons.append(f"Suspicious patterns: {', '.join(suspicious)}")
                
            if priority_score >= 30:  # Threshold for high-value
                high_value.append({
                    "subdomain": subdomain_data["subdomain"],
                    "priority_score": priority_score,
                    "reasons": reasons,
                    "category": category,
                    "metadata": metadata
                })
        
        # Sort by priority score
        high_value.sort(key=lambda x: x["priority_score"], reverse=True)
        
        return high_value