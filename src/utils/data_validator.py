"""
Data validation utilities for log entries
"""
import re
import ipaddress
from datetime import datetime
from typing import Dict, Any, List, Optional
from jsonschema import validate, ValidationError
from src.core.logger import logger

class LogDataValidator:
    """Validate and sanitize log data"""
    
    def __init__(self):
        # Define schema for security events
        self.security_event_schema = {
            "type": "object",
            "properties": {
                "timestamp": {"type": "string"},
                "event_id": {"type": "string"},
                "event_type": {"type": "string"},
                "severity": {"type": "string", "enum": ["LOW", "MEDIUM", "HIGH", "CRITICAL"]},
                "source_ip": {"type": "string"},
                "description": {"type": "string"}
            },
            "required": ["timestamp", "event_type", "severity"]
        }
    
    def validate_ip_address(self, ip: str) -> bool:
        """Validate IP address format"""
        try:
            ipaddress.ip_address(ip)
            return True
        except ValueError:
            return False
    
    def validate_timestamp(self, timestamp: str) -> bool:
        """Validate timestamp format"""
        try:
            datetime.fromisoformat(timestamp.replace('Z', '+00:00'))
            return True
        except ValueError:
            return False
    
    def sanitize_log_entry(self, entry: Dict[str, Any]) -> Dict[str, Any]:
        """Sanitize log entry data"""
        sanitized = {}
        
        for key, value in entry.items():
            if isinstance(value, str):
                # Remove potential injection attempts
                sanitized_value = re.sub(r'[<>"\';]', '', value)
                sanitized[key] = sanitized_value[:1000]  # Limit length
            else:
                sanitized[key] = value
        
        return sanitized
    
    def validate_security_event(self, event: Dict[str, Any]) -> bool:
        """Validate security event against schema"""
        try:
            validate(instance=event, schema=self.security_event_schema)
            return True
        except ValidationError as e:
            logger.warning(f"Validation error: {e.message}")
            return False
    
    def enrich_log_entry(self, entry: Dict[str, Any]) -> Dict[str, Any]:
        """Enrich log entry with additional metadata"""
        enriched = entry.copy()
        
        # Add processing timestamp
        enriched['processed_at'] = datetime.now().isoformat()
        
        # Add risk score based on content
        enriched['risk_score'] = self._calculate_risk_score(entry)
        
        # Add geolocation info (placeholder)
        if 'source_ip' in entry and self.validate_ip_address(entry['source_ip']):
            enriched['geo_info'] = self._get_geo_info(entry['source_ip'])
        
        return enriched
    
    def _calculate_risk_score(self, entry: Dict[str, Any]) -> int:
        """Calculate risk score for log entry"""
        score = 0
        
        # Check for suspicious keywords
        suspicious_keywords = [
            'admin', 'root', 'password', 'login', 'sql', 'script',
            'exec', 'cmd', 'shell', 'exploit', 'attack'
        ]
        
        content = str(entry).lower()
        for keyword in suspicious_keywords:
            if keyword in content:
                score += 10
        
        # Check severity if present
        if 'severity' in entry:
            severity_scores = {'LOW': 10, 'MEDIUM': 25, 'HIGH': 50, 'CRITICAL': 100}
            score += severity_scores.get(entry['severity'], 0)
        
        return min(score, 100)  # Cap at 100
    
    def _get_geo_info(self, ip: str) -> Dict[str, str]:
        """Get geolocation info for IP (placeholder implementation)"""
        # In a real implementation, you would use a GeoIP database
        return {
            'country': 'Unknown',
            'city': 'Unknown',
            'latitude': '0.0',
            'longitude': '0.0'
        }