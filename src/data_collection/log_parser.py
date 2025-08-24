"""
Log parsing functionality for various log formats
"""
import re
import json
import csv
from datetime import datetime
from typing import Dict, List, Any, Optional
from pathlib import Path
import pandas as pd
from src.core.logger import logger

class LogParser:
    """Universal log parser for different log formats"""
    
    def __init__(self):
        self.parsers = {
            'apache': self._parse_apache_log,
            'nginx': self._parse_nginx_log,
            'syslog': self._parse_syslog,
            'windows_event': self._parse_windows_event,
            'firewall': self._parse_firewall_log,
            'json': self._parse_json_log,
            'csv': self._parse_csv_log
        }
        
        # Common regex patterns
        self.patterns = {
            'ip': r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b',
            'timestamp': r'\d{4}-\d{2}-\d{2}[T\s]\d{2}:\d{2}:\d{2}',
            'apache_common': r'(\S+) \S+ \S+ \[([\w:/]+\s[+\-]\d{4})\] "(\S+) (\S+) (\S+)" (\d{3}) (\d+)',
            'syslog': r'(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+(\S+)\s+(\S+):\s*(.*)'
        }
    
    def parse_log_file(self, file_path: str, log_type: str = 'auto') -> List[Dict[str, Any]]:
        """Parse a log file and return structured data"""
        try:
            file_path = Path(file_path)
            if not file_path.exists():
                raise FileNotFoundError(f"Log file not found: {file_path}")
            
            # Auto-detect log type if not specified
            if log_type == 'auto':
                log_type = self._detect_log_type(file_path)
            
            logger.info(f"Parsing log file: {file_path} (type: {log_type})")
            
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as file:
                lines = file.readlines()
            
            parser_func = self.parsers.get(log_type, self._parse_generic_log)
            parsed_logs = []
            
            for line_num, line in enumerate(lines, 1):
                try:
                    parsed_entry = parser_func(line.strip())
                    if parsed_entry:
                        parsed_entry['line_number'] = line_num
                        parsed_entry['source_file'] = str(file_path)
                        parsed_entry['log_type'] = log_type
                        parsed_logs.append(parsed_entry)
                except Exception as e:
                    logger.warning(f"Error parsing line {line_num}: {e}")
                    continue
            
            logger.info(f"Successfully parsed {len(parsed_logs)} log entries")
            return parsed_logs
            
        except Exception as e:
            logger.error(f"Error parsing log file {file_path}: {e}")
            return []
    
    def _detect_log_type(self, file_path: Path) -> str:
        """Auto-detect log type based on file extension and content"""
        extension = file_path.suffix.lower()
        
        if extension == '.json':
            return 'json'
        elif extension == '.csv':
            return 'csv'
        
        # Sample first few lines to detect format
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as file:
                sample_lines = [file.readline().strip() for _ in range(5)]
            
            sample_text = '\n'.join(sample_lines)
            
            if 'apache' in str(file_path).lower() or re.search(r'\d+\.\d+\.\d+\.\d+ - - \[', sample_text):
                return 'apache'
            elif 'nginx' in str(file_path).lower():
                return 'nginx'
            elif re.search(r'\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}', sample_text):
                return 'syslog'
            elif 'firewall' in str(file_path).lower() or 'fw' in str(file_path).lower():
                return 'firewall'
            
        except Exception:
            pass
        
        return 'generic'
    
    def _parse_apache_log(self, line: str) -> Optional[Dict[str, Any]]:
        """Parse Apache Common Log Format"""
        match = re.match(self.patterns['apache_common'], line)
        if match:
            return {
                'timestamp': self._parse_timestamp(match.group(2)),
                'client_ip': match.group(1),
                'method': match.group(3),
                'url': match.group(4),
                'protocol': match.group(5),
                'status_code': int(match.group(6)),
                'response_size': int(match.group(7)) if match.group(7) != '-' else 0,
                'raw_log': line
            }
        return None
    
    def _parse_nginx_log(self, line: str) -> Optional[Dict[str, Any]]:
        """Parse Nginx log format"""
        # Similar to Apache but with slight variations
        return self._parse_apache_log(line)
    
    def _parse_syslog(self, line: str) -> Optional[Dict[str, Any]]:
        """Parse syslog format"""
        match = re.match(self.patterns['syslog'], line)
        if match:
            return {
                'timestamp': self._parse_timestamp(match.group(1)),
                'hostname': match.group(2),
                'process': match.group(3),
                'message': match.group(4),
                'raw_log': line
            }
        return None
    
    def _parse_windows_event(self, line: str) -> Optional[Dict[str, Any]]:
        """Parse Windows Event Log format"""
        # Simplified Windows event log parsing
        if 'EventID' in line:
            return {
                'timestamp': datetime.now().isoformat(),
                'event_type': 'windows_event',
                'message': line,
                'raw_log': line
            }
        return None
    
    def _parse_firewall_log(self, line: str) -> Optional[Dict[str, Any]]:
        """Parse firewall log format"""
        # Extract common firewall log elements
        ip_matches = re.findall(self.patterns['ip'], line)
        timestamp_match = re.search(self.patterns['timestamp'], line)
        
        return {
            'timestamp': self._parse_timestamp(timestamp_match.group()) if timestamp_match else datetime.now().isoformat(),
            'source_ip': ip_matches[0] if len(ip_matches) > 0 else None,
            'destination_ip': ip_matches[1] if len(ip_matches) > 1 else None,
            'action': 'ALLOW' if 'ALLOW' in line.upper() else 'DENY' if 'DENY' in line.upper() else 'UNKNOWN',
            'message': line,
            'raw_log': line
        }
    
    def _parse_json_log(self, line: str) -> Optional[Dict[str, Any]]:
        """Parse JSON formatted logs"""
        try:
            data = json.loads(line)
            # Ensure timestamp is present
            if 'timestamp' not in data:
                data['timestamp'] = datetime.now().isoformat()
            data['raw_log'] = line
            return data
        except json.JSONDecodeError:
            return None
    
    def _parse_csv_log(self, line: str) -> Optional[Dict[str, Any]]:
        """Parse CSV formatted logs"""
        try:
            # This is a simplified CSV parser - in practice, you'd use pandas
            fields = line.split(',')
            return {
                'timestamp': datetime.now().isoformat(),
                'fields': fields,
                'raw_log': line
            }
        except Exception:
            return None
    
    def _parse_generic_log(self, line: str) -> Optional[Dict[str, Any]]:
        """Generic log parser for unknown formats"""
        if not line.strip():
            return None
        
        # Extract IP addresses
        ips = re.findall(self.patterns['ip'], line)
        
        # Extract timestamp
        timestamp_match = re.search(self.patterns['timestamp'], line)
        
        return {
            'timestamp': self._parse_timestamp(timestamp_match.group()) if timestamp_match else datetime.now().isoformat(),
            'ips_found': ips,
            'message': line,
            'raw_log': line
        }
    
    def _parse_timestamp(self, timestamp_str: str) -> str:
        """Parse various timestamp formats to ISO format"""
        try:
            # Try different timestamp formats
            formats = [
                '%Y-%m-%d %H:%M:%S',
                '%Y-%m-%dT%H:%M:%S',
                '%d/%b/%Y:%H:%M:%S %z',
                '%b %d %H:%M:%S',
                '%Y-%m-%d %H:%M:%S.%f'
            ]
            
            for fmt in formats:
                try:
                    # Try parsing the entire timestamp first to preserve information
                    dt = datetime.strptime(timestamp_str, fmt)
                    return dt.isoformat()
                except ValueError:
                    try:
                        # Some logs may include extra data after a space; fall back to the first token
                        dt = datetime.strptime(timestamp_str.split()[0], fmt)
                        return dt.isoformat()
                    except ValueError:
                        continue
            
            # If no format matches, return current time
            return datetime.now().isoformat()
            
        except Exception:
            return datetime.now().isoformat()