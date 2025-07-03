"""
Generate sample security log data for testing and demonstration
"""
import random
import json
from datetime import datetime, timedelta
from typing import List, Dict, Any
from faker import Faker
import ipaddress
from src.core.logger import logger
from src.core.config import config

class SecurityLogGenerator:
    """Generate realistic security log data for testing"""
    
    def __init__(self):
        self.fake = Faker()
        self.security_config = config.get_security_config()
        self.threat_indicators = self.security_config.get('threat_indicators', [])
        self.suspicious_ports = self.security_config.get('suspicious_ports', [])
        
        # Common attack patterns
        self.attack_patterns = {
            'brute_force': [
                'Failed login attempt',
                'Authentication failure',
                'Invalid credentials',
                'Login failed for user'
            ],
            'malware': [
                'Malicious file detected',
                'Virus signature match',
                'Suspicious executable',
                'Trojan detected'
            ],
            'ddos': [
                'High connection rate',
                'Traffic anomaly detected',
                'Bandwidth threshold exceeded',
                'Connection flood detected'
            ],
            'sql_injection': [
                'SQL injection attempt',
                'Malicious SQL query',
                'Database attack detected',
                'Suspicious database query'
            ]
        }
        
        # Common user agents for web logs
        self.user_agents = [
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36',
            'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36',
            'curl/7.68.0',
            'python-requests/2.25.1'
        ]
    
    def generate_apache_logs(self, count: int = 1000) -> List[str]:
        """Generate Apache access logs"""
        logs = []
        base_time = datetime.now() - timedelta(days=1)
        
        for i in range(count):
            timestamp = base_time + timedelta(seconds=random.randint(0, 86400))
            ip = self.fake.ipv4()
            method = random.choice(['GET', 'POST', 'PUT', 'DELETE'])
            url = random.choice([
                '/',
                '/login',
                '/admin',
                '/api/users',
                '/dashboard',
                '/static/css/style.css',
                '/images/logo.png'
            ])
            
            # Occasionally generate suspicious activity
            if random.random() < 0.1:  # 10% suspicious
                url = random.choice([
                    '/admin/config.php',
                    '/wp-admin/',
                    '/.env',
                    '/etc/passwd',
                    '/admin/login.php?id=1\' OR 1=1--'
                ])
            
            status_code = random.choices(
                [200, 404, 403, 500, 301],
                weights=[70, 15, 8, 5, 2]
            )[0]
            
            size = random.randint(200, 50000)
            
            log_entry = f'{ip} - - [{timestamp.strftime("%d/%b/%Y:%H:%M:%S +0000")}] "{method} {url} HTTP/1.1" {status_code} {size}'
            logs.append(log_entry)
        
        return logs
    
    def generate_firewall_logs(self, count: int = 500) -> List[str]:
        """Generate firewall logs"""
        logs = []
        base_time = datetime.now() - timedelta(days=1)
        
        for i in range(count):
            timestamp = base_time + timedelta(seconds=random.randint(0, 86400))
            src_ip = self.fake.ipv4()
            dst_ip = self.fake.ipv4()
            src_port = random.randint(1024, 65535)
            dst_port = random.choice(self.suspicious_ports + [80, 443, 53, 25])
            
            action = random.choices(['ALLOW', 'DENY'], weights=[70, 30])[0]
            protocol = random.choice(['TCP', 'UDP', 'ICMP'])
            
            log_entry = f'{timestamp.strftime("%Y-%m-%d %H:%M:%S")} FIREWALL {action} {protocol} {src_ip}:{src_port} -> {dst_ip}:{dst_port}'
            logs.append(log_entry)
        
        return logs
    
    def generate_security_events(self, count: int = 200) -> List[Dict[str, Any]]:
        """Generate security event logs in JSON format"""
        events = []
        base_time = datetime.now() - timedelta(days=1)
        
        for i in range(count):
            timestamp = base_time + timedelta(seconds=random.randint(0, 86400))
            
            # Choose attack type
            attack_type = random.choice(list(self.attack_patterns.keys()))
            severity = random.choices(
                ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL'],
                weights=[40, 30, 20, 10]
            )[0]
            
            event = {
                'timestamp': timestamp.isoformat(),
                'event_id': f'SEC-{random.randint(10000, 99999)}',
                'event_type': 'security_alert',
                'attack_type': attack_type,
                'severity': severity,
                'source_ip': self.fake.ipv4(),
                'destination_ip': self.fake.ipv4(),
                'user_agent': random.choice(self.user_agents),
                'description': random.choice(self.attack_patterns[attack_type]),
                'affected_system': random.choice(['web_server', 'database', 'mail_server', 'dns_server']),
                'status': random.choice(['detected', 'blocked', 'investigating']),
                'analyst': self.fake.name()
            }
            
            events.append(event)
        
        return events
    
    def generate_authentication_logs(self, count: int = 300) -> List[str]:
        """Generate authentication logs"""
        logs = []
        base_time = datetime.now() - timedelta(days=1)
        
        for i in range(count):
            timestamp = base_time + timedelta(seconds=random.randint(0, 86400))
            username = self.fake.user_name()
            ip = self.fake.ipv4()
            
            # Generate failed logins more frequently for certain IPs (brute force simulation)
            if random.random() < 0.2:  # 20% failed logins
                status = 'FAILED'
                reason = random.choice([
                    'Invalid password',
                    'Account locked',
                    'User not found',
                    'Too many attempts'
                ])
            else:
                status = 'SUCCESS'
                reason = 'Authentication successful'
            
            log_entry = f'{timestamp.strftime("%Y-%m-%d %H:%M:%S")} AUTH {status} user={username} ip={ip} reason="{reason}"'
            logs.append(log_entry)
        
        return logs
    
    def save_sample_data(self, output_dir: str = "data/sample_data"):
        """Generate and save all sample data types"""
        from pathlib import Path
        
        output_path = Path(output_dir)
        output_path.mkdir(parents=True, exist_ok=True)
        
        logger.info("Generating sample security data...")
        
        # Generate Apache logs
        apache_logs = self.generate_apache_logs(1000)
        with open(output_path / "apache_access.log", 'w') as f:
            f.write('\n'.join(apache_logs))
        
        # Generate firewall logs
        firewall_logs = self.generate_firewall_logs(500)
        with open(output_path / "firewall.log", 'w') as f:
            f.write('\n'.join(firewall_logs))
        
        # Generate security events
        security_events = self.generate_security_events(200)
        with open(output_path / "security_events.json", 'w') as f:
            for event in security_events:
                f.write(json.dumps(event) + '\n')
        
        # Generate authentication logs
        auth_logs = self.generate_authentication_logs(300)
        with open(output_path / "auth.log", 'w') as f:
            f.write('\n'.join(auth_logs))
        
        logger.info(f"Sample data generated and saved to {output_path}")
        return {
            'apache_logs': len(apache_logs),
            'firewall_logs': len(firewall_logs),
            'security_events': len(security_events),
            'auth_logs': len(auth_logs)
        }