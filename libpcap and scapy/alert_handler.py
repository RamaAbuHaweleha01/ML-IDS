"""
Alert handler module for sending alerts via multiple channels (Telegram, console, file).
"""

import logging
from typing import Dict, Any, Optional, List
import requests
from datetime import datetime
import time
import json
from dataclasses import dataclass, asdict
from enum import Enum
import asyncio
from concurrent.futures import ThreadPoolExecutor
import threading
import os

class SeverityLevel(Enum):
    """Severity levels for alerts"""
    INFO = "INFO"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"

@dataclass
class Alert:
    """Alert data structure"""
    timestamp: str
    attack_type: str
    severity: str
    confidence: float
    flow_key: str
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: str
    packet_length: int
    additional_info: Dict[str, Any]
    telegram_sent: bool = False
    console_displayed: bool = False
    logged_to_file: bool = False
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert alert to dictionary"""
        return asdict(self)

class AlertHandler:
    """Enhanced alert handler with multiple notification channels"""
    
    def __init__(self, config):
        self.config = config
        self.logger = logging.getLogger(__name__)
        
        # Telegram configuration
        self.telegram_token = config.telegram.token
        self.chat_id = config.telegram.chat_id
        self.telegram_enabled = config.get_telegram_enabled()
        
        # Alert cooldown mechanism
        self.alert_cooldown: Dict[str, float] = {}
        self.cooldown_period = config.alerts.severity_levels.get('COOLDOWN', 60)  # seconds
        
        # Alert history
        self.alert_history: List[Alert] = []
        self.max_history = 1000
        
        # Thread pool for async operations
        self.executor = ThreadPoolExecutor(max_workers=3)
        self.lock = threading.Lock()
        
        # Setup logging file
        self.setup_alert_logging()
        
        self.logger.info(f"Alert Handler initialized - Telegram: "
                        f"{'ENABLED' if self.telegram_enabled else 'DISABLED'}")
    
    def setup_alert_logging(self):
        """Setup alert logging directory and file"""
        log_dir = 'logs'
        if not os.path.exists(log_dir):
            os.makedirs(log_dir)
        
        self.alert_log_file = os.path.join(log_dir, 'alerts.log')
        self.alert_json_file = os.path.join(log_dir, 'alerts.json')
    
    def create_alert(self, packet_info: Dict[str, Any]) -> Alert:
        """Create an Alert object from packet information"""
        now = datetime.now().isoformat()
        
        # Extract basic information
        src_ip = packet_info.get('src_ip', '0.0.0.0')
        dst_ip = packet_info.get('dst_ip', '0.0.0.0')
        src_port = packet_info.get('src_port', 0)
        dst_port = packet_info.get('dst_port', 0)
        protocol_num = packet_info.get('protocol', 0)
        
        # Map protocol number to name
        protocol_map = {6: 'TCP', 17: 'UDP', 1: 'ICMP'}
        protocol = protocol_map.get(protocol_num, f'Proto-{protocol_num}')
        
        # Create flow key
        flow_key = f"{src_ip}:{src_port}→{dst_ip}:{dst_port}/{protocol}"
        
        # Determine severity level
        confidence = packet_info.get('confidence', 0.0)
        attack_type = packet_info.get('attack_type', 'Unknown')
        severity = self._determine_severity(confidence, attack_type)
        
        return Alert(
            timestamp=now,
            attack_type=attack_type,
            severity=severity.value if isinstance(severity, SeverityLevel) else severity,
            confidence=confidence,
            flow_key=flow_key,
            src_ip=src_ip,
            dst_ip=dst_ip,
            src_port=src_port,
            dst_port=dst_port,
            protocol=protocol,
            packet_length=packet_info.get('packet_length', 0),
            additional_info={
                'features': packet_info.get('features', {}),
                'prediction': packet_info.get('prediction', ''),
                'model_confidence': packet_info.get('confidence', 0.0),
                'window_stats': packet_info.get('window_stats', {})
            }
        )
    
    def _determine_severity(self, confidence: float, attack_type: str) -> SeverityLevel:
        """Determine severity level based on confidence and attack type"""
        # Adjust thresholds based on attack type
        if attack_type in ['DDoS', 'R2L', 'U2R']:
            if confidence >= 0.8:
                return SeverityLevel.CRITICAL
            elif confidence >= 0.6:
                return SeverityLevel.HIGH
            elif confidence >= 0.4:
                return SeverityLevel.MEDIUM
            else:
                return SeverityLevel.LOW
        else:
            if confidence >= 0.9:
                return SeverityLevel.CRITICAL
            elif confidence >= 0.7:
                return SeverityLevel.HIGH
            elif confidence >= 0.5:
                return SeverityLevel.MEDIUM
            elif confidence >= 0.3:
                return SeverityLevel.LOW
            else:
                return SeverityLevel.INFO
    
    def check_cooldown(self, alert: Alert) -> bool:
        """Check if alert should be suppressed due to cooldown"""
        alert_key = f'{alert.attack_type}:{alert.flow_key}'
        current_time = time.time()
        
        with self.lock:
            last_alert_time = self.alert_cooldown.get(alert_key, 0)
            
            if current_time - last_alert_time < self.cooldown_period:
                self.logger.debug(f"Alert on cooldown: {alert_key}")
                return True
            
            # Update cooldown time
            self.alert_cooldown[alert_key] = current_time
            return False
    
    async def send_alert(self, packet_info: Dict[str, Any]) -> bool:
        """Main method to send alerts through all channels"""
        try:
            # Create alert object
            alert = self.create_alert(packet_info)
            
            # Check cooldown
            if self.check_cooldown(alert):
                self.logger.debug(f"Alert suppressed (cooldown): {alert.attack_type}")
                return False
            
            # Send alerts in parallel
            tasks = [
                self._send_telegram_alert(alert),
                self._display_console_alert(alert),
                self._log_alert_to_file(alert)
            ]
            
            # Run tasks concurrently
            results = await asyncio.gather(*tasks, return_exceptions=True)
            
            # Update alert status
            alert.telegram_sent = results[0] if isinstance(results[0], bool) else False
            alert.console_displayed = results[1] if isinstance(results[1], bool) else False
            alert.logged_to_file = results[2] if isinstance(results[2], bool) else False
            
            # Add to history
            with self.lock:
                self.alert_history.append(alert)
                if len(self.alert_history) > self.max_history:
                    self.alert_history.pop(0)
            
            # Save to JSON file periodically
            if len(self.alert_history) % 10 == 0:
                self._save_alerts_to_json()
            
            self.logger.info(f"Alert processed: {alert.attack_type} - Severity: {alert.severity}")
            return True
            
        except Exception as e:
            self.logger.error(f"Error sending alert: {e}")
            return False
    
    async def _send_telegram_alert(self, alert: Alert) -> bool:
        """Send alert to Telegram (async version)"""
        if not self.telegram_enabled:
            return False
        
        loop = asyncio.get_event_loop()
        
        try:
            # Run blocking request in thread pool
            result = await loop.run_in_executor(
                self.executor,
                self._send_telegram_sync,
                alert
            )
            return result
            
        except Exception as e:
            self.logger.error(f"Telegram alert error: {e}")
            return False
    
    def _send_telegram_sync(self, alert: Alert) -> bool:
        """Synchronous Telegram sending"""
        try:
            url = f"https://api.telegram.org/bot{self.telegram_token}/sendMessage"
            
            # Format message with HTML
            message = self._format_telegram_message(alert)
            
            payload = {
                'chat_id': self.chat_id,
                'text': message,
                'parse_mode': 'HTML',
                'disable_web_page_preview': True
            }
            
            response = requests.post(url, json=payload, timeout=10)
            
            if response.status_code == 200:
                self.logger.debug(f"Telegram alert sent: {alert.attack_type}")
                return True
            else:
                error_msg = response.json().get('description', 'Unknown error')
                self.logger.error(f"Telegram API error: {response.status_code} - {error_msg}")
                return False
                
        except requests.exceptions.Timeout:
            self.logger.warning("Telegram request timeout")
            return False
        except Exception as e:
            self.logger.error(f"Telegram request failed: {e}")
            return False
    
    def _format_telegram_message(self, alert: Alert) -> str:
        """Format alert message for Telegram with rich formatting"""
        # Emoji mapping
        severity_emoji = {
            'CRITICAL': '🛑',
            'HIGH': '🔴',
            'MEDIUM': '🟡',
            'LOW': '🟢',
            'INFO': 'ℹ️'
        }
        
        emoji = severity_emoji.get(alert.severity, '📡')
        
        message = f"""{emoji} <b>IDS ALERT DETECTED</b> {emoji}

<b>Time:</b> {alert.timestamp}
<b>Attack Type:</b> {alert.attack_type}
<b>Severity:</b> {alert.severity}
<b>Confidence:</b> {alert.confidence:.2%}

<b>Network Information:</b>
• <b>Source:</b> {alert.src_ip}:{alert.src_port}
• <b>Destination:</b> {alert.dst_ip}:{alert.dst_port}
• <b>Protocol:</b> {alert.protocol}
• <b>Packet Size:</b> {alert.packet_length} bytes

<b>Detection Details:</b>
• <b>Flow:</b> {alert.flow_key}
• <b>Timestamp:</b> {alert.timestamp}

<b>Recommended Action:</b>
{'🚨 IMMEDIATE ACTION REQUIRED' if alert.severity in ['CRITICAL', 'HIGH'] else '📊 Monitor and investigate' if alert.severity == 'MEDIUM' else '📝 Log and review'}

<i>Automated alert from Real-time IDS System</i>"""
        
        return message
    
    async def _display_console_alert(self, alert: Alert) -> bool:
        """Display alert in console with colors"""
        try:
            # Color codes based on severity
            colors = {
                'CRITICAL': '\033[91m',  # Red
                'HIGH': '\033[93m',      # Yellow
                'MEDIUM': '\033[96m',    # Cyan
                'LOW': '\033[92m',       # Green
                'INFO': '\033[94m'       # Blue
            }
            
            reset = '\033[0m'
            color = colors.get(alert.severity, '\033[0m')
            
            # Format timestamp
            dt = datetime.fromisoformat(alert.timestamp.replace('Z', '+00:00'))
            display_time = dt.strftime('%H:%M:%S')
            
            print(f"\n{color}{'='*80}{reset}")
            print(f"{color}{display_time} {alert.severity} ALERT - {alert.attack_type}{reset}")
            print(f"{color}Source: {alert.src_ip}:{alert.src_port} -> Destination: {alert.dst_ip}:{alert.dst_port}{reset}")
            print(f"{color}Protocol: {alert.protocol} | Size: {alert.packet_length} bytes | Confidence: {alert.confidence:.2%}{reset}")
            print(f"{color}Flow: {alert.flow_key}{reset}")
            print(f"{color}{'='*80}{reset}\n")
            
            return True
            
        except Exception as e:
            self.logger.error(f"Console display error: {e}")
            return False
    
    async def _log_alert_to_file(self, alert: Alert) -> bool:
        """Log alert to text file"""
        try:
            log_entry = (
                f"[{alert.timestamp}] "
                f"TYPE: {alert.attack_type} | "
                f"SEVERITY: {alert.severity} | "
                f"CONFIDENCE: {alert.confidence:.4f} | "
                f"FLOW: {alert.flow_key} | "
                f"SRC: {alert.src_ip}:{alert.src_port} | "
                f"DST: {alert.dst_ip}:{alert.dst_port}\n"
            )
            
            with open(self.alert_log_file, 'a') as f:
                f.write(log_entry)
            
            return True
            
        except Exception as e:
            self.logger.error(f"File logging error: {e}")
            return False
    
    def _save_alerts_to_json(self):
        """Save alert history to JSON file"""
        try:
            with open(self.alert_json_file, 'w') as f:
                alerts_data = [alert.to_dict() for alert in self.alert_history[-100:]]
                json.dump(alerts_data, f, indent=2, default=str)
        except Exception as e:
            self.logger.error(f"JSON save error: {e}")
    
    def get_alert_stats(self) -> Dict[str, Any]:
        """Get alert statistics"""
        with self.lock:
            total_alerts = len(self.alert_history)
            
            # Count by severity
            severity_counts = {}
            for severity in SeverityLevel:
                severity_counts[severity.value] = sum(
                    1 for alert in self.alert_history if alert.severity == severity.value
                )
            
            # Count by attack type
            attack_counts = {}
            for alert in self.alert_history:
                attack_type = alert.attack_type
                attack_counts[attack_type] = attack_counts.get(attack_type, 0) + 1
            
            return {
                'total_alerts': total_alerts,
                'severity_distribution': severity_counts,
                'attack_type_distribution': attack_counts,
                'telegram_enabled': self.telegram_enabled,
                'telegram_success_rate': sum(1 for a in self.alert_history if a.telegram_sent) / max(total_alerts, 1)
            }
    
    def cleanup(self):
        """Cleanup resources"""
        self.executor.shutdown(wait=True)
        self._save_alerts_to_json()
        self.logger.info("Alert Handler cleaned up")
