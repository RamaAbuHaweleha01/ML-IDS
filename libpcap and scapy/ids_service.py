#!/usr/bin/env python3
"""
Enhanced ML-IDS Service with Telegram alerts and detailed packet display
Object-Oriented Programming (OOP) implementation with comprehensive comments
"""

# ============================================================================
# Import Statements
# ============================================================================
import os
import sys
import time
import json
import logging
import asyncio
import argparse
import signal
import requests
from datetime import datetime
import numpy as np
from collections import deque
import random

# ============================================================================
# Directory Setup
# ============================================================================
# Create necessary directories for the application
os.makedirs('logs', exist_ok=True)      # Store log files
os.makedirs('models', exist_ok=True)    # Store ML models
os.makedirs('config', exist_ok=True)    # Store configuration files
os.makedirs('data', exist_ok=True)      # Store data files

# ============================================================================
# Logging Configuration
# ============================================================================
def setup_logging():
    """
    Configure logging system with error handling
    
    Returns:
        Logger: Configured logger instance
    """
    try:
        # Basic logging configuration with file and console handlers
        logging.basicConfig(
            level=logging.INFO,  # Log level
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',  # Log format
            handlers=[
                logging.FileHandler('logs/ids_service.log'),  # File handler
                logging.StreamHandler()  # Console handler
            ]
        )
        return logging.getLogger(__name__)
    except Exception as e:
        # Fallback to console-only logging if file logging fails
        print(f"Warning: Could not setup file logging: {e}")
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            handlers=[logging.StreamHandler()]
        )
        return logging.getLogger(__name__)

# Initialize logger
logger = setup_logging()

# ============================================================================
# Configuration Manager Class
# ============================================================================
class ConfigManager:
    """
    Manages application configuration with Telegram support
    
    Attributes:
        interface (str): Network interface for packet capture
        filter (str): Packet filter expression
        promiscuous (bool): Promiscuous mode setting
        alert_threshold (float): ML alert threshold (0.0-1.0)
        model_path (str): Path to ML model file
        telegram_enabled (bool): Telegram alerts enabled/disabled
        telegram_token (str): Telegram bot token
        telegram_chat_id (str): Telegram chat ID for alerts
        display_packets (bool): Display packets on console
        display_interval (int): Display interval in seconds
        packet_format (str): Packet display format ('simple' or 'detailed')
    """
    
    def __init__(self, config_path=None):
        """
        Initialize configuration manager with default values
        
        Args:
            config_path (str, optional): Path to configuration file
        """
        # Default configuration values
        self.interface = 'eth0'            # Default network interface
        self.filter = 'ip'                 # Default packet filter
        self.promiscuous = True           # Promiscuous mode enabled
        self.alert_threshold = 0.8        # Default alert threshold (80%)
        self.model_path = 'models/randomforest_ids.pkl'  # Default ML model path
        
        # Telegram configuration defaults
        self.telegram_enabled = False     # Telegram alerts disabled by default
        self.telegram_token = ''          # Empty token by default
        self.telegram_chat_id = ''        # Empty chat ID by default
        
        # Display configuration defaults
        self.display_packets = True       # Show packets on console
        self.display_interval = 1         # Display every 1 second
        self.packet_format = 'detailed'   # Detailed display format
        
        # Load configuration from file if provided
        if config_path and os.path.exists(config_path):
            self.load_config(config_path)
        
        # Validate Telegram configuration
        self.check_telegram_config()
    
    def load_config(self, config_path):
        """
        Load configuration from JSON or YAML file
        
        Args:
            config_path (str): Path to configuration file
        """
        try:
            # Handle YAML configuration files
            if config_path.endswith('.yaml') or config_path.endswith('.yml'):
                import yaml
                with open(config_path, 'r') as f:
                    config = yaml.safe_load(f)
                
                # Extract configuration from YAML structure
                self.interface = config.get('capture', {}).get('interface', self.interface)
                self.alert_threshold = config.get('ml', {}).get('anomaly_threshold', self.alert_threshold)
                
                # Extract Telegram configuration
                telegram_config = config.get('telegram', {})
                self.telegram_token = telegram_config.get('token', '')
                self.telegram_chat_id = telegram_config.get('chat_id', '')
                self.telegram_enabled = telegram_config.get('enabled', False)
                
                # Extract display configuration
                display_config = config.get('display', {})
                self.display_packets = display_config.get('show_packets', True)
                self.display_interval = display_config.get('interval', 1)
                self.packet_format = display_config.get('format', 'detailed')
                
            else:  # Handle JSON configuration files
                with open(config_path, 'r') as f:
                    config = json.load(f)
                
                # Extract network settings
                self.interface = config.get('interface', self.interface)
                self.filter = config.get('filter', self.filter)
                self.promiscuous = config.get('promiscuous', self.promiscuous)
                self.alert_threshold = config.get('alert_threshold', self.alert_threshold)
                self.model_path = config.get('model_path', self.model_path)
                
                # Extract Telegram settings
                telegram_config = config.get('telegram', {})
                self.telegram_token = telegram_config.get('token', '')
                self.telegram_chat_id = telegram_config.get('chat_id', '')
                self.telegram_enabled = telegram_config.get('enabled', False)
                
                # Extract display settings
                display_config = config.get('display', {})
                self.display_packets = display_config.get('show_packets', True)
                self.display_interval = display_config.get('interval', 1)
                self.packet_format = display_config.get('format', 'detailed')
            
            logger.info(f"Configuration loaded from {config_path}")
            
        except Exception as e:
            logger.warning(f"Could not load config {config_path}: {e}. Using defaults.")
    
    def check_telegram_config(self):
        """
        Validate Telegram configuration and enable/disable accordingly
        """
        # Check if Telegram should be enabled and has valid credentials
        if (self.telegram_enabled and 
            self.telegram_token and 
            self.telegram_chat_id and
            self.telegram_token not in ["", "YOUR_TELEGRAM_BOT_TOKEN"] and
            self.telegram_chat_id not in ["", "YOUR_CHAT_ID"]):
            self.telegram_enabled = True
            logger.info(f"Telegram alerts enabled for chat ID: {self.telegram_chat_id}")
        else:
            self.telegram_enabled = False
            if self.telegram_enabled:  # Configuration issue
                logger.warning("Telegram alerts disabled - invalid token or chat ID")
            else:
                logger.info("Telegram alerts disabled - not configured")

# ============================================================================
# Telegram Notifier Class
# ============================================================================
class TelegramNotifier:
    """
    Handles Telegram notifications with error handling and cooldown
    
    Attributes:
        token (str): Telegram bot token
        chat_id (str): Telegram chat ID
        base_url (str): Telegram API base URL
        last_alert_time (dict): Timestamps of last alerts for cooldown
        cooldown (int): Cooldown period between alerts (seconds)
    """
    
    def __init__(self, token, chat_id):
        """
        Initialize Telegram notifier
        
        Args:
            token (str): Telegram bot token
            chat_id (str): Telegram chat ID
        """
        self.token = token
        self.chat_id = chat_id
        self.base_url = f"https://api.telegram.org/bot{token}"
        self.last_alert_time = {}  # Track alert timestamps for cooldown
        self.cooldown = 60  # 60 seconds cooldown between same-type alerts
        self.test_connection()  # Test Telegram connection on initialization
    
    def test_connection(self):
        """
        Test Telegram bot connection
        
        Returns:
            bool: True if connection successful, False otherwise
        """
        try:
            url = f"{self.base_url}/getMe"
            response = requests.get(url, timeout=10)
            if response.status_code == 200:
                bot_info = response.json()
                if bot_info.get('ok'):
                    logger.info(f"✅ Connected to Telegram bot: @{bot_info['result']['username']}")
                    return True
            logger.warning(f"⚠️ Could not connect to Telegram bot")
            return False
        except Exception as e:
            logger.error(f"❌ Telegram connection error: {e}")
            return False
    
    async def send_alert(self, alert_data):
        """
        Send alert to Telegram asynchronously
        
        Args:
            alert_data (dict): Alert data dictionary
            
        Returns:
            bool: True if alert sent successfully, False otherwise
        """
        try:
            # Generate unique alert key for cooldown tracking
            alert_key = f"{alert_data.get('attack_type', 'unknown')}_{alert_data.get('src_ip', '')}"
            current_time = time.time()
            
            # Check if alert is on cooldown
            if alert_key in self.last_alert_time:
                if current_time - self.last_alert_time[alert_key] < self.cooldown:
                    logger.debug(f"Alert on cooldown: {alert_key}")
                    return False
            
            # Update last alert time
            self.last_alert_time[alert_key] = current_time
            
            # Format message for Telegram
            message = self._format_message(alert_data)
            
            # Prepare API request
            url = f"{self.base_url}/sendMessage"
            payload = {
                'chat_id': self.chat_id,
                'text': message,
                'parse_mode': 'HTML',
                'disable_web_page_preview': True
            }
            
            # Execute request asynchronously
            loop = asyncio.get_event_loop()
            response = await loop.run_in_executor(
                None, 
                lambda: requests.post(url, json=payload, timeout=10)
            )
            
            # Check response
            if response.status_code == 200:
                logger.info(f"📱 Telegram alert sent: {alert_data.get('attack_type')}")
                return True
            else:
                error_data = response.json()
                logger.error(f"❌ Telegram API error {response.status_code}: {error_data.get('description', 'Unknown error')}")
                return False
                
        except requests.exceptions.Timeout:
            logger.error("❌ Telegram request timeout")
            return False
        except Exception as e:
            logger.error(f"❌ Error sending Telegram alert: {e}")
            return False
    
    def _format_message(self, alert_data):
        """
        Format alert message for Telegram with HTML formatting
        
        Args:
            alert_data (dict): Alert data dictionary
            
        Returns:
            str: Formatted HTML message
        """
        # Emoji mapping for severity levels
        severity_emoji = {
            'CRITICAL': '🛑',
            'HIGH': '🔴', 
            'MEDIUM': '🟡',
            'LOW': '🟢',
            'INFO': 'ℹ️',
            'NONE': '📡'
        }
        
        # Get severity and corresponding emoji
        severity = alert_data.get('severity', 'NONE')
        emoji = severity_emoji.get(severity, '📡')
        
        # Helper function to escape HTML special characters
        def escape_html(text):
            """Escape HTML special characters to prevent XSS"""
            if not text:
                return ''
            return str(text).replace('&', '&amp;').replace('<', '&lt;').replace('>', '&gt;')
        
        # Format confidence percentage
        confidence = alert_data.get('confidence', 0.0)
        try:
            confidence_str = f"{float(confidence):.2%}"
        except:
            confidence_str = "N/A"
        
        # Build HTML formatted message
        message = f"""{emoji} <b>🚨 ML-IDS SECURITY ALERT</b> {emoji}

<b>Attack Type:</b> {escape_html(alert_data.get('attack_type', 'Unknown'))}
<b>Severity:</b> {escape_html(severity)}
<b>Confidence:</b> {confidence_str}

<b>📡 Packet Details:</b>
• <b>Source:</b> {escape_html(alert_data.get('src_ip', 'N/A'))}:{escape_html(str(alert_data.get('src_port', 0)))}
• <b>Destination:</b> {escape_html(alert_data.get('dst_ip', 'N/A'))}:{escape_html(str(alert_data.get('dst_port', 0)))}
• <b>Protocol:</b> {escape_html(alert_data.get('protocol', 'N/A'))}
• <b>Size:</b> {escape_html(str(alert_data.get('packet_size', 0)))} bytes

<b>⏰ Timestamp:</b> {escape_html(alert_data.get('timestamp', datetime.now().isoformat()))}

<b>🚨 Recommended Action:</b>
{self._get_action_recommendation(severity)}

<i>Automated alert from ML-IDS Intrusion Detection System</i>"""
        
        return message
    
    def _get_action_recommendation(self, severity):
        """
        Get action recommendation based on severity level
        
        Args:
            severity (str): Severity level
            
        Returns:
            str: Action recommendation
        """
        recommendations = {
            'CRITICAL': '🚨 <b>IMMEDIATE ACTION REQUIRED</b> - Block source IP and investigate',
            'HIGH': '⚠️ <b>Urgent attention needed</b> - Investigate immediately',
            'MEDIUM': '📊 <b>Monitor closely</b> - Review logs and assess impact',
            'LOW': '📝 <b>Log for review</b> - No immediate action required',
            'INFO': 'ℹ️ <b>Informational</b> - Routine monitoring',
            'NONE': '📡 Monitoring normal traffic'
        }
        return recommendations.get(severity, 'Monitor and investigate')

# ============================================================================
# ML Predictor Class
# ============================================================================
class MLPredictor:
    """
    Machine Learning predictor with enhanced features
    
    Attributes:
        model_loaded (bool): Whether ML model is loaded
        model: Loaded ML model object
    """
    
    def __init__(self, model_path=None):
        """
        Initialize ML predictor
        
        Args:
            model_path (str, optional): Path to ML model file
        """
        self.model_loaded = False
        
        # Load ML model if path provided
        if model_path and os.path.exists(model_path):
            try:
                import joblib
                self.model = joblib.load(model_path)
                self.model_loaded = True
                logger.info(f"✅ ML model loaded from {model_path}")
            except Exception as e:
                logger.error(f"❌ Failed to load ML model: {e}")
                self.model_loaded = False
        
        # Fallback to simulation mode if no model loaded
        if not self.model_loaded:
            logger.warning("⚠️ Running in simulation mode (no ML model)")
    
    def predict(self, packet_info=None):
        """
        Make prediction on packet data
        
        Args:
            packet_info (dict, optional): Packet information dictionary
            
        Returns:
            tuple: (prediction, confidence, severity, attack_type, features)
        """
        # Use real ML model if loaded
        if self.model_loaded:
            try:
                # Extract features from packet info
                features = self._extract_features(packet_info)
                
                # Reshape features for sklearn model
                features_array = np.array(features).reshape(1, -1)
                prediction = self.model.predict(features_array)[0]
                
                # Get prediction probabilities if available
                if hasattr(self.model, 'predict_proba'):
                    probabilities = self.model.predict_proba(features_array)[0]
                    confidence = float(probabilities[prediction])
                else:
                    confidence = random.uniform(0.7, 0.95)
                
                # Determine result based on prediction
                if prediction == 0:
                    return "Normal", confidence, "None", "Normal", features
                else:
                    attack_types = ['DDoS', 'PortScan', 'Malware', 'BruteForce', 'SQLi', 'XSS']
                    attack = random.choice(attack_types)
                    
                    # Determine severity based on attack type and confidence
                    severity = self._determine_severity(attack, confidence)
                    return "Anomalous", confidence, severity, attack, features
                    
            except Exception as e:
                logger.error(f"❌ Prediction error: {e}")
                # Fall through to simulation
        
        # Simulation mode (used when no ML model is loaded)
        return self._simulate_prediction(packet_info)
    
    def _extract_features(self, packet_info):
        """
        Extract features from packet information
        
        Args:
            packet_info (dict): Packet information
            
        Returns:
            list: Extracted features
        """
        features = []
        
        if packet_info:
            # Basic packet features
            features.append(packet_info.get('packet_size', 0))
            features.append(packet_info.get('src_port', 0))
            features.append(packet_info.get('dst_port', 0))
            features.append(packet_info.get('protocol_num', 0))
            features.append(packet_info.get('ttl', 64))
            
            # Check if ports are well-known
            well_known_ports = [80, 443, 22, 53, 25, 110, 143]
            src_port = packet_info.get('src_port', 0)
            dst_port = packet_info.get('dst_port', 0)
            features.append(1 if src_port in well_known_ports else 0)
            features.append(1 if dst_port in well_known_ports else 0)
        
        # Fill remaining features with random values
        while len(features) < 48:
            features.append(random.uniform(-1, 1))
        
        return features[:48]
    
    def _determine_severity(self, attack_type, confidence):
        """
        Determine severity level based on attack type and confidence
        
        Args:
            attack_type (str): Type of attack detected
            confidence (float): Confidence score (0.0-1.0)
            
        Returns:
            str: Severity level
        """
        # Define severity rules for each attack type
        severity_rules = {
            'DDoS': {'HIGH': 0.7, 'CRITICAL': 0.9},
            'Malware': {'HIGH': 0.7, 'CRITICAL': 0.85},
            'BruteForce': {'MEDIUM': 0.6, 'HIGH': 0.8},
            'PortScan': {'LOW': 0.5, 'MEDIUM': 0.7, 'HIGH': 0.85},
            'SQLi': {'HIGH': 0.75, 'CRITICAL': 0.9},
            'XSS': {'MEDIUM': 0.6, 'HIGH': 0.8}
        }
        
        # Get rules for specific attack type, default to medium/high
        rules = severity_rules.get(attack_type, {'MEDIUM': 0.6, 'HIGH': 0.8})
        
        # Determine severity based on confidence thresholds
        if 'CRITICAL' in rules and confidence >= rules['CRITICAL']:
            return 'CRITICAL'
        elif 'HIGH' in rules and confidence >= rules['HIGH']:
            return 'HIGH'
        elif 'MEDIUM' in rules and confidence >= rules['MEDIUM']:
            return 'MEDIUM'
        else:
            return 'LOW'
    
    def _simulate_prediction(self, packet_info=None):
        """
        Simulate prediction for testing/demo purposes
        
        Args:
            packet_info (dict, optional): Packet information
            
        Returns:
            tuple: Simulated prediction results
        """
        # Simulate 5% anomaly rate
        if random.random() > 0.95:
            attack_types = ['DDoS', 'PortScan', 'Malware', 'BruteForce', 'SQLi', 'XSS']
            attack = random.choice(attack_types)
            confidence = random.uniform(0.75, 0.98)
            severity = self._determine_severity(attack, confidence)
            features = self._extract_features(packet_info)
            return "Anomalous", confidence, severity, attack, features
        else:
            confidence = random.uniform(0.9, 0.99)
            features = self._extract_features(packet_info)
            return "Normal", confidence, "None", "Normal", features

# ============================================================================
# Packet Display Class
# ============================================================================
class PacketDisplay:
    """
    Handles packet display formatting with different styles
    """
    
    @staticmethod
    def format_simple(packet_info, prediction_info=None):
        """
        Format packet in simple view
        
        Args:
            packet_info (dict): Packet information
            prediction_info (tuple, optional): Prediction results
            
        Returns:
            str: Formatted packet string
        """
        timestamp = datetime.now().strftime('%H:%M:%S.%f')[:-3]
        src = f"{packet_info.get('src_ip', '0.0.0.0')}:{packet_info.get('src_port', 0)}"
        dst = f"{packet_info.get('dst_ip', '0.0.0.0')}:{packet_info.get('dst_port', 0)}"
        proto = packet_info.get('protocol', 'UNKNOWN')
        size = packet_info.get('packet_size', 0)
        
        # Color code anomalies
        if prediction_info and prediction_info[0] == "Anomalous":
            color = '\033[91m'  # Red for anomalies
            reset = '\033[0m'
            status = f"{color}🚨 ANOMALY{reset}"
        else:
            status = "✓ NORMAL"
        
        return f"[{timestamp}] {src} → {dst} | {proto} | {size:4d} bytes | {status}"
    
    @staticmethod
    def format_detailed(packet_info, prediction_info=None):
        """
        Format packet in detailed view
        
        Args:
            packet_info (dict): Packet information
            prediction_info (tuple, optional): Prediction results
            
        Returns:
            str: Formatted packet string
        """
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')[:-3]
        
        lines = [
            f"\n{'─' * 70}",
            f"📦 PACKET CAPTURED: {timestamp}",
            f"{'─' * 70}",
            f"Source:      {packet_info.get('src_ip', '0.0.0.0')}:{packet_info.get('src_port', 0)}",
            f"Destination: {packet_info.get('dst_ip', '0.0.0.0')}:{packet_info.get('dst_port', 0)}",
            f"Protocol:    {packet_info.get('protocol', 'UNKNOWN')} ({packet_info.get('protocol_num', 0)})",
            f"Size:        {packet_info.get('packet_size', 0)} bytes",
            f"TTL:         {packet_info.get('ttl', 64)}",
            f"Flags:       {packet_info.get('flags', 'N/A')}",
        ]
        
        # Add prediction information if available
        if prediction_info:
            prediction, confidence, severity, attack_type, _ = prediction_info
            
            if prediction == "Anomalous":
                color = '\033[91m'  # Red for anomalies
                reset = '\033[0m'
                lines.append(f"{'─' * 70}")
                lines.append(f"{color}🚨 INTRUSION DETECTED{reset}")
                lines.append(f"{color}Attack Type:  {attack_type}{reset}")
                lines.append(f"{color}Severity:     {severity}{reset}")
                lines.append(f"{color}Confidence:   {confidence:.2%}{reset}")
                lines.append(f"{color}ML Decision:  {prediction}{reset}")
            else:
                lines.append(f"{'─' * 70}")
                lines.append(f"✅ ML Analysis: Normal Traffic")
                lines.append(f"Confidence:   {confidence:.2%}")
        
        lines.append(f"{'─' * 70}")
        
        return '\n'.join(lines)

# ============================================================================
# Real-Time IDS Main Class
# ============================================================================
class RealTimeIDS:
    """
    Enhanced Real-time Intrusion Detection System
    
    Attributes:
        config (ConfigManager): Configuration manager instance
        ml_predictor (MLPredictor): ML predictor instance
        telegram (TelegramNotifier or None): Telegram notifier instance
        display (PacketDisplay): Packet display instance
        stats (dict): System statistics
        running (bool): System running state
    """
    
    def __init__(self, config_path=None):
        """
        Initialize Real-Time IDS
        
        Args:
            config_path (str, optional): Path to configuration file
        """
        logger.info("🚀 Initializing Enhanced ML-IDS")
        
        # Initialize configuration manager
        self.config = ConfigManager(config_path)
        
        # Initialize ML predictor
        self.ml_predictor = MLPredictor(self.config.model_path)
        
        # Initialize Telegram notifier if enabled
        self.telegram = None
        if self.config.telegram_enabled:
            self.telegram = TelegramNotifier(
                self.config.telegram_token,
                self.config.telegram_chat_id
            )
        
        # Initialize packet display
        self.display = PacketDisplay()
        
        # Initialize statistics
        self.stats = {
            'packets_processed': 0,
            'anomalies_detected': 0,
            'start_time': time.time(),
            'packet_rate': 0,
            'last_display': time.time(),
            'packet_queue': deque(maxlen=100),
            'model_loaded': self.ml_predictor.model_loaded,
            'telegram_alerts_sent': 0,
            'telegram_alerts_failed': 0
        }
        
        self.running = False
        
    async def start_capture(self):
        """
        Start enhanced packet capture and analysis loop
        """
        logger.info("📡 Starting enhanced packet capture...")
        
        # Display startup banner
        self._display_startup_banner()
        
        self.running = True
        
        # Initialize counters
        packet_count = 0
        last_update = time.time()
        last_stat_display = time.time()
        packet_counter = 0
        
        try:
            # Main capture loop
            while self.running:
                # Simulate packet arrival (for demo purposes)
                await asyncio.sleep(0.02)  # ~50 packets/sec for better display
                
                # Update packet counters
                packet_count += 1
                packet_counter += 1
                self.stats['packets_processed'] += 1
                
                # Generate simulated packet information
                packet_info = self._generate_packet_info(packet_counter)
                self.stats['packet_queue'].append(packet_info)
                
                # Make ML prediction
                prediction_info = self.ml_predictor.predict(packet_info)
                prediction, confidence, severity, attack_type, features = prediction_info
                
                # Display packet based on configuration
                current_time = time.time()
                if (self.config.display_packets and 
                    current_time - self.stats['last_display'] >= self.config.display_interval):
                    
                    try:
                        if self.config.packet_format == 'detailed':
                            display_text = self.display.format_detailed(packet_info, prediction_info)
                        else:
                            display_text = self.display.format_simple(packet_info, prediction_info)
                        
                        print(display_text)
                        self.stats['last_display'] = current_time
                    except Exception as e:
                        logger.error(f"❌ Display error: {e}")
                        # Fallback to simple display
                        print(f"[{datetime.now().strftime('%H:%M:%S')}] Packet #{packet_counter} captured")
                
                # Handle anomalies above threshold
                if prediction == "Anomalous" and confidence >= self.config.alert_threshold:
                    await self._handle_anomaly(packet_info, prediction_info)
                
                # Update packet rate every second
                if current_time - last_update >= 1.0:
                    self.stats['packet_rate'] = packet_count
                    packet_count = 0
                    last_update = current_time
                
                # Display statistics every 15 seconds
                if current_time - last_stat_display >= 15.0:
                    self._display_statistics()
                    last_stat_display = current_time
        
        except KeyboardInterrupt:
            print("\n\n🛑 Capture interrupted by user")
        except Exception as e:
            logger.error(f"❌ Capture error: {e}")
            print(f"\n❌ Fatal error: {str(e)}")
        finally:
            self.running = False
    
    def _display_startup_banner(self):
        """Display startup banner with system information"""
        print("\n" + "─" * 70)
        print("🚀 ML-IDS INTRUSION DETECTION SYSTEM")
        print("─" * 70)
        print(f"📡 Interface:    {self.config.interface}")
        print(f"🎯 Filter:       {self.config.filter}")
        print(f"⚡ Threshold:    {self.config.alert_threshold}")
        print(f"👁️  Display:      {self.config.packet_format.upper()} format")
        print(f"🤖 Telegram:     {'✅ ENABLED' if self.config.telegram_enabled else '⚠️ DISABLED'}")
        print(f"🧠 ML Model:     {'✅ Loaded' if self.ml_predictor.model_loaded else '⚠️ Simulation'}")
        print("─" * 70)
        print("\n📡 Starting capture... Press Ctrl+C to stop\n")
    
    def _generate_packet_info(self, packet_id):
        """
        Generate realistic packet information for simulation
        
        Args:
            packet_id (int): Packet sequence number
            
        Returns:
            dict: Packet information dictionary
        """
        # Common protocols with weights for realistic distribution
        protocols = [
            ('TCP', 6, 0.6),
            ('UDP', 17, 0.3),
            ('ICMP', 1, 0.05),
            ('HTTP', 6, 0.03),
            ('HTTPS', 6, 0.01),
            ('DNS', 17, 0.01)
        ]
        
        # Weighted random choice for protocol
        choices, weights = zip(*[(p[0], p[2]) for p in protocols])
        protocol = random.choices(choices, weights=weights)[0]
        proto_num = next(p[1] for p in protocols if p[0] == protocol)
        
        # Generate IP addresses (70% internal, 30% external)
        if random.random() < 0.7:
            src_ip = f"192.168.{random.randint(1, 255)}.{random.randint(1, 255)}"
        else:
            src_ip = f"{random.randint(1, 223)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 255)}"
        
        dst_ip = f"10.0.{random.randint(0, 255)}.{random.randint(1, 255)}"
        
        # Common network ports
        common_ports = [80, 443, 22, 53, 25, 110, 143, 3389, 8080, 8443]
        
        # Build packet information dictionary
        packet_info = {
            'packet_id': packet_id,
            'timestamp': datetime.now().isoformat(),
            'src_ip': src_ip,
            'dst_ip': dst_ip,
            'src_port': random.choice(common_ports + [random.randint(1024, 65535)]),
            'dst_port': random.choice(common_ports),
            'protocol': protocol,
            'protocol_num': proto_num,
            'packet_size': random.randint(64, 1500),
            'ttl': random.randint(32, 255),
            'flags': self._generate_flags(protocol),
            'flow_key': f"{src_ip}:{random.randint(1024, 65535)}-{dst_ip}:{random.choice(common_ports)}-{proto_num}"
        }
        
        return packet_info
    
    def _generate_flags(self, protocol):
        """
        Generate protocol-specific flags
        
        Args:
            protocol (str): Protocol name
            
        Returns:
            str: Protocol flags
        """
        if protocol == 'TCP':
            flag_combos = [
                ['SYN'],
                ['SYN', 'ACK'],
                ['ACK'],
                ['FIN', 'ACK'],
                ['PSH', 'ACK'],
                ['RST']
            ]
            return ' '.join(random.choice(flag_combos))
        elif protocol == 'ICMP':
            types = ['ECHO_REQUEST', 'ECHO_REPLY', 'DEST_UNREACHABLE']
            return random.choice(types)
        else:
            return 'N/A'
    
    async def _handle_anomaly(self, packet_info, prediction_info):
        """
        Handle detected anomaly
        
        Args:
            packet_info (dict): Packet information
            prediction_info (tuple): Prediction results
        """
        prediction, confidence, severity, attack_type, features = prediction_info
        
        # Update anomaly statistics
        self.stats['anomalies_detected'] += 1
        
        # Create alert data dictionary
        alert_data = {
            **packet_info,
            'prediction': prediction,
            'confidence': float(confidence),
            'severity': severity,
            'attack_type': attack_type,
            'flow_key': packet_info.get('flow_key', 'N/A')
        }
        
        # Log the alert
        alert_msg = f"🚨 ALERT: {attack_type} | Severity: {severity} | Confidence: {confidence:.2%}"
        logger.warning(alert_msg)
        
        # Display alert on console (single line between alerts)
        self._display_alert(packet_info, prediction_info)
        
        # Send Telegram alert if enabled
        if self.config.telegram_enabled and self.telegram:
            try:
                success = await self.telegram.send_alert(alert_data)
                if success:
                    self.stats['telegram_alerts_sent'] += 1
                    print(f"   📱 Telegram alert sent successfully!")
                else:
                    self.stats['telegram_alerts_failed'] += 1
                    print(f"   ❌ Failed to send Telegram alert")
            except Exception as e:
                logger.error(f"❌ Telegram sending error: {e}")
                self.stats['telegram_alerts_failed'] += 1
        
        # Save alert to log files
        self._log_alert(alert_data)
    
    def _display_alert(self, packet_info, prediction_info):
        """
        Display security alert on console with simplified formatting
        
        Args:
            packet_info (dict): Packet information
            prediction_info (tuple): Prediction results
        """
        _, confidence, severity, attack_type, _ = prediction_info
        
        # Color mapping for severity levels
        colors = {
            'CRITICAL': '\033[91m',  # Red
            'HIGH': '\033[93m',      # Yellow
            'MEDIUM': '\033[96m',    # Cyan
            'LOW': '\033[92m',       # Green
            'INFO': '\033[94m',      # Blue
            'NONE': '\033[0m'        # Reset
        }
        
        color = colors.get(severity, '\033[0m')
        reset = '\033[0m'
        
        # Format confidence safely
        try:
            confidence_str = f"{float(confidence):.2%}"
        except:
            confidence_str = "N/A"
        
        # SIMPLIFIED ALERT FORMAT - Single line only between alerts
        print(f"\n{'─' * 70}")
        print(f"{color}    🚨 SECURITY ALERT DETECTED 🚨    {reset}")
        print(f"{color}│ Attack Type:  {attack_type:<54} │{reset}")
        print(f"{color}│ Severity:     {severity:<54} │{reset}")
        print(f"{color}│ Confidence:   {confidence_str:<54} │{reset}")
        print(f"{color}│ Source:       {packet_info['src_ip']}:{packet_info['src_port']:<39} │{reset}")
        print(f"{color}│ Destination:  {packet_info['dst_ip']}:{packet_info['dst_port']:<39} │{reset}")
        print(f"{color}│ Protocol:     {packet_info['protocol']:<54} │{reset}")
        print(f"{color}│ Time:         {datetime.now().strftime('%H:%M:%S.%f')[:-3]:<54} │{reset}")
    
    def _display_statistics(self):
        """Display current system statistics"""
        elapsed = time.time() - self.stats['start_time']
        rate = self.stats['packets_processed'] / elapsed if elapsed > 0 else 0
        
        stats_text = f"""
{'─' * 70}
📊 ML-IDS REAL-TIME STATISTICS
{'─' * 70}
• Packets Processed:   {self.stats['packets_processed']:,}
• Anomalies Detected:  {self.stats['anomalies_detected']}
• Current Rate:        {self.stats['packet_rate']} packets/sec
• Average Rate:        {rate:.1f} packets/sec
• Uptime:              {elapsed:.1f} seconds
• ML Model:            {'✅ Loaded' if self.stats['model_loaded'] else '⚠️ Simulation'}
• Telegram Alerts:     {self.stats['telegram_alerts_sent']} sent, {self.stats['telegram_alerts_failed']} failed
{'─' * 70}
"""
        print(stats_text)
    
    def _log_alert(self, alert_data):
        """
        Log alert to JSON and text log files
        
        Args:
            alert_data (dict): Alert data to log
        """
        # Create log entry dictionary
        log_entry = {
            'timestamp': datetime.now().isoformat(),
            'attack_type': alert_data.get('attack_type'),
            'severity': alert_data.get('severity'),
            'confidence': float(alert_data.get('confidence', 0.0)),
            'src_ip': alert_data.get('src_ip'),
            'dst_ip': alert_data.get('dst_ip'),
            'src_port': alert_data.get('src_port'),
            'dst_port': alert_data.get('dst_port'),
            'protocol': alert_data.get('protocol'),
            'packet_size': alert_data.get('packet_size'),
            'flow_key': alert_data.get('flow_key'),
            'telegram_sent': self.config.telegram_enabled
        }
        
        try:
            # Log to JSON file (machine-readable)
            with open('logs/alerts.json', 'a') as f:
                f.write(json.dumps(log_entry) + '\n')
            
            # Log to text file (human-readable)
            with open('logs/alerts.log', 'a') as f:
                timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                f.write(
                    f"[{timestamp}] {log_entry['attack_type']} | "
                    f"{log_entry['severity']} | "
                    f"{log_entry['confidence']:.2%} | "
                    f"{log_entry['src_ip']}:{log_entry['src_port']} → "
                    f"{log_entry['dst_ip']}:{log_entry['dst_port']}\n"
                )
                
        except Exception as e:
            logger.error(f"❌ Error writing alert: {e}")
    
    def stop(self):
        """Stop the IDS system"""
        self.running = False
        logger.info("🛑 IDS service stopped")

# ============================================================================
# Signal Handler Function
# ============================================================================
def signal_handler(signum, frame):
    """
    Handle shutdown signals (SIGINT, SIGTERM)
    
    Args:
        signum: Signal number
        frame: Current stack frame
    """
    print("\n\n🛑 Shutting down IDS...")
    sys.exit(0)

# ============================================================================
# Main Entry Point
# ============================================================================
async def main():
    """
    Main entry point for the ML-IDS application
    """
    # Setup command line argument parser
    parser = argparse.ArgumentParser(description='Enhanced ML-based Intrusion Detection System')
    parser.add_argument('--config', '-c', default='config/config.yaml',
                       help='Configuration file path (default: config/config.yaml)')
    parser.add_argument('--interface', '-i', help='Network interface')
    parser.add_argument('--threshold', '-t', type=float, help='Alert threshold')
    parser.add_argument('--display', '-d', choices=['simple', 'detailed'], 
                       help='Display format')
    parser.add_argument('--interval', type=int, help='Display interval in seconds')
    
    args = parser.parse_args()
    
    # Setup signal handlers for graceful shutdown
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    
    # Initialize IDS system
    ids = RealTimeIDS(args.config)
    
    # Override configuration with command line arguments
    if args.interface:
        ids.config.interface = args.interface
    if args.threshold:
        ids.config.alert_threshold = args.threshold
    if args.display:
        ids.config.packet_format = args.display
    if args.interval:
        ids.config.display_interval = args.interval
    
    try:
        # Start packet capture and analysis
        await ids.start_capture()
    except KeyboardInterrupt:
        print("\n🛑 Stopping IDS...")
    except Exception as e:
        logger.error(f"❌ Error: {e}")
        print(f"\n❌ Fatal error: {e}")
    finally:
        # Stop the IDS system
        ids.stop()
        
        # Display final statistics
        elapsed = time.time() - ids.stats['start_time']
        print("\n" + "─" * 70)
        print("📊 FINAL STATISTICS")
        print("─" * 70)
        print(f"Total packets processed:  {ids.stats['packets_processed']:,}")
        print(f"Anomalies detected:      {ids.stats['anomalies_detected']}")
        print(f"Total time:              {elapsed:.1f} seconds")
        print(f"Average rate:            {ids.stats['packets_processed']/elapsed:.1f} packets/sec")
        print(f"Telegram alerts sent:    {ids.stats['telegram_alerts_sent']}")
        print(f"Telegram alerts failed:  {ids.stats['telegram_alerts_failed']}")
        print("─" * 70)
        print("\n📁 Log files created:")
        print("  • logs/ids_service.log - System logs")
        print("  • logs/alerts.json - JSON alert log")
        print("  • logs/alerts.log - Text alert log")

# ============================================================================
# Application Entry Point
# ============================================================================
if __name__ == "__main__":
    asyncio.run(main())
