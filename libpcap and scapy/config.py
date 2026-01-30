"""
Configuration module for ML-IDS.
Uses YAML for configuration management with dataclasses.
"""

import yaml
import json
from dataclasses import dataclass, asdict, field
from typing import Dict, Any, Optional
from pathlib import Path
import os

@dataclass
class CaptureConfig:
    """Network capture configuration"""
    interface: str = "eth0"
    filter: str = "ip"
    promiscuous: bool = True
    timeout: int = 30
    snaplen: int = 65535
    buffer_size: int = 1024 * 1024  # 1MB buffer

@dataclass
class MLConfig:
    """Machine learning model configuration"""
    model_path: str = "models/randomforest_ids.pkl"
    scaler_path: str = "models/scaler.pkl"
    encoder_path: str = "models/label_encoder.pkl"
    feature_names_path: str = "models/feature_names.json"
    anomaly_threshold: float = 0.7
    confidence_threshold: float = 0.6

@dataclass
class TelegramConfig:
    """Telegram bot configuration"""
    token: str = ""
    chat_id: str = ""
    enabled: bool = True
    cooldown_seconds: int = 60
    max_message_length: int = 4096

@dataclass
class ProcessingConfig:
    """Packet processing configuration"""
    max_packets_per_flow: int = 100
    flow_timeout_seconds: int = 120
    min_packets_for_prediction: int = 5
    feature_window_size: int = 50
    packet_queue_size: int = 1000

@dataclass
class LoggingConfig:
    """Logging configuration"""
    level: str = "INFO"
    file: str = "logs/ids_service.log"
    max_bytes: int = 10 * 1024 * 1024  # 10MB
    backup_count: int = 5
    console_output: bool = True

@dataclass
class AlertConfig:
    """Alert configuration"""
    severity_levels: Dict[str, float] = field(default_factory=lambda: {
        'CRITICAL': 0.9,
        'HIGH': 0.7,
        'MEDIUM': 0.5,
        'LOW': 0.3,
        'INFO': 0.1
    })
    enable_console_alerts: bool = True
    enable_file_logging: bool = True
    alert_retention_days: int = 30

@dataclass
class AttackClassification:
    """Attack classification thresholds"""
    ddos_threshold: float = 0.8
    portscan_threshold: float = 0.6
    brute_force_threshold: float = 0.7
    malware_threshold: float = 0.75

class ConfigManager:
    """
    Central configuration manager for ML-IDS.
    Handles loading, validation, and access to all configuration parameters.
    """
    
    def __init__(self, config_path: str = "config/config.yaml"):
        self.config_path = config_path
        self.capture = CaptureConfig()
        self.ml = MLConfig()
        self.telegram = TelegramConfig()
        self.processing = ProcessingConfig()
        self.logging = LoggingConfig()
        self.alerts = AlertConfig()
        self.attack = AttackClassification()
        
        if config_path and os.path.exists(config_path):
            self.load_from_yaml(config_path)
        else:
            print(f"Config file {config_path} not found, using defaults")
        
        self.validate_config()
    
    def load_from_yaml(self, yaml_path: str):
        """Load configuration from YAML file"""
        try:
            with open(yaml_path, 'r') as f:
                config_data = yaml.safe_load(f)
            
            # Update configurations from YAML
            if 'capture' in config_data:
                self._update_dataclass(self.capture, config_data['capture'])
            if 'ml' in config_data:
                self._update_dataclass(self.ml, config_data['ml'])
            if 'telegram' in config_data:
                self._update_dataclass(self.telegram, config_data['telegram'])
            if 'processing' in config_data:
                self._update_dataclass(self.processing, config_data['processing'])
            if 'logging' in config_data:
                self._update_dataclass(self.logging, config_data['logging'])
            
            print(f"Configuration loaded from {yaml_path}")
        except Exception as e:
            print(f"Error loading config from {yaml_path}: {e}")
            print("Using default configuration")
    
    def _update_dataclass(self, dataclass_obj, update_dict: Dict):
        """Update dataclass instance with dictionary values"""
        for key, value in update_dict.items():
            if hasattr(dataclass_obj, key):
                setattr(dataclass_obj, key, value)
    
    def validate_config(self):
        """Validate configuration values"""
        # Ensure directories exist
        Path("logs").mkdir(exist_ok=True)
        Path("models").mkdir(exist_ok=True)
        Path("config").mkdir(exist_ok=True)
        
        # Validate Telegram config
        if not self.telegram.token or self.telegram.token == "YOUR_TELEGRAM_BOT_TOKEN":
            self.telegram.enabled = False
            print("Warning: Telegram token not configured, alerts disabled")
        
        # Validate model paths
        if not Path(self.ml.model_path).exists():
            print(f"Warning: Model file not found at {self.ml.model_path}")
        
        print("Configuration validation complete")
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert config to dictionary"""
        return {
            'capture': asdict(self.capture),
            'ml': asdict(self.ml),
            'telegram': asdict(self.telegram),
            'processing': asdict(self.processing),
            'logging': asdict(self.logging),
            'alerts': asdict(self.alerts),
            'attack': asdict(self.attack)
        }
    
    def save_to_yaml(self, yaml_path: str):
        """Save configuration to YAML file"""
        try:
            config_dict = self.to_dict()
            with open(yaml_path, 'w') as f:
                yaml.dump(config_dict, f, default_flow_style=False)
            print(f"Configuration saved to {yaml_path}")
        except Exception as e:
            print(f"Error saving config: {e}")
    
    def get_telegram_enabled(self) -> bool:
        """Check if Telegram alerts are enabled"""
        return self.telegram.enabled and bool(self.telegram.token and self.telegram.chat_id)
