#!/usr/bin/env python3
"""
Complete setup script for ML-IDS
Run this first to create all necessary files and directories
"""

import os
import sys
import numpy as np
import joblib
import json
import pickle
import yaml
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import StandardScaler, LabelEncoder

def print_header(text):
    """Print formatted header"""
    print("\n" + "="*60)
    print(text)
    print("="*60)

def create_directories():
    """Create all necessary directories"""
    print_header("Creating Directories")
    
    directories = ['logs', 'models', 'config', 'data']
    for directory in directories:
        os.makedirs(directory, exist_ok=True)
        print(f"✓ Created directory: {directory}")

def create_config_file():
    """Create default configuration file"""
    print_header("Creating Configuration")
    
    config_content = {
        'capture': {
            'interface': 'eth0',
            'filter': 'ip',
            'promiscuous': True,
            'timeout': 30,
            'snaplen': 65535,
            'buffer_size': 1048576
        },
        'ml': {
            'model_path': 'models/randomforest_ids.pkl',
            'scaler_path': 'models/scaler.pkl',
            'encoder_path': 'models/label_encoder.pkl',
            'feature_names_path': 'models/feature_names.json',
            'anomaly_threshold': 0.7,
            'confidence_threshold': 0.6
        },
        'telegram': {
            'token': '',
            'chat_id': '',
            'enabled': False,
            'cooldown_seconds': 60,
            'max_message_length': 4096
        },
        'processing': {
            'max_packets_per_flow': 100,
            'flow_timeout_seconds': 120,
            'min_packets_for_prediction': 5,
            'feature_window_size': 50,
            'packet_queue_size': 1000
        },
        'logging': {
            'level': 'INFO',
            'file': 'logs/ids_service.log',
            'max_bytes': 10485760,
            'backup_count': 5,
            'console_output': True
        },
        'alerts': {
            'severity_levels': {
                'CRITICAL': 0.9,
                'HIGH': 0.7,
                'MEDIUM': 0.5,
                'LOW': 0.3,
                'INFO': 0.1,
                'COOLDOWN': 60
            },
            'enable_console_alerts': True,
            'enable_file_logging': True,
            'alert_retention_days': 30
        },
        'attack': {
            'ddos_threshold': 0.8,
            'portscan_threshold': 0.6,
            'brute_force_threshold': 0.7,
            'malware_threshold': 0.75
        }
    }
    
    config_path = 'config/config.yaml'
    with open(config_path, 'w') as f:
        yaml.dump(config_content, f, default_flow_style=False)
    
    print(f"✓ Created configuration file: {config_path}")
    
    # Also create a simple JSON config for compatibility
    json_config = {
        'model_path': 'models/random_forest_model.pkl',
        'interface': 'eth0',
        'filter': 'ip',
        'promiscuous': True,
        'alert_threshold': 0.8,
        'log_file': 'logs/ids.log',
        'alert_file': 'logs/alerts.log',
        'stats_interval': 60,
        'max_packets_per_batch': 100,
        'simulation_mode': False
    }
    
    with open('config/ids_config.json', 'w') as f:
        json.dump(json_config, f, indent=2)
    
    print("✓ Created JSON config file: config/ids_config.json")

def create_dummy_model():
    """Create a dummy ML model for testing"""
    print_header("Creating ML Model")
    
    try:
        # Generate synthetic training data
        print("Generating training data...")
        np.random.seed(42)
        n_samples = 1000
        n_features = 48  # Matching our feature extractor
        
        # 80% normal traffic (class 0), 20% attacks (classes 1, 2)
        X = np.random.randn(n_samples, n_features)
        y = np.random.choice([0, 1, 2], size=n_samples, p=[0.8, 0.1, 0.1])
        
        # Add some patterns to make it learnable
        X[y == 1, :10] += 2  # Attack type 1 has higher first 10 features
        X[y == 2, 10:20] -= 2  # Attack type 2 has lower features 10-20
        
        print(f"Training data shape: {X.shape}")
        print(f"Class distribution: Normal={sum(y==0)}, Attack1={sum(y==1)}, Attack2={sum(y==2)}")
        
        # Create and train model
        print("Training Random Forest model...")
        model = RandomForestClassifier(
            n_estimators=50,
            random_state=42,
            n_jobs=-1,
            max_depth=10,
            min_samples_split=5
        )
        model.fit(X, y)
        
        # Create scaler
        scaler = StandardScaler()
        X_scaled = scaler.fit_transform(X)
        
        # Create label encoder
        encoder = LabelEncoder()
        y_encoded = encoder.fit_transform(y)
        
        # Save models
        model_path = 'models/randomforest_ids.pkl'
        scaler_path = 'models/scaler.pkl'
        encoder_path = 'models/label_encoder.pkl'
        
        joblib.dump(model, model_path)
        joblib.dump(scaler, scaler_path)
        joblib.dump(encoder, encoder_path)
        
        print(f"✓ Saved model: {model_path}")
        print(f"✓ Saved scaler: {scaler_path}")
        print(f"✓ Saved encoder: {encoder_path}")
        
        # Save feature names
        feature_names = [f'feature_{i}' for i in range(n_features)]
        with open('models/feature_names.json', 'w') as f:
            json.dump(feature_names, f, indent=2)
        
        print("✓ Saved feature names: models/feature_names.json")
        
        # Save metadata
        metadata = {
            'n_features': n_features,
            'classes': ['Normal', 'Attack_DoS', 'Attack_Probe'],
            'feature_names': feature_names,
            'attack_mapping': {'0': 'Normal', '1': 'Attack_DoS', '2': 'Attack_Probe'},
            'model_info': {
                'n_estimators': 50,
                'max_depth': 10,
                'random_state': 42
            }
        }
        
        with open('models/model_metadata.pkl', 'wb') as f:
            pickle.dump(metadata, f)
        
        print("✓ Saved model metadata: models/model_metadata.pkl")
        
        # Test the model
        test_score = model.score(X, y)
        print(f"✓ Model trained with accuracy: {test_score:.2%}")
        
        return True
        
    except Exception as e:
        print(f"✗ Error creating model: {e}")
        return False

def create_python_modules():
    """Create all Python module files"""
    print_header("Creating Python Modules")
    
    # Create __init__.py files
    for dir in ['models', 'logs', 'config', 'data']:
        init_file = os.path.join(dir, '__init__.py')
        if not os.path.exists(init_file):
            with open(init_file, 'w') as f:
                f.write('# Package initialization\n')
    
    modules = {
        'config.py': '''"""
Configuration module for ML-IDS
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
    buffer_size: int = 1048576

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
    max_bytes: int = 10485760
    backup_count: int = 5
    console_output: bool = True

@dataclass
class AlertConfig:
    """Alert configuration"""
    severity_levels: Dict[str, float] = field(default_factory=lambda: {
        'CRITICAL': 0.9, 'HIGH': 0.7, 'MEDIUM': 0.5, 'LOW': 0.3, 'INFO': 0.1
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
    """Central configuration manager"""
    
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
            
            # Update each configuration section
            sections = ['capture', 'ml', 'telegram', 'processing', 'logging', 'alerts', 'attack']
            for section in sections:
                if section in config_data and hasattr(self, section):
                    obj = getattr(self, section)
                    self._update_dataclass(obj, config_data[section])
            
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
        Path("data").mkdir(exist_ok=True)
        
        # Validate Telegram config
        if not self.telegram.token or self.telegram.token == "YOUR_TELEGRAM_BOT_TOKEN":
            self.telegram.enabled = False
            print("Warning: Telegram token not configured, alerts disabled")
        
        # Validate model paths
        model_files = [
            (self.ml.model_path, "Model"),
            (self.ml.scaler_path, "Scaler"),
            (self.ml.encoder_path, "Encoder")
        ]
        
        for path, name in model_files:
            if not Path(path).exists():
                print(f"Warning: {name} file not found at {path}")
        
        print("Configuration validation complete")
    
    def get_telegram_enabled(self) -> bool:
        """Check if Telegram alerts are enabled"""
        return self.telegram.enabled and bool(self.telegram.token and self.telegram.chat_id)
    
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
''',
        
        'requirements.txt': '''scapy>=2.5.0
scikit-learn>=1.0.0
numpy>=1.21.0
pandas>=1.3.0
joblib>=1.1.0
pyyaml>=6.0
requests>=2.28.0
streamlit>=1.12.0
plotly>=5.10.0'''
    }
    
    for filename, content in modules.items():
        if not os.path.exists(filename):
            with open(filename, 'w') as f:
                f.write(content)
            print(f"✓ Created: {filename}")
        else:
            print(f"✓ Already exists: {filename}")

def create_simple_ids_service():
    """Create a simple IDS service that works"""
    print_header("Creating IDS Service")
    
    ids_service_content = '''#!/usr/bin/env python3
"""
Simple ML-IDS Service for testing
Run this to test your setup
"""

import os
import sys
import time
import json
import logging
import asyncio
from datetime import datetime
import numpy as np

# Create directories first
os.makedirs('logs', exist_ok=True)
os.makedirs('models', exist_ok=True)
os.makedirs('config', exist_ok=True)

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('logs/ids_service.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

class SimpleMLIDS:
    """Simple ML-based IDS for testing"""
    
    def __init__(self):
        logger.info("Initializing Simple ML-IDS")
        
        # Check for model files
        self.model_loaded = False
        self.model_files = [
            'models/randomforest_ids.pkl',
            'models/scaler.pkl', 
            'models/label_encoder.pkl'
        ]
        
        # Check which files exist
        for file in self.model_files:
            if os.path.exists(file):
                logger.info(f"Found model file: {file}")
                self.model_loaded = True
            else:
                logger.warning(f"Missing model file: {file}")
        
        # Statistics
        self.stats = {
            'packets_processed': 0,
            'anomalies_detected': 0,
            'start_time': time.time(),
            'packet_rate': 0
        }
        
        self.running = False
        
        if self.model_loaded:
            logger.info("ML model files found. System ready.")
        else:
            logger.warning("Running in simulation mode (no ML model)")
    
    async def simulate_packets(self):
        """Simulate packet processing"""
        logger.info("Starting packet simulation...")
        self.running = True
        
        packet_count = 0
        last_update = time.time()
        
        try:
            while self.running:
                # Simulate packet arrival
                await asyncio.sleep(0.05)  # ~20 packets/sec
                
                packet_count += 1
                self.stats['packets_processed'] += 1
                
                # Update packet rate every second
                current_time = time.time()
                if current_time - last_update >= 1.0:
                    self.stats['packet_rate'] = packet_count
                    packet_count = 0
                    last_update = current_time
                
                # Simulate ML prediction (every 10 packets)
                if self.stats['packets_processed'] % 10 == 0:
                    self._simulate_prediction()
                
                # Print status every 100 packets
                if self.stats['packets_processed'] % 100 == 0:
                    self._print_status()
        
        except KeyboardInterrupt:
            logger.info("Simulation stopped by user")
        except Exception as e:
            logger.error(f"Error in simulation: {e}")
        finally:
            self.running = False
    
    def _simulate_prediction(self):
        """Simulate ML prediction"""
        # Simulate normal traffic 95% of the time
        if np.random.random() > 0.05:
            return
        
        # Simulate anomaly
        self.stats['anomalies_detected'] += 1
        
        attack_types = ['DDoS', 'PortScan', 'BruteForce', 'Malware']
        severity_levels = ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL']
        
        attack = np.random.choice(attack_types)
        severity = np.random.choice(severity_levels, p=[0.4, 0.3, 0.2, 0.1])
        confidence = np.random.uniform(0.7, 0.95)
        
        # Log the alert
        alert_msg = (
            f"🚨 ALERT: {attack} detected | "
            f"Severity: {severity} | "
            f"Confidence: {confidence:.2%} | "
            f"Source: 10.0.{np.random.randint(0,255)}.{np.random.randint(1,255)}"
        )
        
        logger.warning(alert_msg)
        
        # Also print to console
        colors = {
            'CRITICAL': '\\033[91m',  # Red
            'HIGH': '\\033[93m',      # Yellow
            'MEDIUM': '\\033[96m',    # Cyan
            'LOW': '\\033[92m'        # Green
        }
        
        color = colors.get(severity, '\\033[0m')
        reset = '\\033[0m'
        
        print(f"\\n{color}{'='*60}{reset}")
        print(f"{color}🚨 INTRUSION DETECTED!{reset}")
        print(f"{color}Attack Type: {attack}{reset}")
        print(f"{color}Severity: {severity}{reset}")
        print(f"{color}Confidence: {confidence:.2%}{reset}")
        print(f"{color}{'='*60}{reset}\\n")
        
        # Save to alert log
        self._log_alert(attack, severity, confidence)
    
    def _log_alert(self, attack_type, severity, confidence):
        """Log alert to file"""
        alert_entry = {
            'timestamp': datetime.now().isoformat(),
            'attack_type': attack_type,
            'severity': severity,
            'confidence': float(confidence),
            'packets_processed': self.stats['packets_processed']
        }
        
        try:
            with open('logs/alerts.json', 'a') as f:
                f.write(json.dumps(alert_entry) + '\\n')
        except Exception as e:
            logger.error(f"Error writing alert: {e}")
    
    def _print_status(self):
        """Print current status"""
        elapsed = time.time() - self.stats['start_time']
        rate = self.stats['packets_processed'] / elapsed if elapsed > 0 else 0
        
        status = (
            f"\\n{'='*50}\\n"
            f"ML-IDS STATUS\\n"
            f"{'='*50}\\n"
            f"Packets Processed: {self.stats['packets_processed']:,}\\n"
            f"Anomalies Detected: {self.stats['anomalies_detected']}\\n"
            f"Current Rate: {self.stats['packet_rate']} packets/sec\\n"
            f"Average Rate: {rate:.1f} packets/sec\\n"
            f"Uptime: {elapsed:.1f} seconds\\n"
            f"{'='*50}"
        )
        
        print(status)
        logger.info(f"Status: {self.stats['packets_processed']} packets, "
                   f"{self.stats['anomalies_detected']} anomalies")
    
    def stop(self):
        """Stop the IDS"""
        self.running = False
        logger.info("IDS service stopped")

async def main():
    """Main function"""
    print("\\n" + "="*60)
    print("ML-IDS SIMPLE TEST SYSTEM")
    print("="*60)
    print("This is a test version that simulates network traffic.")
    print("Press Ctrl+C to stop.")
    print("="*60 + "\\n")
    
    # Initialize IDS
    ids = SimpleMLIDS()
    
    try:
        # Start simulation
        await ids.simulate_packets()
    except KeyboardInterrupt:
        print("\\n\\nStopping IDS...")
    except Exception as e:
        print(f"\\nError: {e}")
    finally:
        ids.stop()
        
        # Print final stats
        elapsed = time.time() - ids.stats['start_time']
        print("\\n" + "="*60)
        print("FINAL STATISTICS")
        print("="*60)
        print(f"Total packets: {ids.stats['packets_processed']:,}")
        print(f"Anomalies detected: {ids.stats['anomalies_detected']}")
        print(f"Total time: {elapsed:.1f} seconds")
        print(f"Average rate: {ids.stats['packets_processed']/elapsed:.1f} packets/sec")
        print("="*60)
        print("\\nCheck logs/alerts.json for detected anomalies.")
        print("="*60)

if __name__ == "__main__":
    asyncio.run(main())
'''
    
    with open('simple_ids.py', 'w') as f:
        f.write(ids_service_content)
    
    print("✓ Created: simple_ids.py (test version)")

def main():
    """Main setup function"""
    print("="*60)
    print("ML-IDS COMPLETE SETUP")
    print("="*60)
    
    try:
        # Create directories
        create_directories()
        
        # Create config files
        create_config_file()
        
        # Create ML model
        if create_dummy_model():
            print("\n✅ ML Model created successfully!")
        else:
            print("\n⚠️  Could not create ML model, but continuing setup...")
        
        # Create Python modules
        create_python_modules()
        
        # Create simple IDS service
        create_simple_ids_service()
        
        print_header("SETUP COMPLETE!")
        
        print("\n📋 NEXT STEPS:")
        print("1. Test the system:")
        print("   python3 simple_ids.py")
        print("")
        print("2. If that works, try the full version:")
        print("   python3 ids_service.py")
        print("")
        print("3. Configure Telegram alerts (optional):")
        print("   Edit config/config.yaml and add your bot token/chat ID")
        print("")
        print("4. Run dashboard:")
        print("   streamlit run dashboard_streamlit.py")
        print("")
        print("="*60)
        
    except Exception as e:
        print(f"\n❌ Setup failed: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
