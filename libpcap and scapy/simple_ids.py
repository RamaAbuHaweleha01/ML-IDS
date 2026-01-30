#!/usr/bin/env python3
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
            'CRITICAL': '\033[91m',  # Red
            'HIGH': '\033[93m',      # Yellow
            'MEDIUM': '\033[96m',    # Cyan
            'LOW': '\033[92m'        # Green
        }
        
        color = colors.get(severity, '\033[0m')
        reset = '\033[0m'
        
        print(f"\n{color}{'='*60}{reset}")
        print(f"{color}🚨 INTRUSION DETECTED!{reset}")
        print(f"{color}Attack Type: {attack}{reset}")
        print(f"{color}Severity: {severity}{reset}")
        print(f"{color}Confidence: {confidence:.2%}{reset}")
        print(f"{color}{'='*60}{reset}\n")
        
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
                f.write(json.dumps(alert_entry) + '\n')
        except Exception as e:
            logger.error(f"Error writing alert: {e}")
    
    def _print_status(self):
        """Print current status"""
        elapsed = time.time() - self.stats['start_time']
        rate = self.stats['packets_processed'] / elapsed if elapsed > 0 else 0
        
        status = (
            f"\n{'='*50}\n"
            f"ML-IDS STATUS\n"
            f"{'='*50}\n"
            f"Packets Processed: {self.stats['packets_processed']:,}\n"
            f"Anomalies Detected: {self.stats['anomalies_detected']}\n"
            f"Current Rate: {self.stats['packet_rate']} packets/sec\n"
            f"Average Rate: {rate:.1f} packets/sec\n"
            f"Uptime: {elapsed:.1f} seconds\n"
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
    print("\n" + "="*60)
    print("ML-IDS SIMPLE TEST SYSTEM")
    print("="*60)
    print("This is a test version that simulates network traffic.")
    print("Press Ctrl+C to stop.")
    print("="*60 + "\n")
    
    # Initialize IDS
    ids = SimpleMLIDS()
    
    try:
        # Start simulation
        await ids.simulate_packets()
    except KeyboardInterrupt:
        print("\n\nStopping IDS...")
    except Exception as e:
        print(f"\nError: {e}")
    finally:
        ids.stop()
        
        # Print final stats
        elapsed = time.time() - ids.stats['start_time']
        print("\n" + "="*60)
        print("FINAL STATISTICS")
        print("="*60)
        print(f"Total packets: {ids.stats['packets_processed']:,}")
        print(f"Anomalies detected: {ids.stats['anomalies_detected']}")
        print(f"Total time: {elapsed:.1f} seconds")
        print(f"Average rate: {ids.stats['packets_processed']/elapsed:.1f} packets/sec")
        print("="*60)
        print("\nCheck logs/alerts.json for detected anomalies.")
        print("="*60)

if __name__ == "__main__":
    asyncio.run(main())
