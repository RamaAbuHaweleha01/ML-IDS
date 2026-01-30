#!/usr/bin/env python3
"""
Simplified IDS Service for testing
"""

import os
import sys
import time
import logging
import asyncio
from datetime import datetime

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

class SimpleIDS:
    def __init__(self):
        logger.info("Simple IDS initialized")
        self.running = False
        self.stats = {
            'packets_processed': 0,
            'start_time': time.time()
        }
    
    async def simulate_packet_capture(self):
        """Simulate packet capture for testing"""
        logger.info("Starting simulated packet capture...")
        self.running = True
        
        try:
            while self.running:
                # Simulate receiving a packet
                await asyncio.sleep(0.1)  # 10 packets per second
                
                self.stats['packets_processed'] += 1
                
                # Print stats every 10 packets
                if self.stats['packets_processed'] % 10 == 0:
                    elapsed = time.time() - self.stats['start_time']
                    rate = self.stats['packets_processed'] / elapsed if elapsed > 0 else 0
                    
                    print(f"\rPackets: {self.stats['packets_processed']} | "
                          f"Rate: {rate:.1f} pkt/s | "
                          f"Time: {datetime.now().strftime('%H:%M:%S')}", end='')
                
                # Simulate occasional anomaly (every 50 packets)
                if self.stats['packets_processed'] % 50 == 0:
                    logger.warning(f"Simulated anomaly detected at packet #{self.stats['packets_processed']}")
                    print(f"\n⚠️  Simulated anomaly detected!")
                
        except KeyboardInterrupt:
            logger.info("Packet capture stopped by user")
        except Exception as e:
            logger.error(f"Error in packet capture: {e}")
        finally:
            self.running = False
    
    def stop(self):
        self.running = False
        logger.info("IDS stopped")

async def main():
    print("="*60)
    print("SIMPLE IDS TEST SYSTEM")
    print("="*60)
    print("This is a test version without ML or packet capture.")
    print("Press Ctrl+C to stop.")
    print("="*60)
    
    # Initialize simple IDS
    ids = SimpleIDS()
    
    try:
        # Start simulated packet capture
        await ids.simulate_packet_capture()
    except KeyboardInterrupt:
        print("\n\nStopped by user")
    finally:
        ids.stop()
        
        # Print final stats
        elapsed = time.time() - ids.stats['start_time']
        print("\n" + "="*60)
        print("FINAL STATISTICS:")
        print(f"Total packets processed: {ids.stats['packets_processed']}")
        print(f"Total time: {elapsed:.1f} seconds")
        print(f"Average rate: {ids.stats['packets_processed']/elapsed:.1f} packets/sec")
        print("="*60)

if __name__ == "__main__":
    asyncio.run(main())
