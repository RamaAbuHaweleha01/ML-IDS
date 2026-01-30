"""
Feature extraction module for network flows.
Extracts features from packets and aggregates them into flow-based features for ML prediction.
"""

import time
import numpy as np
from typing import Dict, Any, Optional, List, Tuple
from collections import defaultdict, deque
import hashlib
import logging

class FlowFeatureExtractor:
    """
    Extracts features from network packets and flows for ML prediction.
    
    Attributes:
        flow_timeout (int): Time in seconds before flow is considered expired.
        max_packets_per_flow (int): Maximum packets to store per flow.
        flow_stats (dict): Statistics for each flow.
        last_packet_time (dict): Last packet timestamp for each flow.
        packet_buffer (dict): Circular buffer for packet features per flow.
    """
    
    def __init__(self, flow_timeout: int = 120, max_packets_per_flow: int = 100):
        self.flow_timeout = flow_timeout
        self.max_packets_per_flow = max_packets_per_flow
        self.flow_stats = {}
        self.last_packet_time = {}
        self.packet_buffer = defaultdict(lambda: deque(maxlen=max_packets_per_flow))
        self.logger = logging.getLogger(__name__)
    
    def create_flow_key(self, packet_info: Dict[str, Any]) -> Optional[str]:
        """
        Create unique flow key from packet information.
        
        Args:
            packet_info: Dictionary containing packet information.
        
        Returns:
            Flow key string or None if packet doesn't have required info.
        """
        if not packet_info.get('has_ip', False):
            return None
        
        src_ip = packet_info.get('src_ip')
        dst_ip = packet_info.get('dst_ip')
        protocol = packet_info.get('protocol')
        
        if not (src_ip and dst_ip and protocol):
            return None
        
        # For TCP/UDP, include ports
        if packet_info.get('src_port') and packet_info.get('dst_port'):
            src_port = packet_info['src_port']
            dst_port = packet_info['dst_port']
            
            # Create bidirectional flow key (order doesn't matter)
            if src_ip < dst_ip or (src_ip == dst_ip and src_port < dst_port):
                flow_key = f'{src_ip}:{src_port}-{dst_ip}:{dst_port}-{protocol}'
            else:
                flow_key = f'{dst_ip}:{dst_port}-{src_ip}:{src_port}-{protocol}'
        else:
            # For ICMP and other protocols
            if src_ip < dst_ip:
                flow_key = f'{src_ip}-{dst_ip}-{protocol}'
            else:
                flow_key = f'{dst_ip}-{src_ip}-{protocol}'
        
        return flow_key
    
    def extract_packet_features(self, packet_info: Dict[str, Any]) -> Dict[str, Any]:
        """
        Extract features from a single packet.
        
        Args:
            packet_info: Dictionary containing packet information.
        
        Returns:
            Dictionary with packet features.
        """
        features = {
            'timestamp': packet_info.get('timestamp', time.time()),
            'src_ip': packet_info.get('src_ip', ''),
            'dst_ip': packet_info.get('dst_ip', ''),
            'protocol': packet_info.get('protocol', 0),
            'src_port': packet_info.get('src_port', 0),
            'dst_port': packet_info.get('dst_port', 0),
            'packet_length': packet_info.get('length', 0),
            'ttl': packet_info.get('ttl', 0),
            'tos': packet_info.get('tos', 0),
            'payload_length': packet_info.get('payload_length', 0),
            'ip_id': packet_info.get('ip_id', 0),
            'ip_flags': packet_info.get('ip_flags', 0)
        }
        
        # TCP specific features
        if packet_info.get('has_tcp', False):
            features.update({
                'tcp_flags': packet_info.get('tcp_flags', 0),
                'window_size': packet_info.get('tcp_window', 0),
                'tcp_seq': packet_info.get('tcp_seq', 0),
                'tcp_ack': packet_info.get('tcp_ack', 0),
                'tcp_urgptr': packet_info.get('tcp_urgptr', 0),
                'tcp_dataofs': packet_info.get('tcp_dataofs', 0)
            })
        # UDP specific features
        elif packet_info.get('has_udp', False):
            features.update({
                'udp_len': packet_info.get('udp_len', 0),
                'udp_chksum': packet_info.get('udp_chksum', 0)
            })
        # ICMP specific features
        elif packet_info.get('has_icmp', False):
            features.update({
                'icmp_type': packet_info.get('icmp_type', 0),
                'icmp_code': packet_info.get('icmp_code', 0),
                'icmp_chksum': packet_info.get('icmp_chksum', 0)
            })
        
        # Calculate inter-arrival time
        current_time = features['timestamp']
        flow_key = self.create_flow_key(packet_info)
        
        if flow_key:
            if flow_key in self.last_packet_time:
                features['inter_arrival_time'] = current_time - self.last_packet_time[flow_key]
            else:
                features['inter_arrival_time'] = 0
            
            self.last_packet_time[flow_key] = current_time
            
            # Store in packet buffer
            self.packet_buffer[flow_key].append(features)
        
        return features
    
    def update_flow_stats(self, flow_key: str, packet_features: Dict[str, Any]) -> Dict[str, Any]:
        """
        Update flow statistics with new packet.
        
        Args:
            flow_key: Unique flow identifier.
            packet_features: Features of the current packet.
        
        Returns:
            Updated flow statistics.
        """
        current_time = packet_features['timestamp']
        
        # Clean old flows
        self._cleanup_old_flows(current_time)
        
        # Initialize flow stats if needed
        if flow_key not in self.flow_stats:
            self.flow_stats[flow_key] = {
                'start_time': current_time,
                'last_time': current_time,
                'total_packets': 0,
                'total_bytes': 0,
                'packet_lengths': [],
                'inter_arrival_times': [],
                'protocol': packet_features.get('protocol', 0),
                'src_ip': packet_features.get('src_ip', ''),
                'dst_ip': packet_features.get('dst_ip', ''),
                'src_port': packet_features.get('src_port', 0),
                'dst_port': packet_features.get('dst_port', 0),
                'tcp_flags': [],
                'ttls': [],
                'window_sizes': [],
                'payload_lengths': []
            }
        
        flow = self.flow_stats[flow_key]
        
        # Update statistics
        flow['last_time'] = current_time
        flow['total_packets'] += 1
        flow['total_bytes'] += packet_features['packet_length']
        flow['packet_lengths'].append(packet_features['packet_length'])
        
        # Collect various features
        if 'inter_arrival_time' in packet_features:
            flow['inter_arrival_times'].append(packet_features['inter_arrival_time'])
        
        if 'tcp_flags' in packet_features:
            flow['tcp_flags'].append(packet_features['tcp_flags'])
        
        if 'ttl' in packet_features:
            flow['ttls'].append(packet_features['ttl'])
        
        if 'window_size' in packet_features:
            flow['window_sizes'].append(packet_features['window_size'])
        
        if 'payload_length' in packet_features:
            flow['payload_lengths'].append(packet_features['payload_length'])
        
        return flow
    
    def get_flow_features(self, flow_key: str) -> Optional[List[float]]:
        """
        Extract ML features from flow statistics.
        
        Args:
            flow_key: Unique flow identifier.
        
        Returns:
            List of feature values for ML model (78 features based on CIC-IDS2017).
        """
        if flow_key not in self.flow_stats:
            return None
        
        flow = self.flow_stats[flow_key]
        
        if flow['total_packets'] < 5:  # Need minimum packets for meaningful features
            return None
        
        features = []
        
        try:
            # 1. Basic Flow Features (10 features)
            features.append(flow['total_packets'])  # 0: Total Fwd Packets
            features.append(flow['total_bytes'])     # 1: Total Length of Fwd Packets
            
            # Count forward packets
            fwd_packets = len([p for p in self.packet_buffer[flow_key] 
                              if p['src_ip'] == flow['src_ip']])
            features.append(fwd_packets)  # 2: Fwd Packet Length Total
            
            # 2. Duration Features (4 features)
            duration = flow['last_time'] - flow['start_time']
            features.append(duration)  # 3: Flow Duration
            
            if duration > 0:
                features.append(flow['total_packets'] / duration)  # 4: Flow Packets/s
                features.append(flow['total_bytes'] / duration)    # 5: Flow Bytes/s
            else:
                features.extend([0.0, 0.0])
            
            # 3. Packet Length Statistics (20 features)
            if flow['packet_lengths']:
                lengths = np.array(flow['packet_lengths'])
                features.append(float(np.mean(lengths)))   # 6: Packet Length Mean
                features.append(float(np.std(lengths)))    # 7: Packet Length Std
                features.append(float(np.var(lengths)))    # 8: Packet Length Variance
                features.append(float(np.min(lengths)))    # 9: Packet Length Min
                features.append(float(np.max(lengths)))    # 10: Packet Length Max
            else:
                features.extend([0.0, 0.0, 0.0, 0.0, 0.0])
            
            # 4. Inter-Arrival Time Statistics (10 features)
            if flow['inter_arrival_times']:
                iats = np.array(flow['inter_arrival_times'])
                features.append(float(np.mean(iats)))   # 11: IAT Mean
                features.append(float(np.std(iats)))    # 12: IAT Std
                features.append(float(np.min(iats)))    # 13: IAT Min
                features.append(float(np.max(iats)))    # 14: IAT Max
                features.append(float(np.sum(iats)))    # 15: Total IAT
            else:
                features.extend([0.0, 0.0, 0.0, 0.0, 0.0])
            
            # 5. TCP Flag Statistics (6 features)
            if flow['tcp_flags']:
                flags = np.array(flow['tcp_flags'])
                syn_count = np.sum((flags & 0x02) > 0)
                ack_count = np.sum((flags & 0x10) > 0)
                fin_count = np.sum((flags & 0x01) > 0)
                rst_count = np.sum((flags & 0x04) > 0)
                psh_count = np.sum((flags & 0x08) > 0)
                urg_count = np.sum((flags & 0x20) > 0)
                
                features.extend([syn_count, ack_count, fin_count, 
                               rst_count, psh_count, urg_count])
            else:
                features.extend([0.0, 0.0, 0.0, 0.0, 0.0, 0.0])
            
            # 6. TTL Statistics (5 features)
            if flow['ttls']:
                ttls = np.array(flow['ttls'])
                features.append(float(np.mean(ttls)))   # 22: TTL Mean
                features.append(float(np.std(ttls)))    # 23: TTL Std
                features.append(float(np.min(ttls)))    # 24: TTL Min
                features.append(float(np.max(ttls)))    # 25: TTL Max
                features.append(float(len(set(ttls))))  # 26: Unique TTLs
            else:
                features.extend([0.0, 0.0, 0.0, 0.0, 0.0])
            
            # 7. Window Size Statistics (5 features)
            if flow['window_sizes']:
                windows = np.array(flow['window_sizes'])
                features.append(float(np.mean(windows)))   # 27: Window Size Mean
                features.append(float(np.std(windows)))    # 28: Window Size Std
                features.append(float(np.min(windows)))    # 29: Window Size Min
                features.append(float(np.max(windows)))    # 30: Window Size Max
                features.append(float(len(set(windows))))  # 31: Unique Window Sizes
            else:
                features.extend([0.0, 0.0, 0.0, 0.0, 0.0])
            
            # 8. Payload Statistics (10 features)
            if flow['payload_lengths']:
                payloads = np.array(flow['payload_lengths'])
                features.append(float(np.sum(payloads)))          # 32: Total Payload
                features.append(float(np.mean(payloads)))         # 33: Payload Mean
                features.append(float(np.std(payloads)))          # 34: Payload Std
                features.append(float(np.min(payloads)))          # 35: Payload Min
                features.append(float(np.max(payloads)))          # 36: Payload Max
                features.append(float(np.sum(payloads > 0)))      # 37: Packets with Payload
                
                # Payload rate
                if duration > 0:
                    features.append(float(np.sum(payloads) / duration))  # 38: Payload Rate
                else:
                    features.append(0.0)
                
                # Payload entropy approximation
                features.append(self._calculate_payload_entropy(flow_key))  # 39: Payload Entropy
                features.append(float(len(set(payloads))))                  # 40: Unique Payload Sizes
                features.append(float(np.median(payloads)))                 # 41: Payload Median
            else:
                features.extend([0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0])
            
            # 9. Protocol and Port Features (8 features)
            features.append(float(flow['protocol']))  # 42: Protocol
            
            # Port statistics
            if flow['src_port'] > 0:
                features.append(1.0 if flow['src_port'] < 1024 else 0.0)  # 43: Well-known Source Port
                features.append(float(flow['src_port']))                  # 44: Source Port
            else:
                features.extend([0.0, 0.0])
            
            if flow['dst_port'] > 0:
                features.append(1.0 if flow['dst_port'] < 1024 else 0.0)  # 45: Well-known Dest Port
                features.append(float(flow['dst_port']))                  # 46: Destination Port
            else:
                features.extend([0.0, 0.0])
            
            # Port ratio
            if flow['dst_port'] > 0:
                features.append(float(flow['src_port'] / max(flow['dst_port'], 1)))  # 47: Port Ratio
            else:
                features.append(0.0)
            
            # Is ephemeral port
            features.append(1.0 if 49152 <= flow['src_port'] <= 65535 else 0.0)  # 48: Ephemeral Source Port
            
            return features
            
        except Exception as e:
            self.logger.error(f"Error extracting flow features: {e}")
            return None
    
    def _calculate_payload_entropy(self, flow_key: str) -> float:
        """Calculate entropy of payloads in a flow."""
        try:
            if flow_key not in self.packet_buffer:
                return 0.0
            
            # Collect all payloads
            all_payloads = []
            for packet in self.packet_buffer[flow_key]:
                if 'payload' in packet and packet['payload']:
                    all_payloads.extend(packet['payload'])
            
            if not all_payloads:
                return 0.0
            
            # Calculate byte frequency
            byte_counts = {}
            total_bytes = len(all_payloads)
            
            for byte_val in all_payloads:
                byte_counts[byte_val] = byte_counts.get(byte_val, 0) + 1
            
            # Calculate entropy
            entropy = 0.0
            for count in byte_counts.values():
                probability = count / total_bytes
                entropy -= probability * np.log2(probability)
            
            return entropy
            
        except Exception:
            return 0.0
    
    def _cleanup_old_flows(self, current_time: float):
        """Remove flows that have timed out."""
        flows_to_remove = []
        
        for flow_key, flow in self.flow_stats.items():
            if current_time - flow['last_time'] > self.flow_timeout:
                flows_to_remove.append(flow_key)
        
        for flow_key in flows_to_remove:
            del self.flow_stats[flow_key]
            if flow_key in self.packet_buffer:
                del self.packet_buffer[flow_key]
            if flow_key in self.last_packet_time:
                del self.last_packet_time[flow_key]
        
        if flows_to_remove:
            self.logger.debug(f"Cleaned up {len(flows_to_remove)} old flows")
    
    def reset_flow(self, flow_key: str):
        """Reset flow statistics after prediction."""
        if flow_key in self.flow_stats:
            del self.flow_stats[flow_key]
        if flow_key in self.packet_buffer:
            self.packet_buffer[flow_key].clear()
    
    def get_all_flow_keys(self) -> List[str]:
        """Get list of all active flow keys."""
        return list(self.flow_stats.keys())
    
    def get_flow_count(self) -> int:
        """Get number of active flows."""
        return len(self.flow_stats)
