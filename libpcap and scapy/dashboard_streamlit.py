#!/usr/bin/env python3
"""
Enhanced ML-IDS Streamlit Dashboard with Real-time Packet Monitoring
OOP style with comprehensive packet information display
"""

import streamlit as st
import pandas as pd
import numpy as np
import plotly.graph_objects as go
import plotly.express as px
from datetime import datetime, timedelta
import time
import json
import os
from collections import deque
import threading
import queue
import random

# Page configuration
st.set_page_config(
    page_title="ML-IDS Dashboard",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Custom CSS with enhanced styling
st.markdown("""
<style>
    .main-header {
        font-size: 2.5rem;
        color: #1E88E5;
        text-align: center;
        margin-bottom: 2rem;
        padding: 1rem;
        background: linear-gradient(90deg, #1E88E5, #0D47A1);
        -webkit-background-clip: text;
        -webkit-text-fill-color: transparent;
        text-shadow: 2px 2px 4px rgba(0,0,0,0.1);
    }
    
    .metric-card {
        background-color: #f8f9fa;
        padding: 1rem;
        border-radius: 15px;
        box-shadow: 0 4px 6px rgba(0,0,0,0.1);
        border-left: 5px solid #1E88E5;
        transition: transform 0.3s;
    }
    
    .metric-card:hover {
        transform: translateY(-5px);
        box-shadow: 0 6px 12px rgba(0,0,0,0.15);
    }
    
    .alert-critical {
        background-color: #ffebee;
        border-left: 5px solid #f44336;
        padding: 15px;
        margin: 10px 0;
        border-radius: 10px;
        animation: pulse 2s infinite;
    }
    
    .alert-high {
        background-color: #fff3e0;
        border-left: 5px solid #ff9800;
        padding: 15px;
        margin: 10px 0;
        border-radius: 10px;
    }
    
    .alert-medium {
        background-color: #fffde7;
        border-left: 5px solid #ffeb3b;
        padding: 15px;
        margin: 10px 0;
        border-radius: 10px;
    }
    
    .alert-low {
        background-color: #e8f5e9;
        border-left: 5px solid #4caf50;
        padding: 15px;
        margin: 10px 0;
        border-radius: 10px;
    }
    
    .alert-info {
        background-color: #e3f2fd;
        border-left: 5px solid #2196f3;
        padding: 15px;
        margin: 10px 0;
        border-radius: 10px;
    }
    
    .packet-table {
        font-size: 0.9rem;
        border-collapse: collapse;
        width: 100%;
    }
    
    .packet-table th {
        background-color: #1E88E5;
        color: white;
        padding: 12px;
        text-align: left;
        position: sticky;
        top: 0;
    }
    
    .packet-table tr:nth-child(even) {
        background-color: #f8f9fa;
    }
    
    .packet-table tr:hover {
        background-color: #e3f2fd;
    }
    
    .packet-table td {
        padding: 10px;
        border-bottom: 1px solid #ddd;
    }
    
    .status-normal {
        color: #4caf50;
        font-weight: bold;
    }
    
    .status-anomaly {
        color: #f44336;
        font-weight: bold;
        animation: blink 1s infinite;
    }
    
    @keyframes pulse {
        0% { opacity: 1; }
        50% { opacity: 0.8; }
        100% { opacity: 1; }
    }
    
    @keyframes blink {
        0% { opacity: 1; }
        50% { opacity: 0.5; }
        100% { opacity: 1; }
    }
    
    .protocol-tcp {
        color: #EF5350;
        font-weight: bold;
    }
    
    .protocol-udp {
        color: #FF7043;
        font-weight: bold;
    }
    
    .protocol-icmp {
        color: #FFCA28;
        font-weight: bold;
    }
    
    .protocol-http {
        color: #66BB6A;
        font-weight: bold;
    }
    
    .tab-content {
        padding: 20px;
        background-color: white;
        border-radius: 10px;
        box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        margin-top: 10px;
    }
    
    .stTabs [data-baseweb="tab-list"] {
        gap: 2px;
    }
    
    .stTabs [data-baseweb="tab"] {
        height: 50px;
        white-space: pre-wrap;
        background-color: #f0f2f6;
        border-radius: 5px 5px 0 0;
        gap: 1px;
        padding: 10px 16px;
    }
</style>
""", unsafe_allow_html=True)

class PacketDataGenerator:
    """
    Generates realistic packet data for dashboard simulation.
    In a real system, this would read from actual packet capture logs.
    """
    
    def __init__(self):
        """Initialize packet generator with realistic distributions"""
        # Protocol distribution weights
        self.protocols = {
            'TCP': 0.6,
            'UDP': 0.25,
            'ICMP': 0.1,
            'HTTP': 0.03,
            'HTTPS': 0.01,
            'DNS': 0.01
        }
        
        # Common ports
        self.common_ports = [80, 443, 22, 53, 25, 110, 143, 3389, 8080, 8443]
        
        # IP address ranges for simulation
        self.internal_ip_range = ['192.168.', '10.0.', '172.16.']
        self.external_ip_range = ['203.0.113.', '198.51.100.', '203.0.113.']
        
        # Attack types and probabilities
        self.attack_types = ['DDoS', 'PortScan', 'Malware', 'BruteForce', 'SQLi', 'XSS']
        self.attack_probability = 0.05  # 5% chance of attack
        
        # Packet size ranges by protocol
        self.packet_sizes = {
            'TCP': (64, 1500),
            'UDP': (64, 1472),
            'ICMP': (64, 1500),
            'HTTP': (500, 1500),
            'HTTPS': (500, 1500),
            'DNS': (64, 512)
        }
        
        # Initialize data structures
        self.reset_stats()
    
    def reset_stats(self):
        """Reset all statistics"""
        self.stats = {
            'total_packets': 0,
            'total_flows': 0,
            'anomalies': 0,
            'packet_rate': 0,
            'protocols': {p: 0 for p in self.protocols.keys()},
            'attack_types': {a: 0 for a in self.attack_types},
            'recent_packets': deque(maxlen=100),  # Store recent packets for table
            'recent_alerts': deque(maxlen=20),
            'rate_history': deque(maxlen=50),
            'packet_history': deque(maxlen=1000),  # For time series
            'start_time': datetime.now()
        }
    
    def generate_packet(self):
        """Generate a realistic packet with metadata"""
        # Select protocol based on weights
        protocol = random.choices(
            list(self.protocols.keys()),
            weights=list(self.protocols.values())
        )[0]
        
        # Determine if internal or external source
        if random.random() < 0.7:  # 70% internal
            src_ip_prefix = random.choice(self.internal_ip_range)
            src_ip = f"{src_ip_prefix}{random.randint(1, 255)}.{random.randint(1, 255)}"
        else:  # 30% external
            src_ip_prefix = random.choice(self.external_ip_range)
            src_ip = f"{src_ip_prefix}{random.randint(1, 255)}"
        
        # Generate IPs and ports
        dst_ip = f"10.0.{random.randint(0, 255)}.{random.randint(1, 255)}"
        src_port = random.choice(self.common_ports + [random.randint(1024, 65535)])
        dst_port = random.choice(self.common_ports)
        
        # Generate packet size based on protocol
        size_range = self.packet_sizes.get(protocol, (64, 1500))
        packet_size = random.randint(*size_range)
        
        # Generate TTL
        ttl = random.randint(32, 255)
        
        # Determine if this is an anomaly
        is_anomaly = random.random() < self.attack_probability
        
        # Create packet dictionary
        packet = {
            'id': self.stats['total_packets'] + 1,
            'timestamp': datetime.now(),
            'src_ip': src_ip,
            'dst_ip': dst_ip,
            'src_port': src_port,
            'dst_port': dst_port,
            'protocol': protocol,
            'packet_size': packet_size,
            'ttl': ttl,
            'flags': self._generate_flags(protocol),
            'status': 'ANOMALY' if is_anomaly else 'NORMAL',
            'attack_type': random.choice(self.attack_types) if is_anomaly else None,
            'severity': random.choice(['LOW', 'MEDIUM', 'HIGH', 'CRITICAL']) if is_anomaly else None,
            'confidence': random.uniform(0.7, 0.95) if is_anomaly else random.uniform(0.9, 0.99)
        }
        
        return packet
    
    def _generate_flags(self, protocol):
        """Generate protocol-specific flags"""
        if protocol == 'TCP':
            flag_combinations = [
                ['SYN'],
                ['SYN', 'ACK'],
                ['ACK'],
                ['FIN', 'ACK'],
                ['PSH', 'ACK'],
                ['RST']
            ]
            return ' '.join(random.choice(flag_combinations))
        elif protocol == 'ICMP':
            icmp_types = ['ECHO_REQUEST', 'ECHO_REPLY', 'DEST_UNREACHABLE', 'TIME_EXCEEDED']
            return random.choice(icmp_types)
        else:
            return 'N/A'
    
    def update_stats(self, num_packets=10):
        """Update statistics with new packets"""
        new_packets = []
        
        for _ in range(num_packets):
            packet = self.generate_packet()
            
            # Update statistics
            self.stats['total_packets'] += 1
            self.stats['protocols'][packet['protocol']] += 1
            
            # Add to recent packets
            self.stats['recent_packets'].append(packet)
            self.stats['packet_history'].append(packet)
            
            # Handle anomalies
            if packet['status'] == 'ANOMALY':
                self.stats['anomalies'] += 1
                attack_type = packet['attack_type']
                self.stats['attack_types'][attack_type] += 1
                
                # Create alert entry
                alert = {
                    'id': len(self.stats['recent_alerts']) + 1,
                    'timestamp': packet['timestamp'],
                    'attack_type': attack_type,
                    'severity': packet['severity'],
                    'confidence': packet['confidence'],
                    'src_ip': packet['src_ip'],
                    'dst_ip': packet['dst_ip'],
                    'src_port': packet['src_port'],
                    'dst_port': packet['dst_port']
                }
                self.stats['recent_alerts'].append(alert)
            
            new_packets.append(packet)
        
        # Update packet rate (simulated)
        self.stats['packet_rate'] = random.randint(50, 500)
        self.stats['rate_history'].append(self.stats['packet_rate'])
        
        return new_packets

class DashboardDataManager:
    """
    Manages data flow and updates for the dashboard.
    Handles simulation and real data reading.
    """
    
    def __init__(self, simulation_mode=True):
        """
        Initialize data manager
        
        Args:
            simulation_mode (bool): If True, use packet generator for simulation
        """
        self.simulation_mode = simulation_mode
        self.data_queue = queue.Queue()
        self.running = True
        
        if simulation_mode:
            self.packet_generator = PacketDataGenerator()
            self.stats = self.packet_generator.stats
        else:
            self.stats = self._initialize_empty_stats()
        
        # Start data generation thread
        self.thread = threading.Thread(target=self._update_data, daemon=True)
        self.thread.start()
    
    def _initialize_empty_stats(self):
        """Initialize empty statistics structure"""
        return {
            'total_packets': 0,
            'total_flows': 0,
            'anomalies': 0,
            'packet_rate': 0,
            'protocols': {'TCP': 0, 'UDP': 0, 'ICMP': 0, 'HTTP': 0, 'HTTPS': 0, 'DNS': 0},
            'attack_types': {},
            'recent_packets': deque(maxlen=100),
            'recent_alerts': deque(maxlen=20),
            'rate_history': deque(maxlen=50),
            'packet_history': deque(maxlen=1000),
            'start_time': datetime.now()
        }
    
    def _update_data(self):
        """Update data in background thread"""
        while self.running:
            try:
                if self.simulation_mode:
                    # Generate new packets
                    new_packets = self.packet_generator.update_stats(random.randint(1, 5))
                    
                    # Update stats reference
                    self.stats = self.packet_generator.stats.copy()
                    
                    # Put data in queue
                    self.data_queue.put({
                        'type': 'update',
                        'stats': self.stats,
                        'new_packets': new_packets
                    })
                
                time.sleep(1)  # Update every second
                
            except Exception as e:
                print(f"Error in data update: {e}")
                time.sleep(5)
    
    def get_latest_data(self):
        """Get latest data from queue"""
        try:
            while True:  # Process all items in queue
                data = self.data_queue.get_nowait()
                if data['type'] == 'update':
                    return data
        except queue.Empty:
            pass
        
        # Return current stats if no new data
        return {
            'type': 'current',
            'stats': self.stats,
            'new_packets': []
        }
    
    def get_packet_dataframe(self, num_packets=20):
        """Get recent packets as pandas DataFrame"""
        recent_packets = list(self.stats.get('recent_packets', []))[-num_packets:]
        
        if not recent_packets:
            return pd.DataFrame()
        
        # Convert to DataFrame
        df = pd.DataFrame(recent_packets)
        
        # Format timestamp
        if 'timestamp' in df.columns:
            df['timestamp'] = pd.to_datetime(df['timestamp'])
            df['time_str'] = df['timestamp'].dt.strftime('%H:%M:%S.%f').str[:-3]
        
        # Select and order columns
        columns = ['time_str', 'src_ip', 'dst_ip', 'src_port', 'dst_port', 
                  'protocol', 'packet_size', 'ttl', 'flags', 'status']
        
        # Add attack info if anomaly
        if 'attack_type' in df.columns and 'severity' in df.columns:
            df['attack_info'] = df.apply(
                lambda row: f"{row['attack_type']} ({row['severity']})" 
                if row['status'] == 'ANOMALY' else '', 
                axis=1
            )
            columns.append('attack_info')
        
        return df[columns] if all(col in df.columns for col in columns) else df
    
    def stop(self):
        """Stop data generation"""
        self.running = False

class ChartGenerator:
    """
    Generates various charts for the dashboard using Plotly
    """
    
    @staticmethod
    def create_packet_rate_chart(rate_history):
        """Create packet rate time series chart"""
        if not rate_history:
            # Create empty chart
            fig = go.Figure()
            fig.update_layout(
                title="Packet Rate (packets/sec)",
                height=300,
                margin=dict(l=20, r=20, t=40, b=20),
                paper_bgcolor='rgba(0,0,0,0)',
                plot_bgcolor='rgba(0,0,0,0)',
                annotations=[dict(
                    text="No data available",
                    x=0.5, y=0.5,
                    xref="paper", yref="paper",
                    showarrow=False
                )]
            )
            return fig
        
        fig = go.Figure()
        fig.add_trace(go.Scatter(
            x=list(range(len(rate_history))),
            y=list(rate_history),
            mode='lines+markers',
            name='Packet Rate',
            line=dict(color='#1E88E5', width=3),
            fill='tozeroy',
            fillcolor='rgba(30, 136, 229, 0.2)',
            marker=dict(size=6, color='#0D47A1')
        ))
        
        fig.update_layout(
            title="📈 Packet Rate (packets/sec)",
            xaxis_title="Time (seconds ago)",
            yaxis_title="Packets/sec",
            height=320,
            margin=dict(l=20, r=20, t=50, b=20),
            paper_bgcolor='rgba(0,0,0,0)',
            plot_bgcolor='rgba(0,0,0,0)',
            hovermode='x unified'
        )
        
        return fig
    
    @staticmethod
    def create_protocol_chart(protocols):
        """Create protocol distribution donut chart"""
        if not protocols:
            fig = go.Figure()
            fig.update_layout(
                title="Protocol Distribution",
                height=300,
                margin=dict(l=20, r=20, t=40, b=20),
                paper_bgcolor='rgba(0,0,0,0)',
                plot_bgcolor='rgba(0,0,0,0)',
                annotations=[dict(
                    text="No data available",
                    x=0.5, y=0.5,
                    xref="paper", yref="paper",
                    showarrow=False
                )]
            )
            return fig
        
        labels = list(protocols.keys())
        values = list(protocols.values())
        
        # Color palette for protocols
        colors = ['#EF5350', '#FF7043', '#FFCA28', '#66BB6A', '#42A5F5', '#AB47BC']
        
        fig = go.Figure(data=[go.Pie(
            labels=labels,
            values=values,
            hole=.4,
            marker_colors=colors,
            textinfo='label+percent',
            hoverinfo='label+value+percent',
            textposition='inside'
        )])
        
        fig.update_layout(
            title="🌐 Protocol Distribution",
            height=320,
            margin=dict(l=20, r=20, t=50, b=20),
            paper_bgcolor='rgba(0,0,0,0)',
            plot_bgcolor='rgba(0,0,0,0)',
            legend=dict(
                orientation="h",
                yanchor="bottom",
                y=1.02,
                xanchor="right",
                x=1
            )
        )
        
        return fig
    
    @staticmethod
    def create_attack_chart(attack_types):
        """Create attack type distribution horizontal bar chart"""
        if not attack_types or sum(attack_types.values()) == 0:
            fig = go.Figure()
            fig.update_layout(
                title="Attack Types",
                height=300,
                margin=dict(l=20, r=20, t=40, b=20),
                paper_bgcolor='rgba(0,0,0,0)',
                plot_bgcolor='rgba(0,0,0,0)',
                annotations=[dict(
                    text="No attacks detected",
                    x=0.5, y=0.5,
                    xref="paper", yref="paper",
                    showarrow=False,
                    font=dict(color="green", size=16)
                )]
            )
            return fig
        
        # Filter out zero values
        filtered_data = {k: v for k, v in attack_types.items() if v > 0}
        
        if not filtered_data:
            fig = go.Figure()
            fig.update_layout(
                title="Attack Types",
                height=300,
                annotations=[dict(
                    text="No active attacks",
                    x=0.5, y=0.5,
                    xref="paper", yref="paper",
                    showarrow=False,
                    font=dict(color="green", size=16)
                )]
            )
            return fig
        
        labels = list(filtered_data.keys())
        values = list(filtered_data.values())
        
        # Color based on attack severity
        severity_colors = {
            'DDoS': '#f44336',
            'Malware': '#ff9800',
            'BruteForce': '#ffeb3b',
            'PortScan': '#4caf50',
            'SQLi': '#2196f3',
            'XSS': '#9c27b0'
        }
        
        colors = [severity_colors.get(label, '#607d8b') for label in labels]
        
        fig = go.Figure(data=[go.Bar(
            x=values,
            y=labels,
            orientation='h',
            marker_color=colors,
            text=values,
            textposition='auto',
        )])
        
        fig.update_layout(
            title="🚨 Attack Type Distribution",
            xaxis_title="Count",
            yaxis_title="Attack Type",
            height=320,
            margin=dict(l=20, r=20, t=50, b=20),
            paper_bgcolor='rgba(0,0,0,0)',
            plot_bgcolor='rgba(0,0,0,0)'
        )
        
        return fig
    
    @staticmethod
    def create_packet_size_chart(packet_history, num_points=50):
        """Create packet size distribution chart"""
        if not packet_history:
            return go.Figure()
        
        recent_packets = list(packet_history)[-num_points:]
        sizes = [p.get('packet_size', 0) for p in recent_packets]
        timestamps = [p.get('timestamp', datetime.now()) for p in recent_packets]
        
        fig = go.Figure()
        fig.add_trace(go.Scatter(
            x=timestamps,
            y=sizes,
            mode='markers',
            name='Packet Size',
            marker=dict(
                size=8,
                color=sizes,
                colorscale='Viridis',
                showscale=True,
                colorbar=dict(title="Size (bytes)")
            ),
            hovertext=[f"Size: {s} bytes" for s in sizes]
        ))
        
        fig.update_layout(
            title="📊 Packet Size Distribution",
            xaxis_title="Time",
            yaxis_title="Packet Size (bytes)",
            height=300,
            margin=dict(l=20, r=20, t=40, b=20)
        )
        
        return fig

class DashboardUI:
    """
    Manages the Streamlit user interface components
    """
    
    def __init__(self, data_manager):
        """
        Initialize UI components
        
        Args:
            data_manager (DashboardDataManager): Data manager instance
        """
        self.data_manager = data_manager
        self.chart_generator = ChartGenerator()
        
    def display_header(self):
        """Display dashboard header"""
        st.markdown('<h1 class="main-header">🛡️ ML-IDS Real-Time Dashboard</h1>', 
                   unsafe_allow_html=True)
        
        # Display mode indicator
        mode = "SIMULATION" if self.data_manager.simulation_mode else "LIVE"
        st.info(f"**Mode:** {mode} | **Last Update:** {datetime.now().strftime('%H:%M:%S')}")
    
    def display_sidebar(self):
        """Display sidebar controls"""
        with st.sidebar:
            st.markdown("## ⚙️ Dashboard Controls")
            
            # Display settings
            st.markdown("### 📊 Display Settings")
            self.update_rate = st.slider("Update Rate (seconds)", 1, 10, 2)
            
            st.markdown("### 👁️ Display Options")
            self.show_packet_table = st.checkbox("Show Packet Table", True)
            self.show_alerts = st.checkbox("Show Security Alerts", True)
            self.show_charts = st.checkbox("Show Charts", True)
            self.auto_refresh = st.checkbox("Auto Refresh", True)
            
            # Packet table settings
            if self.show_packet_table:
                st.markdown("### 📋 Packet Table Settings")
                self.table_size = st.slider("Table Size (rows)", 10, 100, 20)
            
            st.markdown("---")
            st.markdown("## ℹ️ System Information")
            
            system_info = """
            **ML-IDS Dashboard v2.0**
            
            **Features:**
            - Real-time packet monitoring
            - Anomaly detection visualization
            - Protocol distribution analysis
            - Attack type classification
            - Historical data trends
            
            **Data Sources:**
            - Simulated network traffic
            - ML model predictions
            - Security alert logs
            
            **Status:** Running
            """
            st.info(system_info)
            
            # Control buttons
            col1, col2 = st.columns(2)
            with col1:
                if st.button("🔄 Manual Refresh"):
                    st.rerun()
            with col2:
                if st.button("📊 Reset Stats"):
                    if hasattr(self.data_manager, 'packet_generator'):
                        self.data_manager.packet_generator.reset_stats()
                    st.rerun()
    
    def display_metrics(self, stats):
        """Display key metrics cards"""
        col1, col2, col3, col4, col5 = st.columns(5)
        
        with col1:
            st.metric(
                label="📦 Total Packets",
                value=f"{stats['total_packets']:,}",
                delta=f"+{stats['packet_rate']}"
            )
        
        with col2:
            st.metric(
                label="🚨 Anomalies",
                value=f"{stats['anomalies']}",
                delta_color="inverse"
            )
        
        with col3:
            st.metric(
                label="⚡ Packet Rate",
                value=f"{stats['packet_rate']}/s"
            )
        
        with col4:
            anomaly_rate = (stats['anomalies'] / stats['total_packets'] * 100) if stats['total_packets'] > 0 else 0
            st.metric(
                label="📊 Anomaly Rate",
                value=f"{anomaly_rate:.2f}%"
            )
        
        with col5:
            elapsed = (datetime.now() - stats.get('start_time', datetime.now())).total_seconds()
            hours = int(elapsed // 3600)
            minutes = int((elapsed % 3600) // 60)
            seconds = int(elapsed % 60)
            st.metric(
                label="⏱️ Uptime",
                value=f"{hours:02d}:{minutes:02d}:{seconds:02d}"
            )
        
        st.markdown("---")
    
    def display_charts(self, stats):
        """Display visualization charts"""
        if not self.show_charts:
            return
        
        # Charts row 1
        col1, col2, col3 = st.columns(3)
        
        with col1:
            fig_rate = self.chart_generator.create_packet_rate_chart(list(stats.get('rate_history', [])))
            st.plotly_chart(fig_rate, use_container_width=True, key="rate_chart")
        
        with col2:
            fig_protocol = self.chart_generator.create_protocol_chart(stats.get('protocols', {}))
            st.plotly_chart(fig_protocol, use_container_width=True, key="protocol_chart")
        
        with col3:
            fig_attack = self.chart_generator.create_attack_chart(stats.get('attack_types', {}))
            st.plotly_chart(fig_attack, use_container_width=True, key="attack_chart")
        
        # Packet size chart
        if stats.get('packet_history'):
            st.markdown("### 📦 Packet Size Distribution")
            fig_size = self.chart_generator.create_packet_size_chart(stats['packet_history'])
            st.plotly_chart(fig_size, use_container_width=True, key="size_chart")
    
    def display_packet_table(self, stats):
        """Display real-time packet table"""
        if not self.show_packet_table:
            return
        
        st.markdown("### 📋 Real-time Packet Monitoring")
        
        # Get packet data
        df = self.data_manager.get_packet_dataframe(self.table_size if hasattr(self, 'table_size') else 20)
        
        if df.empty:
            st.info("No packet data available yet. Waiting for data...")
            return
        
        # Create styled DataFrame
        st.dataframe(
            self._style_dataframe(df),
            use_container_width=True,
            height=400,
            hide_index=True
        )
        
        # Display table statistics
        col1, col2, col3 = st.columns(3)
        with col1:
            st.caption(f"Showing {len(df)} most recent packets")
        with col2:
            anomalies = df[df['status'] == 'ANOMALY'].shape[0]
            st.caption(f"Anomalies in table: {anomalies}")
        with col3:
            protocols = df['protocol'].unique()
            st.caption(f"Protocols: {', '.join(protocols)}")
    
    def _style_dataframe(self, df):
        """Apply styling to DataFrame based on packet status"""
        if df.empty:
            return df
        
        # Create a copy for styling
        styled_df = df.copy()
        
        # Function to apply status styling
        def color_status(val):
            if val == 'ANOMALY':
                return 'background-color: #ffebee; color: #d32f2f; font-weight: bold;'
            else:
                return 'background-color: #e8f5e9; color: #388e3c;'
        
        # Function to style protocol cells
        def color_protocol(val):
            colors = {
                'TCP': '#ffebee',
                'UDP': '#fff3e0',
                'ICMP': '#fffde7',
                'HTTP': '#e8f5e9',
                'HTTPS': '#e3f2fd',
                'DNS': '#f3e5f5'
            }
            color = colors.get(val, '#f5f5f5')
            return f'background-color: {color}; font-weight: bold;'
        
        # Apply styling
        styled = styled_df.style.applymap(color_status, subset=['status'])
        styled = styled.applymap(color_protocol, subset=['protocol'])
        
        return styled
    
    def display_alerts(self, stats):
        """Display security alerts"""
        if not self.show_alerts:
            return
        
        alerts = list(stats.get('recent_alerts', []))[-10:]  # Last 10 alerts
        
        if alerts:
            st.markdown("### 🚨 Recent Security Alerts")
            
            for alert in reversed(alerts):  # Show newest first
                if isinstance(alert.get('timestamp'), datetime):
                    time_str = alert['timestamp'].strftime('%H:%M:%S')
                else:
                    time_str = str(alert.get('timestamp', 'N/A'))
                
                severity = alert.get('severity', 'INFO')
                confidence = alert.get('confidence', 0.0)
                
                # Determine CSS class based on severity
                css_class = f'alert-{severity.lower()}'
                
                st.markdown(f"""
                <div class="{css_class}">
                    <strong>🚨 {alert.get('attack_type', 'Unknown Attack')}</strong><br>
                    <small>⏰ Time: {time_str} | 🎯 Severity: {severity} | 📊 Confidence: {confidence:.1%}</small><br>
                    <small>📡 Source: {alert.get('src_ip', 'Unknown')}:{alert.get('src_port', 0)} → 
                    Target: {alert.get('dst_ip', 'Unknown')}:{alert.get('dst_port', 0)}</small>
                </div>
                """, unsafe_allow_html=True)
        else:
            st.success("✅ No security alerts detected. System is running normally.")
    
    def display_system_status(self, stats):
        """Display system status panel"""
        st.markdown("---")
        st.markdown("### 🖥️ System Status")
        
        col1, col2, col3, col4 = st.columns(4)
        
        with col1:
            st.success("✅ Packet Capture")
            st.caption("Active")
        
        with col2:
            st.success("✅ ML Engine")
            st.caption("Running")
        
        with col3:
            if self.data_manager.simulation_mode:
                st.info("🔬 Simulation Mode")
                st.caption("Using generated data")
            else:
                st.success("🌐 Live Mode")
                st.caption("Real network data")
        
        with col4:
            if stats.get('anomalies', 0) > 0:
                st.warning("⚠️ Threats Detected")
                st.caption(f"{stats['anomalies']} anomalies")
            else:
                st.success("✅ System Secure")
                st.caption("No threats")

def main():
    """Main Streamlit application"""
    
    # Initialize data manager
    if 'data_manager' not in st.session_state:
        st.session_state.data_manager = DashboardDataManager(simulation_mode=True)
    
    # Initialize UI
    ui = DashboardUI(st.session_state.data_manager)
    
    # Display header
    ui.display_header()
    
    # Display sidebar
    ui.display_sidebar()
    
    # Get latest data
    latest_data = st.session_state.data_manager.get_latest_data()
    stats = latest_data['stats']
    
    # Store last stats in session state
    st.session_state.last_stats = stats
    
    # Display metrics
    ui.display_metrics(stats)
    
    # Create tabs for different views
    tab1, tab2, tab3 = st.tabs(["📊 Overview", "📋 Packets", "🚨 Alerts"])
    
    with tab1:
        # Display charts in overview tab
        ui.display_charts(stats)
        
        # Display system status
        ui.display_system_status(stats)
    
    with tab2:
        # Display packet table
        ui.display_packet_table(stats)
        
        # Additional packet statistics
        col1, col2 = st.columns(2)
        with col1:
            st.markdown("#### Protocol Statistics")
            protocol_df = pd.DataFrame({
                'Protocol': list(stats['protocols'].keys()),
                'Count': list(stats['protocols'].values())
            })
            st.dataframe(protocol_df, use_container_width=True, hide_index=True)
        
        with col2:
            st.markdown("#### Traffic Summary")
            summary_data = {
                'Metric': ['Total Packets', 'Anomalies', 'Packet Rate', 'Uptime'],
                'Value': [
                    f"{stats['total_packets']:,}",
                    f"{stats['anomalies']}",
                    f"{stats['packet_rate']}/s",
                    f"{(datetime.now() - stats['start_time']).seconds}s"
                ]
            }
            summary_df = pd.DataFrame(summary_data)
            st.dataframe(summary_df, use_container_width=True, hide_index=True)
    
    with tab3:
        # Display alerts
        ui.display_alerts(stats)
        
        # Alert statistics
        if stats.get('attack_types'):
            st.markdown("#### Alert Statistics")
            attack_df = pd.DataFrame({
                'Attack Type': list(stats['attack_types'].keys()),
                'Count': list(stats['attack_types'].values())
            })
            st.dataframe(attack_df, use_container_width=True, hide_index=True)
    
    # Auto-refresh logic
    if ui.auto_refresh:
        time.sleep(ui.update_rate)
        st.rerun()

if __name__ == "__main__":
    main()
