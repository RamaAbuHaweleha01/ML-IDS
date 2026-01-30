"""
Asynchronous packet capture module using Scapy.
"""

import asyncio
import time
from typing import Dict, Any, AsyncGenerator
import logging
from scapy.all import AsyncSniffer, IP, TCP, UDP, Ether, ICMP, Raw
from scapy.packet import Packet

class AsyncPacketCapture:
    """
    Asynchronous packet capture using Scapy.
    """
    
    def __init__(self, interface: str = "eth0", filter_exp: str = "ip", 
                 promiscuous: bool = True, timeout: int = 30):
        self.interface = interface
        self.filter_exp = filter_exp
        self.promiscuous = promiscuous
        self.timeout = timeout
        self.sniffer = None
        self.logger = logging.getLogger(__name__)
    
    async def capture(self) -> AsyncGenerator[Dict[str, Any], None]:
        """
        Asynchronously capture packets.
        
        Yields:
            Processed packet information as dictionary.
        """
        packet_queue = asyncio.Queue()
        
        def packet_callback(packet: Packet):
            """Callback for each captured packet."""
            try:
                # Put packet in queue for async processing
                packet_queue.put_nowait(packet)
            except Exception as e:
                self.logger.error(f"Error in packet callback: {e}")
        
        # Start the sniffer
        self.sniffer = AsyncSniffer(
            iface=self.interface,
            filter=self.filter_exp,
            prn=packet_callback,
            store=False,
            promisc=self.promiscuous
        )
        
        self.sniffer.start()
        self.logger.info(f"Started packet capture on {self.interface}")
        
        try:
            while True:
                try:
                    # Get packet from queue with timeout
                    packet = await asyncio.wait_for(packet_queue.get(), timeout=1.0)
                    yield self._process_packet(packet)
                except asyncio.TimeoutError:
                    continue
        finally:
            if self.sniffer:
                self.sniffer.stop()
                self.logger.info("Packet capture stopped")
    
    def _process_packet(self, packet: Packet) -> Dict[str, Any]:
        """
        Process raw packet into structured dictionary.
        
        Args:
            packet: Scapy packet object.
        
        Returns:
            Dictionary with packet information.
        """
        packet_info = {
            'timestamp': time.time(),
            'has_ether': Ether in packet,
            'has_ip': IP in packet,
            'has_tcp': TCP in packet,
            'has_udp': UDP in packet,
            'has_icmp': ICMP in packet,
            'has_raw': Raw in packet,
            'length': len(packet)
        }
        
        # Ethernet layer
        if Ether in packet:
            eth = packet[Ether]
            packet_info.update({
                'src_mac': eth.src,
                'dst_mac': eth.dst,
                'ether_type': eth.type
            })
        
        # IP layer
        if IP in packet:
            ip = packet[IP]
            packet_info.update({
                'src_ip': ip.src,
                'dst_ip': ip.dst,
                'protocol': ip.proto,
                'ttl': ip.ttl,
                'tos': ip.tos,
                'ip_id': ip.id,
                'ip_flags': ip.flags,
                'ip_len': ip.len
            })
        
        # TCP layer
        if TCP in packet:
            tcp = packet[TCP]
            packet_info.update({
                'src_port': tcp.sport,
                'dst_port': tcp.dport,
                'tcp_flags': tcp.flags,
                'tcp_window': tcp.window,
                'tcp_seq': tcp.seq,
                'tcp_ack': tcp.ack,
                'tcp_urgptr': tcp.urgptr,
                'tcp_dataofs': tcp.dataofs
            })
        
        # UDP layer
        elif UDP in packet:
            udp = packet[UDP]
            packet_info.update({
                'src_port': udp.sport,
                'dst_port': udp.dport,
                'udp_len': udp.len,
                'udp_chksum': udp.chksum
            })
        
        # ICMP layer
        elif ICMP in packet:
            icmp = packet[ICMP]
            packet_info.update({
                'icmp_type': icmp.type,
                'icmp_code': icmp.code,
                'icmp_chksum': icmp.chksum
            })
        
        # Payload
        if Raw in packet:
            raw = packet[Raw]
            packet_info['payload'] = bytes(raw.load)
            packet_info['payload_length'] = len(raw.load)
        else:
            packet_info['payload'] = b''
            packet_info['payload_length'] = 0
        
        return packet_info
    
    def stop(self):
        """Stop packet capture."""
        if self.sniffer:
            self.sniffer.stop()
            self.sniffer = None
            self.logger.info("Packet capture stopped manually")
