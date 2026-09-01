"""
packet_sniffer.py   Network Packet Capture

Uses Scapy to capture live network packets, extract key fields,
determine traffic direction, and pass them to the rule engine for evaluation.
"""

import socket
import threading

from scapy.all import sniff, IP, TCP, UDP, ICMP, conf


class PacketSniffer:
    """Captures and inspects network packets using Scapy."""

    # Map IP protocol numbers to readable names
    PROTOCOL_MAP = {
        6: "TCP",
        17: "UDP",
        1: "ICMP",
    }

    def __init__(self, rule_engine, logger, interface=None):
        """
        Args:
            rule_engine: RuleEngine instance for packet evaluation.
            logger: FirewallLogger instance for logging decisions.
            interface: Network interface to sniff on (None = default).
        """
        self.rule_engine = rule_engine
        self.logger = logger
        self.interface = interface
        self._running = False
        self._thread = None
        self._host_ip = self._get_host_ip()

 
    # Public API
 

    def start(self):
        """Start packet capture in a background thread."""
        if self._running:
            print("[!] Sniffer is already running.")
            return

        self._running = True
        self._thread = threading.Thread(target=self._sniff_loop, daemon=True)
        self._thread.start()

        iface_display = self.interface or "default"
        print(f"[*] Packet sniffer started on interface: {iface_display}")
        print(f"[*] Host IP detected as: {self._host_ip}")

    def stop(self):
        """Signal the sniffer to stop."""
        self._running = False
        print("[*] Packet sniffer stopped.")

    def is_running(self):
        return self._running

 
    # Capture loop
 

    def _sniff_loop(self):
        """Run the Scapy sniffer (blocking). Runs inside a daemon thread."""
        try:
            sniff_kwargs = {
                "prn": self._process_packet,
                "store": False,  # Don't accumulate packets in memory
                "stop_filter": lambda _: not self._running,
            }
            if self.interface:
                sniff_kwargs["iface"] = self.interface

            # Filter only IP traffic to reduce noise
            sniff_kwargs["filter"] = "ip"

            sniff(**sniff_kwargs)
        except PermissionError:
            print("\n[!] ERROR: Permission denied. Run as Administrator / root.")
            self._running = False
        except Exception as e:
            print(f"\n[!] Sniffer error: {e}")
            self._running = False

 
    # Packet processing
 

    def _process_packet(self, packet):
        """Callback for each captured packet."""
        if not packet.haslayer(IP):
            return

        ip_layer = packet[IP]
        packet_info = {
            "src_ip": ip_layer.src,
            "dst_ip": ip_layer.dst,
            "src_port": None,
            "dst_port": None,
            "protocol": self.PROTOCOL_MAP.get(ip_layer.proto, str(ip_layer.proto)),
            "direction": self._determine_direction(ip_layer.src, ip_layer.dst),
        }

        # Extract ports for TCP / UDP
        if packet.haslayer(TCP):
            packet_info["src_port"] = packet[TCP].sport
            packet_info["dst_port"] = packet[TCP].dport
        elif packet.haslayer(UDP):
            packet_info["src_port"] = packet[UDP].sport
            packet_info["dst_port"] = packet[UDP].dport

        # Evaluate against rules
        action, matched_rule = self.rule_engine.evaluate(packet_info)

        # Log the decision
        self.logger.log(action, packet_info, matched_rule)

 
    # Helpers
 

    def _determine_direction(self, src_ip, dst_ip):
        """Determine if a packet is inbound or outbound relative to this host."""
        if src_ip == self._host_ip:
            return "outbound"
        elif dst_ip == self._host_ip:
            return "inbound"
        else:
            # Forwarded / other traffic
            return "inbound"

    @staticmethod
    def _get_host_ip():
        """Detect the primary IP address of this machine."""
        try:
            # Connect to a public DNS to determine our outbound IP
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            s.close()
            return ip
        except Exception:
            return "127.0.0.1"
