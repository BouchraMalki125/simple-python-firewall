"""
logger.py   Firewall Traffic Logger

Provides colour-coded console output and persistent file logging
for every packet decision made by the firewall.
"""

import logging
import os
from datetime import datetime

try:
    from colorama import Fore, Style, init as colorama_init
    colorama_init(autoreset=True)
    COLORS_AVAILABLE = True
except ImportError:
    COLORS_AVAILABLE = False


class FirewallLogger:
    """Logs firewall decisions to console and a log file."""

    def __init__(self, log_file="firewall.log"):
        self.log_file = log_file

        # Statistics counters
        self.stats = {
            "total": 0,
            "allowed": 0,
            "blocked": 0,
        }

        # Set up Python file logger
        self._file_logger = logging.getLogger("firewall")
        self._file_logger.setLevel(logging.INFO)

        # Avoid duplicate handlers on reload
        if not self._file_logger.handlers:
            handler = logging.FileHandler(log_file)
            handler.setFormatter(logging.Formatter("%(message)s"))
            self._file_logger.addHandler(handler)

  
    # Public API
  

    def log(self, action, packet_info, matched_rule=None):
        """
        Log a firewall decision.

        Args:
            action (str): "ALLOW" or "BLOCK".
            packet_info (dict): Packet details (src_ip, dst_ip, ports, protocol, direction).
            matched_rule (dict | None): The rule that matched, or None for default policy.
        """
        self.stats["total"] += 1
        if action == "ALLOW":
            self.stats["allowed"] += 1
        else:
            self.stats["blocked"] += 1

        # Build readable log line
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        proto = packet_info.get("protocol", "???")
        src = self._format_endpoint(packet_info.get("src_ip"), packet_info.get("src_port"))
        dst = self._format_endpoint(packet_info.get("dst_ip"), packet_info.get("dst_port"))
        direction = packet_info.get("direction", "unknown")
        rule_name = matched_rule["name"] if matched_rule else "Default Policy"

        log_line = (
            f"[{timestamp}] [{action}] {proto} {src} -> {dst} "
            f"({direction}) (Rule: {rule_name})"
        )

        # Write to log file
        self._file_logger.info(log_line)

        # Print to console with colour
        self._print_coloured(action, log_line)

    def get_stats(self):
        """Return a copy of the traffic statistics."""
        return dict(self.stats)

    def get_recent_logs(self, count=10):
        """Read the last `count` lines from the log file."""
        if not os.path.exists(self.log_file):
            return []
        try:
            with open(self.log_file, "r") as f:
                lines = f.readlines()
            return [line.strip() for line in lines[-count:]]
        except IOError:
            return []

  
    # Internal helpers
  

    @staticmethod
    def _format_endpoint(ip, port):
        """Format an IP:port pair, handling missing ports (e.g. ICMP)."""
        if port is not None:
            return f"{ip}:{port}"
        return str(ip)

    @staticmethod
    def _print_coloured(action, text):
        """Print a colour-coded line to the console."""
        if COLORS_AVAILABLE:
            if action == "BLOCK":
                print(f"{Fore.RED}{text}{Style.RESET_ALL}")
            else:
                print(f"{Fore.GREEN}{text}{Style.RESET_ALL}")
        else:
            symbol = "[-]" if action == "BLOCK" else "[+]"
            print(f"{symbol} {text}")
