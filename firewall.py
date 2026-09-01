"""
firewall.py   Simple Python Firewall (Entry Point)

A basic firewall that monitors network traffic and filters packets
based on user-defined security rules (IP, port, protocol, direction).

Usage:
    python firewall.py [OPTIONS]

Options:
    --interface, -i     Network interface to sniff on (default: auto-detect)
    --rules, -r         Path to rules JSON file (default: rules.json)
    --log, -l           Path to log file (default: firewall.log)
    --help, -h          Show this help message

Requires: Administrator / root privileges for packet capture.
"""

import argparse
import os
import sys

# Ensure the script's directory is in the path so local imports work
# regardless of the working directory.
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
if SCRIPT_DIR not in sys.path:
    sys.path.insert(0, SCRIPT_DIR)

from rule_engine import RuleEngine
from logger import FirewallLogger
from packet_sniffer import PacketSniffer
from cli import FirewallCLI


BANNER = r"""
  ____  _                 _        _____ _                        _ _
 / ___|(_)_ __ ___  _ __ | | ___  |  ___(_)_ __ _____      ____ _| | |
 \___ \| | '_ ` _ \| '_ \| |/ _ \ | |_  | | '__/ _ \ \ /\ / / _` | | |
  ___) | | | | | | | |_) | |  __/ |  _| | | | |  __/\ V  V / (_| | | |
 |____/|_|_| |_| |_| .__/|_|\___| |_|   |_|_|  \___| \_/\_/ \__,_|_|_|
                    |_|
                              [ Python Network Firewall ]
"""


def parse_args():
    """Parse command-line arguments."""
    parser = argparse.ArgumentParser(
        description="Simple Python Firewall   monitor and filter network traffic.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "-i", "--interface",
        default=None,
        help="Network interface to capture on (default: auto-detect).",
    )
    parser.add_argument(
        "-r", "--rules",
        default=os.path.join(SCRIPT_DIR, "rules.json"),
        help="Path to rules JSON file (default: rules.json).",
    )
    parser.add_argument(
        "-l", "--log",
        default=os.path.join(SCRIPT_DIR, "firewall.log"),
        help="Path to log output file (default: firewall.log).",
    )
    return parser.parse_args()


def main():
    """Initialize components and start the firewall."""
    args = parse_args()

    print(BANNER)

    #   Initialize components  
    print("[*] Initializing firewall components...")

    rule_engine = RuleEngine(rules_file=args.rules)
    logger = FirewallLogger(log_file=args.log)
    sniffer = PacketSniffer(rule_engine, logger, interface=args.interface)

    #   Start packet capture  
    sniffer.start()

    #   Launch interactive CLI (blocks until exit)  
    cli = FirewallCLI(rule_engine, logger, sniffer)

    try:
        cli.run()
    except KeyboardInterrupt:
        print("\n[*] Interrupted. Shutting down...")
        sniffer.stop()
        sys.exit(0)


if __name__ == "__main__":
    main()
