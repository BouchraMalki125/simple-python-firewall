#Simple Python Firewall

A basic network firewall built in Python that monitors and filters network traffic based on user-defined security rules. Built as a cybersecurity learning project.

## Features

- **Real-time packet capture** using Scapy
- **Rule-based filtering**   block or allow traffic by IP, port, protocol, and direction
- **Interactive CLI**   manage rules, view logs, and monitor stats without stopping the firewall
- **Color-coded logging**   green for allowed, red for blocked traffic
- **Persistent rules**   stored in JSON, survive restarts
- **Traffic statistics**   track total, allowed, and blocked packet counts

## Prerequisites

- **Python 3.8+**
- **Npcap** (Windows)   Download from [npcap.com](https://npcap.com/#download)
  - During installation, check **"Install Npcap in WinPcap API-compatible Mode"**
- **Administrator privileges**   required for packet capture

## Installation

```bash
# Clone or navigate to the project directory
cd simple-firewall

# Install Python dependencies
pip install -r requirements.txt
```

## Usage

### Start the Firewall

**Windows** (run Command Prompt or PowerShell as Administrator):
```powershell
python firewall.py
```

**Linux/macOS**:
```bash
sudo python3 firewall.py
```

### Command-Line Options

| Option | Description | Default |
|--------|-------------|---------|
| `-i`, `--interface` | Network interface to capture on | Auto-detect |
| `-r`, `--rules` | Path to rules JSON file | `rules.json` |
| `-l`, `--log` | Path to log output file | `firewall.log` |

### Interactive Commands

Once running, the firewall presents an interactive menu:

```
╔══════════════════════════════════════╗
║       SIMPLE FIREWALL   MENU        ║
╠══════════════════════════════════════╣
║  1. List all rules                  ║
║  2. Add a new rule                  ║
║  3. Remove a rule                   ║
║  4. Enable / Disable a rule         ║
║  5. View recent logs                ║
║  6. Show traffic statistics         ║
║  7. Reload rules from file          ║
║  8. Exit                            ║
╚══════════════════════════════════════╝
```

## Rule Format

Rules are stored in `rules.json`. Each rule has these fields:

| Field | Type | Description | Example |
|-------|------|-------------|---------|
| `id` | int | Unique identifier | `1` |
| `name` | string | Human-readable name | `"Block Telnet"` |
| `direction` | string | `"inbound"`, `"outbound"`, or `"any"` | `"inbound"` |
| `protocol` | string | `"TCP"`, `"UDP"`, `"ICMP"`, or `"any"` | `"TCP"` |
| `src_ip` | string | Source IP or `"*"` for any | `"192.168.1.100"` |
| `dst_ip` | string | Destination IP or `"*"` for any | `"*"` |
| `src_port` | int/string | Source port or `"*"` for any | `"*"` |
| `dst_port` | int/string | Destination port or `"*"` for any | `23` |
| `action` | string | `"ALLOW"` or `"BLOCK"` | `"BLOCK"` |
| `enabled` | bool | Whether the rule is active | `true` |

### Default Rules

The firewall ships with these starter rules:

1. **Block Telnet**   Block inbound TCP traffic on port 23
2. **Block FTP**   Block all TCP traffic on port 21
3. **Allow DNS**   Allow outbound UDP traffic on port 53
4. **Block Suspicious IP**   Block all traffic from 192.168.1.100
5. **Allow HTTP**   Allow outbound TCP traffic on port 80
6. **Allow HTTPS**   Allow outbound TCP traffic on port 443

## Project Structure

```
simple-firewall/
├── firewall.py          # Main entry point
├── rule_engine.py       # Rule loading, saving, and matching
├── packet_sniffer.py    # Scapy-based packet capture
├── logger.py            # Console + file logging
├── cli.py               # Interactive command-line interface
├── rules.json           # Security rules (editable)
├── requirements.txt     # Python dependencies
└── README.md            # This file
```

## How It Works

1. **Capture**   Scapy sniffs IP packets on the selected network interface
2. **Extract**   Source/destination IPs, ports, and protocol are extracted from each packet
3. **Classify**   Traffic direction (inbound/outbound) is determined by comparing against the host's IP
4. **Evaluate**   The packet is checked against rules in order; the first match determines the action
5. **Log**   The decision is logged to both the console (color-coded) and `firewall.log`

## Important Notes

> ⚠️ **Educational Purpose**   This firewall **monitors and logs** traffic decisions but does not actually block packets at the OS kernel level. To truly block traffic, you would need to integrate with iptables (Linux), WFP (Windows), or pf (macOS).

> ⚠️ **Admin Required**   Packet capture requires elevated privileges. Always run as Administrator (Windows) or with `sudo` (Linux/macOS).

## License

This project is for educational purposes. Feel free to modify and extend it.
