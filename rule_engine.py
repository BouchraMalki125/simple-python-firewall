"""
rule_engine.py   Firewall Rule Engine

Loads, saves, and evaluates security rules against captured packets.
Each rule specifies conditions (IP, port, protocol, direction) and an
action (ALLOW or BLOCK). Rules are evaluated in order; the first match wins.
"""

import json
import os
import threading


class RuleEngine:
    """Manages firewall rules and evaluates packets against them."""

    def __init__(self, rules_file="rules.json"):
        self.rules_file = rules_file
        self.rules = []
        self.default_policy = "ALLOW"
        self._lock = threading.Lock()  # Thread-safe rule access
        self.load_rules()

 
    # Persistence
 

    def load_rules(self):
        """Load rules from the JSON file."""
        if not os.path.exists(self.rules_file):
            print(f"[!] Rules file '{self.rules_file}' not found. Starting with empty rule set.")
            self.rules = []
            return

        try:
            with open(self.rules_file, "r") as f:
                data = json.load(f)
            self.rules = data.get("rules", [])
            self.default_policy = data.get("default_policy", "ALLOW")
            print(f"[*] Loaded {len(self.rules)} rules from '{self.rules_file}'")
        except (json.JSONDecodeError, IOError) as e:
            print(f"[!] Error loading rules: {e}")
            self.rules = []

    def save_rules(self):
        """Persist the current rules back to the JSON file."""
        data = {
            "rules": self.rules,
            "default_policy": self.default_policy,
        }
        try:
            with open(self.rules_file, "w") as f:
                json.dump(data, f, indent=4)
        except IOError as e:
            print(f"[!] Error saving rules: {e}")

 
    # Rule Management
 

    def add_rule(self, name, direction, protocol, src_ip, dst_ip,
                 src_port, dst_port, action):
        """Add a new rule and save to disk."""
        with self._lock:
            # Auto-increment ID
            max_id = max((r["id"] for r in self.rules), default=0)
            rule = {
                "id": max_id + 1,
                "name": name,
                "direction": direction,
                "protocol": protocol.upper(),
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "src_port": src_port,
                "dst_port": dst_port,
                "action": action.upper(),
                "enabled": True,
            }
            self.rules.append(rule)
            self.save_rules()
            return rule

    def remove_rule(self, rule_id):
        """Remove a rule by its ID. Returns True if found and removed."""
        with self._lock:
            for i, rule in enumerate(self.rules):
                if rule["id"] == rule_id:
                    self.rules.pop(i)
                    self.save_rules()
                    return True
            return False

    def toggle_rule(self, rule_id):
        """Enable/disable a rule by its ID. Returns the new state or None."""
        with self._lock:
            for rule in self.rules:
                if rule["id"] == rule_id:
                    rule["enabled"] = not rule["enabled"]
                    self.save_rules()
                    return rule["enabled"]
            return None

    def get_rules(self):
        """Return a copy of the current rule list."""
        with self._lock:
            return list(self.rules)

 
    # Packet Evaluation
 

    def evaluate(self, packet_info):
        """
        Evaluate a packet against the rule set.

        Args:
            packet_info (dict): Extracted packet fields  
                {
                    "src_ip": str,
                    "dst_ip": str,
                    "src_port": int | None,
                    "dst_port": int | None,
                    "protocol": str,        # "TCP", "UDP", "ICMP", etc.
                    "direction": str,       # "inbound" or "outbound"
                }

        Returns:
            tuple: (action: str, matched_rule: dict | None)
                   action is "ALLOW" or "BLOCK".
        """
        with self._lock:
            for rule in self.rules:
                if not rule.get("enabled", True):
                    continue
                if self._matches(rule, packet_info):
                    return rule["action"], rule

        # No rule matched   apply default policy
        return self.default_policy, None

 
    # Internal helpers
 

    @staticmethod
    def _matches(rule, pkt):
        """Check if a single rule matches the packet info."""

        # Direction
        if rule["direction"] != "any" and rule["direction"] != pkt["direction"]:
            return False

        # Protocol
        if rule["protocol"] != "any" and rule["protocol"] != pkt["protocol"]:
            return False

        # Source IP
        if rule["src_ip"] != "*" and rule["src_ip"] != pkt["src_ip"]:
            return False

        # Destination IP
        if rule["dst_ip"] != "*" and rule["dst_ip"] != pkt["dst_ip"]:
            return False

        # Source port (may be None for ICMP)
        if rule["src_port"] != "*":
            if pkt["src_port"] is None:
                return False
            if int(rule["src_port"]) != pkt["src_port"]:
                return False

        # Destination port
        if rule["dst_port"] != "*":
            if pkt["dst_port"] is None:
                return False
            if int(rule["dst_port"]) != pkt["dst_port"]:
                return False

        return True
