"""
cli.py   Interactive Firewall Command-Line Interface

Provides a menu-driven interface for managing firewall rules,
viewing traffic logs, and monitoring statistics   all while the
sniffer is running in the background.
"""


class FirewallCLI:
    """Interactive CLI for the Simple Firewall."""

    MENU = """
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
"""

    def __init__(self, rule_engine, logger, sniffer):
        self.rule_engine = rule_engine
        self.logger = logger
        self.sniffer = sniffer

  
    # Main loop
  

    def run(self):
        """Run the interactive CLI loop."""
        print(self.MENU)

        while True:
            try:
                choice = input("\n[firewall]> ").strip()
            except (EOFError, KeyboardInterrupt):
                self._exit()
                break

            if choice == "1":
                self._list_rules()
            elif choice == "2":
                self._add_rule()
            elif choice == "3":
                self._remove_rule()
            elif choice == "4":
                self._toggle_rule()
            elif choice == "5":
                self._view_logs()
            elif choice == "6":
                self._show_stats()
            elif choice == "7":
                self._reload_rules()
            elif choice == "8":
                self._exit()
                break
            elif choice.lower() in ("help", "menu", "h", "?"):
                print(self.MENU)
            else:
                print("[!] Invalid option. Type 'help' to see the menu.")

  
    # Menu actions
  

    def _list_rules(self):
        """Display all firewall rules in a formatted table."""
        rules = self.rule_engine.get_rules()
        if not rules:
            print("\n  (No rules configured)\n")
            return

        print(f"\n  {'ID':<4} {'Status':<9} {'Action':<7} {'Name':<22} "
              f"{'Dir':<10} {'Proto':<6} {'Src IP':<16} {'Dst IP':<16} "
              f"{'SPort':<7} {'DPort':<7}")
        print("  " + "-" * 104)

        for r in rules:
            status = "ON" if r.get("enabled", True) else "OFF"
            print(f"  {r['id']:<4} {status:<9} {r['action']:<7} {r['name']:<22} "
                  f"{r['direction']:<10} {r['protocol']:<6} {r['src_ip']:<16} "
                  f"{r['dst_ip']:<16} {str(r['src_port']):<7} {str(r['dst_port']):<7}")
        print()

    def _add_rule(self):
        """Walk the user through adding a new rule."""
        print("\n--- Add New Rule ---")
        try:
            name = input("  Rule name: ").strip()
            if not name:
                print("[!] Rule name cannot be empty.")
                return

            direction = self._choose("  Direction", ["inbound", "outbound", "any"])
            protocol = self._choose("  Protocol", ["TCP", "UDP", "ICMP", "any"])
            src_ip = input("  Source IP (* for any): ").strip() or "*"
            dst_ip = input("  Destination IP (* for any): ").strip() or "*"
            src_port = input("  Source port (* for any): ").strip() or "*"
            dst_port = input("  Destination port (* for any): ").strip() or "*"
            action = self._choose("  Action", ["BLOCK", "ALLOW"])

            # Validate port inputs
            for label, val in [("Source port", src_port), ("Dest port", dst_port)]:
                if val != "*":
                    if not val.isdigit() or not (0 <= int(val) <= 65535):
                        print(f"[!] Invalid {label}: must be 0-65535 or *")
                        return

            rule = self.rule_engine.add_rule(
                name=name,
                direction=direction,
                protocol=protocol,
                src_ip=src_ip,
                dst_ip=dst_ip,
                src_port=src_port if src_port == "*" else int(src_port),
                dst_port=dst_port if dst_port == "*" else int(dst_port),
                action=action,
            )
            print(f"\n[+] Rule #{rule['id']} '{rule['name']}' added successfully.")

        except (EOFError, KeyboardInterrupt):
            print("\n[!] Cancelled.")

    def _remove_rule(self):
        """Remove a rule by ID."""
        self._list_rules()
        try:
            raw = input("  Enter rule ID to remove: ").strip()
            if not raw.isdigit():
                print("[!] Invalid ID.")
                return
            rule_id = int(raw)
            if self.rule_engine.remove_rule(rule_id):
                print(f"[+] Rule #{rule_id} removed.")
            else:
                print(f"[!] Rule #{rule_id} not found.")
        except (EOFError, KeyboardInterrupt):
            print("\n[!] Cancelled.")

    def _toggle_rule(self):
        """Enable or disable a rule by ID."""
        self._list_rules()
        try:
            raw = input("  Enter rule ID to toggle: ").strip()
            if not raw.isdigit():
                print("[!] Invalid ID.")
                return
            rule_id = int(raw)
            new_state = self.rule_engine.toggle_rule(rule_id)
            if new_state is not None:
                state_str = "ENABLED" if new_state else "DISABLED"
                print(f"[+] Rule #{rule_id} is now {state_str}.")
            else:
                print(f"[!] Rule #{rule_id} not found.")
        except (EOFError, KeyboardInterrupt):
            print("\n[!] Cancelled.")

    def _view_logs(self):
        """Show the most recent log entries."""
        try:
            raw = input("  How many recent entries? [10]: ").strip()
            count = int(raw) if raw.isdigit() else 10
        except (EOFError, KeyboardInterrupt):
            count = 10

        logs = self.logger.get_recent_logs(count)
        if not logs:
            print("\n  (No log entries yet)\n")
            return

        print(f"\n  --- Last {len(logs)} log entries ---")
        for entry in logs:
            print(f"  {entry}")
        print()

    def _show_stats(self):
        """Display traffic statistics."""
        stats = self.logger.get_stats()
        total = stats["total"]
        allowed = stats["allowed"]
        blocked = stats["blocked"]

        print(f"\n  ╔════════════════════════════════╗")
        print(f"  ║     TRAFFIC STATISTICS         ║")
        print(f"  ╠════════════════════════════════╣")
        print(f"  ║  Total packets:  {total:<13} ║")
        print(f"  ║  Allowed:        {allowed:<13} ║")
        print(f"  ║  Blocked:        {blocked:<13} ║")
        if total > 0:
            pct = (blocked / total) * 100
            print(f"  ║  Block rate:     {pct:<12.1f}% ║")
        print(f"  ╚════════════════════════════════╝\n")

    def _reload_rules(self):
        """Reload rules from the JSON file."""
        self.rule_engine.load_rules()
        print("[+] Rules reloaded from file.")

    def _exit(self):
        """Shut down the firewall gracefully."""
        print("\n[*] Shutting down firewall...")
        self.sniffer.stop()
        print("[*] Goodbye!")

  
    # Helpers
  

    @staticmethod
    def _choose(prompt, options):
        """Present a numbered choice and return the selected value."""
        options_str = " / ".join(f"{i+1}.{opt}" for i, opt in enumerate(options))
        while True:
            raw = input(f"{prompt} ({options_str}): ").strip()
            # Accept the option name directly
            if raw in options:
                return raw
            # Accept the number
            if raw.isdigit():
                idx = int(raw) - 1
                if 0 <= idx < len(options):
                    return options[idx]
            print(f"  [!] Please choose one of: {options_str}")
