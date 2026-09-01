"""Quick smoke test for the rule engine and logger."""
import sys, os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from rule_engine import RuleEngine
from logger import FirewallLogger

re = RuleEngine()
logger = FirewallLogger(log_file="test_firewall.log")

# Test 1: Block suspicious IP (rule #4)
pkt = {"src_ip": "192.168.1.100", "dst_ip": "10.0.0.1",
       "src_port": 5000, "dst_port": 80, "protocol": "TCP", "direction": "outbound"}
action, rule = re.evaluate(pkt)
logger.log(action, pkt, rule)
assert action == "BLOCK", f"Expected BLOCK, got {action}"
print(f"PASS Test 1 - Suspicious IP: {action} (Rule: {rule['name']})")

# Test 2: Block Telnet (rule #1)
pkt2 = {"src_ip": "10.0.0.5", "dst_ip": "10.0.0.1",
        "src_port": 4000, "dst_port": 23, "protocol": "TCP", "direction": "inbound"}
action2, rule2 = re.evaluate(pkt2)
logger.log(action2, pkt2, rule2)
assert action2 == "BLOCK", f"Expected BLOCK, got {action2}"
print(f"PASS Test 2 - Telnet inbound: {action2} (Rule: {rule2['name']})")

# Test 3: Allow HTTPS (rule #6)
pkt3 = {"src_ip": "10.0.0.1", "dst_ip": "8.8.8.8",
        "src_port": 5000, "dst_port": 443, "protocol": "TCP", "direction": "outbound"}
action3, rule3 = re.evaluate(pkt3)
logger.log(action3, pkt3, rule3)
assert action3 == "ALLOW", f"Expected ALLOW, got {action3}"
print(f"PASS Test 3 - HTTPS outbound: {action3} (Rule: {rule3['name']})")

# Test 4: No matching rule -> default ALLOW
pkt4 = {"src_ip": "10.0.0.1", "dst_ip": "8.8.8.8",
        "src_port": 5000, "dst_port": 9999, "protocol": "TCP", "direction": "outbound"}
action4, rule4 = re.evaluate(pkt4)
logger.log(action4, pkt4, rule4)
assert action4 == "ALLOW", f"Expected ALLOW, got {action4}"
assert rule4 is None
print(f"PASS Test 4 - No match (default policy): {action4}")

# Test 5: Block FTP (rule #2)
pkt5 = {"src_ip": "10.0.0.1", "dst_ip": "5.5.5.5",
        "src_port": 3000, "dst_port": 21, "protocol": "TCP", "direction": "outbound"}
action5, rule5 = re.evaluate(pkt5)
logger.log(action5, pkt5, rule5)
assert action5 == "BLOCK", f"Expected BLOCK, got {action5}"
print(f"PASS Test 5 - FTP: {action5} (Rule: {rule5['name']})")

# Test 6: ICMP (no ports) - should hit default policy
pkt6 = {"src_ip": "10.0.0.1", "dst_ip": "8.8.8.8",
        "src_port": None, "dst_port": None, "protocol": "ICMP", "direction": "outbound"}
action6, rule6 = re.evaluate(pkt6)
logger.log(action6, pkt6, rule6)
assert action6 == "ALLOW", f"Expected ALLOW, got {action6}"
print(f"PASS Test 6 - ICMP (default policy): {action6}")

# Show stats
stats = logger.get_stats()
print(f"\nStats: {stats}")
print(f"\nAll {stats['total']} tests PASSED!")

# Cleanup close handler before deleting
for h in logger._file_logger.handlers[:]:
    h.close()
    logger._file_logger.removeHandler(h)
os.remove("test_firewall.log")
