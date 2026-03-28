#!/usr/bin/env python3
"""
Advanced Firewall System with Intrusion Detection
Author: Security Implementation
firewall with packet filtering, logging, and defense mechanisms
"""

import socket
import structst
import threading
import time
import json
import os
import sys
from datetime import datetime, timedelta
from collections import defaultdict
import ipaddress
import logging
from dataclasses import dataclass, asdict
from typing import Dict, List, Set, Tuple
import queue

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('firewall.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger('Firewall')

@dataclass
class Rule:
    """Firewall rule structure"""
    id: int
    action: str  # 'ALLOW', 'DENY', 'LOG'
    protocol: str  # 'TCP', 'UDP', 'ICMP', 'ALL'
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    direction: str  # 'IN', 'OUT', 'BOTH'
    enabled: bool = True
    description: str = ""

class Packet:
    """Network packet structure"""
    def __init__(self, raw_data, src_ip, dst_ip, protocol, src_port=None, dst_port=None):
        self.raw_data = raw_data
        self.src_ip = src_ip
        self.dst_ip = dst_ip
        self.protocol = protocol
        self.src_port = src_port
        self.dst_port = dst_port
        self.timestamp = datetime.now()

class ConnectionTracker:
    """Track network connections for stateful inspection"""
    def __init__(self, timeout=60):
        self.connections = {}
        self.timeout = timeout
        self.lock = threading.Lock()
        
    def add_connection(self, src_ip, dst_ip, src_port, dst_port, protocol):
        """Add a new connection to tracking table"""
        key = f"{src_ip}:{src_port}-{dst_ip}:{dst_port}-{protocol}"
        with self.lock:
            self.connections[key] = {
                'src_ip': src_ip,
                'dst_ip': dst_ip,
                'src_port': src_port,
                'dst_port': dst_port,
                'protocol': protocol,
                'created': datetime.now(),
                'last_seen': datetime.now(),
                'packets': 0
            }
        return key
    
    def update_connection(self, key):
        """Update connection activity"""
        with self.lock:
            if key in self.connections:
                self.connections[key]['last_seen'] = datetime.now()
                self.connections[key]['packets'] += 1
                
    def cleanup_old_connections(self):
        """Remove stale connections"""
        with self.lock:
            now = datetime.now()
            expired = [k for k, v in self.connections.items() 
                      if (now - v['last_seen']).seconds > self.timeout]
            for key in expired:
                del self.connections[key]
            return len(expired)

class IntrusionDetectionSystem:
    """Simple IDS to detect common attack patterns"""
    def __init__(self):
        self.suspicious_ips = defaultdict(list)
        self.blocked_ips = set()
        self.thresholds = {
            'port_scan': 10,  # ports in 1 second
            'syn_flood': 50,  # SYN packets per second
            'icmp_flood': 30,  # ICMP packets per second
        }
        self.attack_patterns = {
            'port_scan': self.detect_port_scan,
            'syn_flood': self.detect_syn_flood,
            'icmp_flood': self.detect_icmp_flood,
        }
        
    def detect_port_scan(self, packet):
        """Detect port scanning attempts"""
        key = packet.src_ip
        now = datetime.now()
        self.suspicious_ips[key].append(now)
        
        # Clean old entries
        self.suspicious_ips[key] = [t for t in self.suspicious_ips[key] 
                                     if (now - t).seconds < 1]
        
        if len(self.suspicious_ips[key]) > self.thresholds['port_scan']:
            logger.warning(f"Port scan detected from {packet.src_ip}")
            return True
        return False
    
    def detect_syn_flood(self, packet):
        """Detect SYN flood attacks"""
        if packet.protocol == 'TCP' and hasattr(packet, 'flags') and packet.flags == 'S':
            key = packet.src_ip
            now = datetime.now()
            self.suspicious_ips[key].append(now)
            
            self.suspicious_ips[key] = [t for t in self.suspicious_ips[key] 
                                         if (now - t).seconds < 1]
            
            if len(self.suspicious_ips[key]) > self.thresholds['syn_flood']:
                logger.warning(f"SYN flood detected from {packet.src_ip}")
                self.blocked_ips.add(packet.src_ip)
                return True
        return False
    
    def detect_icmp_flood(self, packet):
        """Detect ICMP flood attacks"""
        if packet.protocol == 'ICMP':
            key = packet.src_ip
            now = datetime.now()
            self.suspicious_ips[key].append(now)
            
            self.suspicious_ips[key] = [t for t in self.suspicious_ips[key] 
                                         if (now - t).seconds < 1]
            
            if len(self.suspicious_ips[key]) > self.thresholds['icmp_flood']:
                logger.warning(f"ICMP flood detected from {packet.src_ip}")
                self.blocked_ips.add(packet.src_ip)
                return True
        return False

class Firewall:
    """Main Firewall Class"""
    def __init__(self):
        self.rules = []
        self.rule_counter = 1
        self.packet_queue = queue.Queue()
        self.running = False
        self.stats = {
            'packets_processed': 0,
            'packets_allowed': 0,
            'packets_denied': 0,
            'packets_logged': 0,
            'attacks_detected': 0,
            'start_time': datetime.now()
        }
        self.connection_tracker = ConnectionTracker()
        self.ids = IntrusionDetectionSystem()
        self.lock = threading.Lock()
        
        # Load default rules
        self.load_default_rules()
        
    def load_default_rules(self):
        """Load default security rules"""
        default_rules = [
            Rule(self.rule_counter, 'ALLOW', 'ALL', '192.168.0.0/24', 'ANY', 0, 0, 'IN', True, "Allow local network"),
            Rule(self.rule_counter + 1, 'DENY', 'ALL', 'ANY', 'ANY', 0, 0, 'IN', True, "Default deny"),
            Rule(self.rule_counter + 2, 'ALLOW', 'TCP', 'ANY', 'ANY', 80, 80, 'BOTH', True, "Allow HTTP"),
            Rule(self.rule_counter + 3, 'ALLOW', 'TCP', 'ANY', 'ANY', 443, 443, 'BOTH', True, "Allow HTTPS"),
            Rule(self.rule_counter + 4, 'ALLOW', 'TCP', 'ANY', 'ANY', 22, 22, 'IN', True, "Allow SSH"),
            Rule(self.rule_counter + 5, 'LOG', 'ICMP', 'ANY', 'ANY', 0, 0, 'BOTH', True, "Log ICMP"),
        ]
        
        for rule in default_rules:
            self.add_rule(rule)
            self.rule_counter += 1
    
    def add_rule(self, rule):
        """Add a new firewall rule"""
        with self.lock:
            rule.id = self.rule_counter
            self.rules.append(rule)
            self.rule_counter += 1
            logger.info(f"Added rule: {rule.action} {rule.protocol} from {rule.src_ip} to {rule.dst_ip}")
    
    def remove_rule(self, rule_id):
        """Remove a firewall rule by ID"""
        with self.lock:
            self.rules = [r for r in self.rules if r.id != rule_id]
            logger.info(f"Removed rule: {rule_id}")
    
    def enable_rule(self, rule_id, enabled=True):
        """Enable or disable a rule"""
        with self.lock:
            for rule in self.rules:
                if rule.id == rule_id:
                    rule.enabled = enabled
                    logger.info(f"Rule {rule_id} {'enabled' if enabled else 'disabled'}")
                    break
    
    def match_rule(self, packet, rule):
        """Check if packet matches a rule"""
        if not rule.enabled:
            return False
        
        # Check protocol
        if rule.protocol != 'ALL' and packet.protocol != rule.protocol:
            return False
        
        # Check source IP
        if rule.src_ip != 'ANY':
            try:
                if '/' in rule.src_ip:
                    if ipaddress.ip_address(packet.src_ip) not in ipaddress.ip_network(rule.src_ip):
                        return False
                elif packet.src_ip != rule.src_ip:
                    return False
            except:
                if packet.src_ip != rule.src_ip:
                    return False
        
        # Check destination IP
        if rule.dst_ip != 'ANY':
            try:
                if '/' in rule.dst_ip:
                    if ipaddress.ip_address(packet.dst_ip) not in ipaddress.ip_network(rule.dst_ip):
                        return False
                elif packet.dst_ip != rule.dst_ip:
                    return False
            except:
                if packet.dst_ip != rule.dst_ip:
                    return False
        
        # Check ports if applicable
        if packet.src_port and rule.src_port > 0:
            if packet.src_port != rule.src_port:
                return False
        
        if packet.dst_port and rule.dst_port > 0:
            if packet.dst_port != rule.dst_port:
                return False
        
        # Check direction
        if rule.direction != 'BOTH':
            # This would require knowledge of packet direction
            pass
        
        return True
    
    def process_packet(self, packet):
        """Process a single packet through the firewall rules"""
        self.stats['packets_processed'] += 1
        
        # Check IDS first
        for detection in self.ids.attack_patterns.values():
            if detection(packet):
                self.stats['attacks_detected'] += 1
                if packet.src_ip in self.ids.blocked_ips:
                    logger.info(f"Blocked packet from {packet.src_ip} due to attack detection")
                    return False
        
        # Check if source is blocked
        if packet.src_ip in self.ids.blocked_ips:
            logger.info(f"Blocked packet from {packet.src_ip} (blacklisted)")
            return False
        
        # Apply firewall rules
        action = 'DENY'  # Default action
        matching_rules = []
        
        with self.lock:
            for rule in self.rules:
                if self.match_rule(packet, rule):
                    matching_rules.append(rule)
                    action = rule.action
                    if rule.action != 'LOG':
                        break
        
        # Take action
        if action == 'ALLOW':
            self.stats['packets_allowed'] += 1
            # Track connection
            if packet.src_port and packet.dst_port:
                key = self.connection_tracker.add_connection(
                    packet.src_ip, packet.dst_ip, 
                    packet.src_port, packet.dst_port,
                    packet.protocol
                )
                self.connection_tracker.update_connection(key)
            return True
        elif action == 'DENY':
            self.stats['packets_denied'] += 1
            logger.debug(f"Packet denied: {packet.src_ip}:{packet.src_port} -> {packet.dst_ip}:{packet.dst_port} ({packet.protocol})")
            return False
        elif action == 'LOG':
            self.stats['packets_logged'] += 1
            logger.info(f"Packet logged: {packet.src_ip}:{packet.src_port} -> {packet.dst_ip}:{packet.dst_port} ({packet.protocol})")
            return True
        
        return False
    
    def sniff_packets(self):
        """Sniff network packets (requires admin/root privileges)"""
        try:
            # This creates a raw socket to capture packets
            # Note: Requires root/admin privileges on most systems any Error occurring
            sniffer = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
            logger.info("Packet sniffer started")
            
            while self.running:
                try:
                    raw_data, addr = sniffer.recvfrom(65536)
                    self.packet_queue.put((raw_data, addr))
                except Exception as e:
                    logger.error(f"Error capturing packet: {e}")
                    break
                    
        except PermissionError:
            logger.error("Permission denied: Run as administrator/root to capture packets")
        except Exception as e:
            logger.error(f"Error starting packet sniffer: {e}")
    
    def process_packet_queue(self):
        """Process packets from the queue"""
        while self.running:
            try:
                raw_data, addr = self.packet_queue.get(timeout=1)
                packet = self.parse_packet(raw_data, addr)
                if packet:
                    self.process_packet(packet)
            except queue.Empty:
                continue
            except Exception as e:
                logger.error(f"Error processing packet: {e}")
    
    def parse_packet(self, raw_data, addr):
        """Parse raw packet data (simplified version)"""
        try:
            # Simplified packet parsing
            # In a real implementation, you'd parse Ethernet, IP, TCP/UDP headers
            # This is a placeholder for demonstration
            packet = Packet(
                raw_data=raw_data,
                src_ip=addr[0] if isinstance(addr, tuple) else '0.0.0.0',
                dst_ip='0.0.0.0',
                protocol='TCP',
                src_port=12345,
                dst_port=80
            )
            return packet
        except Exception as e:
            logger.error(f"Error parsing packet: {e}")
            return None
    
    def print_stats(self):
        """Print firewall statistics"""
        uptime = datetime.now() - self.stats['start_time']
        print("\n" + "="*50)
        print("FIREWALL STATISTICS")
        print("="*50)
        print(f"Uptime: {uptime}")
        print(f"Packets Processed: {self.stats['packets_processed']}")
        print(f"Packets Allowed: {self.stats['packets_allowed']}")
        print(f"Packets Denied: {self.stats['packets_denied']}")
        print(f"Packets Logged: {self.stats['packets_logged']}")
        print(f"Attacks Detected: {self.stats['attacks_detected']}")
        print(f"Blocked IPs: {len(self.ids.blocked_ips)}")
        print(f"Active Connections: {len(self.connection_tracker.connections)}")
        print("="*50)
    
    def list_rules(self):
        """List all firewall rules"""
        print("\n" + "="*80)
        print("FIREWALL RULES")
        print("="*80)
        print(f"{'ID':<4} {'Status':<8} {'Action':<8} {'Protocol':<8} {'Source':<20} {'Destination':<20} {'Ports':<12} {'Description'}")
        print("-"*80)
        
        for rule in self.rules:
            status = "Enabled" if rule.enabled else "Disabled"
            src = f"{rule.src_ip}:{rule.src_port}" if rule.src_port > 0 else rule.src_ip
            dst = f"{rule.dst_ip}:{rule.dst_port}" if rule.dst_port > 0 else rule.dst_ip
            ports = f"{rule.src_port}->{rule.dst_port}" if rule.src_port > 0 and rule.dst_port > 0 else "any"
            
            print(f"{rule.id:<4} {status:<8} {rule.action:<8} {rule.protocol:<8} {src:<20} {dst:<20} {ports:<12} {rule.description}")
        print("="*80)
    
    def start(self):
        """Start the firewall"""
        if self.running:
            logger.warning("Firewall is already running")
            return
        
        self.running = True
        logger.info("Starting firewall system...")
        
        # Start packet sniffer thread
        sniffer_thread = threading.Thread(target=self.sniff_packets, daemon=True)
        sniffer_thread.start()
        
        # Start packet processor thread
        processor_thread = threading.Thread(target=self.process_packet_queue, daemon=True)
        processor_thread.start()
        
        # Start connection cleanup thread
        def cleanup_connections():
            while self.running:
                time.sleep(30)
                self.connection_tracker.cleanup_old_connections()
        
        cleanup_thread = threading.Thread(target=cleanup_connections, daemon=True)
        cleanup_thread.start()
        
        logger.info("Firewall system started successfully")
    
    def stop(self):
        """Stop the firewall"""
        self.running = False
        logger.info("Firewall system stopped")
    
    def block_ip(self, ip_address):
        """Manually block an IP address"""
        self.ids.blocked_ips.add(ip_address)
        logger.info(f"Manually blocked IP: {ip_address}")
    
    def unblock_ip(self, ip_address):
        """Unblock an IP address"""
        if ip_address in self.ids.blocked_ips:
            self.ids.blocked_ips.remove(ip_address)
            logger.info(f"Unblocked IP: {ip_address}")
    
    def save_configuration(self, filename='firewall_config.json'):
        """Save firewall configuration to file"""
        config = {
            'rules': [asdict(rule) for rule in self.rules],
            'blocked_ips': list(self.ids.blocked_ips),
            'thresholds': self.ids.thresholds
        }
        
        with open(filename, 'w') as f:
            json.dump(config, f, indent=2, default=str)
        
        logger.info(f"Configuration saved to {filename}")
    
    def load_configuration(self, filename='firewall_config.json'):
        """Load firewall configuration from file"""
        try:
            with open(filename, 'r') as f:
                config = json.load(f)
            
            # Load rules
            self.rules = []
            for rule_data in config['rules']:
                rule = Rule(**rule_data)
                self.rules.append(rule)
            
            # Load blocked IPs
            self.ids.blocked_ips = set(config['blocked_ips'])
            
            # Load thresholds
            self.ids.thresholds = config['thresholds']
            
            logger.info(f"Configuration loaded from {filename}")
        except FileNotFoundError:
            logger.warning(f"Configuration file {filename} not found")
        except Exception as e:
            logger.error(f"Error loading configuration: {e}")

class FirewallCLI:
    """Command-line interface for firewall management"""
    def __init__(self, firewall):
        self.firewall = firewall
    
    def run(self):
        """Run the CLI"""
        print("\n" + "="*60)
        print("ADVANCED FIREWALL SYSTEM")
        print("="*60)
        print("Commands: start, stop, rules, add, remove, enable, disable, stats")
        print("          block, unblock, save, load, help, exit")
        print("="*60)
        
        while True:
            try:
                command = input("\nfirewall> ").strip().lower().split()
                
                if not command:
                    continue
                
                cmd = command[0]
                
                if cmd == 'start':
                    self.firewall.start()
                    
                elif cmd == 'stop':
                    self.firewall.stop()
                    
                elif cmd == 'rules':
                    self.firewall.list_rules()
                    
                elif cmd == 'add':
                    self.add_rule_interactive()
                    
                elif cmd == 'remove':
                    if len(command) > 1:
                        rule_id = int(command[1])
                        self.firewall.remove_rule(rule_id)
                    else:
                        print("Usage: remove <rule_id>")
                        
                elif cmd == 'enable':
                    if len(command) > 1:
                        rule_id = int(command[1])
                        self.firewall.enable_rule(rule_id, True)
                    else:
                        print("Usage: enable <rule_id>")
                        
                elif cmd == 'disable':
                    if len(command) > 1:
                        rule_id = int(command[1])
                        self.firewall.enable_rule(rule_id, False)
                    else:
                        print("Usage: disable <rule_id>")
                        
                elif cmd == 'stats':
                    self.firewall.print_stats()
                    
                elif cmd == 'block':
                    if len(command) > 1:
                        ip = command[1]
                        self.firewall.block_ip(ip)
                    else:
                        print("Usage: block <ip_address>")
                        
                elif cmd == 'unblock':
                    if len(command) > 1:
                        ip = command[1]
                        self.firewall.unblock_ip(ip)
                    else:
                        print("Usage: unblock <ip_address>")
                        
                elif cmd == 'save':
                    filename = command[1] if len(command) > 1 else 'firewall_config.json'
                    self.firewall.save_configuration(filename)
                    
                elif cmd == 'load':
                    filename = command[1] if len(command) > 1 else 'firewall_config.json'
                    self.firewall.load_configuration(filename)
                    
                elif cmd == 'help':
                    self.print_help()
                    
                elif cmd == 'exit':
                    self.firewall.stop()
                    print("Goodbye!")
                    break
                    
                else:
                    print(f"Unknown command: {cmd}")
                    print("Type 'help' for available commands")
                    
            except KeyboardInterrupt:
                print("\nShutting down...")
                self.firewall.stop()
                break
            except Exception as e:
                print(f"Error: {e}")
    
    def add_rule_interactive(self):
        """Interactive rule addition"""
        print("\nAdd New Firewall Rule")
        print("-" * 40)
        
        try:
            action = input("Action (ALLOW/DENY/LOG): ").strip().upper()
            protocol = input("Protocol (TCP/UDP/ICMP/ALL): ").strip().upper()
            src_ip = input("Source IP (ANY or IP/network): ").strip()
            dst_ip = input("Destination IP (ANY or IP/network): ").strip()
            src_port = int(input("Source Port (0 for any): ").strip() or "0")
            dst_port = int(input("Destination Port (0 for any): ").strip() or "0")
            direction = input("Direction (IN/OUT/BOTH): ").strip().upper()
            description = input("Description: ").strip()
            
            rule = Rule(
                id=0,
                action=action,
                protocol=protocol,
                src_ip=src_ip,
                dst_ip=dst_ip,
                src_port=src_port,
                dst_port=dst_port,
                direction=direction,
                enabled=True,
                description=description
            )
            
            self.firewall.add_rule(rule)
            print(f"Rule added successfully with ID: {self.firewall.rule_counter - 1}")
            
        except Exception as e:
            print(f"Error adding rule: {e}")
    
    def print_help(self):
        """Print help information"""
        print("\nAvailable Commands:")
        print("  start           - Start the firewall")
        print("  stop            - Stop the firewall")
        print("  rules           - List all firewall rules")
        print("  add             - Add a new rule interactively")
        print("  remove <id>     - Remove rule by ID")
        print("  enable <id>     - Enable rule by ID")
        print("  disable <id>    - Disable rule by ID")
        print("  stats           - Show firewall statistics")
        print("  block <ip>      - Block an IP address")
        print("  unblock <ip>    - Unblock an IP address")
        print("  save [file]     - Save configuration to file")
        print("  load [file]     - Load configuration from file")
        print("  help            - Show this help")
        print("  exit            - Exit the firewall system")

def main():
    """Main entry point"""
    # Check for root/admin privileges
    if os.name == 'posix' and os.geteuid() != 0:
        print("Warning: Running without root privileges. Packet capture may not work.")
        print("Consider running with sudo for full functionality.\n")
    
    # Create firewall instance
    firewall = Firewall()
    
    # Create and run CLI
    cli = FirewallCLI(firewall)
    
    try:
        cli.run()
    except Exception as e:
        logger.error(f"Fatal error: {e}")
        return 1
    
    return 0

if __name__ == "__main__":
    sys.exit(main())