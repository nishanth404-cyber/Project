import random
import time
import itertools
import networkx as nx
import numpy as np
import math
from heapq import heappush, heappop
from collections import defaultdict
import matplotlib.pyplot as plt
import matplotlib.animation as animation
from matplotlib.widgets import Button
from matplotlib.widgets import RadioButtons
from matplotlib.patches import Circle
import re

class MANET:
    def __init__(self, num_nodes, width, height, communication_range, initial_movement_type="random", routing_mode="olsr"):
        self.routing_mode = routing_mode
        self.nodes = []
        self.blocking_start_timestamps = []
        if initial_movement_type == "convoy":
            convoy_spacing = 10
            for i in range(num_nodes):
                x = width * i / num_nodes
                y = height / 2
                node = Node(i, x, y, communication_range, self)
                self.nodes.append(node)
        elif initial_movement_type == "small_teams":
            team_size = 3
            team_spacing = 50
            for i in range(num_nodes):
                team_index = i // team_size
                x = team_spacing * team_index + random.uniform(0, team_spacing / 2)
                y = random.uniform(0, height)
                node = Node(i, x, y, communication_range, self)
                self.nodes.append(node)
        else:
            for i in range(num_nodes):
                x = random.uniform(0, width)
                y = random.uniform(0, height)
                node = Node(i, x, y, communication_range, self)
                self.nodes.append(node)

    def generate_malicious_victim_pairs(self, num_pairs, multiple_victims=False, multiple_malicious=False):
        pairs = []

        if not multiple_malicious:
            for _ in range(num_pairs):
                malicious_node = random.choice(self.nodes)
                while malicious_node.is_victim:
                    malicious_node = random.choice(self.nodes)
                malicious_node.is_malicious = True

        else:
            available_nodes = [node for node in self.nodes if not node.is_victim]
            num_malicious_nodes = random.randint(1, len(available_nodes) - 1)
            malicious_nodes = random.sample(available_nodes, num_malicious_nodes)

            for malicious_node in malicious_nodes:
                malicious_node.is_malicious = True

                if multiple_victims:
                    available_victims = [node for node in self.nodes if node != malicious_node and not node.is_malicious]
                    num_victims = random.randint(1, len(available_victims))
                    victims = random.sample(available_victims, num_victims)
                else:
                    victims = [random.choice([node for node in self.nodes if node != malicious_node and not node.is_malicious])]

                for victim_node in victims:
                    victim_node.is_victim = True

                pairs.append((malicious_node, victims))

        return pairs
    
    def update_connectivity(self):
        """Updates the connectivity between the nodes in the network."""
        for node in self.nodes:
            node.neighbors = []
            for other_node in self.nodes:
                if node != other_node and node.is_in_range(other_node):
                    node.neighbors.append(other_node)
            if self.routing_mode == "olsr":
                node.select_mprs()

    def find_shortest_path(self, source, target):
        if self.routing_mode == "olsr":
            return self.find_shortest_path_olsr(source, target)
        else:
            return self.find_shortest_path_simple(source, target)

    def find_shortest_path_simple(self, source, target):
        visited = set()
        queue = [(source, [source])]

        while queue:
            current_node, path = queue.pop(0)

            if current_node == target:
                return path

            if current_node not in visited:
                visited.add(current_node)

                for neighbor in current_node.neighbors:
                    new_path = list(path)
                    new_path.append(neighbor)
                    queue.append((neighbor, new_path))

        return None

    def find_shortest_path_olsr(self, source, target):
        visited = set()
        queue = [(source, [source])]

        while queue:
            current_node, path = queue.pop(0)

            if current_node == target:
                return path

            if current_node not in visited:
                visited.add(current_node)

                for neighbor in current_node.mprs:
                    new_path = list(path)
                    new_path.append(neighbor)
                    queue.append((neighbor, new_path))

        return None

    def update_controller_and_ids_nodes(self, best_controller_ip, best_ids_ips):
        for node in self.nodes:
            if node.ip == best_controller_ip:
                node.is_controller = True
            else:
                node.is_controller = False

            if node.ip in best_ids_ips:
                node.is_ids = True
            else:
                node.is_ids = False
    
    def block_malicious_ips(self, malicious_ips):
        # Set the current time as the blocking start timestamp
        self.blocking_start_timestamps.append(time.time())

        # Iterate through all nodes in the network
        for node in self.nodes:
            # Skip the controller node and malicious nodes
            if not node.is_controller and not node.is_malicious:
                # Iterate through the list of malicious IPs
                for ip in malicious_ips:
                    # Add the malicious IP to the node's blocked_ips list
                    node.blocked_ips.add(ip)

                    # Remove the malicious node from the node's neighbors list
                    malicious_node = self.get_node_by_ip(ip)
                    if malicious_node in node.neighbors:
                        node.neighbors.remove(malicious_node)

    def get_blocking_delay(manet, controller_node, processing_capacity):
        if not controller_node.alerts_received_timestamps or not manet.blocking_start_timestamps:
            return None

        blocking_delays = []
        for alert_ts, blocking_ts, packet in zip(controller_node.alerts_received_timestamps, manet.blocking_start_timestamps, controller_node.received_alerts):
            data_rate = controller_node.get_data_rate(packet.src_ip)
            transmission_time = packet.size * 8 / data_rate
            processing_delay = 1 / processing_capacity
            blocking_delays.append(blocking_ts - alert_ts + transmission_time + processing_delay)

        return sum(blocking_delays) / len(blocking_delays)
    
    def get_blocking_delay_for_node(self, node, malicious_node):
        if not node.blocked_ips or malicious_node.ip not in node.blocked_ips:
            return None

        controller_node = self.get_controller_node()
        processing_capacity = self.get_processing_capacity()

        return self.get_blocking_delay(self, controller_node, processing_capacity)

    def get_total_mitigation_delay(self, controller_ip, ids_ips):
        total_mitigation_delay = 0

        # Detection delay component
        for node in self.nodes:
            if node.is_ids:
                for neighbor in node.neighbors:
                    if neighbor.is_malicious:
                        detection_delay = node.get_detection_delay(neighbor, self.get_processing_capacity())
                        if detection_delay is not None:
                            total_mitigation_delay += detection_delay

        controller_node = self.get_node_by_ip(controller_ip)

        # Alerting delay component
        for ids_ip in ids_ips:
            ids_node = self.get_node_by_ip(ids_ip)
            if ids_node == controller_node:
                alerting_delay = 0
            else:
                alerting_delay = ids_node.get_alerting_delay(controller_node)
            if alerting_delay is not None:
                total_mitigation_delay += alerting_delay

        # Blocking delay component
        for node in self.nodes:
            if not node.is_malicious and not node.is_controller:
                for malicious_node in node.neighbors:
                    if malicious_node.is_malicious:
                        blocking_delay = self.get_blocking_delay_for_node(node, malicious_node)
                        if blocking_delay is not None:
                            total_mitigation_delay += blocking_delay


        return total_mitigation_delay

    def get_controller_node(self):
        for node in self.nodes:
            if node.is_controller:
                return node
        return None

    def get_processing_capacity(self):
        # You can replace this with the actual processing capacity value or logic to obtain it.
        processing_capacity = 1000  # Example value
        return processing_capacity

    def get_node_by_ip(self, ip):
        for node in self.nodes:
            if node.ip == ip:
                return node

        return None

    def simulate_normal_udp_traffic(self, node_pairs, packet_count):
        for src_node, dst_node in node_pairs:
            for _ in range(packet_count):
                packet = Packet(src_ip=src_node.ip, dst_ip=dst_node.ip, payload="Normal UDP payload", packet_type="UDP", size=512)
                src_node.send_packet(dst_node, packet)

    def simulate_normal_tcp_traffic(self, node_pairs, packet_count):
        for src_node, dst_node in node_pairs:
            for _ in range(packet_count):
                packet = Packet(src_ip=src_node.ip, dst_ip=dst_node.ip, payload="Normal TCP payload", packet_type="TCP", size=1024)
                src_node.send_packet(dst_node, packet)

    def simulate_udp_flood_attack(self, malicious_victim_pairs, packet_count):
        for malicious_node, victims in malicious_victim_pairs:
            for _ in range(packet_count):
                victim_node = random.choice(victims)
                packet = Packet(src_ip=malicious_node.ip, dst_ip=victim_node.ip, payload="UDP flood attack payload", packet_type="UDP", size=64)
                malicious_node.send_packet(victim_node, packet)

    def simulate_tcp_syn_flood_attack(self, malicious_victim_pairs, packet_count):
        for malicious_node, victims in malicious_victim_pairs:
            for _ in range(packet_count):
                victim_node = random.choice(victims)
                packet = Packet(src_ip=malicious_node.ip, dst_ip=victim_node.ip, payload="TCP SYN flood attack payload", packet_type="TCP_SYN", size=64)
                malicious_node.send_packet(victim_node, packet)


class Packet:
    def __init__(self, src_ip, dst_ip, payload, packet_type=None, sent_time=None, received_time=None, size=None, data_rate=None):
        self.src_ip = src_ip
        self.dst_ip = dst_ip
        self.payload = payload
        self.packet_type = packet_type
        self.sent_time = sent_time
        self.received_time = received_time
        self.size = size

class Node:
    def __init__(self, ip, x, y, communication_range,manet):
        self.ip = ip
        print("Node IP:",self.ip)
        self.x = x
        self.y = y
        self.manet = manet
        self.communication_range = communication_range
        self.neighbors = set()
        self.is_malicious = False
        self.is_victim = False
        self.is_controller = False
        self.is_ids = False
        self.mprs = set()
        self.udp_attack_packet_count = 0
        self.tcp_syn_attack_packet_count = 0
        self.threshold = 100 #Threshold for traffic analyzer (IDS) for packets recevied by the node. This distinguishes the normal from the malicious flows.
        self.packet_counter = {"UDP": 0, "TCP": 0, "TCP_SYN": 0}
        self.alerts_received_timestamps = []
        self.attack_start_timestamps = []
        self.packets_received_timestamps = []
        self.attack_detection_timestamps = []
        self.alert_sent_timestamps = []
        self.received_packets = []
        self.sent_alerts = []
        self.received_alerts = [] 
        self.malicious_ips= []
        self.blocked_ips = set()

    def distance_to(self, other_node):
        dx = self.x - other_node.x
        dy = self.y - other_node.y
        return math.sqrt(dx**2 + dy**2)

    def simplified_signal_strength(self, other_node):
        distance = self.distance_to(other_node)
        # Assuming the signal strength decreases with the square of the distance
        return 1 / (distance ** 2 + 1)  # Adding 1 to avoid division by zero
    
    #Implementing the Friis transmistion equation for free space propagation:
    # The Friis transmission equation is as follows:
    # Pr = Pt * Gt * Gr * (λ / (4 * π * d))^2
    # where:
    # Pr is the received power at the receiving node's antenna
    # Pt is the transmission power of the transmitting node's transceiver
    # Gt is the gain of the transmitting node's antenna
    # Gr is the gain of the receiving node's antenna
    # λ is the wavelength of the transmitted signal
    # d is the distance between the transmitting and receiving nodes
    # To calculate the signal strength in dB, you can use the following equation:
    # Signal_strength_dB = 10 * log10(Pr / Pt)
    def signal_strength(self, other_node, pt=12, gt=0, gr=0, frequency=2.4e9):
        """Calculates the signal strength in dB between the two nodes."""
        distance = self.distance_to(other_node)
        #print("Distance between node "+str(self.ip)+" and node "+str(other_node.ip)+" is "+str(distance)+"m")
        # Convert pt from dBm to watts
        pt_watts = 10 ** (pt / 10) / 1000
        
        # Convert gt and gr from dBi to linear scale
        gt_linear = 10 ** (gt / 10)
        gr_linear = 10 ** (gr / 10)

        # Calculate the wavelength of the transmitted signal
        speed_of_light = 3e8  # Speed of light in m/s
        wavelength = speed_of_light / frequency
        
        # Calculate the received power using the Friis transmission equation
        pr = pt_watts * gt_linear * gr_linear * (wavelength / (4 * math.pi * distance))**2
        
        # Calculate the signal strength in dB
        signal_strength_dB = 10 * math.log10(pr / pt_watts)
        
        return signal_strength_dB
    
    def get_data_rate_simplified(self, other_node, max_data_rate=1000000, data_rate_scaling_factor=10): #max datarate --> 1Mbps
        # Calculate data rate based on factors such as distance, signal strength, etc.
        # For simplicity, I will use an inverse relationship between distance and data rate.
        distance = self.distance_to(other_node)
        data_rate = max_data_rate / (1 + distance / data_rate_scaling_factor)
        return data_rate
    
    def get_data_rate(self, other_node, max_data_rate=1000000, snr_scaling_factor=10):
        """Calculates the data rate based on the signal strength."""        
        signal_strength = self.signal_strength(other_node)
        noise_level = -100  # Assuming a constant noise level in dBm

        # Calculate the signal-to-noise ratio (SNR) in dB
        snr_dB = signal_strength - noise_level

        # Calculate the SNR in linear scale
        snr_linear = 10 ** (snr_dB / 10)

        # Scale the data rate based on the SNR
        epsilon = 1e-6
        data_rate = max_data_rate * (min(snr_linear / snr_scaling_factor, 1) + epsilon)
        return data_rate
    
    def get_detection_delay(self, node, processing_capacity):
        if not node.attack_start_timestamps or not node.packets_received_timestamps:
            return None

        detection_delays = []
        for start_ts, received_ts, packet in zip(node.attack_start_timestamps, node.packets_received_timestamps, node.received_packets):
            sender_node = node.manet.get_node_by_ip(packet.src_ip)
            data_rate = sender_node.get_data_rate(node)
            transmission_time = packet.size * 8 / data_rate
            processing_delay = 1 / processing_capacity
            detection_delays.append(received_ts - start_ts + transmission_time + processing_delay)

        return sum(detection_delays) / len(detection_delays)

    def get_alerting_delay(self, controller_node):
        if not self.attack_detection_timestamps or not self.alert_sent_timestamps:
            return None

        alerting_delays = []
        for detection_ts, alert_ts, packet in zip(self.attack_detection_timestamps, self.alert_sent_timestamps, self.sent_alerts):
            data_rate = self.get_data_rate(controller_node)
            transmission_time = packet.size * 8 / data_rate
            alerting_delays.append(alert_ts - detection_ts + transmission_time)

        return sum(alerting_delays) / len(alerting_delays)
  
    def move(self, dx, dy):
        """Moves the node by a given amount in x and y directions."""
        self.x += dx
        self.y += dy
    
    # I consider a signal strength threshold at -85dBm. In Wi-Fi networks (802.11 standards), the receiver sensitivity can range from -70 dBm to -100 dBm or even lower, depending on the data rate and modulation scheme.
    def is_in_range(self, other_node, signal_strength_threshold=-85):
        """Checks if the other_node is within the communication range based on signal strength."""
        signal_strength = self.signal_strength(other_node)
        #print("Signal Strength of node "+str(self.ip)+" is "+str(signal_strength))
        return signal_strength >= signal_strength_threshold
    
    def enable_controller_service(self):
        self.is_controller = True

    def disable_controller_service(self):
        self.is_controller = False

    def enable_ids_service(self):
        self.is_ids = True

    def disable_ids_service(self):
        self.is_ids = False
    
    def select_mprs(self):
        self.mprs = set()
        two_hop_neighbors = set()

        for neighbor in self.neighbors:
            two_hop_neighbors |= set(neighbor.neighbors) - {self}

        uncovered_two_hop_neighbors = two_hop_neighbors.copy()

        while uncovered_two_hop_neighbors:
            best_mpr = None
            best_mpr_covered_neighbors = set()

            for neighbor in self.neighbors:
                if neighbor in self.mprs:
                    continue

                covered_neighbors = (uncovered_two_hop_neighbors & set(neighbor.neighbors)) - {self}
                if len(covered_neighbors) > len(best_mpr_covered_neighbors):
                    best_mpr = neighbor
                    best_mpr_covered_neighbors = covered_neighbors

            self.mprs.add(best_mpr)
            uncovered_two_hop_neighbors -= best_mpr_covered_neighbors
    
    def receive_packet(self, packet):
        packet.received_time = time.time()
        self.received_packets.append(packet)
        self.packets_received_timestamps.append(time.time())  # Add the timestamp to the list
        self.process_packet(packet)
    
    def process_packet(self, packet):
        if self.is_victim and packet.dst_ip == self.ip:
            if packet.packet_type == "UDP":
                # Handle UDP flood attack packet
                self.packet_counter["UDP"] += 1
            elif packet.packet_type == "TCP":
                # Handle regular TCP packet
                self.packet_counter["TCP"] += 1
            elif packet.packet_type == "TCP_SYN":
                # Handle TCP SYN flood attack packet
                self.packet_counter["TCP_SYN"] += 1
            elif packet.packet_type == "ALERT" and self.is_controller:
                self.handle_alert(packet)

    def get_malicious_ip_for_udp_attack(self):
        max_packets = 0
        malicious_ip = None
        for neighbor in self.neighbors:
            if neighbor.is_malicious and neighbor.packet_counter["UDP"] > max_packets:
                max_packets = neighbor.packet_counter["UDP"]
                malicious_ip = neighbor.ip
        return malicious_ip
    
    def get_malicious_ip_for_tcp_syn_attack(self):
        max_packets = 0
        malicious_ip = None
        for neighbor in self.neighbors:
            if neighbor.is_malicious and neighbor.packet_counter["TCP_SYN"] > max_packets:
                max_packets = neighbor.packet_counter["TCP_SYN"]
                malicious_ip = neighbor.ip
        return malicious_ip
    
    @staticmethod
    def extract_malicious_ip_from_payload(payload):
        # Extract the malicious IP from the payload
        match = re.search(r"IP: (\d+\.\d+\.\d+\.\d+)", payload)
        if match:
            return match.group(1)
        return None

    def handle_alert(self, packet):
        malicious_ip = self.extract_malicious_ip_from_payload(packet.payload)  # You'll need to implement this function
        self.malicious_ips.append(malicious_ip)
        self.alerts_received_timestamps.append(time.time())  # Add this line
        self.received_alerts.append(packet)                  # Add this line
        print(f"Controller received alert from node {packet.src_ip}: {packet.payload}")
        # Call the block_malicious_ips function
        self.manet.block_malicious_ips(self.malicious_ips)
        
    def analyze_traffic(self, controller, manet, interval=1):
        # Thresholds for detecting flood attacks
        udp_threshold = 500  # Adjust as needed
        tcp_syn_threshold = 500  # Adjust as needed

        self.udp_attack_packet_count = self.packet_counter["UDP"] // interval
        self.tcp_syn_attack_packet_count = self.packet_counter["TCP_SYN"] // interval

        if self.udp_attack_packet_count > udp_threshold or self.tcp_syn_attack_packet_count > tcp_syn_threshold:
            self.attack_detection_timestamps.append(time.time())  # Add the detection timestamp here
            self.send_alert(controller, manet)

        # Reset packet counters for the next analysis interval
        self.packet_counter["UDP"] = 0
        self.packet_counter["TCP_SYN"] = 0

    def send_packet(self, destination, packet):
        """
        Sends a packet from this node to the destination node.
        :param destination: The destination Node for the packet.
        :param packet: The Packet to be sent.
        :param manet: The MANET object containing the nodes.
        """
        if self.is_malicious and packet.packet_type in ["UDP", "TCP_SYN"]:
            self.attack_start_timestamps.append(time.time())
        packet.sent_time = time.time()
        #Transferring of packet
        path = self.manet.find_shortest_path(self, destination)
        if path:
            # Simulate sending the packet along the path
            for i in range(1, len(path)):
                from_node = path[i - 1]
                to_node = path[i]
                #print(f"Packet sent from {from_node.ip} to {to_node.ip}")
                to_node.receive_packet(packet)
        #else:
            #print(f"No path found from {self.ip} to {destination.ip}")

    def send_alert(self, controller, manet):
        malicious_ips = []

        if self.udp_attack_packet_count > 0:
            malicious_ips.append(self.get_malicious_ip_for_udp_attack())  # You'll need to implement this function
        if self.tcp_syn_attack_packet_count > 0:
            malicious_ips.append(self.get_malicious_ip_for_tcp_syn_attack())  # You'll need to implement this function

        if not malicious_ips:
            return  # No attack detected, do not send an alert

        for malicious_ip in malicious_ips:
            alert_msg = f"Node {self.ip} detected malicious activity from IP: {malicious_ip}"
            packet = Packet(self.ip, controller.ip, alert_msg, packet_type="ALERT", size=256)
            self.sent_alerts.append(packet)
            self.alert_sent_timestamps.append(time.time())
            self.send_packet(controller, packet)

class HeuristicGreedyMitigationOptimizer:
    def __init__(self, network, max_ids_nodes, min_coverage_percentage):
        self.network = network
        self.max_ids_nodes = max_ids_nodes
        self.min_coverage_percentage = min_coverage_percentage

    def run(self):
        best_controller_ip = None
        best_ids_ips = []
        best_total_mitigation_delay = float("inf")

        for controller_node in self.network.nodes:
            for ids_nodes in itertools.combinations(self.network.nodes, self.max_ids_nodes):
                ids_ips = [node.ip for node in ids_nodes]
                if not self.is_coverage_satisfied(ids_nodes):
                    continue

                total_mitigation_delay = self.network.get_total_mitigation_delay(controller_node.ip, ids_ips)
                #print("Mitigation delay of Combination ["+str(controller_node.ip)+","+str(ids_ips)+"]:"+str(total_mitigation_delay))
                if total_mitigation_delay < best_total_mitigation_delay:
                    best_total_mitigation_delay = total_mitigation_delay
                    best_controller_ip = controller_node.ip
                    best_ids_ips = ids_ips

        return best_controller_ip, best_ids_ips, best_total_mitigation_delay
    
    def is_coverage_satisfied(self, ids_nodes):
        ids_ips = {node.ip for node in ids_nodes}
        covered_pairs = set()

        for node1, node2 in itertools.combinations(self.network.nodes, 2):
            if node1.ip in ids_ips or node2.ip in ids_ips:
                covered_pairs.add((node1.ip, node2.ip))
                covered_pairs.add((node2.ip, node1.ip))

        total_pairs = len(self.network.nodes) * (len(self.network.nodes) - 1)
        coverage_percentage = len(covered_pairs) / total_pairs

        return coverage_percentage >= self.min_coverage_percentage

class WeightedHeuristicGreedyMitigationOptimizer:
    def __init__(self, network, max_ids_nodes, min_coverage_percentage):
        self.network = network
        self.max_ids_nodes = max_ids_nodes
        self.min_coverage_percentage = min_coverage_percentage
        self.node_weights = self.create_node_weights()

    def run(self):
        best_controller_ip = None
        best_ids_ips = []
        best_total_mitigation_delay = float("inf")

        for controller_node in self.network.nodes:
            # Update the weight of the controller node to be higher than the others
            self.node_weights[controller_node.ip] *= 2

            for ids_nodes in itertools.combinations(self.network.nodes, self.max_ids_nodes):
                ids_ips = [node.ip for node in ids_nodes]
                if not self.is_coverage_satisfied(ids_nodes):
                    continue

                total_weight = sum(self.node_weights.get(node.ip, 0) for node in ids_nodes)
                total_mitigation_delay = self.network.get_total_mitigation_delay(controller_node.ip, ids_ips)

                if total_mitigation_delay < best_total_mitigation_delay or \
                        (total_mitigation_delay == best_total_mitigation_delay and total_weight > best_total_weight):
                    best_total_weight = total_weight
                    best_total_mitigation_delay = total_mitigation_delay
                    best_controller_ip = controller_node.ip
                    best_ids_ips = ids_ips

            # Reset the weight of the controller node to its original value
            self.node_weights[controller_node.ip] /= 2

        return best_controller_ip, best_ids_ips, best_total_mitigation_delay

    def is_coverage_satisfied(self, ids_nodes):
        ids_ips = set(node.ip for node in ids_nodes)
        covered_pairs = set()

        for node1, node2 in itertools.combinations(self.network.nodes, 2):
            if node1.ip in ids_ips or node2.ip in ids_ips:
                covered_pairs.add((node1.ip, node2.ip))
                covered_pairs.add((node2.ip, node1.ip))

        total_pairs = len(self.network.nodes) * (len(self.network.nodes) - 1)
        coverage_percentage = len(covered_pairs) / total_pairs
        return coverage_percentage >= self.min_coverage_percentage

    def create_node_weights(self):
        node_weights = {}
        for node in self.network.nodes:
            node_weights[node.ip] = 1
        return node_weights


'''
Simulated annealing is a probabilistic optimization algorithm that is inspired by the physical process of annealing in metals. The basic idea is to start with an initial solution and iteratively improve it by randomly perturbing the current solution and accepting or rejecting the perturbation based on a probability function.

The algorithm works as follows:
1. Initialize the current solution x and the temperature T.
2. Repeat until a stopping condition is met:
    a. Generate a new candidate solution x' by randomly perturbing x.
    b. Calculate the change in cost delta_cost between x and x'.
    c. If delta_cost is negative, accept x' as the new solution.
    d. If delta_cost is positive, accept x' as the new solution with probability P = e^(-delta_cost / T).
    e. If delta_cost is zero, accept x' as the new solution.
    f. Reduce the temperature T.
3. Return the best solution found during the search.

The temperature T controls the probability of accepting worse solutions as the search progresses. At high temperatures, the algorithm is more likely to accept worse solutions, while at low temperatures, it becomes more selective and only accepts better solutions. The temperature is reduced over time, usually by a constant factor or according to a cooling schedule.
The algorithm can be tuned by adjusting the temperature schedule, the perturbation function, and the acceptance probability function. It is important to note that simulated annealing is a metaheuristic algorithm and does not guarantee an optimal solution, but it can often find good solutions quickly for a wide range of optimization problems.
'''
class SimulatedAnnealingOptimizer:
    def __init__(self, network, max_ids_nodes, min_coverage_percentage, temperature=1000, cooling_rate=0.03):
        self.network = network
        self.max_ids_nodes = max_ids_nodes
        self.min_coverage_percentage = min_coverage_percentage
        self.temperature = temperature
        self.cooling_rate = cooling_rate

    def run(self):
        current_controller_node = random.choice(self.network.nodes)
        current_ids_nodes = random.sample(self.network.nodes, self.max_ids_nodes)
        current_ids_ips = [node.ip for node in current_ids_nodes]

        best_controller_node = current_controller_node
        best_ids_ips = current_ids_ips
        best_total_mitigation_delay = self.network.get_total_mitigation_delay(current_controller_node.ip, current_ids_ips)

        while self.temperature > 1:
            # Generate a neighbor solution by randomly swapping an IDS node with another node
            neighbor_controller_node = current_controller_node
            neighbor_ids_nodes = current_ids_nodes.copy()
            swap_index = random.randrange(len(current_ids_nodes))
            while neighbor_controller_node in neighbor_ids_nodes:
                neighbor_controller_node = random.choice(self.network.nodes)
            while neighbor_ids_nodes[swap_index] == neighbor_controller_node:
                swap_index = random.randrange(len(current_ids_nodes))
            neighbor_ids_nodes[swap_index] = neighbor_controller_node
            neighbor_ids_ips = [node.ip for node in neighbor_ids_nodes]

            # Calculate the cost of the neighbor solution
            neighbor_total_mitigation_delay = self.network.get_total_mitigation_delay(neighbor_controller_node.ip, neighbor_ids_ips)

            # Determine whether to accept the neighbor solution
            delta = neighbor_total_mitigation_delay - best_total_mitigation_delay
            if delta < 0 or random.uniform(0, 1) < math.exp(-delta / self.temperature):
                current_controller_node = neighbor_controller_node
                current_ids_nodes = neighbor_ids_nodes
                current_ids_ips = neighbor_ids_ips

            # Update the best solution found so far
            current_total_mitigation_delay = self.network.get_total_mitigation_delay(current_controller_node.ip, current_ids_ips)
            if current_total_mitigation_delay < best_total_mitigation_delay:
                best_controller_node = current_controller_node
                best_ids_ips = current_ids_ips
                best_total_mitigation_delay = current_total_mitigation_delay

            # Cool the system
            self.temperature *= 1 - self.cooling_rate

        return best_controller_node.ip, best_ids_ips, best_total_mitigation_delay

    def is_coverage_satisfied(self, ids_nodes):
        ids_ips = set(node.ip for node in ids_nodes)
        covered_pairs = set()

        for node1, node2 in itertools.combinations(self.network.nodes, 2):
            if node1.ip in ids_ips or node2.ip in ids_ips:
                covered_pairs.add((node1.ip, node2.ip))
                covered_pairs.add((node2.ip, node1.ip))

        total_pairs = len(self.network.nodes) * (len(self.network.nodes) - 1)
        coverage_percentage = len(covered_pairs) / total_pairs
        return coverage_percentage >= self.min_coverage_percentage

global convoy_direction
convoy_direction = np.array([1, 0])

def main():
    # Simulation parameters
    random.seed(42)
    num_nodes = 10
    width = 300
    height = 300
    max_ids_nodes = 5
    min_coverage_percentage = 0.7
    update_interval = 1
    move_range = 30
    communication_range = 200
    routing_algorithm = "olsr"

    # For random movement
    network = MANET(num_nodes, width, height, communication_range, initial_movement_type="random", routing_mode=routing_algorithm)
    # For convoy movement
    #network = MANET(num_nodes, width, height, communication_range, initial_movement_type="convoy", routing_mode="olsr")
    # For small teams movement
    #network = MANET(num_nodes, width, height, communication_range, initial_movement_type="small_teams", routing_mode="olsr")
    
    # Initialize a random Controller node
    controller_node = random.choice(network.nodes)
    controller_node.enable_controller_service()
    # Initialize random IDS nodes
    ids_nodes = random.sample(network.nodes, max_ids_nodes)
    for node in ids_nodes:
        node.enable_ids_service()
    
    #Initialize the optimizer
    #optimizer = HeuristicGreedyMitigationOptimizer(network, max_ids_nodes, min_coverage_percentage)
    optimizer = SimulatedAnnealingOptimizer(network, max_ids_nodes, min_coverage_percentage)

    # Plotting setup
    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(16, 8))
    plt.subplots_adjust(bottom=0.3)
    mitigation_delays = []

    movement_type = 'random'  # initial movement type

    def random_movement():
        for node in network.nodes:
            dx = random.uniform(-move_range, move_range)
            dy = random.uniform(-move_range, move_range)
            node.move(dx, dy)

    def convoy_movement(network, move_range, change_direction_interval, current_time):
        # Check if it's time to change the direction of the convoy
        if current_time % change_direction_interval == 0:
            # Update convoy_direction as a class variable or a global variable
            global convoy_direction
            angle = np.random.uniform(-np.pi, np.pi)
            convoy_direction = np.array([np.cos(angle), np.sin(angle)])

        # Move each node in the convoy according to the current direction
        for node in network.nodes:
            dx, dy = convoy_direction * move_range
            node.move(dx, dy)

    def small_teams_movement():
        team_size = 3
        teams = [network.nodes[i:i + team_size] for i in range(0, len(network.nodes), team_size)]

        for team in teams:
            team_direction = np.random.rand(2)
            team_direction /= np.linalg.norm(team_direction)  # normalize direction

            for node in team:
                dx, dy = team_direction * move_range
                node.move(dx, dy)


    def update_plot(frame_number):
        nonlocal network, optimizer, controller_node, ids_nodes, mitigation_delays 
        if not pause:
            # Move the nodes based on the selected movement type
            if movement_type == "random":
                random_movement()
            elif movement_type == "convoy":
                convoy_movement(network, move_range, change_direction_interval=5, current_time=frame_number)
            elif movement_type == "small_teams":
                small_teams_movement()
                pass
            
            # Generate malicious-victim pairs
            num_pairs = 1
            multiple_victims = True  # Set to True for multiple victims per malicious node, False otherwise
            multiple_malicious = True  # Set to True for multiple malicious nodes, False otherwise
            malicious_victim_pairs = network.generate_malicious_victim_pairs(num_pairs, multiple_victims, multiple_malicious)

            print("Malicious-Victim pairs:")
            for i, pair in enumerate(malicious_victim_pairs):
                print(f"Pair {i + 1}: (M: {pair[0].ip}, V: {[victim.ip for victim in pair[1]]})")

            print("\nPaths between Malicious and Victim nodes:")
            for i, (malicious, victims) in enumerate(malicious_victim_pairs):
                print(f"Malicious Node {i + 1}: {malicious.ip}")
                for j, victim in enumerate(victims):
                    path = network.find_shortest_path(malicious, victim)
                    path_ips = [node.ip for node in path] if path else "No path found"
                    print(f"\tVictim {j + 1}: {victim.ip} -> Path: {path_ips}")

            # Move the nodes randomly
            #for node in network.nodes:
            #    dx = random.uniform(-move_range, move_range)
            #    dy = random.uniform(-move_range, move_range)
            #    node.move(dx, dy)

            # Update the connectivity between nodes
            network.update_connectivity()

            # Generate random pairs for normal UDP and TCP traffic
            num_normal_pairs = 2 #number of normal flow pairs.
            normal_udp_pairs = []
            normal_tcp_pairs = []

            for _ in range(num_normal_pairs):
                sender = random.choice(network.nodes)
                receiver = random.choice(network.nodes)
                while sender == receiver:
                    receiver = random.choice(network.nodes)
                normal_udp_pairs.append((sender, receiver))

                sender = random.choice(network.nodes)
                receiver = random.choice(network.nodes)
                while sender == receiver:
                    receiver = random.choice(network.nodes)
                normal_tcp_pairs.append((sender, receiver))
            # Simulate normal UDP and TCP traffic
            network.simulate_normal_udp_traffic(normal_udp_pairs, packet_count=10)
            network.simulate_normal_tcp_traffic(normal_tcp_pairs, packet_count=10)
            
            # Simulate UDP flood attack
            udp_flood_packet_count = 1000  # number of packets per second, much greater than the normal one (i.e., 10)
            network.simulate_udp_flood_attack(malicious_victim_pairs, packet_count=udp_flood_packet_count)

            # Simulate TCP SYN flood attack
            tcp_syn_flood_packet_count = 1000  # number of packets per second, much greater than the normal one (i.e., 10)
            network.simulate_tcp_syn_flood_attack(malicious_victim_pairs, packet_count=tcp_syn_flood_packet_count)
            
            # Monitor and analyze traffic at IDS-enabled nodes
            controller = None
            for node in network.nodes:
                if node.is_controller:
                    controller = node
                    break
            for node in network.nodes:
                if node.is_ids:
                    node.analyze_traffic(controller, network, interval=1)
            
            #!!!!!!!!!!!!!!! Afou exei ginei to implementation gia flood attacks alert ktl, prepei na ginetai kai antistoixa katallhlos ypologismos twn delays.

            # Run the optimizer and update the network
            best_controller_ip, best_ids_ips, best_total_mitigation_delay = optimizer.run()
            network.update_controller_and_ids_nodes(best_controller_ip, best_ids_ips)

            # Update the mitigation delays list
            mitigation_delays.append(best_total_mitigation_delay)
            
            # Print the malicious and victim nodes pair IP addresses
            
            # Print the best controller and IDS nodes IP addresses
            print("Best controller IP:", best_controller_ip)
            print("Best IDS nodes IPs:", best_ids_ips)

            # Print the best total mitigation delay
            print("Best total mitigation delay:", best_total_mitigation_delay)
          
            # Update the mitigation delay plot
            ax1.clear()
            ax1.set_title("Best Total Mitigation Delay vs Time")
            ax1.set_xlabel("Time (simulation frame interval)")
            ax1.set_ylabel("Total Mitigation Delay (ms)")
            ax1.plot(range(len(mitigation_delays)), mitigation_delays, marker="o")
            ax1.set_xlim(0, num_frames)
            ax1.set_ylim(0, max(mitigation_delays) * 1.1)

            # Update the node movement plot
            ax2.clear()
            ax2.set_title("Node Movement")
            ax2.set_xlabel("X")
            ax2.set_ylabel("Y")
            ax2.set_xlim(-400, width+400)
            ax2.set_ylim(-400, height+400)

            if routing_algorithm == "olsr":
                # Draw the OLSR communication links between nodes
                for node in network.nodes:
                    for mpr in node.mprs:
                        ax2.plot([node.x, mpr.x], [node.y, mpr.y], 'k-', alpha=0.5)

                # Draw the links between the controller and IDS nodes
                #for ids_node in ids_nodes:
                #    ax2.plot([controller_node.x, ids_node.x], [controller_node.y, ids_node.y], 'k--', alpha=0.5)
            else:
                # Draw the communication links between nodes
                for node in network.nodes:
                    for neighbor in node.neighbors:
                        ax2.plot([node.x, neighbor.x], [node.y, neighbor.y], 'k-', alpha=0.5)


            for node in network.nodes:
                ax2.plot(node.x, node.y, "bo" if node.is_controller else "go", markersize=17)
                ax2.text(node.x, node.y, str(node.ip), fontsize=12, ha="center", va="center")

                # Draw a circle for each role: controller, IDS, malicious
                circle_radius = 20
                circle_linewidth = 3  # Set the linewidth for circle
                if node.is_ids:
                    ids_circle = Circle((node.x, node.y), circle_radius+15, edgecolor='y', fill=False, linestyle='-', linewidth=circle_linewidth)
                    ax2.add_patch(ids_circle)
                    circle_radius += 10

                if node.is_malicious:
                    malicious_circle = Circle((node.x, node.y), circle_radius, edgecolor='r', fill=False, linestyle='-', linewidth=circle_linewidth)
                    ax2.add_patch(malicious_circle)

                #time.sleep(update_interval)

    def on_pause(event):
        nonlocal pause
        pause = not pause
        if pause:
            pause_button.label.set_text("Play")
        else:
            pause_button.label.set_text("Pause")
        fig.canvas.draw()

    def on_movement_button(label):
        nonlocal movement_type
        movement_type = label

    movement_button_ax = plt.axes([0.30, 0.05, 0.3, 0.15])
    movement_buttons = RadioButtons(movement_button_ax, ['random', 'convoy', 'small_teams'])
    movement_buttons.on_clicked(on_movement_button)

    pause = False
    num_frames = 100
    ani = animation.FuncAnimation(fig, update_plot, frames=num_frames, interval=500, repeat=False)

    pause_button_ax = plt.axes([0.45, 0.05, 0.1, 0.075])
    pause_button = Button(pause_button_ax, 'Pause')
    pause_button.on_clicked(on_pause)

    plt.show()

if __name__ == "__main__":
    main()

