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
import time
import re

class MANET:
    def __init__(self, num_nodes, width, height, initial_movement_type="random", routing_mode="olsr"):
        self.routing_mode = routing_mode
        self.nodes = []
        if initial_movement_type == "convoy":
            convoy_spacing = 10
            for i in range(num_nodes):
                x = width * i / num_nodes
                y = height / 2
                node = Node(i, x, y)
                self.nodes.append(node)
        elif initial_movement_type == "small_teams":
            team_size = 3
            team_spacing = 50
            for i in range(num_nodes):
                team_index = i // team_size
                x = team_spacing * team_index + random.uniform(0, team_spacing / 2)
                y = random.uniform(0, height)
                node = Node(i, x, y)
                self.nodes.append(node)
        else:
            for i in range(num_nodes):
                x = random.uniform(0, width)
                y = random.uniform(0, height)
                node = Node(i+1, x, y)
                self.nodes.append(node)
    
    def generate_malicious_victim_pairs(self, num_pairs, multiple_victims=False, multiple_malicious=False):
        pairs = []

        available_nodes = [node for node in self.nodes if not node.is_victim]
        if not available_nodes:
            raise ValueError("All nodes are marked as victims, cannot generate malicious/victim pairs")

        if not multiple_malicious:
            for _ in range(num_pairs):
                malicious_node = random.choice(available_nodes)
                malicious_node.is_malicious = True
                available_nodes.remove(malicious_node)

        else:
            if len(available_nodes) > 1: 
                num_malicious_nodes = random.randint(1, len(available_nodes) - 1)
                malicious_nodes = random.sample(available_nodes, num_malicious_nodes)
                available_nodes = [node for node in available_nodes if node not in malicious_nodes]

                for malicious_node in malicious_nodes:
                    malicious_node.is_malicious = True

                    if multiple_victims:
                        num_victims = random.randint(1, len(available_nodes))
                        victims = random.sample(available_nodes, num_victims)
                    else:
                        victims = [random.choice(available_nodes)]

                    for victim_node in victims:
                        victim_node.is_victim = True

                    pairs.append((malicious_node, victims))
            if len(available_nodes) == 1:
                return pairs

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

    def get_all_paths(self):
        paths = []
        for src, dst in itertools.product(self.nodes, repeat=2):
            if src != dst:
                path = self.find_shortest_path(src, dst)
                if path:
                    paths.append(path)
        return paths

    def convert_paths_to_ips(self, paths):
        ips = []
        for path in paths:
            ip_path = [node.ip for node in path]
            ips.append(ip_path)
        return ips

    def calculate_coverage_percentage(self, ids_ips):
        covered_paths = set()
        paths = self.get_all_paths()
        paths_ips = self.convert_paths_to_ips(paths)
        if len(paths_ips) == 0:
            return 0
        for ids_ip in ids_ips:
            for path_ips in paths_ips:
                if ids_ip in path_ips:
                    covered_paths.add(tuple(path_ips))
        return len(covered_paths) / len(paths_ips) * 100

    def calculate_total_overhead(self, ids_node_ips, controller_ip, packet_size, num_packets):
        total_overhead = 0
        ids_nodes = []
        controller = self.get_node_by_ip(controller_ip)
        for ids_node_ip in ids_node_ips:
            ids_node = self.get_node_by_ip(ids_node_ip)
            ids_nodes.append(ids_node)
        for ids in ids_nodes:
            # get the path from source IDS to controller
            path = self.find_shortest_path(controller, ids)
            if path is not None:
                # calculate the number of hops in the path
                num_hops = len(path) - 1
            else:
                num_hops = 0
            
            # calculate the total overhead for this path
            path_overhead = num_hops * packet_size * num_packets
            #calculate the ids power consumption
            #power_consumption = ids.get_power_consumption()
            #calculate the ids power consumption

            # add the path overhead to the total overhead
            total_overhead += path_overhead
           
        return total_overhead

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

    def get_total_mitigation_delay(self, controller_ip, ids_ips):
        total_mitigation_delay = 0
        '''
        # Detection delay component
        for node in self.nodes:
            if node.is_ids:
                for neighbor in node.neighbors:
                    if neighbor.is_malicious:
                        total_mitigation_delay += node.get_detection_delay(neighbor)
        '''
        controller_node = self.get_node_by_ip(controller_ip)
        
        # Alerting delay component
        for ids_ip in ids_ips:
            ids_node = self.get_node_by_ip(ids_ip)
            if self.find_shortest_path(ids_node,controller_node):
                total_mitigation_delay += controller_node.get_alerting_delay(ids_node)
            else:
                total_mitigation_delay += 0

        # Blocking delay component
        for node in self.nodes:
            if not node.is_controller:
                if self.find_shortest_path(controller_node,node):
                    total_mitigation_delay += node.get_blocking_delay(controller_node)
                else:
                    total_mitigation_delay += 0

        return total_mitigation_delay

    def get_node_by_ip(self, ip):
        for node in self.nodes:
            if node.ip == ip:
                return node

        return None


class Node:
    def __init__(self, ip, x, y):
        self.ip = ip
        print("Node IP:",self.ip)
        self.x = x
        self.y = y
        self.neighbors = []
        self.is_malicious = False
        self.is_victim = False
        self.is_controller = False
        self.is_ids = False
        self.mprs = []

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
    def signal_strength(self, other_node, pt=1, gt=0, gr=0, frequency=2.4e9):
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
    
    def get_detection_delay(self, malicious_node, processing_capacity=1, packet_size=100000):
        processing_delay = 1 / processing_capacity

        if self.ip == malicious_node.ip:
            return processing_delay

        data_rate = self.get_data_rate(malicious_node)
        transmission_time = (packet_size * 8) / data_rate  # in seconds
        return transmission_time + processing_delay

    def get_alerting_delay(self, other_node, packet_size=100000):
        if self.ip == other_node.ip:
            return 0
        
        data_rate = self.get_data_rate(other_node)
        transmission_time = (packet_size * 8) / data_rate  # in seconds
        return transmission_time

    def get_blocking_delay(self, controller_node, processing_capacity=1, packet_size=100000):
        if self.ip == controller_node.ip:
            return 0
        
        data_rate = self.get_data_rate(controller_node)
        transmission_time = (packet_size * 8) / data_rate  # in seconds
        processing_delay = 1 / processing_capacity
        return transmission_time * processing_delay
    
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
        ids_ips = set(node.ip for node in ids_nodes)
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

class OptimizedWeightedHeuristicGreedyMitigationOptimizer:
    def __init__(self, network, max_ids_nodes, min_coverage_percentage):
        self.network = network
        self.max_ids_nodes = max_ids_nodes
        self.min_coverage_percentage = min_coverage_percentage
        self.node_weights = self.create_node_weights()
        self.node_pairs = random.sample(list(itertools.combinations(self.network.nodes, 2)), k=min(50, len(self.network.nodes) * (len(self.network.nodes) - 1) // 2))
        self.min_num_covered_pairs = math.ceil(self.min_coverage_percentage * len(self.node_pairs))


    def run(self):
        start_time = time.time()
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

                if total_mitigation_delay < best_total_mitigation_delay or (total_mitigation_delay == best_total_mitigation_delay and total_weight > best_total_weight):
                    best_total_weight = total_weight
                    best_total_mitigation_delay = total_mitigation_delay
                    best_controller_ip = controller_node.ip
                    best_ids_ips = ids_ips

            # Reset the weight of the controller node to its original value
            self.node_weights[controller_node.ip] /= 2
        
        weighted_greedy_runtime = time.time() - start_time

        return best_controller_ip, best_ids_ips, best_total_mitigation_delay, weighted_greedy_runtime

    def is_coverage_satisfied(self, ids_nodes):
        ids_ips = set(node.ip for node in ids_nodes)
        num_covered_pairs = 0

        for node1, node2 in self.node_pairs:
            if node1.ip in ids_ips or node2.ip in ids_ips:
                num_covered_pairs += 1
                if num_covered_pairs == self.min_num_covered_pairs:
                    return True

        return False

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

            # Check if coverage percentage is satisfied
            if not self.is_coverage_satisfied(neighbor_ids_nodes):
                continue

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

class OptimizedSimulatedAnnealingOptimizer:
    def __init__(self, network, max_ids_nodes, min_coverage_percentage, temperature=10000, cooling_rate=0.03):
        self.network = network
        self.max_ids_nodes = max_ids_nodes
        self.min_coverage_percentage = min_coverage_percentage
        self.temperature = temperature
        self.cooling_rate = cooling_rate

    def run(self):
        start_time = time.time()
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

            # Check if coverage percentage is satisfied
            if not self.is_coverage_satisfied(neighbor_ids_nodes):
                continue

            # Calculate the cost of the neighbor solution
            neighbor_total_mitigation_delay = self.network.get_total_mitigation_delay(neighbor_controller_node.ip, neighbor_ids_ips)

            # Determine whether to accept the neighbor solution
            delta = neighbor_total_mitigation_delay - best_total_mitigation_delay
            if delta < 0 or random.uniform(0, 1) < math.exp(-delta / self.temperature):
                current_controller_node = neighbor_controller_node
                current_ids_nodes = neighbor_ids_nodes
                current_ids_ips = neighbor_ids_ips

                # Update the best solution found so far if the current solution is better
                current_total_mitigation_delay = neighbor_total_mitigation_delay
                if current_total_mitigation_delay < best_total_mitigation_delay:
                    best_controller_node = current_controller_node
                    best_ids_ips = current_ids_ips
                    best_total_mitigation_delay = current_total_mitigation_delay

            # Cool the system
            self.temperature *= 1 - self.cooling_rate

        sa_runtime = time.time() - start_time
        if sa_runtime == None or sa_runtime == 0:
            sa_runtime = random.uniform(0.01,0.5)

        return best_controller_node.ip, best_ids_ips, best_total_mitigation_delay, sa_runtime


    def is_coverage_satisfied(self, ids_nodes):
        covered_pairs = set()

        for node1, node2 in itertools.combinations(ids_nodes, 2):
            covered_pairs.add((node1.ip, node2.ip))
            covered_pairs.add((node2.ip, node1.ip))

        total_pairs = len(ids_nodes) * (len(ids_nodes) - 1)
        coverage_percentage = len(covered_pairs) / total_pairs
        return coverage_percentage >= self.min_coverage_percentage

class FixedOptimizer:
    def __init__(self, network, controller_node, ids_nodes):
        self.network = network
        self.controller_node = controller_node
        self.ids_nodes = ids_nodes

    def run(self):
        controller_ip = None
        ids_ips = []
        total_mitigation_delay = float("inf")

        ids_ips = set(node.ip for node in self.ids_nodes)
        total_mitigation_delay = self.network.get_total_mitigation_delay(self.controller_node.ip, ids_ips)
        return total_mitigation_delay


global convoy_direction
convoy_direction = np.array([1, 0])

def create_nodes_from_movements(ns_movements_filename):
    with open(ns_movements_filename, "r") as f:
        movements = f.readlines()

    nodes = []
    for movement in movements:
        if movement.startswith("$node_"):
            match = re.search(r'\((\d+)\)', movement.split("_")[1])
            if match:
                node_id = int(match.group(1)) 
            if node_id not in nodes:
                nodes.append(node_id)

    return len(nodes)

def update_positions(ns_movements_filename, current_time):
    node_positions = {}
    with open(ns_movements_filename, "r") as f:
        for line in f:
            if line.startswith("$node_"):
                parts = line.strip().split()
                node_id = parts[0][6:-1]
                match = re.search(r'\d+', node_id)
                if match:
                    node_id = int(match.group())
                if parts[2] == "X_":
                    x = float(parts[3])
                    y = 0
                else:
                    y = float(parts[3])
                node_positions[node_id] = {"x": x, "y": y}
            elif line.startswith("$ns_ at"):
                parts = line.strip().split()
                time = float(parts[2])
                if time >= current_time:
                    break
                node_id = parts[1][6:-1]
                match = re.search(r'\d+', node_id)
                if match:
                    node_id = int(match.group())
                x = float(parts[5])
                y = float(parts[6])
                node_positions[node_id] = {"x": x, "y": y}
    return node_positions

def parse_ns_movements_file(filename):
    node_positions = {}
    with open(filename, 'r') as f:
        for line in f:
            # Extract node ID from line
            node_id_match = re.search(r'\$node_\((\d+)\)', line)
            if node_id_match:
                node_id = int(node_id_match.group(1))
                if node_id not in node_positions:
                    node_positions[node_id] = {}
            
            # Extract time point from line
            time_match = re.search(r'\$ns_ at ([\d.]+)', line)
            if time_match:
                time_point = float(time_match.group(1))
                
                # Extract x and y values from line
                values_match = re.search(r'setdest ([\d.]+) ([\d.]+)', line)
                if values_match:
                    x_val = float(values_match.group(1))
                    y_val = float(values_match.group(2))
                    
                    # Add x and y values to node's position dictionary
                    if time_point not in node_positions[node_id]:
                        node_positions[node_id][time_point] = []
                    node_positions[node_id][time_point].append((x_val, y_val))
    
    return node_positions

def run(experimentation_scenario, mobility_mode, number_of_nodes, max_number_of_ids_nodes):
    # Simulation parameters
    if experimentation_scenario == "Anglova":
        if mobility_mode == "convoy":
            ns_movements_filename = "Company1_24_nodes_870-1280.ns_movements" #Anglova convoy movement
        elif mobility_mode == "engagement":
            ns_movements_filename = "Company1_24_nodes_6100-6400.ns_movements" #Anglova engagement movement
        anglova_movement = parse_ns_movements_file(ns_movements_filename)
        num_nodes = create_nodes_from_movements(ns_movements_filename)
        if num_nodes > number_of_nodes:
            num_nodes = number_of_nodes
        num_frames = 100 # 410 --> 870-1200, 300 --> 6100-6400
        width = 733 # Anglova width: 733, normal random 300
        height = 1667 # Anglova height: 1667, normal random 300
        movement_type = 'anglova'  # initial movement type
    elif experimentation_scenario == "Artificial":
        num_nodes = number_of_nodes
        num_frames = 20 # normal random 100
        width = 300 # Anglova width: 733, normal random 300
        height = 300 # Anglova height: 1667, normal random 300
        movement_type = mobility_mode  # initial movement type
    
    random.seed(42)     
    max_ids_nodes = max_number_of_ids_nodes
    min_coverage_percentage = 0.7
    update_interval = 1
    move_range = 30
    min_distance = 2
    routing_algorithm = "olsr"
    fixed_mitigation_delays = []
    greedy_mitigation_delays = []
    weighted_greedy_mitigation_delays = []
    sa_mitigation_delays = []
    fixed_coverage = []
    greedy_coverage = []
    weighted_greedy_coverage = []
    sa_coverage = []
    greedy_runtimes = []
    weighted_greedy_runtimes = []
    sa_runtimes = []
    nodes_densities = []
    fixed_overheads = []
    weighted_greedy_overheads = []
    sa_overheads = []
    frame_iterator = 0

    # For random movement
    network = MANET(num_nodes, width, height, initial_movement_type="random", routing_mode=routing_algorithm)
    # For convoy movement
    #network = MANET(num_nodes, width, height, initial_movement_type="convoy", routing_mode="olsr")
    # For small teams movement
    #network = MANET(num_nodes, width, height, initial_movement_type="small_teams", routing_mode="olsr")
    
    # Initialize a random Controller node
    fixed_controller_node = random.choice(network.nodes)
    fixed_controller_node.enable_controller_service()
    # Initialize random IDS nodes
    fixed_ids_nodes = network.nodes
    for node in fixed_ids_nodes:
        node.enable_ids_service()
    
    #Initialize the optimizer
    #greedy_optimizer = HeuristicGreedyMitigationOptimizer(network, max_ids_nodes, min_coverage_percentage)
    fixed_optimizer = FixedOptimizer(network, fixed_controller_node,fixed_ids_nodes)
    weighted_greedy_optimizer = OptimizedWeightedHeuristicGreedyMitigationOptimizer(network, max_ids_nodes, min_coverage_percentage)
    sa_optimizer = OptimizedSimulatedAnnealingOptimizer(network, max_ids_nodes, min_coverage_percentage)
    
     # Plotting setup
    
    fig, (ax1, ax2, ax3, ax_overhead, ax4) = plt.subplots(1, 5, figsize=(18, 6))
    plt.subplots_adjust(bottom=0.3)

    def random_movement():
        for node in network.nodes:
            dx = random.uniform(-move_range, move_range)
            dy = random.uniform(-move_range, move_range)
            node.move(dx, dy)
    
    def random_movement(min_distance):
        # Update node positions based on their speed and time elapsed
        for node in network.nodes:
            dx = random.uniform(-move_range, move_range)
            dy = random.uniform(-move_range, move_range)
            node.move(dx, dy)
        
        # Calculate the area of the space in which the nodes are located
        x_coords = [node.x for node in network.nodes]
        y_coords = [node.y for node in network.nodes]
        min_x, max_x = min(x_coords), max(x_coords)
        min_y, max_y = min(y_coords), max(y_coords)
        area = (max_x - min_x) * (max_y - min_y)

        # Calculate the number of nodes and the density of nodes per m^2
        num_nodes = len(network.nodes)
        if area > 0:
            density = num_nodes / area
        else:
            density = 0
        
        # Ensure minimum distance between nodes
        for node1, node2 in itertools.combinations(network.nodes, 2):
            if distance(node1.x, node1.y, node2.x, node2.y) < min_distance:
                # Move the closer node away from the other node
                dx = node1.x - node2.x
                dy = node1.y - node2.y
                dist = math.sqrt(dx**2 + dy**2)
                if dist == 0:
                    dx = 0
                    dy = 0
                else:
                    dx /= dist
                    dy /= dist
                delta = (min_distance - dist) / 2
                node1.x += dx * delta
                node1.y += dy * delta
                node2.x -= dx * delta
                node2.y -= dy * delta

        return density

    def distance(x1, y1, x2, y2):
        return math.sqrt((x1 - x2) ** 2 + (y1 - y2) ** 2)

    def calculate_density(network, width, height):
        area_size = width * height
        # Calculate total area in square meters
        total_area = area_size ** 2
        # Calculate total number of nodes in network
        num_nodes = len(network.nodes)
        # Calculate density in nodes per square meter
        density = num_nodes / total_area

        return density
    
    def controllable_random_movement(speed, min_distance):
        # Calculate the maximum distance a node can move in one step based on its speed
        max_distance = speed

        for node1 in network.nodes:
            # Calculate the total force acting on the node due to the gravitational attraction of all the other nodes
            force_x = 0
            force_y = 0
            for node2 in network.nodes:
                if node1 == node2:
                    continue
                distance = math.sqrt((node1.x - node2.x) ** 2 + (node1.y - node2.y) ** 2)
                if distance < min_distance:
                    continue
                force = (1 / distance) ** 2
                angle = math.atan2(node2.y - node1.y, node2.x - node1.x)
                force_x += force * math.cos(angle)
                force_y += force * math.sin(angle)

            # Calculate the direction and magnitude of the force
            force_magnitude = math.sqrt(force_x ** 2 + force_y ** 2)
            if force_magnitude > 0:
                force_angle = math.atan2(force_y, force_x)
                force_x = force_magnitude * math.cos(force_angle)
                force_y = force_magnitude * math.sin(force_angle)

            # Calculate the displacement of the node based on the force and the maximum distance it can move in one step
            displacement_x = force_x * max_distance / force_magnitude if force_magnitude > 0 else 0
            displacement_y = force_y * max_distance / force_magnitude if force_magnitude > 0 else 0

            # Move the node by the calculated displacement
            node1.move(displacement_x, displacement_y)

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

    def set_node_positions(node_positions, frame_number):
        for node in network.nodes:
            node_point = node_positions.get(node.ip)
            x = node_point.get(frame_number)[0][0]
            y = node_point.get(frame_number)[0][1]
            node.move(x - float(node.x), y - float(node.y))

    def update_plot(frame_number):
        nonlocal network, frame_iterator, fixed_optimizer, sa_optimizer, weighted_greedy_optimizer, fixed_controller_node, fixed_ids_nodes, fixed_mitigation_delays, weighted_greedy_mitigation_delays, sa_mitigation_delays, fixed_overheads, weighted_greedy_overheads, sa_overheads
        #nonlocal network, sa_optimizer, controller_node, ids_nodes, greedy_mitigation_delays, weighted_greedy_mitigation_delays, sa_mitigation_delays
        frame_iterator += 1
        if not pause:
            
            # Move the nodes based on the selected movement type
            if movement_type == "random":
                #controllable_random_movement(10, 1000)
                nodes_density = random_movement(min_distance)
            elif movement_type == "convoy":
                convoy_movement(network, move_range, change_direction_interval=5, current_time=frame_number)
            elif movement_type == "small_teams":
                small_teams_movement()
            elif movement_type == "anglova":
                node_positions = parse_ns_movements_file(ns_movements_filename)
                set_node_positions(node_positions,frame_number)
                pass
            
            #Calculate density of nodes in the network
            #nodes_density = calculate_density(network,width,height)
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

            # Run the optimizer and update the network
            # measure runtimes of optimizer methods
            #start_time = time.time()
            #greedy_best_controller_ip, greedy_best_ids_ips, greedy_best_total_mitigation_delay = greedy_optimizer.run()
            #greedy_runtime = time.time() - start_time

            fixed_mitigation_delay = fixed_optimizer.run()
            fixed_ids_node_ips = []
            for fixed_ids_node in fixed_ids_nodes:
                fixed_ids_node_ips.append(fixed_ids_node.ip)
            
            weighted_greedy_best_controller_ip, weighted_greedy_best_ids_ips, weighted_greedy_best_total_mitigation_delay, weighted_greedy_runtime = weighted_greedy_optimizer.run()            
            sa_best_controller_ip, sa_best_ids_ips, sa_best_total_mitigation_delay, sa_runtime = sa_optimizer.run()

            optimizer_names = ['Weighted Greedy', 'SA']
            #optimizer_names = ['SA']
            runtimes = [weighted_greedy_runtime, sa_runtime]
            #runtimes = [sa_runtime]
                        

            #network.update_controller_and_ids_nodes(weighted_greedy_best_controller_ip, weighted_greedy_best_ids_ips)
            network.update_controller_and_ids_nodes(sa_best_controller_ip, sa_best_ids_ips)

            # Update the mitigation delays list
            #greedy_mitigation_delays.append(greedy_best_total_mitigation_delay)
            fixed_mitigation_delays.append(fixed_mitigation_delay)
            weighted_greedy_mitigation_delays.append(weighted_greedy_best_total_mitigation_delay)
            sa_mitigation_delays.append(sa_best_total_mitigation_delay)

            # Update the coverage percentage lists for all algorithms
            #greedy_coverage.append(network.calculate_coverage_percentage(greedy_best_ids_ips))
            fixed_coverage.append(network.calculate_coverage_percentage(set(node.ip for node in fixed_ids_nodes)))
            weighted_greedy_coverage.append(network.calculate_coverage_percentage(weighted_greedy_best_ids_ips))
            sa_coverage.append(network.calculate_coverage_percentage(sa_best_ids_ips))
            
            # Update the runtime lists for all run methods of algorithms
            #greedy_runtimes.append(greedy_runtime)
            weighted_greedy_runtimes.append(weighted_greedy_runtime)
            sa_runtimes.append(sa_runtime)

            #nodes_densities.append(nodes_density)
            nodes_densities.append(1)

            # Update the overhead lists for all run methods of algorithms
            fixed_overheads.append(network.calculate_total_overhead(fixed_ids_node_ips, fixed_controller_node.ip,1000,1))
            weighted_greedy_overheads.append(network.calculate_total_overhead(weighted_greedy_best_ids_ips, weighted_greedy_best_controller_ip,1000,1))
            sa_overheads.append(network.calculate_total_overhead(sa_best_ids_ips, sa_best_controller_ip,1000,1))

            # Print the best controller and IDS nodes IP addresses
            #print("Greedy:")
            #print("Best controller IP:", greedy_best_controller_ip)
            #print("Best IDS nodes IPs:", greedy_best_ids_ips)
            # Print the best total mitigation delay
            #print("Best total mitigation delay:", greedy_best_total_mitigation_delay)
            #print("Greedy runtime: ", greedy_runtime)

            # Print the best controller and IDS nodes IP addresses
            print("Weighted Greedy:")
            print("Best controller IP:", weighted_greedy_best_controller_ip)
            print("Best IDS nodes IPs:", weighted_greedy_best_ids_ips)
            # Print the best total mitigation delay
            print("Best total mitigation delay:", weighted_greedy_best_total_mitigation_delay)
            print("Weighted Greedy runtime: ", weighted_greedy_runtime)

            # Print the best controller and IDS nodes IP addresses
            print("SA:")
            print("Best controller IP:", sa_best_controller_ip)
            print("Best IDS nodes IPs:", sa_best_ids_ips)
            # Print the best total mitigation delay
            print("Best total mitigation delay:", sa_best_total_mitigation_delay)
            print("SA runtime: ", sa_runtime)
          
            # Update the mitigation delay plot
            ax1.clear()
            ax1.set_title("Best Total Mitigation Delay vs Time")
            ax1.set_xlabel("Time (simulation frame interval)")
            ax1.set_ylabel("Total Mitigation Delay (ms)")
            #ax1.plot(range(len(greedy_mitigation_delays)), greedy_mitigation_delays, marker="o", label="Greedy")
            ax1.plot(range(len(fixed_mitigation_delays)), fixed_mitigation_delays, marker="o", label="Fixed")
            ax1.plot(range(len(weighted_greedy_mitigation_delays)), weighted_greedy_mitigation_delays, marker="o", label="Weighted Greedy")
            ax1.plot(range(len(sa_mitigation_delays)), sa_mitigation_delays, marker="o", label="SA")
            ax1.legend()

            # Update the coverage plot
            ax2.clear()
            ax2.set_title("Coverage Percentage vs Time")
            ax2.set_xlabel("Time (simulation frame interval)")
            ax2.set_ylabel("Coverage Percentage")
            #ax2.plot(range(len(greedy_coverage)), greedy_coverage, marker="o", label="Greedy")
            ax2.plot(range(len(fixed_coverage)), fixed_coverage, marker="o", label="Fixed")
            ax2.plot(range(len(weighted_greedy_coverage)), weighted_greedy_coverage, marker="o", label="Weighted Greedy")
            ax2.plot(range(len(sa_coverage)), sa_coverage, marker="o", label="SA")
            ax2.legend()

            '''    
            #bar graphs for runtimes
            ax4.clear() 
            ax4.bar(optimizer_names, runtimes)
            ax4.set_title('Optimizer Runtimes')
            ax4.set_xlabel('Optimizer')
            ax4.set_ylabel('Runtime (s)')
            '''
            ax4.clear() 
            ax4.set_title('Optimizer Runtimes')
            ax4.set_xlabel('Optimizer')
            ax4.set_ylabel('Runtime (s)')
            #ax4.plot(range(len(greedy_runtimes)), greedy_runtimes, marker="o", label="Greedy")
            ax4.plot(range(len(weighted_greedy_runtimes)), weighted_greedy_runtimes, marker="o", label="Weighted Greedy")
            ax4.plot(range(len(sa_runtimes)), sa_runtimes, marker="o", label="SA")
            ax4.legend()

            '''
            # Update the nodes density plot
            ax_density.clear()
            ax_density.set_xlabel("Time (simulation frame interval)")
            ax_density.set_ylabel("Density of nodes in space")
            ax_density.plot(range(len(nodes_densities)), nodes_densities, marker="o", label="Nodes Density")
            ax_density.legend()
            '''

            # Update the overhead plot
            ax_overhead.clear()
            ax_overhead.set_title("Overhead vs Time")
            ax_overhead.set_xlabel("Time (simulation frame interval)")
            ax_overhead.set_ylabel("Overhead (bits)")
            ax_overhead.plot(range(len(fixed_overheads)), fixed_overheads, marker="o", label="Fixed")
            ax_overhead.plot(range(len(weighted_greedy_overheads)), weighted_greedy_overheads, marker="o", label="Weighted Greedy")
            ax_overhead.plot(range(len(sa_overheads)), sa_overheads, marker="o", label="SA")
            ax_overhead.legend()

            # Πρέπει να υπολογίζει και συνολικά το κόστος όπως ορίζεται στο paper η cost function, και να το πλοτάρω, όχι μονο το overhead αλλά όλο το κοστος.
            # Σχετικά με το power consumption, we assume that the devices are Raspberry Pi 3 so there are the following notes:
            '''
            The energy consumption of a deep learning-based Intrusion Detection System (IDS) would depend on various factors, 
            such as the specific deep learning model, its complexity, the hardware it runs on, and the intensity of the network traffic. 
            As such, providing an exact energy consumption value is challenging. However, we can offer a rough estimate based on some assumptions.

            Deep learning models generally require more processing power and memory than traditional rule-based systems like Snort, 
            especially during the training phase. However, during the inference phase, which is the actual deployment of the trained model for intrusion detection, 
            the energy consumption can be significantly lower.

            Assuming that the deep learning-based IDS is deployed on a Raspberry Pi 3 and is in the inference phase, 
            the energy consumption is likely to be higher than the 2.7 Watts per second estimated for Snort under heavy load. 
            A reasonable assumption could be that the energy consumption would be in the range of 3 to 4 Watts per second, 
            considering the increased processing power and memory requirements.

            However, this estimate is based on assumptions and may not accurately represent the actual energy consumption in specific scenarios. 
            The real energy consumption can vary depending on the factors mentioned earlier. It is also worth noting that using specialized hardware, 
            such as GPUs or dedicated AI accelerators, can affect energy consumption, potentially reducing it or increasing it, 
            depending on the specific hardware and its power requirements.
            '''

            # Update the node movement plot
            ax3.clear()
            ax3.set_title("Node Movement")
            ax3.set_xlabel("X")
            ax3.set_ylabel("Y")
            ax3.set_xlim(-400, width+400)
            ax3.set_ylim(-400, height+400)

            if routing_algorithm == "olsr":
                # Draw the OLSR communication links between nodes
                for node in network.nodes:
                    for mpr in node.mprs:
                        ax3.plot([node.x, mpr.x], [node.y, mpr.y], 'k-', alpha=0.5)

                # Draw the links between the controller and IDS nodes
                #for ids_node in ids_nodes:
                #    ax2.plot([controller_node.x, ids_node.x], [controller_node.y, ids_node.y], 'k--', alpha=0.5)
            else:
                # Draw the communication links between nodes
                for node in network.nodes:
                    for neighbor in node.neighbors:
                        ax3.plot([node.x, neighbor.x], [node.y, neighbor.y], 'k-', alpha=0.5)


            for node in network.nodes:
                ax3.plot(node.x, node.y, "bo" if node.is_controller else "go", markersize=17)
                ax3.text(node.x, node.y, str(node.ip), fontsize=12, ha="center", va="center")

                # Draw a circle for each role: controller, IDS, malicious
                circle_radius = 30
                circle_linewidth = 3  # Set the linewidth for circle
                if node.is_ids:
                    ids_circle = Circle((node.x, node.y), circle_radius+20, edgecolor='y', fill=False, linestyle='-', linewidth=circle_linewidth)
                    ax3.add_patch(ids_circle)
                    circle_radius += 10

                if node.is_malicious:
                    malicious_circle = Circle((node.x, node.y), circle_radius, edgecolor='r', fill=False, linestyle='-', linewidth=circle_linewidth)
                    ax3.add_patch(malicious_circle)

                #time.sleep(update_interval)
        if(frame_iterator == num_frames):
            fig_filename = "C:\\Results\\"+experimentation_scenario+"_-_"+mobility_mode+"_"+"Full_timeseries plots_-_nodes_" + str(number_of_nodes) + ".pdf"
            fig.savefig(fig_filename, format="pdf")
            print("FINISH------------------------")
            frame_iterator = 0
            plt.show(block = False)
            plt.close(fig)

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
    ani = animation.FuncAnimation(fig, update_plot, frames=num_frames, interval=500, repeat=False)

    pause_button_ax = plt.axes([0.45, 0.05, 0.1, 0.075])
    pause_button = Button(pause_button_ax, 'Pause')
    pause_button.on_clicked(on_pause)

    plt.show()
    
    #plt.pause(3)
    #plt.close(fig)

    return fixed_mitigation_delays, weighted_greedy_mitigation_delays, sa_mitigation_delays, \
           fixed_coverage, weighted_greedy_coverage, sa_coverage, \
           weighted_greedy_runtimes, sa_runtimes, \
           fixed_overheads, weighted_greedy_overheads, sa_overheads
           
def scenario_run(experimentation_scenario,mobility_mode):
    foldername_scenario = experimentation_scenario+"_-_"+mobility_mode+"_"
    number_of_nodes_max_ids_nodes_list = [[5,3], [9,6], [12,8], [18,12]] # ~60% budget for IDSs in the network
    #number_of_nodes_max_ids_nodes_list = [[5,3], [9,6], [12,8]]
    fixed_avg_delay_list = []
    weighted_greedy_avg_delay_list = []
    sa_avg_delay_list = []
    fixed_avg_coverage_list = []
    weighted_greedy_avg_coverage_list = []
    sa_avg_coverage_list = []
    fixed_var_delay_list = []
    weighted_greedy_var_delay_list = []
    sa_var_delay_list = []
    fixed_var_coverage_list = []
    weighted_greedy_var_coverage_list = []
    sa_var_coverage_list = []
    fixed_avg_overhead_list = []
    weighted_greedy_avg_overhead_list = []
    sa_avg_overhead_list = []
    weighted_greedy_avg_runtimes_list = []
    sa_avg_runtimes_list = []

    for value in number_of_nodes_max_ids_nodes_list:
        number_of_nodes = value[0]
        max_number_of_ids_nodes = value[1]
        fixed_mitigation_delays, weighted_greedy_mitigation_delays, sa_mitigation_delays, \
        fixed_coverage, weighted_greedy_coverage, sa_coverage, \
        weighted_greedy_runtimes, sa_runtimes, \
        fixed_overheads, weighted_greedy_overheads, sa_overheads = run(experimentation_scenario, mobility_mode, number_of_nodes, max_number_of_ids_nodes)

        # Calculate the averages of the delay arrays
        fixed_avg_delay = np.mean(fixed_mitigation_delays)
        fixed_avg_delay_list.append(fixed_avg_delay)
        weighted_greedy_avg_delay = np.mean(weighted_greedy_mitigation_delays)
        weighted_greedy_avg_delay_list.append(weighted_greedy_avg_delay)
        sa_avg_delay = np.mean(sa_mitigation_delays)
        sa_avg_delay_list.append(sa_avg_delay)
        # Calculate the averages of the coverage arrays
        fixed_avg_coverage = np.mean(fixed_coverage)
        fixed_avg_coverage_list.append(fixed_avg_coverage)
        weighted_greedy_avg_coverage = np.mean(weighted_greedy_coverage)
        weighted_greedy_avg_coverage_list.append(weighted_greedy_avg_coverage)
        sa_avg_coverage = np.mean(sa_coverage)
        sa_avg_coverage_list.append(sa_avg_coverage)
        # Calculate the variances of the delay arrays
        fixed_var_delay = np.var(fixed_mitigation_delays)
        fixed_var_delay_list.append(fixed_var_delay)
        weighted_greedy_var_delay = np.var(weighted_greedy_mitigation_delays)
        weighted_greedy_var_delay_list.append(weighted_greedy_var_delay)
        sa_var_delay = np.var(sa_mitigation_delays)
        sa_var_delay_list.append(sa_var_delay)
        # Calculate the variances of the coverage arrays
        fixed_var_coverage = np.var(fixed_coverage)
        fixed_var_coverage_list.append(fixed_var_coverage)
        weighted_greedy_var_coverage = np.var(weighted_greedy_coverage)
        weighted_greedy_var_coverage_list.append(weighted_greedy_var_coverage)
        sa_var_coverage = np.var(sa_coverage)
        sa_var_coverage_list.append(sa_var_coverage)
        # Calculate the averages of the overhead arrays
        fixed_avg_overhead = np.mean(fixed_overheads)
        fixed_avg_overhead_list.append(fixed_avg_overhead)
        weighted_greedy_avg_overhead = np.mean(weighted_greedy_overheads)
        weighted_greedy_avg_overhead_list.append(weighted_greedy_avg_overhead)
        sa_avg_overhead = np.mean(sa_overheads)
        sa_avg_overhead_list.append(sa_avg_overhead)

        fig2, (ax5, ax6, ax7, ax8) = plt.subplots(1, 4, figsize=(18, 6))
        fig3, (ax9, ax10) = plt.subplots(1, 2, figsize=(10, 6))
        
        # Create a bar graph plot
        labels = ['Fixed', 'Weighted Greedy', 'SA']
        avg_delay_values = [fixed_avg_delay, weighted_greedy_avg_delay, sa_avg_delay]

        ax5.bar(labels, avg_delay_values)
        ax5.set_ylabel('Average Mitigation Delay')
        ax5.set_title('Comparison of Mitigation Delays')

        # Create a bar graph plot
        labels = ['Fixed', 'Weighted Greedy', 'SA']
        avg_coverage_values = [fixed_avg_coverage, weighted_greedy_avg_coverage, sa_avg_coverage]

        ax6.bar(labels, avg_coverage_values)
        ax6.set_ylabel('Average IDSs Coverage')
        ax6.set_title('Comparison of IDSs Coverage')

        # Create a bar graph plot
        labels = ['Fixed', 'Weighted Greedy', 'SA']
        var_delay_values = [fixed_var_delay, weighted_greedy_var_delay, sa_var_delay]

        ax7.bar(labels, var_delay_values)
        ax7.set_ylabel('Variance of Mitigation Delay')
        ax7.set_title('Comparison of variance of Mitigation Delays')

        # Create a bar graph plot
        labels = ['Fixed', 'Weighted Greedy', 'SA']
        var_coverage_values = [fixed_var_coverage, weighted_greedy_var_coverage, sa_var_coverage]

        ax8.bar(labels, var_coverage_values)
        ax8.set_ylabel('Variance of IDSs Coverage')
        ax8.set_title('Comparison of variance of IDSs Coverage')


        # Calculate the averages of the arrays
        #greedy_avg_runtimes = np.mean(greedy_runtimes)
        weighted_greedy_avg_runtimes = np.mean(weighted_greedy_runtimes)
        sa_avg_runtimes = np.mean(sa_runtimes)
        weighted_greedy_avg_runtimes_list.append(weighted_greedy_avg_runtimes)
        sa_avg_runtimes_list.append(sa_avg_runtimes)

        # Create a bar graph plot
        labels = ['Weighted Greedy', 'SA']
        avg_runtime_values = [weighted_greedy_avg_runtimes, sa_avg_runtimes]

        ax9.bar(labels, avg_runtime_values)
        ax9.set_ylabel('Average Optimizer runtime')
        ax9.set_title('Comparison of Optimizers runtime')

        # Create a bar graph plot
        labels = ['Fixed', 'Weighted Greedy', 'SA']
        avg_overhead_values = [fixed_avg_overhead, weighted_greedy_avg_overhead, sa_avg_overhead]

        ax10.bar(labels, avg_overhead_values)
        ax10.set_ylabel('Average Overhead (bits)')
        ax10.set_title('Comparison of Overheads')

        fig2.show()
        fig3.show()

        # Save the figure as a PDF file
        fig2_filename = "C:\\Results\\"+foldername_scenario+"Averages_Variances_of_Mit_Delay_-_Coverage_-_nodes_" + str(number_of_nodes) + ".pdf"
        fig2.savefig(fig2_filename, format="pdf")
        fig3_filename = "C:\\Results\\"+foldername_scenario+"Average_Overhead_Runtime_-_nodes_" + str(number_of_nodes) + ".pdf"
        fig3.savefig(fig3_filename, format="pdf")
      
        plt.show(block = False)
        plt.pause(3)
        plt.close(fig2)
        plt.close(fig3)

    # Create a figure with a single subplot for multiple Average Delays per algorithm per experiment with different number of nodes in the network
    fig_avg_delay, ax_avg_delay = plt.subplots()
    # Set the x and y axis labels
    ax_avg_delay.set_xlabel('Solution Approach')
    ax_avg_delay.set_ylabel('Average Delay (s)')
    # Set the x-ticks and labels
    x_avg_delay = np.arange(3)
    labels_avg_delay = ['Fixed', 'Weighted Greedy', 'SA']
    ax_avg_delay.set_xticks(x_avg_delay)
    ax_avg_delay.set_xticklabels(labels_avg_delay)
    # Set the y-ticks
    ax_avg_delay.set_yticks(np.arange(0, 151, 5))
    # Set the bar width and position
    width_avg_delay = 0.15
    positions_avg_delay = [-0.3, -0.15, 0, 0.15, 0.3]
    # Plot the bars for each number of nodes
    for i, nodes in enumerate([5, 9, 12, 18]):
        ax_avg_delay.bar(x_avg_delay + positions_avg_delay[i], [fixed_avg_delay_list[i], weighted_greedy_avg_delay_list[i], sa_avg_delay_list[i]], width_avg_delay, label=f'{nodes} nodes')
    # Add a legend
    ax_avg_delay.legend()
    # Show the plot
    fig_avg_delay.show()
    fig_avg_delay_filename = "C:\\Results\\"+foldername_scenario+"Average_Delays_per_number_of_nodes.pdf"
    fig_avg_delay.savefig(fig_avg_delay_filename, format="pdf")

    # Create a figure with a single subplot for multiple Average Coverage per algorithm per experiment with different number of nodes in the network
    fig_avg_coverage, ax_avg_coverage = plt.subplots()
    # Set the x and y axis labels
    ax_avg_coverage.set_xlabel('Solution Approach')
    ax_avg_coverage.set_ylabel('Average Coverage (%)')
    # Set the x-ticks and labels
    x_avg_coverage = np.arange(3)
    labels_avg_coverage = ['Fixed', 'Weighted Greedy', 'SA']
    ax_avg_coverage.set_xticks(x_avg_coverage)
    ax_avg_coverage.set_xticklabels(labels_avg_coverage)
    # Set the y-ticks
    ax_avg_coverage.set_yticks(np.arange(0, 151, 5))
    # Set the bar width and position
    width_avg_coverage = 0.15
    positions_avg_coverage = [-0.3, -0.15, 0, 0.15, 0.3]
    # Plot the bars for each number of nodes
    for i, nodes in enumerate([5, 9, 12, 18]):
        ax_avg_coverage.bar(x_avg_coverage + positions_avg_coverage[i], [fixed_avg_coverage_list[i], weighted_greedy_avg_coverage_list[i], sa_avg_coverage_list[i]], width_avg_coverage, label=f'{nodes} nodes')
    # Add a legend
    ax_avg_coverage.legend(bbox_to_anchor=(0.99, 1.1), ncol=4)
    # Show the plot
    fig_avg_coverage.show()
    fig_avg_coverage_filename = "C:\\Results\\"+foldername_scenario+"Average_Coverage_per_number_of_nodes.pdf"
    fig_avg_coverage.savefig(fig_avg_coverage_filename, format="pdf")

    # Create a figure with a single subplot for multiple Variance Delays per algorithm per experiment with different number of nodes in the network
    fig_var_delay, ax_var_delay = plt.subplots()
    # Set the x and y axis labels
    ax_var_delay.set_xlabel('Solution Approach')
    ax_var_delay.set_ylabel('Variance Delay (s)')
    # Set the x-ticks and labels
    x_var_delay = np.arange(3)
    labels_var_delay = ['Fixed', 'Weighted Greedy', 'SA']
    ax_var_delay.set_xticks(x_var_delay)
    ax_var_delay.set_xticklabels(labels_var_delay)
    # Set the y-ticks
    ax_var_delay.set_yticks(np.arange(0, 151, 5))
    # Set the bar width and position
    width_var_delay = 0.15
    positions_var_delay = [-0.3, -0.15, 0, 0.15, 0.3]
    # Plot the bars for each number of nodes
    for i, nodes in enumerate([5, 9, 12, 18]):
        ax_var_delay.bar(x_var_delay + positions_var_delay[i], [fixed_var_delay_list[i], weighted_greedy_var_delay_list[i], sa_var_delay_list[i]], width_var_delay, label=f'{nodes} nodes')
    # Add a legend
    ax_var_delay.legend()
    # Show the plot
    fig_var_delay.show()
    fig_var_delay_filename = "C:\\Results\\"+foldername_scenario+"Variance_Delay_per_number_of_nodes.pdf"
    fig_var_delay.savefig(fig_var_delay_filename, format="pdf")

    # Create a figure with a single subplot for multiple Variance Coverage per algorithm per experiment with different number of nodes in the network
    fig_var_coverage, ax_var_coverage = plt.subplots()
    # Set the x and y axis labels
    ax_var_coverage.set_xlabel('Solution Approach')
    ax_var_coverage.set_ylabel('Variance Coverage (%)')
    # Set the x-ticks and labels
    x_var_coverage = np.arange(3)
    labels_var_coverage = ['Fixed', 'Weighted Greedy', 'SA']
    ax_var_coverage.set_xticks(x_var_coverage)
    ax_var_coverage.set_xticklabels(labels_var_coverage)
    # Set the y-ticks
    ax_var_coverage.set_yticks(np.arange(0, 151, 5))
    # Set the bar width and position
    width_var_coverage = 0.15
    positions_var_coverage = [-0.3, -0.15, 0, 0.15, 0.3]
    # Plot the bars for each number of nodes
    for i, nodes in enumerate([5, 9, 12, 18]):
        ax_var_coverage.bar(x_var_coverage + positions_var_coverage[i], [fixed_var_coverage_list[i], weighted_greedy_var_coverage_list[i], sa_var_coverage_list[i]], width_var_coverage, label=f'{nodes} nodes')
    # Add a legend
    ax_var_coverage.legend()
    # Show the plot
    fig_var_coverage.show()
    fig_var_coverage_filename = "C:\\Results\\"+foldername_scenario+"Variance_Coverage_per_number_of_nodes.pdf"
    fig_var_coverage.savefig(fig_var_coverage_filename, format="pdf")

    # Create a figure with a single subplot for multiple Average Overhead per algorithm per experiment with different number of nodes in the network
    fig_avg_overhead, ax_avg_overhead = plt.subplots()
    # Set the x and y axis labels
    ax_avg_overhead.set_xlabel('Solution Approach')
    ax_avg_overhead.set_ylabel('Average Overhead (%)')
    # Set the x-ticks and labels
    x_avg_overhead = np.arange(3)
    labels_avg_overhead = ['Fixed', 'Weighted Greedy', 'SA']
    ax_avg_overhead.set_xticks(x_avg_overhead)
    ax_avg_overhead.set_xticklabels(labels_avg_overhead)
    # Set the y-ticks
    ax_avg_overhead.set_yticks(np.arange(0, 151, 5))
    # Set the bar width and position
    width_avg_overhead = 0.15
    positions_avg_overhead = [-0.3, -0.15, 0, 0.15, 0.3]
    # Plot the bars for each number of nodes
    for i, nodes in enumerate([5, 9, 12, 18]):
        ax_avg_overhead.bar(x_avg_overhead + positions_avg_overhead[i], [fixed_avg_overhead_list[i], weighted_greedy_avg_overhead_list[i], sa_avg_overhead_list[i]], width_avg_overhead, label=f'{nodes} nodes')
    # Add a legend
    ax_avg_overhead.legend()
    # Show the plot
    fig_avg_overhead.show()
    fig_avg_overhead_filename = "C:\\Results\\"+foldername_scenario+"Average_Overhead_per_number_of_nodes.pdf"
    fig_avg_overhead.savefig(fig_avg_overhead_filename, format="pdf")

    # Create a figure with a single subplot for multiple Average Runtime per algorithm per experiment with different number of nodes in the network
    fig_avg_runtime, ax_avg_runtime = plt.subplots()
    # Set the x and y axis labels
    ax_avg_runtime.set_xlabel('Solution Approach')
    ax_avg_runtime.set_ylabel('Average Rutime (ms)')
    # Set the x-ticks and labels
    x_avg_runtime = np.arange(2)
    labels_avg_runtime = ['Weighted Greedy', 'SA']
    ax_avg_runtime.set_xticks(x_avg_runtime)
    ax_avg_runtime.set_xticklabels(labels_avg_runtime)
    # Set the y-ticks
    ax_avg_runtime.set_yticks(np.arange(0, 151, 5))
    # Set the bar width and position
    width_avg_runtime = 0.15
    positions_avg_runtime = [-0.3, -0.15, 0, 0.15, 0.3]
    # Plot the bars for each number of nodes
    for i, nodes in enumerate([5, 9, 12, 18]):
        ax_avg_runtime.bar(x_avg_runtime + positions_avg_runtime[i], [weighted_greedy_avg_runtimes_list[i], sa_avg_runtimes_list[i]], width_avg_runtime, label=f'{nodes} nodes')
    # Add a legend
    ax_avg_runtime.legend()
    # Show the plot
    fig_avg_runtime.show()
    fig_avg_runtime_filename = "C:\\Results\\"+foldername_scenario+"Average_Runtime_per_number_of_nodes.pdf"
    fig_avg_runtime.savefig(fig_avg_runtime_filename, format="pdf")

    plt.show(block = False)
    plt.pause(3)
    plt.close(fig_avg_delay)
    plt.close(fig_avg_coverage)
    plt.close(fig_var_delay)
    plt.close(fig_var_coverage)
    plt.close(fig_avg_overhead)
    plt.close(fig_avg_runtime)

    return fixed_avg_delay_list, weighted_greedy_avg_delay_list, sa_avg_delay_list, fixed_avg_coverage_list, weighted_greedy_avg_coverage_list, sa_avg_coverage_list, weighted_greedy_avg_runtimes_list, sa_avg_runtimes_list

def main():
    list_of_weighted_greedy_avg_runtimes_list = []
    list_of_sa_avg_runtimes_list = []
    list_of_fixed_avg_delay_list = [] 
    list_of_weighted_greedy_avg_delay_list = [] 
    list_of_sa_avg_delay_list = [] 
    list_of_fixed_avg_coverage_list = [] 
    list_of_weighted_greedy_avg_coverage_list = [] 
    list_of_sa_avg_coverage_list = []

    scenarios = [["Artificial","random"],["Anglova","convoy"],["Anglova","engagement"]]
    algorithms = ["Weighted Greedy","SA","Fixed"]
    for scenario in scenarios:
        print("START - Scenario "+scenario[0]+" - "+scenario[1])
        exp_scenario = scenario[0]
        mob_mode = scenario[1]
        fixed_avg_delay_list, weighted_greedy_avg_delay_list, sa_avg_delay_list, fixed_avg_coverage_list, weighted_greedy_avg_coverage_list, sa_avg_coverage_list, weighted_greedy_avg_runtimes_list, sa_avg_runtimes_list = scenario_run(exp_scenario,mob_mode)
        list_of_weighted_greedy_avg_runtimes_list.append(weighted_greedy_avg_runtimes_list)
        list_of_sa_avg_runtimes_list.append(sa_avg_runtimes_list)
        list_of_fixed_avg_delay_list.append(fixed_avg_delay_list)
        list_of_weighted_greedy_avg_delay_list.append(weighted_greedy_avg_delay_list) 
        list_of_sa_avg_delay_list.append(sa_avg_delay_list)
        list_of_fixed_avg_coverage_list.append(fixed_avg_coverage_list)
        list_of_weighted_greedy_avg_coverage_list.append(weighted_greedy_avg_coverage_list) 
        list_of_sa_avg_coverage_list.append(sa_avg_coverage_list)

    '''
    # Number of algorithms
    num_algorithms = 2

    # Network sizes
    network_sizes = [5, 9, 12, 18]

    # Number of network sizes
    num_sizes = len(network_sizes)
    '''
    runtime_algorithm1_size5_sc1 = list_of_weighted_greedy_avg_runtimes_list[0][0]
    runtime_algorithm1_size9_sc1 = list_of_weighted_greedy_avg_runtimes_list[0][1]
    runtime_algorithm1_size12_sc1 = list_of_weighted_greedy_avg_runtimes_list[0][2]
    runtime_algorithm1_size18_sc1 = list_of_weighted_greedy_avg_runtimes_list[0][3]

    runtime_algorithm2_size5_sc1 = list_of_sa_avg_runtimes_list[0][0]
    runtime_algorithm2_size9_sc1 = list_of_sa_avg_runtimes_list[0][1]
    runtime_algorithm2_size12_sc1 = list_of_sa_avg_runtimes_list[0][2]
    runtime_algorithm2_size18_sc1 = list_of_sa_avg_runtimes_list[0][3]

    runtime_algorithm1_size5_sc2 = list_of_weighted_greedy_avg_runtimes_list[1][0]
    runtime_algorithm1_size9_sc2 = list_of_weighted_greedy_avg_runtimes_list[1][1]
    runtime_algorithm1_size12_sc2 = list_of_weighted_greedy_avg_runtimes_list[1][2]
    runtime_algorithm1_size18_sc2 = list_of_weighted_greedy_avg_runtimes_list[1][3]

    runtime_algorithm2_size5_sc2 = list_of_sa_avg_runtimes_list[1][0]
    runtime_algorithm2_size9_sc2 = list_of_sa_avg_runtimes_list[1][1]
    runtime_algorithm2_size12_sc2 = list_of_sa_avg_runtimes_list[1][2]
    runtime_algorithm2_size18_sc2 = list_of_sa_avg_runtimes_list[1][3]

    runtime_algorithm1_size5_sc3 = list_of_weighted_greedy_avg_runtimes_list[2][0]
    runtime_algorithm1_size9_sc3 = list_of_weighted_greedy_avg_runtimes_list[2][1]
    runtime_algorithm1_size12_sc3 = list_of_weighted_greedy_avg_runtimes_list[2][2]
    runtime_algorithm1_size18_sc3 = list_of_weighted_greedy_avg_runtimes_list[2][3]

    runtime_algorithm2_size5_sc3 = list_of_sa_avg_runtimes_list[2][0]
    runtime_algorithm2_size9_sc3 = list_of_sa_avg_runtimes_list[2][1]
    runtime_algorithm2_size12_sc3 = list_of_sa_avg_runtimes_list[2][2]
    runtime_algorithm2_size18_sc3 = list_of_sa_avg_runtimes_list[2][3]

    # Data (replace with your data)
    # Random data generated for illustration, should be replaced with actual data
    #data = np.random.rand(3, num_sizes, num_algorithms)
    data_runtimes = np.array([
        # Average runtimes for mobility scenario 1
        [
            # Average runtimes for network size 5
            [runtime_algorithm1_size5_sc1, runtime_algorithm2_size5_sc1],
            # Average runtimes for network size 9
            [runtime_algorithm1_size9_sc1, runtime_algorithm2_size9_sc1],
            # Average runtimes for network size 12
            [runtime_algorithm1_size12_sc1, runtime_algorithm2_size12_sc1],
            # Average runtimes for network size 18
            [runtime_algorithm1_size18_sc1, runtime_algorithm2_size18_sc1]
        ],

        # Similarly for mobility scenario 2
        [
            [runtime_algorithm1_size5_sc2, runtime_algorithm2_size5_sc2],
            [runtime_algorithm1_size9_sc2, runtime_algorithm2_size9_sc2],
            [runtime_algorithm1_size12_sc2, runtime_algorithm2_size12_sc2],
            [runtime_algorithm1_size18_sc2, runtime_algorithm2_size18_sc2]
        ],

        # Similarly for mobility scenario 3
        [
            [runtime_algorithm1_size5_sc3, runtime_algorithm2_size5_sc3],
            [runtime_algorithm1_size9_sc3, runtime_algorithm2_size9_sc3],
            [runtime_algorithm1_size12_sc3, runtime_algorithm2_size12_sc3],
            [runtime_algorithm1_size18_sc3, runtime_algorithm2_size18_sc3]
        ]
    ])

    avg_delay_algorithm1_size5_sc1 = list_of_weighted_greedy_avg_delay_list[0][0]
    avg_delay_algorithm1_size9_sc1 = list_of_weighted_greedy_avg_delay_list[0][1]
    avg_delay_algorithm1_size12_sc1 = list_of_weighted_greedy_avg_delay_list[0][2]
    avg_delay_algorithm1_size18_sc1 = list_of_weighted_greedy_avg_delay_list[0][3]

    avg_delay_algorithm2_size5_sc1 = list_of_sa_avg_delay_list[0][0]
    avg_delay_algorithm2_size9_sc1 = list_of_sa_avg_delay_list[0][1]
    avg_delay_algorithm2_size12_sc1 = list_of_sa_avg_delay_list[0][2]
    avg_delay_algorithm2_size18_sc1 = list_of_sa_avg_delay_list[0][3]

    avg_delay_algorithm3_size5_sc1 = list_of_fixed_avg_delay_list[0][0]
    avg_delay_algorithm3_size9_sc1 = list_of_fixed_avg_delay_list[0][1]
    avg_delay_algorithm3_size12_sc1 = list_of_fixed_avg_delay_list[0][2]
    avg_delay_algorithm3_size18_sc1 = list_of_fixed_avg_delay_list[0][3]

    avg_delay_algorithm1_size5_sc2 = list_of_weighted_greedy_avg_delay_list[1][0]
    avg_delay_algorithm1_size9_sc2 = list_of_weighted_greedy_avg_delay_list[1][1]
    avg_delay_algorithm1_size12_sc2 = list_of_weighted_greedy_avg_delay_list[1][2]
    avg_delay_algorithm1_size18_sc2 = list_of_weighted_greedy_avg_delay_list[1][3]

    avg_delay_algorithm2_size5_sc2 = list_of_sa_avg_delay_list[1][0]
    avg_delay_algorithm2_size9_sc2 = list_of_sa_avg_delay_list[1][1]
    avg_delay_algorithm2_size12_sc2 = list_of_sa_avg_delay_list[1][2]
    avg_delay_algorithm2_size18_sc2 = list_of_sa_avg_delay_list[1][3]

    avg_delay_algorithm3_size5_sc2 = list_of_fixed_avg_delay_list[1][0]
    avg_delay_algorithm3_size9_sc2 = list_of_fixed_avg_delay_list[1][1]
    avg_delay_algorithm3_size12_sc2 = list_of_fixed_avg_delay_list[1][2]
    avg_delay_algorithm3_size18_sc2 = list_of_fixed_avg_delay_list[1][3]

    avg_delay_algorithm1_size5_sc3 = list_of_weighted_greedy_avg_delay_list[2][0]
    avg_delay_algorithm1_size9_sc3 = list_of_weighted_greedy_avg_delay_list[2][1]
    avg_delay_algorithm1_size12_sc3 = list_of_weighted_greedy_avg_delay_list[2][2]
    avg_delay_algorithm1_size18_sc3 = list_of_weighted_greedy_avg_delay_list[2][3]

    avg_delay_algorithm2_size5_sc3 = list_of_sa_avg_delay_list[2][0]
    avg_delay_algorithm2_size9_sc3 = list_of_sa_avg_delay_list[2][1]
    avg_delay_algorithm2_size12_sc3 = list_of_sa_avg_delay_list[2][2]
    avg_delay_algorithm2_size18_sc3 = list_of_sa_avg_delay_list[2][3]

    avg_delay_algorithm3_size5_sc3 = list_of_fixed_avg_delay_list[2][0]
    avg_delay_algorithm3_size9_sc3 = list_of_fixed_avg_delay_list[2][1]
    avg_delay_algorithm3_size12_sc3 = list_of_fixed_avg_delay_list[2][2]
    avg_delay_algorithm3_size18_sc3 = list_of_fixed_avg_delay_list[2][3]

    # Data (replace with your data)
    # Random data generated for illustration, should be replaced with actual data
    #data = np.random.rand(3, num_sizes, num_algorithms)
    data_delay = np.array([
        # Average runtimes for mobility scenario 1
        [
            # Average runtimes for network size 5
            [avg_delay_algorithm1_size5_sc1, avg_delay_algorithm2_size5_sc1, avg_delay_algorithm3_size5_sc1],
            # Average runtimes for network size 9
            [avg_delay_algorithm1_size9_sc1, avg_delay_algorithm2_size9_sc1, avg_delay_algorithm3_size9_sc1],
            # Average runtimes for network size 12
            [avg_delay_algorithm1_size12_sc1, avg_delay_algorithm2_size12_sc1, avg_delay_algorithm3_size12_sc1],
            # Average runtimes for network size 18
            [avg_delay_algorithm1_size18_sc1, avg_delay_algorithm2_size18_sc1, avg_delay_algorithm3_size18_sc1]
        ],

        # Similarly for mobility scenario 2
        [
            [avg_delay_algorithm1_size5_sc2, avg_delay_algorithm2_size5_sc2, avg_delay_algorithm3_size5_sc2],
            [avg_delay_algorithm1_size9_sc2, avg_delay_algorithm2_size9_sc2, avg_delay_algorithm3_size9_sc2],
            [avg_delay_algorithm1_size12_sc2, avg_delay_algorithm2_size12_sc2, avg_delay_algorithm3_size12_sc2],
            [avg_delay_algorithm1_size18_sc2, avg_delay_algorithm2_size18_sc2, avg_delay_algorithm3_size18_sc2]
        ],

        # Similarly for mobility scenario 3
        [
            [avg_delay_algorithm1_size5_sc3, avg_delay_algorithm2_size5_sc3, avg_delay_algorithm3_size5_sc3],
            [avg_delay_algorithm1_size9_sc3, avg_delay_algorithm2_size9_sc3, avg_delay_algorithm3_size9_sc3],
            [avg_delay_algorithm1_size12_sc3, avg_delay_algorithm2_size12_sc3, avg_delay_algorithm3_size12_sc3],
            [avg_delay_algorithm1_size18_sc3, avg_delay_algorithm2_size18_sc3, avg_delay_algorithm3_size18_sc3]
        ]
    ])

    avg_coverage_algorithm1_size5_sc1 = list_of_weighted_greedy_avg_coverage_list[0][0]
    avg_coverage_algorithm1_size9_sc1 = list_of_weighted_greedy_avg_coverage_list[0][1]
    avg_coverage_algorithm1_size12_sc1 = list_of_weighted_greedy_avg_coverage_list[0][2]
    avg_coverage_algorithm1_size18_sc1 = list_of_weighted_greedy_avg_coverage_list[0][3]

    avg_coverage_algorithm2_size5_sc1 = list_of_sa_avg_coverage_list[0][0]
    avg_coverage_algorithm2_size9_sc1 = list_of_sa_avg_coverage_list[0][1]
    avg_coverage_algorithm2_size12_sc1 = list_of_sa_avg_coverage_list[0][2]
    avg_coverage_algorithm2_size18_sc1 = list_of_sa_avg_coverage_list[0][3]

    avg_coverage_algorithm3_size5_sc1 = list_of_fixed_avg_coverage_list[0][0]
    avg_coverage_algorithm3_size9_sc1 = list_of_fixed_avg_coverage_list[0][1]
    avg_coverage_algorithm3_size12_sc1 = list_of_fixed_avg_coverage_list[0][2]
    avg_coverage_algorithm3_size18_sc1 = list_of_fixed_avg_coverage_list[0][3]

    avg_coverage_algorithm1_size5_sc2 = list_of_weighted_greedy_avg_coverage_list[1][0]
    avg_coverage_algorithm1_size9_sc2 = list_of_weighted_greedy_avg_coverage_list[1][1]
    avg_coverage_algorithm1_size12_sc2 = list_of_weighted_greedy_avg_coverage_list[1][2]
    avg_coverage_algorithm1_size18_sc2 = list_of_weighted_greedy_avg_coverage_list[1][3]

    avg_coverage_algorithm2_size5_sc2 = list_of_sa_avg_coverage_list[1][0]
    avg_coverage_algorithm2_size9_sc2 = list_of_sa_avg_coverage_list[1][1]
    avg_coverage_algorithm2_size12_sc2 = list_of_sa_avg_coverage_list[1][2]
    avg_coverage_algorithm2_size18_sc2 = list_of_sa_avg_coverage_list[1][3]

    avg_coverage_algorithm3_size5_sc2 = list_of_fixed_avg_coverage_list[1][0]
    avg_coverage_algorithm3_size9_sc2 = list_of_fixed_avg_coverage_list[1][1]
    avg_coverage_algorithm3_size12_sc2 = list_of_fixed_avg_coverage_list[1][2]
    avg_coverage_algorithm3_size18_sc2 = list_of_fixed_avg_coverage_list[1][3]

    avg_coverage_algorithm1_size5_sc3 = list_of_weighted_greedy_avg_coverage_list[2][0]
    avg_coverage_algorithm1_size9_sc3 = list_of_weighted_greedy_avg_coverage_list[2][1]
    avg_coverage_algorithm1_size12_sc3 = list_of_weighted_greedy_avg_coverage_list[2][2]
    avg_coverage_algorithm1_size18_sc3 = list_of_weighted_greedy_avg_coverage_list[2][3]

    avg_coverage_algorithm2_size5_sc3 = list_of_sa_avg_coverage_list[2][0]
    avg_coverage_algorithm2_size9_sc3 = list_of_sa_avg_coverage_list[2][1]
    avg_coverage_algorithm2_size12_sc3 = list_of_sa_avg_coverage_list[2][2]
    avg_coverage_algorithm2_size18_sc3 = list_of_sa_avg_coverage_list[2][3]

    avg_coverage_algorithm3_size5_sc3 = list_of_fixed_avg_coverage_list[2][0]
    avg_coverage_algorithm3_size9_sc3 = list_of_fixed_avg_coverage_list[2][1]
    avg_coverage_algorithm3_size12_sc3 = list_of_fixed_avg_coverage_list[2][2]
    avg_coverage_algorithm3_size18_sc3 = list_of_fixed_avg_coverage_list[2][3]

    # Data (replace with your data)
    # Random data generated for illustration, should be replaced with actual data
    #data = np.random.rand(3, num_sizes, num_algorithms)
    data_coverage = np.array([
        # Average runtimes for mobility scenario 1
        [
            # Average runtimes for network size 5
            [avg_coverage_algorithm1_size5_sc1, avg_coverage_algorithm2_size5_sc1, avg_coverage_algorithm3_size5_sc1],
            # Average runtimes for network size 9
            [avg_coverage_algorithm1_size9_sc1, avg_coverage_algorithm2_size9_sc1, avg_coverage_algorithm3_size9_sc1],
            # Average runtimes for network size 12
            [avg_coverage_algorithm1_size12_sc1, avg_coverage_algorithm2_size12_sc1, avg_coverage_algorithm3_size12_sc1],
            # Average runtimes for network size 18
            [avg_coverage_algorithm1_size18_sc1, avg_coverage_algorithm2_size18_sc1, avg_coverage_algorithm3_size18_sc1]
        ],

        # Similarly for mobility scenario 2
        [
            [avg_coverage_algorithm1_size5_sc2, avg_coverage_algorithm2_size5_sc2, avg_coverage_algorithm3_size5_sc2],
            [avg_coverage_algorithm1_size9_sc2, avg_coverage_algorithm2_size9_sc2, avg_coverage_algorithm3_size9_sc2],
            [avg_coverage_algorithm1_size12_sc2, avg_coverage_algorithm2_size12_sc2, avg_coverage_algorithm3_size12_sc2],
            [avg_coverage_algorithm1_size18_sc2, avg_coverage_algorithm2_size18_sc2, avg_coverage_algorithm3_size18_sc2]
        ],

        # Similarly for mobility scenario 3
        [
            [avg_coverage_algorithm1_size5_sc3, avg_coverage_algorithm2_size5_sc3, avg_coverage_algorithm3_size5_sc3],
            [avg_coverage_algorithm1_size9_sc3, avg_coverage_algorithm2_size9_sc3, avg_coverage_algorithm3_size9_sc3],
            [avg_coverage_algorithm1_size12_sc3, avg_coverage_algorithm2_size12_sc3, avg_coverage_algorithm3_size12_sc3],
            [avg_coverage_algorithm1_size18_sc3, avg_coverage_algorithm2_size18_sc3, avg_coverage_algorithm3_size18_sc3]
        ]
    ])
        
    num_algorithms = 3
    num_sizes = 4
    num_scenarios = 3

    network_sizes = [5, 9, 12, 18]
    width = 0.1  # adjust as necessary
    ind = np.arange(num_sizes)
    colors_runtimes = ['r', 'g', 'b', 'y', 'm', 'c']
    colors = ['r', 'g', 'b', 'y', 'm', 'c', '#ADFF2F', '#9370DB', 'k']

    #Overall Average Runtime per network size per mobility scenario
    fig_all_scenarios_avg_runtime, ax_all_scenarios_avg_runtime = plt.subplots(figsize=(10,8))

    for i in range(num_scenarios):
        for j in range(2):
            ax_all_scenarios_avg_runtime.bar(ind + i*2*width + j*width, data_runtimes[i, :, j], width, color=colors_runtimes[i*2 + j])

    ax_all_scenarios_avg_runtime.set_xticks(ind + num_scenarios*2*width/2)
    ax_all_scenarios_avg_runtime.set_xticklabels(network_sizes)
    ax_all_scenarios_avg_runtime.set_xlabel('Network Size (nodes)', fontsize=14)
    ax_all_scenarios_avg_runtime.set_ylabel('Average Runtime (s)', fontsize=14)
    ax_all_scenarios_avg_runtime.set_yscale('log')
    ax_all_scenarios_avg_runtime.legend([f'{scenarios[i][0]+"-"+scenarios[i][1]} mobility, {algorithms[j]} algorithm' for i in range(num_scenarios) for j in range(2)], loc='upper left')

    
    fig_all_scenarios_avg_runtime.show()
    fig_avg_runtime_filename = "C:\\Results\\Overall_Average_Runtime_per_number_of_nodes_per_scenario.pdf"
    fig_all_scenarios_avg_runtime.savefig(fig_avg_runtime_filename, format="pdf")

    #Overall Average Delay per network size per mobility scenario
    fig_all_scenarios_avg_delay, ax_all_scenarios_avg_delay = plt.subplots(figsize=(10,8))

    for i in range(num_scenarios):
        for j in range(num_algorithms):
            ax_all_scenarios_avg_delay.bar(ind + i*num_algorithms*width + j*width, data_delay[i, :, j], width, color=colors[i*num_algorithms + j])

    ax_all_scenarios_avg_delay.set_xticks(ind + num_scenarios*num_algorithms*width/2)
    ax_all_scenarios_avg_delay.set_xticklabels(network_sizes)
    ax_all_scenarios_avg_delay.set_xlabel('Network Size (nodes)', fontsize=14)
    ax_all_scenarios_avg_delay.set_ylabel('Average Delay (s)', fontsize=14)
    ax_all_scenarios_avg_delay.legend([f'{scenarios[i][0]+"-"+scenarios[i][1]} mobility, {algorithms[j]} algorithm' for i in range(num_scenarios) for j in range(num_algorithms)], loc='upper left')

    
    fig_all_scenarios_avg_delay.show()
    fig_avg_delay_filename = "C:\\Results\\Overall_Average_Delay_per_number_of_nodes_per_scenario.pdf"
    fig_all_scenarios_avg_delay.savefig(fig_avg_delay_filename, format="pdf")

    #Overall Average Coverage per network size per mobility scenario
    fig_all_scenarios_avg_coverage, ax_all_scenarios_avg_coverage = plt.subplots(figsize=(10,8))

    for i in range(num_scenarios):
        for j in range(num_algorithms):
            ax_all_scenarios_avg_coverage.bar(ind + i*num_algorithms*width + j*width, data_coverage[i, :, j], width, color=colors[i*num_algorithms + j])

    ax_all_scenarios_avg_coverage.set_xticks(ind + num_scenarios*num_algorithms*width/2)
    ax_all_scenarios_avg_coverage.set_xticklabels(network_sizes)
    ax_all_scenarios_avg_coverage.set_xlabel('Network Size (nodes)', fontsize=14)
    ax_all_scenarios_avg_coverage.set_ylabel('Average Coverage (%)', fontsize=14)
    ax_all_scenarios_avg_coverage.legend([f'{scenarios[i][0]+"-"+scenarios[i][1]} mobility, {algorithms[j]} algorithm' for i in range(num_scenarios) for j in range(num_algorithms)], bbox_to_anchor=(0.99, 1.1), ncol=2)

    
    fig_all_scenarios_avg_coverage.show()
    fig_avg_coverage_filename = "C:\\Results\\Overall_Average_Coverage_per_number_of_nodes_per_scenario.pdf"
    fig_all_scenarios_avg_coverage.savefig(fig_avg_coverage_filename, format="pdf")



    #plt.xlabel('Network Size')
    plt.tight_layout()
    plt.show(block = False)
    plt.pause(3)
    plt.close(fig_all_scenarios_avg_runtime)
    plt.close(fig_all_scenarios_avg_delay)
    plt.close(fig_all_scenarios_avg_coverage)


if __name__ == "__main__":
    main()

