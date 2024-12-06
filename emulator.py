import argparse
import socket
import struct
import time
import logging
from queue import Queue, Empty
from datetime import datetime
from collections import defaultdict
import heapq

# Globals
port = 0
topology_file = ""
log_file = ""
neighbors = {}
topology = {}
forwarding_table = {}
hello_intervals = 5
link_state_intervals = 5
ttl_default = 10
seq_numbers = {}
last_hello = {}
logger = None
emulator = None

def readtopology():
    """
    Reads the topology file to initialize the network graph.
    """
    global topology, neighbors
    with open(topology_file, 'r') as file:
        for line in file:
            parts = line.strip().split()
            node = tuple(parts[0].split(','))
            connections = {}
            for entry in parts[1:]:
                neighbor, distance = entry.rsplit(',', 1)
                neighbor = tuple(neighbor.split(','))
                connections[neighbor] = int(distance)
            topology[node] = connections
            if (socket.gethostname(), str(port)) == node:
                neighbors = connections


def buildForwardTable():
    """
    Builds the forwarding table using Dijkstra's algorithm.
    """
    global forwarding_table
    forwarding_table.clear()

    source = (socket.gethostname(), str(port))
    pq = [(0, source, source)]  # (cost, current_node, next_hop)
    visited = set()
    distances = {source: 0}

    while pq:
        cost, current, next_hop = heapq.heappop(pq)
        if current in visited:
            continue
        visited.add(current)

        if current != source:
            forwarding_table[current] = next_hop

        for neighbor, weight in topology.get(current, {}).items():
            if neighbor not in visited:
                new_cost = cost + weight
                if new_cost < distances.get(neighbor, float('inf')):
                    distances[neighbor] = new_cost
                    heapq.heappush(pq, (new_cost, neighbor, neighbor if current == source else next_hop))

    logger.info("Updated Forwarding Table: %s", forwarding_table)


def send_hello_messages():
    """
    Sends HelloMessages to all neighbors.
    """
    global last_hello
    for neighbor in neighbors:
        packet = struct.pack("!s", b'H')  # HelloMessage identifier
        emulator.sendto(packet, (neighbor[0], int(neighbor[1])))
    logger.info("Sent HelloMessages to neighbors.")


def send_link_state_message():
    """
    Sends LinkStateMessages to all neighbors.
    """
    global seq_numbers
    node = (socket.gethostname(), str(port))
    seq_numbers[node] = seq_numbers.get(node, 0) + 1

    packet = struct.pack("!s", b'L') + struct.pack("!I", seq_numbers[node])
    neighbors_data = [(neighbor[0], int(neighbor[1]), weight) for neighbor, weight in neighbors.items()]
    packet += struct.pack("!I", len(neighbors_data))  # Number of neighbors
    for ip, port, weight in neighbors_data:
        packet += struct.pack("!50sI", ip.encode(), port, weight)

    for neighbor in neighbors:
        emulator.sendto(packet, (neighbor[0], int(neighbor[1])))
    logger.info("Sent LinkStateMessages to neighbors.")


def process_packet():
    """
    Processes incoming packets.
    """
    try:
        packet, addr = emulator.recvfrom(1024)
        packet_type = struct.unpack("!s", packet[:1])[0]
        
        if packet_type == b'H':  # HelloMessage
            last_hello[addr] = time.time()
            logger.info("Received HelloMessage from %s", addr)
        elif packet_type == b'L':  # LinkStateMessage
            process_link_state_message(packet, addr)
        else:
            logger.warning("Unknown packet type received: %s", packet_type)
    except BlockingIOError:
        pass


def process_link_state_message(packet, addr):
    """
    Processes a LinkStateMessage and updates the topology.
    """
    global topology
    node = addr
    seq_no = struct.unpack("!I", packet[1:5])[0]
    if seq_no <= seq_numbers.get(node, 0):
        return  # Ignore old message

    seq_numbers[node] = seq_no
    num_neighbors = struct.unpack("!I", packet[5:9])[0]
    neighbors = {}
    offset = 9
    for _ in range(num_neighbors):
        ip, port, weight = struct.unpack("!50sI", packet[offset:offset + 54])
        neighbors[(ip.decode().strip(), str(port))] = weight
        offset += 54
    topology[node] = neighbors
    logger.info("Updated topology: %s", topology)
    buildForwardTable()


def main():
    global port, topology_file, log_file, emulator, logger
    parser = argparse.ArgumentParser(description="Emulator for Link-State Routing Protocol")
    parser.add_argument('-p', '--port', type=int, required=True, help="Port of the emulator")
    parser.add_argument('-f', '--file', type=str, required=True, help="Topology file")
    parser.add_argument('-l', '--log', type=str, required=True, help="Log file")

    args = parser.parse_args()
    port = args.port
    topology_file = args.file
    log_file = args.log

    logger = logging.getLogger()
    logging.basicConfig(filename=log_file, level=logging.INFO)
    emulator = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    emulator.bind(("", port))
    emulator.setblocking(False)

    readtopology()
    buildForwardTable()

    hello_timer = time.time()
    link_state_timer = time.time()

    while True:
        process_packet()

        # Periodic tasks
        current_time = time.time()
        if current_time - hello_timer >= hello_intervals:
            send_hello_messages()
            hello_timer = current_time
        if current_time - link_state_timer >= link_state_intervals:
            send_link_state_message()
            link_state_timer = current_time


if __name__ == "__main__":
    main()
