import argparse
import socket
import time
import struct
from collections import defaultdict
import heapq

# Constants
HELLO_INTERVAL = 1  # Interval to send Hello messages (in seconds)
LS_INTERVAL = 5     # Interval to send Link-State messages (in seconds)
HELLO_TIMEOUT = 3   # Timeout to consider a neighbor unavailable (in seconds)

# Global variables
emulator = None
route_topology = defaultdict(dict)  # Adjacency list for the topology
forwarding_table = {}  # Destination -> NextHop
previous_topology = {}
last_hello = {}  # Neighbor -> Last Hello timestamp
seq_numbers = defaultdict(int)  # Node -> Sequence number
ip_port = None  # Current node's IP and Port


def parse_topology_file(filename):
    """Parse the topology file and return the route topology."""
    global route_topology
    with open(filename, 'r') as file:
        for line in file:
            parts = line.strip().split()
            src = parts[0]
            for neighbor_info in parts[1:]:
                neighbor, cost = neighbor_info.rsplit(',', 1)
                cost = int(cost)
                route_topology[src][neighbor] = cost
    print("Topology Loaded:")
    print_topology()


def print_topology():
    """Print the current topology."""
    for node, neighbors in route_topology.items():
        print(f"{node}: {neighbors}")


def build_forward_table():
    """Compute the forwarding table using Dijkstra's algorithm."""
    global forwarding_table
    old_forwarding_table = forwarding_table.copy()
    forwarding_table.clear()

    distances = {ip_port: 0}
    prev_hops = {ip_port: None}
    priority_queue = [(0, ip_port)]

    while priority_queue:
        current_distance, current_node = heapq.heappop(priority_queue)
        if current_distance > distances[current_node]:
            continue

        for neighbor, cost in route_topology[current_node].items():
            distance = current_distance + cost
            if neighbor not in distances or distance < distances[neighbor]:
                distances[neighbor] = distance
                prev_hops[neighbor] = current_node
                heapq.heappush(priority_queue, (distance, neighbor))

    for destination in distances:
        if destination == ip_port:
            continue
        next_hop = destination
        while prev_hops[next_hop] != ip_port:
            next_hop = prev_hops[next_hop]
        forwarding_table[destination] = next_hop

    # Print the forwarding table only if it changed
    if forwarding_table != old_forwarding_table:
        print("Forwarding Table Updated:")
        for destination, nexthop in forwarding_table.items():
            print(f"Destination: {destination}, NextHop: {nexthop}")


def send_hello():
    """Send Hello messages to all neighbors."""
    global last_hello
    for neighbor in route_topology[ip_port]:
        message = f"HELLO {ip_port}"
        emulator.sendto(message.encode(), parse_ip_port(neighbor))
    last_hello[ip_port] = time.time()


def handle_hello(sender):
    """Handle a Hello message."""
    if sender not in route_topology[ip_port]:
        return
    last_hello[sender] = time.time()


def send_link_state():
    """Send Link-State messages to all neighbors."""
    seq_numbers[ip_port] += 1
    message = f"LS {ip_port} {seq_numbers[ip_port]} {len(route_topology[ip_port])}"
    for neighbor, cost in route_topology[ip_port].items():
        message += f" {neighbor},{cost}"
    for neighbor in route_topology[ip_port]:
        emulator.sendto(message.encode(), parse_ip_port(neighbor))


def handle_link_state(message):
    """Handle a Link-State message."""
    global previous_topology
    parts = message.split()
    sender, seq_num = parts[1], int(parts[2])
    if seq_num <= seq_numbers[sender]:
        return

    seq_numbers[sender] = seq_num
    neighbors = parts[4:]
    new_neighbors = {n.rsplit(',', 1)[0]: int(n.rsplit(',', 1)[1]) for n in neighbors}

    # Check if the topology actually changed
    if route_topology.get(sender) != new_neighbors:
        route_topology[sender] = new_neighbors
        print(f"Topology updated with Link-State message from {sender}.")
        print("Updated Topology:")
        print_topology()
        build_forward_table()
        if route_topology != previous_topology:
            previous_topology = route_topology.copy()
        


def check_hello_timeout():
    """Check for neighbors that haven't sent Hello messages recently."""
    global route_topology, previous_topology
    current_time = time.time()
    topology_changed = False

    for neighbor in list(last_hello.keys()):
        if current_time - last_hello[neighbor] > HELLO_TIMEOUT:
            print(f"Neighbor {neighbor} timed out.")
            del last_hello[neighbor]
            if neighbor in route_topology[ip_port]:
                del route_topology[ip_port][neighbor]
                topology_changed = True
                print("Changed Topology:")
                print_topology()
                build_forward_table()

    if topology_changed:
        previous_topology = route_topology.copy()


def parse_ip_port(address):
    """Parse an IP:Port string into a tuple."""
    ip, port = address.split(',')
    return ip, int(port)

def handle_binary_packet(data, addr):
    """Handle a binary routetrace packet."""
    try:
        # Unpack the binary packet
        ttl, src_ip, src_port, dst_ip, dst_port = struct.unpack('!I4sH4sH', data)
        src_ip = socket.inet_ntoa(src_ip)
        dst_ip = socket.inet_ntoa(dst_ip)

        print(f"Routetrace packet received: TTL={ttl}, Source=({src_ip}:{src_port}), Destination=({dst_ip}:{dst_port})")

        # Check if this emulator is the destination
        local_ip, local_port = ip_port.split(',')
        if (local_ip == dst_ip and int(local_port) == dst_port) or (ttl == 0):
            response = struct.pack('!I4sH4sH', ttl, socket.inet_aton(local_ip), int(local_port),
                                   socket.inet_aton(dst_ip), dst_port)
            emulator.sendto(response, (src_ip, src_port))
        elif (ttl > 0):
            # Forward the packet to the next hop
            ttl -= 1
            destination = f"{dst_ip},{dst_port}"
            if destination in forwarding_table:
                next_hop = forwarding_table[destination]
                print(f"Forwarding packet to next hop: {next_hop}")
                forwarded_packet = struct.pack('!I4sH4sH', ttl, socket.inet_aton(src_ip), src_port,
                                               socket.inet_aton(dst_ip), dst_port)
                emulator.sendto(forwarded_packet, parse_ip_port(next_hop))
            else:
                print(f"No route to destination {dst_ip}:{dst_port}. Packet dropped.")
        return
    except Exception as e:
        print(f"Error handling binary packet: {e}")


def main():
    parser = argparse.ArgumentParser(description="Emulator for link-state routing.")
    parser.add_argument("-p", "--port", type=int, required=True, help="Port for the emulator.")
    parser.add_argument("-f", "--file", type=str, required=True, help="Topology file.")
    args = parser.parse_args()

    global ip_port, emulator
    local_ip = socket.gethostbyname(socket.gethostname())
    ip_port = f"{local_ip},{args.port}"
    parse_topology_file(args.file)
    build_forward_table()

    # Create socket
    emulator = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    emulator.bind((local_ip, args.port))
    emulator.setblocking(False)

    last_hello_time = time.time()
    last_ls_time = time.time()

    while True:
        try:
            data, addr = emulator.recvfrom(1024)
            try:
                message = data.decode()  # Try decoding as a text message
                if message.startswith("HELLO"):
                    sender = message.split()[1]
                    handle_hello(sender)
                elif message.startswith("LS"):
                    handle_link_state(message)
            except UnicodeDecodeError:
                # Handle binary routetrace packets
                handle_binary_packet(data, addr)
        except BlockingIOError:
            pass

        current_time = time.time()
        if current_time - last_hello_time > HELLO_INTERVAL:
            send_hello()
            last_hello_time = current_time

        if current_time - last_ls_time > LS_INTERVAL:
            send_link_state()
            last_ls_time = current_time

        check_hello_timeout()
        time.sleep(0.1)  


if __name__ == "__main__":
    main()
