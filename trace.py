import argparse
import socket
import struct
from datetime import datetime

def send_routetrace_packet(sock, ttl, src_ip, src_port, dst_ip, dst_port, emulator_ip, emulator_port, debug):
    # Create a routetrace packet with the required fields
    packet = struct.pack('!I4sH4sH', ttl, socket.inet_aton(src_ip), src_port, socket.inet_aton(dst_ip), dst_port)

    if debug:
        print(f"Sending packet: TTL={ttl}, Source=({src_ip}:{src_port}), Destination=({dst_ip}:{dst_port})")
    
    # Send packet to the source emulator
    sock.sendto(packet, (emulator_ip, emulator_port))

def receive_routetrace_packet(sock, debug):
    # Wait for a response packet from the emulator
    try:
        response, (ip, port) = sock.recvfrom(1024)
        ttl, src_ip, src_port, dst_ip, dst_port = struct.unpack('!I4sH4sH', response)
        src_ip = socket.inet_ntoa(src_ip)
        dst_ip = socket.inet_ntoa(dst_ip)
        
        if debug:
            print(f"Received packet: TTL={ttl}, Responder=({ip}:{port}), "
                  f"Source=({src_ip}:{src_port}), Destination=({dst_ip}:{dst_port})")
        
        return ip, port
    except socket.timeout:
        print("Timeout waiting for response.")
        return None

def main():
    # Argument parser for the command-line inputs
    parser = argparse.ArgumentParser(description="Routetrace application to trace the shortest path in a network.")
    parser.add_argument('-a', '--port', type=int, required=True, help="Routetrace port")
    parser.add_argument('-b', '--source_host', type=str, required=True, help="Source hostname")
    parser.add_argument('-c', '--source_port', type=int, required=True, help="Source port")
    parser.add_argument('-d', '--dest_host', type=str, required=True, help="Destination hostname")
    parser.add_argument('-e', '--dest_port', type=int, required=True, help="Destination port")
    parser.add_argument('-f', '--debug', type=int, choices=[0, 1], required=True, help="Debug option (0 or 1)")

    args = parser.parse_args()

    routetrace_port = args.port
    source_host = args.source_host
    source_port = args.source_port
    dest_host = args.dest_host
    dest_port = args.dest_port
    debug = args.debug

    # Initialize the socket for the routetrace application
    routetrace_ip = socket.gethostbyname(socket.gethostname())
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((routetrace_ip, routetrace_port))
    sock.settimeout(5)  # Timeout for receiving packets

    # Convert destination host to IP
    dest_ip = socket.gethostbyname(dest_host)
    source_ip = socket.gethostbyname(source_host)

    print(f"Starting routetrace from ({source_ip}:{source_port}) to ({dest_ip}:{dest_port})")

    ttl = 0
    while True:
        # Send a routetrace packet to the source emulator
        send_routetrace_packet(sock, ttl, routetrace_ip, routetrace_port, dest_ip, dest_port, source_ip, source_port, debug)

        # Wait for a response from the emulator
        response = receive_routetrace_packet(sock, debug)
        if response is None:
            print("No response received. Terminating.")
            break
        
        ip_received, port_received = response

        # Print the hop details
        print(f"Hop: {ip_received}:{port_received}")

        # Check if we reached the destination
        if (ip_received, port_received) == (dest_ip, dest_port):
            print("Destination reached!")
            break
        
        # Increment TTL for the next hop
        ttl += 1

if __name__ == "__main__":
    main()
