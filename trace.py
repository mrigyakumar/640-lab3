import socket
import argparse
import struct
import sys
import time

# Define the packet structure
PACKET_FORMAT = "!I16sH16sH"  # TTL (I), Src IP (16s), Src Port (H), Dst IP (16s), Dst Port (H)

def create_packet(ttl, src_ip, src_port, dst_ip, dst_port):
    """Create a routetrace packet."""
    return struct.pack(PACKET_FORMAT, ttl, socket.inet_aton(src_ip), src_port, socket.inet_aton(dst_ip), dst_port)

def parse_packet(packet):
    """Parse a routetrace packet."""
    ttl, src_ip, src_port, dst_ip, dst_port = struct.unpack(PACKET_FORMAT, packet)
    return ttl, socket.inet_ntoa(src_ip), src_port, socket.inet_ntoa(dst_ip), dst_port

def routetrace(port, src_host, src_port, dst_host, dst_port, debug):
    """Implements the routetrace application."""
    try:
        # Create a UDP socket
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.bind(("", port))

        ttl = 0  # Start with TTL = 0
        while True:
            # Create and send a packet
            packet = create_packet(ttl, src_host, src_port, dst_host, dst_port)
            sock.sendto(packet, (src_host, src_port))

            if debug:
                print(f"Sent packet: TTL={ttl}, Src=({src_host}:{src_port}), Dst=({dst_host}:{dst_port})")

            # Wait for a response
            response, addr = sock.recvfrom(1024)
            resp_ttl, resp_src_ip, resp_src_port, resp_dst_ip, resp_dst_port = parse_packet(response)

            print(f"Received response: Src=({resp_src_ip}:{resp_src_port}), Dst=({resp_dst_ip}:{resp_dst_port})")

            # Check if the destination is reached
            if (resp_src_ip, resp_src_port) == (dst_host, dst_port):
                print("Destination reached!")
                break

            # Increment TTL and continue
            ttl += 1

        sock.close()

    except Exception as e:
        print(f"Error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    # Argument parsing
    parser = argparse.ArgumentParser(description="routetrace application")
    parser.add_argument("-a", type=int, required=True, help="Routetrace port")
    parser.add_argument("-b", required=True, help="Source hostname")
    parser.add_argument("-c", type=int, required=True, help="Source port")
    parser.add_argument("-d", required=True, help="Destination hostname")
    parser.add_argument("-e", type=int, required=True, help="Destination port")
    parser.add_argument("-f", type=int, choices=[0, 1], required=True, help="Debug option (0 or 1)")

    args = parser.parse_args()

    routetrace(args.a, args.b, args.c, args.d, args.e, args.f)
