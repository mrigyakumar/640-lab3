import argparse
import socket
import struct
from datetime import datetime
import time
import logging
import random
from queue import Queue, Empty

port = 0
size = 0
fwd_table_file = ""
log_file = ""
forwarding_table = []
emulator = None
logger = None

# priority queues
high_priority = None
med_priority = None
low_priority = None

# packet being delayed
current_packet = None
current_delay = None
current_nexthop = None

def create_table():
    global forwarding_table
    emulator_host = socket.gethostname()

    with open(fwd_table_file, 'r') as table:
        for line in table:
            cols = line.strip().split()
            e_host, e_port, d_host, d_port, hop_host, hop_port, delay, loss = cols
            # check if emulator matches
            if emulator_host == e_host and int(e_port) == port:
                # add to forwarding table
                forwarding_table.append({
                    'destination': (d_host, int(d_port)),
                    'nexthop': (hop_host, int(hop_port)),
                    'delay': int(delay),
                    'loss_prob': int(loss)/100
                })
    routing()


def routing(): 
    # compare destination of incoming packets with destination in fwd table
    # if destination exists in fwd table, queue packet for forwarding to next hop
    # if destination not found, drop packet, log event
    while True:
        try:
            packet, (sender_ip, sender_port) = emulator.recvfrom(5200)
            priority, src_ip, src_port, dst_ip, dst_port, length = struct.unpack('!c4sH4sHI', packet[:17])
            payload = packet[17:]
            src_ip = socket.inet_ntoa(src_ip)
            dst_ip = socket.inet_ntoa(dst_ip)
            packet_type, seq, payload_length = struct.unpack('!cII',payload[:9])
            found = False
            dst_name = socket.gethostbyaddr(dst_ip)[0].split(".")[0]
            for entry in forwarding_table:
                if entry['destination'] == (dst_name, dst_port):
                    found = True
                    queueing(packet, entry)
                    break

            if found == False:
                reason = "No forwarding entry found"
                logger.info("Source=(%s:%i) Destination=(%s:%i) Type=%c Priority=%c Payload Size=%i Time=%s Reason=%s",
                          socket.inet_ntoa(src_ip), int(src_port), socket.inet_ntoa(dst_ip), int(dst_port), packet_type.decode(), priority.decode(), length, datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3], reason)
        except BlockingIOError:
            pass

        send()

    

def queueing(packet, nexthop):
    # examine priority field on packet and place packet in appropriate queue
    # if queue is full, drop packet, log event
    priority, src_ip, src_port, dst_ip, dst_port, length = struct.unpack('!c4sH4sHI', packet[:17])
    payload = packet[17:]
    packet_type, seq, payload_length = struct.unpack('!cII',payload[:9])
    

    if priority == b'1':
        if high_priority.full():
            reason = "Priority queue 1 was full"
            logger.info("Source=(%s:%i) Destination=(%s:%i) Type=%c Priority=%c Payload Size=%i Time=%s Reason=%s",
                          socket.inet_ntoa(src_ip), int(src_port), socket.inet_ntoa(dst_ip), int(dst_port), packet_type.decode(), priority.decode(), length, datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3], reason)
        else:
            high_priority.put((packet,nexthop))

    elif priority == b'2':
        if med_priority.full():
            reason = "Priority queue 2 was full"
            logger.info("Source=(%s:%i) Destination=(%s:%i) Type=%c Priority=%c Payload Size=%i Time=%s Reason=%s",
                          socket.inet_ntoa(src_ip), int(src_port), socket.inet_ntoa(dst_ip), int(dst_port), packet_type.decode(), priority.decode(), length, datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3], reason)
        else:
            med_priority.put((packet,nexthop))
    
    elif priority == b'3':
        if low_priority.full():
            reason = "Priority queue 3 was full"
            logger.info("Source=(%s:%i) Destination=(%s:%i) Type=%c Priority=%c Payload Size=%i Time=%s Reason=%s",
                          socket.inet_ntoa(src_ip), int(src_port), socket.inet_ntoa(dst_ip), int(dst_port), packet_type.decode(), priority.decode(), length, datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3], reason)
        else:
            low_priority.put((packet,nexthop))

    else:
        reason = "Invalid priority specified in packet"
        logger.info("Source=(%s:%i) Destination=(%s:%i) Type=%c Priority=%c Payload Size=%i Time=%s Reason=%s",
                          socket.inet_ntoa(src_ip), int(src_port), socket.inet_ntoa(dst_ip), int(dst_port), packet_type.decode(), priority.decode(), length, datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3], reason)
def send():
    # accept packets from 3 queues + simulate network link conditions for each dest
    # packets bound for destination are first delayed
    # after delay, packet may be dropped -> log event
    # if not dropped, send packet to network
    global current_packet, current_delay, current_nexthop

    # check if there is a packet being delayed
    if current_packet:
        if time.time() - current_delay >= current_nexthop['delay']/1000 :
            payload = current_packet[17:]
            packet_type, seq, payload_length = struct.unpack('!cII',payload[:9])
            if packet_type!=b'E' and packet_type!=b'R' and random.random() <= current_nexthop['loss_prob']:
                priority, src_ip, src_port, dst_ip, dst_port, length = struct.unpack('!c4sH4sHI', current_packet[:17])
                reason = "Loss event occured"
                logger.info("Source=(%s:%i) Destination=(%s:%i) Type=%c Priority=%c Payload Size=%i Time=%s Reason=%s",
                          socket.inet_ntoa(src_ip), int(src_port), socket.inet_ntoa(dst_ip), int(dst_port), packet_type.decode(), priority.decode(), length, datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3], reason)
            else:
                emulator.sendto(current_packet, (current_nexthop['nexthop'][0], current_nexthop['nexthop'][1]))
            
            # reset values
            current_packet = None
            current_delay = None
            current_nexthop = None
            return
    
    if not current_packet:
        (current_packet, current_nexthop) = get_priority_packet()
        if current_packet:
            current_delay = time.time()

def get_priority_packet():
    for priority_queue in [high_priority, med_priority, low_priority]:
        try:
            (packet, nexthop) = priority_queue.get_nowait()
            return (packet, nexthop)
        except Empty:
            continue
    return None, None


def main():
    global port, size, fwd_table_file, log_file, high_priority, med_priority, low_priority, emulator, logger
    parser = argparse.ArgumentParser(description="Parse command line arguments for emulator")

    parser.add_argument('-p','--port', type=int, required=True, help="Port of the emulator")
    parser.add_argument('-q','--queue_size', type=int, required=True, help="Size of each queue")
    parser.add_argument('-f', '--filename', type=str, required=True, help="Name of file containing static forwarding table")
    parser.add_argument('-l','--log',type=str, required=True, help="Name of the log file")

    args=parser.parse_args()

    port = args.port
    size = args.queue_size
    fwd_table_file = args.filename
    log_file = args.log

    high_priority = Queue(maxsize = size)
    med_priority = Queue(maxsize = size)
    low_priority = Queue(maxsize = size)

    emulator = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    emulator.bind(("",port))
    emulator.setblocking(False)

    logger = logging.getLogger()
    logging.basicConfig(filename=log_file, filemode='w', encoding='utf-8', level = logging.INFO)

    create_table()
   

if __name__ == "__main__":
    main()

