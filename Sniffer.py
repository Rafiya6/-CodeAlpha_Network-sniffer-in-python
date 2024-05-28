import socket
import struct

# Create a raw socket and bind it to the public interface
def create_socket():
    conn = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
    return conn

# Unpack Ethernet frame
def ethernet_frame(data):
    dest_mac, src_mac, proto = struct.unpack('! 6s 6s H', data[:14])
    return get_mac_addr(dest_mac), get_mac_addr(src_mac), socket.htons(proto), data[14:]

# Format MAC address (AA:BB:CC:DD:EE:FF)
def get_mac_addr(bytes_addr):
    bytes_str = map('{:02x}'.format, bytes_addr)
    return ':'.join(bytes_str).upper()

# Unpack IPv4 packet
def ipv4_packet(data):
    version_header_length = data[0]
    version = version_header_length >> 4
    header_length = (version_header_length & 15) * 4
    ttl, proto, src, target = struct.unpack('! 8x B B 2x 4s 4s', data[:20])
    return version, header_length, ttl, proto, ipv4(src), ipv4(target), data[header_length:]

# Format IPv4 address (127.0.0.1)
def ipv4(addr):
    return '.'.join(map(str, addr))

# Unpack TCP segment
def tcp_segment(data):
    src_port, dest_port, sequence, acknowledgment, offset_reserved_flags = struct.unpack('! H H L L H', data[:14])
    offset = (offset_reserved_flags >> 12) * 4
    flags = {
        'URG': (offset_reserved_flags & 32) >> 5,
        'ACK': (offset_reserved_flags & 16) >> 4,
        'PSH': (offset_reserved_flags & 8) >> 3,
        'RST': (offset_reserved_flags & 4) >> 2,
        'SYN': (offset_reserved_flags & 2) >> 1,
        'FIN': offset_reserved_flags & 1,
    }
    return src_port, dest_port, sequence, acknowledgment, flags, data[offset:]

# Unpack UDP segment
def udp_segment(data):
    src_port, dest_port, size = struct.unpack('! H H 2x H', data[:8])
    return src_port, dest_port, size, data[8:]

# Main function
def main():
    conn = create_socket()
    while True:
        raw_data, addr = conn.recvfrom(65536)
        dest_mac, src_mac, eth_proto, data = ethernet_frame(raw_data)
        print('\nEthernet Frame:')
        print(f'Destination: {dest_mac}, Source: {src_mac}, Protocol: {eth_proto}')

        # IPv4
        if eth_proto == 8:
            (version, header_length, ttl, proto, src, target, data) = ipv4_packet(data)
            print('IPv4 Packet:')
            print(f'Version: {version}, Header Length: {header_length}, TTL: {ttl}')
            print(f'Protocol: {proto}, Source: {src}, Target: {target}')

            # TCP
            if proto == 6:
                (src_port, dest_port, sequence, acknowledgment, flags, data) = tcp_segment(data)
                print('TCP Segment:')
                print(f'Source Port: {src_port}, Destination Port: {dest_port}')
                print(f'Sequence: {sequence}, Acknowledgment: {acknowledgment}')
                print(f'Flags:')
                for flag in flags:
                    print(f'  {flag}: {flags[flag]}')

            # UDP
            elif proto == 17:
                src_port, dest_port, size, data = udp_segment(data)
                print('UDP Segment:')
                print(f'Source Port: {src_port}, Destination Port: {dest_port}, Length: {size}')

if __name__ == "__main__":
    main()
