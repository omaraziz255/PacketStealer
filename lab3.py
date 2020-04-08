import socket

TCP = 0x06

class IpPacket(object):
    """
    Represents the *required* data to be extracted from an IP packet.
    """

    def __init__(self, protocol, ihl, source_address, destination_address, payload):
        self.protocol = protocol
        self.ihl = ihl
        self.source_address = source_address
        self.destination_address = destination_address
        self.payload = payload


class TcpPacket(object):
    """
    Represents the *required* data to be extracted from a TCP packet.
    """

    def __init__(self, src_port, dst_port, data_offset, payload):
        self.src_port = src_port
        self.dst_port = dst_port
        # As far as I know, this field doesn't appear in Wireshark for some reason.
        self.data_offset = data_offset
        self.payload = payload


def parse_raw_ip_addr(raw_ip_addr: bytes) -> str:
    # Converts a byte-array IP address to a string
    # the input is on the form b'\xaa\xab'... a byte array
    return ".".join(str(byte) for byte in raw_ip_addr)


def parse_application_layer_packet(ip_packet_payload: bytes) -> TcpPacket:
    # Parses raw bytes of a TCP packet
    # That's a byte literal (~byte array) check resources section
    source = int.from_bytes(ip_packet_payload[0:2], byteorder='big', signed=False)
    destination = int.from_bytes(ip_packet_payload[2:4], byteorder='big', signed=False)
    offset = ip_packet_payload[12] >> 4
    payload = ip_packet_payload[offset*4:]
    return TcpPacket(source,destination,offset, payload)


def parse_network_layer_packet(ip_packet: bytes) -> IpPacket:
    # Parses raw bytes of an IPv4 packet
    # That's a byte literal (~byte array) check resources section
    IHL = ip_packet[0] & 0b00001111
    source = parse_raw_ip_addr(ip_packet[12:16])
    destination = parse_raw_ip_addr(ip_packet[16:20])
    protocol = ip_packet[9]
    payload = ip_packet[IHL*4:]

    return IpPacket(protocol, IHL, source, destination, payload)


def parse_stolen_packet(packet: bytes):
    ip_packet = parse_network_layer_packet(packet)
    if ip_packet.protocol != TCP:
        print("Received IP Packet is not TCP")
        return
    tcp_packet = parse_application_layer_packet(ip_packet.payload)
    try:
        print(tcp_packet.payload.decode('UTF-8'))
    except UnicodeError:
        print("Received TCP Packet is not HTTP")



def main():
    # Un-comment this line if you're getting too much noisy traffic.
    # to bind to an interface on your PC. (or you can simply disconnect from the internet)

    # iface_name = "lo"
    # stealer.setsockopt(socket.SOL_SOCKET,
    #                    socket.SO_BINDTODEVICE, bytes(iface_name, "ASCII"))
    stealer = socket.socket(socket.AF_INET, socket.SOCK_RAW, TCP)
    while True:
        # Receive packets and do processing here
        print("Listening For Packets")
        packet, addr = stealer.recvfrom(4096)
        parse_stolen_packet(packet)


if __name__ == "__main__":
    main()