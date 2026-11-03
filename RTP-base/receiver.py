import argparse
import socket
import sys

from utils import PacketHeader, compute_checksum


HEADER_BYTES = 16
MAX_BUFFER = 1472

PKT_START, PKT_END, PKT_DATA, PKT_ACK = 0, 1, 2, 3


def make_packet(packet_type, seq_num, payload=b""):
    hdr = PacketHeader(
        type=packet_type,
        seq_num=seq_num,
        length=len(payload),
        checksum=0
    )
    hdr.checksum = compute_checksum(hdr / payload)
    return bytes(hdr / payload)


def parse_packet(packet):
    if len(packet) < HEADER_BYTES:
        return None, None

    hdr = PacketHeader(packet[:HEADER_BYTES])
    if len(packet) != HEADER_BYTES + hdr.length:
        return None, None

    body = packet[HEADER_BYTES:]
    orig_chksum = hdr.checksum
    hdr.checksum = 0

    if orig_chksum != compute_checksum(hdr / body):
        return None, None

    return hdr, body


def receiver(receiver_ip, receiver_port, window_size):
    if window_size < 1:
        raise ValueError("window_size must be positive")

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((receiver_ip, receiver_port))

    is_connected = False
    peer_addr = None
    next_seq = 1
    pkt_cache = {}

    def send_ack(seq_val):
        ack_pkt = make_packet(PKT_ACK, seq_val)
        sock.sendto(ack_pkt, peer_addr)

    try:
        while True:
            raw_pkt, addr = sock.recvfrom(MAX_BUFFER)
            hdr, body = parse_packet(raw_pkt)

            if not hdr:
                continue

            p_type, seq = hdr.type, hdr.seq_num

            if p_type == PKT_START:
                if not is_connected and seq == 0:
                    is_connected = True
                    peer_addr = addr
                    next_seq = 1
                    pkt_cache.clear()
                    send_ack(1)
                continue

            if not is_connected or addr != peer_addr:
                continue

            if p_type == PKT_DATA:
                if seq < next_seq + window_size:
                    if seq >= next_seq:
                        pkt_cache.setdefault(seq, body)

                        while next_seq in pkt_cache:
                            chunk = pkt_cache.pop(next_seq)
                            sys.stdout.buffer.write(chunk)
                            sys.stdout.buffer.flush()
                            next_seq += 1

                    send_ack(next_seq)

            elif p_type == PKT_END:
                if seq == next_seq:
                    send_ack(seq + 1)
                    break
                else:
                    send_ack(next_seq)

    finally:
        sock.close()


def main():

    parser = argparse.ArgumentParser()

    parser.add_argument(
        "receiver_ip",
        help="The IP address of the host that receiver is running on"
    )

    parser.add_argument(
        "receiver_port",
        type=int,
        help="The port number on which receiver is listening"
    )

    parser.add_argument(
        "window_size",
        type=int,
        help="Maximum number of outstanding packets"
    )

    args = parser.parse_args()

    receiver(
        args.receiver_ip,
        args.receiver_port,
        args.window_size
    )


if __name__ == "__main__":
    main()