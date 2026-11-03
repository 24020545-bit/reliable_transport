import argparse
import socket
import sys
import time

from utils import PacketHeader, compute_checksum


PKT_HDR_LEN = 16
MAX_PKT_BYTES = 1472
MAX_BODY_BYTES = MAX_PKT_BYTES - PKT_HDR_LEN
RTO = 0.5

TYPE_START, TYPE_END, TYPE_DATA, TYPE_ACK = 0, 1, 2, 3


def build_pkt(p_type, seq, body=b""):
    hdr = PacketHeader(
        type=p_type,
        seq_num=seq,
        length=len(body),
        checksum=0
    )
    hdr.checksum = compute_checksum(hdr / body)
    return bytes(hdr / body)


def unpack_pkt(raw_bytes):
    if len(raw_bytes) < PKT_HDR_LEN:
        return None, None

    hdr = PacketHeader(raw_bytes[:PKT_HDR_LEN])
    if len(raw_bytes) != PKT_HDR_LEN + hdr.length:
        return None, None

    body = raw_bytes[PKT_HDR_LEN:]
    orig_chksum = hdr.checksum
    hdr.checksum = 0

    if orig_chksum != compute_checksum(hdr / body):
        return None, None

    return hdr, body


def sender(receiver_ip, receiver_port, window_size):
    if window_size < 1:
        raise ValueError("window_size must be positive")

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    try:
        dest_addr = (receiver_ip, receiver_port)

        stream = sys.stdin.buffer.read()
        chunks = [
            stream[idx:idx + MAX_BODY_BYTES]
            for idx in range(0, len(stream), MAX_BODY_BYTES)
        ]

        sock.sendto(build_pkt(TYPE_START, 0), dest_addr)

        while True:
            resp, _ = sock.recvfrom(MAX_PKT_BYTES)
            hdr, _ = unpack_pkt(resp)
            if hdr and hdr.type == TYPE_ACK and hdr.seq_num == 1:
                break

        pkt_store = {
            i + 1: build_pkt(TYPE_DATA, i + 1, chunk)
            for i, chunk in enumerate(chunks)
        }

        base, next_seq = 1, 1
        total_pkts = len(chunks)
        t_start = None

        def retransmit_window():
            for s_idx in range(base, next_seq):
                sock.sendto(pkt_store[s_idx], dest_addr)

        while base <= total_pkts:
            while next_seq <= total_pkts and next_seq < base + window_size:
                sock.sendto(pkt_store[next_seq], dest_addr)
                if t_start is None:
                    t_start = time.monotonic()
                next_seq += 1

            time_left = RTO - (time.monotonic() - t_start)

            if time_left <= 0:
                retransmit_window()
                t_start = time.monotonic()
                continue

            sock.settimeout(time_left)

            try:
                resp, _ = sock.recvfrom(MAX_PKT_BYTES)
            except socket.timeout:
                retransmit_window()
                t_start = time.monotonic()
                continue

            hdr, _ = unpack_pkt(resp)

            if not hdr or hdr.type != TYPE_ACK:
                continue

            ack_num = hdr.seq_num

            if base < ack_num <= next_seq:
                base = ack_num
                t_start = time.monotonic() if base < next_seq else None

        fin_seq = total_pkts + 1
        sock.sendto(build_pkt(TYPE_END, fin_seq), dest_addr)
        sock.settimeout(RTO)

        try:
            resp, _ = sock.recvfrom(MAX_PKT_BYTES)
            hdr, _ = unpack_pkt(resp)
            if hdr and hdr.type == TYPE_ACK and hdr.seq_num == fin_seq + 1:
                pass
        except socket.timeout:
            pass

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

    sender(
        args.receiver_ip,
        args.receiver_port,
        args.window_size
    )


if __name__ == "__main__":
    main()