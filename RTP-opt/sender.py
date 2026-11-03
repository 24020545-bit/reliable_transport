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
    if len(packet) < PKT_HDR_LEN:
        return None, None

    hdr = PacketHeader(packet[:PKT_HDR_LEN])
    if len(packet) != PKT_HDR_LEN + hdr.length:
        return None, None

    body = packet[PKT_HDR_LEN:]
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
        target_addr = (receiver_ip, receiver_port)

        raw_data = sys.stdin.buffer.read()
        payload_blocks = [
            raw_data[idx:idx + MAX_BODY_BYTES]
            for idx in range(0, len(raw_data), MAX_BODY_BYTES)
        ]

        sock.sendto(make_packet(TYPE_START, 0), target_addr)

        while True:
            resp, _ = sock.recvfrom(MAX_PKT_BYTES)
            hdr, _ = parse_packet(resp)
            if hdr and hdr.type == TYPE_ACK and hdr.seq_num == 1:
                break

        data_pkts = {
            idx + 1: make_packet(TYPE_DATA, idx + 1, block)
            for idx, block in enumerate(payload_blocks)
        }

        total_pkts = len(payload_blocks)
        win_start, win_next = 1, 1
        ack_records = set()
        t_start = None

        def resend_unacked():
            for seq_idx in range(win_start, win_next):
                if seq_idx not in ack_records:
                    sock.sendto(data_pkts[seq_idx], target_addr)

        while win_start <= total_pkts:
            while win_next <= total_pkts and win_next < win_start + window_size:
                sock.sendto(data_pkts[win_next], target_addr)
                if t_start is None:
                    t_start = time.monotonic()
                win_next += 1

            t_remaining = RTO - (time.monotonic() - t_start)

            if t_remaining <= 0:
                resend_unacked()
                t_start = time.monotonic()
                continue

            sock.settimeout(t_remaining)

            try:
                resp, _ = sock.recvfrom(MAX_PKT_BYTES)
            except socket.timeout:
                resend_unacked()
                t_start = time.monotonic()
                continue

            hdr, _ = parse_packet(resp)

            if not hdr or hdr.type != TYPE_ACK:
                continue

            ack_id = hdr.seq_num

            if win_start <= ack_id < win_next:
                ack_records.add(ack_id)
                prev_start = win_start

                while win_start in ack_records:
                    ack_records.remove(win_start)
                    win_start += 1

                if win_start > prev_start:
                    t_start = time.monotonic() if win_start < win_next else None

        end_seq = total_pkts + 1
        sock.sendto(make_packet(TYPE_END, end_seq), target_addr)
        sock.settimeout(RTO)

        try:
            resp, _ = sock.recvfrom(MAX_PKT_BYTES)
            hdr, _ = parse_packet(resp)
            if hdr and hdr.type == TYPE_ACK and hdr.seq_num == end_seq + 1:
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