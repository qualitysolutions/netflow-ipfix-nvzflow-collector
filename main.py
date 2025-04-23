#!/usr/bin/env python3

import argparse
import json
import logging
import queue
import signal
import socket
import socketserver
import threading
import time
from collections import namedtuple

from netflow.ipfix import IPFIXTemplateNotRecognized
from netflow.utils import UnknownExportVersion, parse_packet
from netflow.v9 import V9TemplateNotRecognized

RawPacket = namedtuple('RawPacket', ['ts', 'client', 'data'])
ParsedPacket = namedtuple('ParsedPacket', ['ts', 'client', 'export'])

PACKET_TIMEOUT = 60 * 60

logger = logging.getLogger("netflow-collector")
ch = logging.StreamHandler()
formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
ch.setFormatter(formatter)
logger.addHandler(ch)


class QueuingRequestHandler(socketserver.BaseRequestHandler):
    def handle(self):
        data = self.request[0]
        self.server.queue.put(RawPacket(time.time(), self.client_address, data))
        logger.debug("Received %d bytes of data from %s", len(data), self.client_address)


class QueuingUDPListener(socketserver.ThreadingUDPServer):
    def __init__(self, interface, queue):
        self.queue = queue
        if ":" in interface[0]:
            self.address_family = socket.AF_INET6
        super().__init__(interface, QueuingRequestHandler)


class ThreadedNetFlowListener(threading.Thread):
    def __init__(self, host: str, port: int):
        logger.info("Starting the NetFlow listener on {}:{}".format(host, port))
        self.output = queue.Queue()
        self.input = queue.Queue()
        self.server = QueuingUDPListener((host, port), self.input)
        self.thread = threading.Thread(target=self.server.serve_forever)
        self.thread.start()
        self._shutdown = threading.Event()
        super().__init__()

    def get(self, block=True, timeout=None) -> ParsedPacket:
        return self.output.get(block, timeout)

    def run(self):
        try:
            templates = {"netflow": {}, "ipfix": {}}
            to_retry = []
            while not self._shutdown.is_set():
                try:
                    pkt = self.input.get(block=True, timeout=0.5)
                except queue.Empty:
                    continue

                try:
                    export = parse_packet(pkt.data, templates)
                except UnknownExportVersion as e:
                    logger.error("%s, ignoring the packet", e)
                    continue
                except (V9TemplateNotRecognized, IPFIXTemplateNotRecognized):
                    if time.time() - pkt.ts > PACKET_TIMEOUT:
                        logger.warning("Dropping an old and undecodable v9/IPFIX ExportPacket")
                    else:
                        to_retry.append(pkt)
                        logger.debug("Failed to decode a v9/IPFIX ExportPacket - will re-attempt when a new template is discovered")
                    continue
                except ValueError as e:
                    logger.error("Failed to decode a packet: %s", e)
                    continue


                if export.header.version in [9, 10] and export.contains_new_templates and to_retry:
                    logger.debug("Received new template(s)")
                    for p in to_retry:
                        self.input.put(p)
                    to_retry.clear()

                self.output.put(ParsedPacket(pkt.ts, pkt.client, export))
        finally:
            self.server.shutdown()
            self.server.server_close()

    def stop(self):
        logger.info("Shutting down the NetFlow listener")
        self._shutdown.set()

    def join(self, timeout=None):
        self.thread.join(timeout=timeout)
        super().join(timeout=timeout)


def get_export_packets(host: str, port: int) -> ParsedPacket:
    def handle_signal(s, f):
        logger.debug("Received signal {}, raising StopIteration".format(s))
        raise StopIteration
    signal.signal(signal.SIGTERM, handle_signal)
    signal.signal(signal.SIGINT, handle_signal)

    listener = ThreadedNetFlowListener(host, port)
    listener.start()

    try:
        while True:
            yield listener.get()
    except StopIteration:
        pass
    finally:
        listener.stop()
        listener.join()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="QLS Netflow/IPFIX/nvzFlow collector.")
    parser.add_argument("--host", type=str, default="0.0.0.0", help="collector listening address")
    parser.add_argument("--port", "-p", type=int, default=2055, help="collector listener port")
    parser.add_argument("--debug", "-D", action="store_true", help="Enable debug output")
    args = parser.parse_args()

    protocol_numbers = {
        1: "ICMP",
        2: "IGMP",
        3: "GGP",
        4: "IPIP",
        5: "ST",
        6: "TCP",
        7: "CBT",
        8: "EGP",
        9: "IGP",
        10: "BBN-RCC",
        11: "NVP-II",
        12: "PUP",
        13: "ARGUS",
        14: "EMCON",
        15: "XNET",
        16: "CHAOS",
        17: "UDP",
        18: "MUX",
        19: "DCN-MEAS",
        20: "HMP",
        21: "PRM",
        22: "XNS-IDP",
        23: "TRUNK-1",
        24: "TRUNK-2",
        25: "LEAF-1",
        26: "LEAF-2",
        27: "RDP",
        28: "IRTP",
        29: "ISO-TP4",
        30: "NETBLT",
        31: "MFE-NSP",
        32: "MERIT-INP",
        33: "DCCP",
        34: "3PC",
        35: "IDPR",
        36: "XTP",
        37: "DDP",
        38: "IDPR-CMTP",
        39: "TP++",
        40: "IL",
        41: "IPv6",
        42: "SDRP",
        43: "IPv6-Route",
        44: "IPv6-Frag",
        45: "IDRP",
        46: "RSVP",
        47: "GRE",
        48: "DSR",
        49: "BNA",
        50: "ESP",
        51: "AH",
        52: "I-NLSP",
        53: "SWIPE",
        54: "NARP",
        55: "MOBILE",
        56: "TLSP",
        57: "SKIP",
        58: "IPv6-ICMP",
        59: "IPv6-NoNxt",
        60: "IPv6-Opts",
        61: "any host internal protocol",
        62: "CFTP",
        63: "any local network",
        64: "SAT-EXPAK",
        65: "KRYPTOLAN",
        66: "RVD",
        67: "IPPC",
        68: "any distributed file system",
        69: "SAT-MON",
        70: "VISA",
        71: "IPCU",
        72: "CPNX",
        73: "CPHB",
        74: "WSN",
        75: "PVP",
        76: "BR-SAT-MON",
        77: "SUN-ND",
        78: "WB-MON",
        79: "WB-EXPAK",
        80: "ISO-IP",
        81: "VMTP",
        82: "SECURE-VMTP",
        83: "VINES",
        84: "TTP",
        85: "NSFNET-IGP",
        86: "DGP",
        87: "TCF",
        88: "EIGRP",
        89: "OSPF",
        90: "Sprite-RPC",
        91: "LARP",
        92: "MTP",
        93: "AX.25",
        94: "OS",
        95: "MICP",
        96: "SCC-SP",
        97: "ETHERIP",
        98: "ENCAP",
        99: "any private encryption scheme",
        100: "GMTP",
        101: "IFMP",
        102: "PNNI",
        103: "PIM",
        104: "ARIS",
        105: "SCPS",
        106: "QNX",
        107: "A/N",
        108: "IPComp",
        109: "SNP",
        110: "Compaq-Peer",
        111: "IPX-in-IP",
        112: "VRRP",
        113: "PGM",
        114: "any 0-hop protocol",
        115: "L2TP",
        116: "DDX",
        117: "IATP",
        118: "STP",
        119: "SRP",
        120: "UTI",
        121: "SMP",
        122: "SM",
        123: "PTP",
        124: "ISIS over IPv4",
        125: "FIRE",
        126: "CRTP",
        127: "CRUDP",
        128: "SSCOPMCE",
        129: "IPLT",
        130: "SPS",
        131: "PIPE",
        132: "SCTP",
        133: "FC",
        134: "RSVP-E2E-IGNORE",
        135: "Mobility Header",
        136: "UDPLite",
        137: "MPLS-in-IP",
        138: "manet",
        139: "HIP",
        140: "Shim6",
        141: "WESP",
        142: "ROHC",
        143: "Ethernet",
        144: "ESP",
        145: "AH",
    }

    if args.debug:
        logger.setLevel(logging.DEBUG)
        ch.setLevel(logging.DEBUG)

    try:
        for ts, client, export in get_export_packets(args.host, args.port):
            exporter_ip = client[0]
            print(f"\n--- NetFlow Packet @ {time.ctime(ts)} from {client} ---")
            print("Header:")
            print(json.dumps(export.header.to_dict(), indent=2))
            print("Flows:")
            for flow in export.flows:
                if export.header.version == 9 and flow:
                    flow.data["PROTOCOL NAME"] = protocol_numbers.get(flow.data.get("PROTOCOL"), "Unknown")
                    flow.data["EXPORTER_IP"] = exporter_ip
                    IPV4_SRC = flow.data.get("IPV4_SRC_ADDR")
                    IPV4_DST = flow.data.get("IPV4_DST_ADDR")
                    PORT = flow.data.get("L4_SRC_PORT")
                    print(json.dumps(flow.data, indent=2))

                if export.header.version == 10:
                    print(json.dumps(flow.data, indent=2, ensure_ascii=False))

    except KeyboardInterrupt:
        logger.info("Received KeyboardInterrupt, exiting.")
