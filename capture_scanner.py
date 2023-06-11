
import os
from dataclasses import dataclass
from typing import Tuple
from scapy.all import PcapNgReader, Dot11, Dot11Elt, Dot11FCS
import networkx as nx
import pickle

# https://en.wikipedia.org/wiki/Multicast_address#Ethernet
MULTICAST_BLOCKS = ("ff:ff:ff:ff:ff:ff", "00:00:00:00:00:00", "01:80:c2", "01:1b:19", "01:00:5e",
                    "33:33", "01:0c:cd", "01:00:0c")

# all devices connected to this bssid have randomized mac
# addresses for almost every packet. No need to clutter
# the graph with it
BAD_APPLE_MAC_ADDRESS = "00:25:00:ff:94:73"


@dataclass()
class AccessPoint:
    bssid: str
    ssid: str = ""

    def __hash__(self) -> int:
        return hash((self.bssid))

    def __eq__(self, __value: object) -> bool:

        return isinstance(__value, AccessPoint) and self.bssid == __value.bssid


@dataclass(frozen=True)
class Device:
    mac_address: str


def is_laa(addr: str) -> bool:
    '''check if mac addr is a locally administered address (laa)
    lla has 2nd LSB of first byte on'''
    return bool(int(addr[:2], 16) & 0b10)


def is_valid_addr(addr: str) -> bool:
    return all([not addr.startswith(block) for block in MULTICAST_BLOCKS]) \
        and BAD_APPLE_MAC_ADDRESS


def is_control_packet(packet: Dot11FCS) -> bool:
    return packet.type == 1


def is_probe_request(packet: Dot11FCS) -> bool:
    return packet.type == 0 and packet.subtype == 4


def add_ap_with_ssid_to_graph(graph: nx.DiGraph, dot11: Dot11) -> None:
    ssid = dot11[Dot11Elt].info.decode('utf-8')
    bssid = dot11.addr3
    for node in graph.nodes:
        if node == AccessPoint(bssid):
            node.ssid = ssid
            break
    else:
        graph.add_node(AccessPoint(bssid, ssid))


def get_addresses_from_packet(dot11: Dot11) -> Tuple[str, str, str]:
    # from the IEEE802.11-2020 spec. Screenshot at https://imgur.com/a/htyn5lF
    match dot11.FCfield & 0b00000011:
        case 0b00:  # from ds = 0 to ds = 0
            bssid = dot11.addr3
            destination = dot11.addr1
            source = dot11.addr2
        case 0b01:  # from ds = 0 to ds = 1
            bssid = dot11.addr1
            destination = dot11.addr3
            source = dot11.addr2
        case 0b10:  # from ds = 1 to ds = 0
            bssid = dot11.addr2
            destination = dot11.addr1
            source = dot11.addr3
        case 0b11:  # from ds = 1 to ds = 1
            return (None, None, None)  # I've never captured a packet like this
    return (bssid, destination, source)


def add_device_and_ap_to_graph(graph: nx.DiGraph, dot11: Dot11) -> None:
    bssid, destination, source = get_addresses_from_packet(dot11)
    if None in (bssid, destination, source):
        return

    if is_valid_addr(bssid) and bssid != BAD_APPLE_MAC_ADDRESS:
        access_point = AccessPoint(bssid)
        graph.add_node(access_point)

        if is_valid_addr(destination) and destination != bssid and not is_laa(destination):
            destination_node = Device(destination)
            graph.add_node(destination_node)
            graph.add_edge(access_point, destination_node)
        if is_valid_addr(source) and source != bssid and not is_laa(source):
            source_node = Device(source)
            graph.add_node(source_node)
            graph.add_edge(access_point, source_node)


def generate_network(pcapng_file: str) -> nx.DiGraph:
    graph = nx.DiGraph()

    with PcapNgReader(pcapng_file) as pcapng_reader:
        for i, packet in enumerate(pcapng_reader):
            if packet.haslayer(Dot11):
                dot11 = packet[Dot11]
                # Beacon frame, Probe Response
                if dot11.type == 0 and dot11.subtype in (8, 5):
                    add_ap_with_ssid_to_graph(graph, dot11)

                # control packets and probe requests don't have a bssid
                elif (not is_control_packet(dot11) and not is_probe_request(dot11)):
                    add_device_and_ap_to_graph(graph, dot11)

    return graph


def get_pickle_fname(pcapng_file: str) -> str:
    return os.path.splitext(pcapng_file)[0] + ".pickle"


def load_networks(pcapng_file: str) -> nx.DiGraph():
    """
    Load the networks network graph array from disk, or generate it if it doesn't exist.
    Caution: There is no security built in to this, verify the pickle file yourself.
    """
    pickle_fname = get_pickle_fname(pcapng_file)
    try:
        with open(pickle_fname, 'rb') as f:
            network_graph = pickle.load(f)
    except (FileNotFoundError, pickle.UnpicklingError):
        network_graph = generate_network(pcapng_file)

        with open(pickle_fname, 'wb') as f:
            pickle.dump(network_graph, f)
    return network_graph


if __name__ == "__main__":
    pcapng_file = "test.pcapng"
    pickle_fname = get_pickle_fname(pcapng_file)
    if os.path.isfile(pickle_fname):
        os.remove(pickle_fname)
    print(load_networks(pcapng_file))
