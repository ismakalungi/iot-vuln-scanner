from scapy.all import ARP, Ether, srp
from concurrent.futures import ThreadPoolExecutor, as_completed
import ipaddress
import socket

from .logger import iot_logger

def arp_scan(ip_range: str, timeout: int = 1, threads: int = 10) -> list[str]:
    """
    Performs an ARP scan on the specified IP range to discover active hosts.

    Args:
        ip_range (str): The IP range to scan (e.g., "192.168.1.0/24").
        timeout (int): Timeout for ARP requests in seconds.
        threads (int): Number of threads for concurrent ARP requests.

    Returns:
        list: A list of active IP addresses found.
    """
    iot_logger.info(f"[*] Starting ARP scan on {ip_range}...")
    active_hosts = []

    try:
        arp_request = Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=ip_range)
        
        answered, _ = srp(arp_request, timeout=timeout, verbose=0, inter=0.1, retry=2)

        for sent, received in answered:
            active_hosts.append(received.psrc)

    except Exception as e:
        iot_logger.error(f"[ERROR] ARP scan failed: {e}")
        iot_logger.error("        Ensure you have sufficient permissions (e.g., run as root/administrator) and Scapy is correctly installed.")

    iot_logger.info(f"[+] ARP scan found {len(active_hosts)} active hosts.")
    return active_hosts

def get_ip_range_from_interface(interface: str) -> str | None:
    """
    Attempts to get the IP range (CIDR) of a given network interface.
    """
    try:
        import psutil
        addrs = psutil.net_if_addrs()
        if interface in addrs:
            for snicaddr in addrs[interface]:
                if snicaddr.family == socket.AF_INET:
                    # Construct CIDR from IP and netmask
                    ip_obj = ipaddress.IPv4Address(snicaddr.address)
                    netmask_obj = ipaddress.IPv4Address(snicaddr.netmask)
                    network = ipaddress.IPv4Network(f'{ip_obj}/{netmask_obj}', strict=False)
                    return str(network)
        return None
    except Exception as e:
        iot_logger.error(f"[ERROR] Could not determine IP range for interface {interface}: {e}")
        return None