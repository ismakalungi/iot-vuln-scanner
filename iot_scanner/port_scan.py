import socket
import time

from .logger import iot_logger

def tcp_connect_scan(host: str, port: int, timeout: int = 1) -> tuple[str, str | None]:
    """
    Performs a TCP Connect scan on the specified port and attempts to grab a banner.

    Args:
        host (str): The target IP address.
        port (int): The port to scan.
        timeout (int): Socket timeout in seconds.

    Returns:
        tuple: (status, banner) where status is 'open', 'closed', 'filtered', or 'error'.
               banner is the service banner if available, else None.
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    status = "error"
    banner = None
    try:
        sock.connect((host, port))
        status = "open"
        # Attempt to grab banner
        try:
            sock.send(b"\r\n\r\n") # Send some data to provoke a banner
            banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
            banner = banner.split('\n')[0] # Take first line
        except socket.timeout:
            banner = "No banner (timeout)"
        except Exception:
            banner = "No banner"

    except socket.timeout:
        status = "filtered" # Timeout usually means filtered
    except ConnectionRefusedError:
        status = "closed"
    except Exception as e:
        iot_logger.debug(f"[ERROR] TCP Connect scan for {host}:{port} failed: {e}")
        status = "error"
    finally:
        sock.close()
    
    iot_logger.debug(f"[SCAN] {host}:{port} -> {status} (Banner: {banner})")
    return status, banner
