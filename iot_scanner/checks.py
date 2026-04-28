import asyncio
#import telnetlib3
import paramiko
import requests
from requests.auth import HTTPBasicAuth

from .logger import iot_logger

#async def check_telnet_default_creds(host: str, port: int, username: str, password: str, timeout: int = 5) -> bool:
#   """
#    Attempts to log into a Telnet service using provided credentials.
#
#    Returns:
#        bool: True if login is successful, False otherwise.
#    """
#    iot_logger.debug(f"[*] Telnet: Trying {username}:{password} on {host}:{port}")
#    try:
#        reader, writer = await asyncio.wait_for(
#            telnetlib3.open_connection(host, port), timeout=timeout
#        )
#        await reader.readuntil(b"login: ", timeout=timeout)
#        writer.write(username.encode('ascii') + b"\n")
#        await reader.readuntil(b"Password: ", timeout=timeout)
#        writer.write(password.encode('ascii') + b"\n")
#        result = await reader.readuntil(b"$", timeout=timeout)
#        writer.close()
#        if b"Login incorrect" not in result and b"Authentication failed" not in result:
#            iot_logger.info(f"[SUCCESS] Telnet: Default credentials {username}:{password} worked on {host}:{port}")
#            return True
#    except Exception as e:
#        iot_logger.debug(f"[FAIL] Telnet: {host}:{port} with {username}:{password} - {e}")
#    return False

def check_ssh_default_creds(host: str, port: int, username: str, password: str, timeout: int = 5) -> bool:
    """
    Attempts to log into an SSH service using provided credentials.

    Returns:
        bool: True if login is successful, False otherwise.
    """
    iot_logger.debug(f"[*] SSH: Trying {username}:{password} on {host}:{port}")
    try:
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        client.connect(hostname=host, port=port, username=username, password=password, timeout=timeout, look_for_keys=False, allow_agent=False)
        client.close()
        iot_logger.info(f"[SUCCESS] SSH: Default credentials {username}:{password} worked on {host}:{port}")
        return True
    except paramiko.AuthenticationException:
        iot_logger.debug(f"[FAIL] SSH: Authentication failed for {username}:{password} on {host}:{port}")
    except paramiko.SSHException as e:
        iot_logger.debug(f"[FAIL] SSH: {host}:{port} with {username}:{password} - {e}")
    except Exception as e:
        iot_logger.debug(f"[FAIL] SSH: {host}:{port} with {username}:{password} - {e}")
    return False

def check_http_default_creds(host: str, port: int, username: str, password: str, timeout: int = 5) -> bool:
    """
    Attempts to log into an HTTP service using basic authentication.

    Returns:
        bool: True if login is successful, False otherwise.
    """
    iot_logger.debug(f"[*] HTTP: Trying {username}:{password} on {host}:{port}")
    url = f"http://{host}:{port}"
    try:
        response = requests.get(url, auth=HTTPBasicAuth(username, password), timeout=timeout)
        if response.status_code == 200:
            iot_logger.info(f"[SUCCESS] HTTP: Default credentials {username}:{password} worked on {host}:{port}")
            return True
    except requests.exceptions.RequestException as e:
        iot_logger.debug(f"[FAIL] HTTP: {host}:{port} with {username}:{password} - {e}")
    return False
