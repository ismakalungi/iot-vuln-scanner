import unittest
from unittest.mock import patch, MagicMock, call, AsyncMock
import asyncio
import os
import socket
import paramiko

from iot_scanner.discovery import arp_scan, get_ip_range_from_interface
from iot_scanner.port_scan import tcp_connect_scan
from iot_scanner.checks import check_telnet_default_creds, check_ssh_default_creds, check_http_default_creds
from iot_scanner.scanner import IoTDeviceScanner
from iot_scanner.config import DEFAULT_CREDS_WORDLIST

class TestDiscovery(unittest.TestCase):

    def setUp(self):
        # Mock logger
        patch('iot_scanner.discovery.iot_logger').start()
        self.addCleanup(patch.stopall)

    @patch('iot_scanner.discovery.srp')
    def test_arp_scan_success(self, mock_srp):
        mock_answered = [
            (MagicMock(), MagicMock(psrc="192.168.1.10")),
            (MagicMock(), MagicMock(psrc="192.168.1.11"))
        ]
        mock_srp.return_value = (mock_answered, [])

        active_hosts = arp_scan("192.168.1.0/24")
        self.assertEqual(len(active_hosts), 2)
        self.assertIn("192.168.1.10", active_hosts)
        self.assertIn("192.168.1.11", active_hosts)

    @patch('iot_scanner.discovery.srp', side_effect=Exception("Scapy error"))
    def test_arp_scan_failure(self, mock_srp):
        active_hosts = arp_scan("192.168.1.0/24")
        self.assertEqual(len(active_hosts), 0)

    @patch('psutil.net_if_addrs')
    def test_get_ip_range_from_interface(self, mock_net_if_addrs):
        mock_net_if_addrs.return_value = {
            'eth0': [
                MagicMock(family=socket.AF_INET, address='192.168.1.5', netmask='255.255.255.0')
            ]
        }
        ip_range = get_ip_range_from_interface('eth0')
        self.assertEqual(ip_range, "192.168.1.0/24")

    @patch('psutil.net_if_addrs', return_value={})
    def test_get_ip_range_from_interface_not_found(self, mock_net_if_addrs):
        ip_range = get_ip_range_from_interface('nonexistent')
        self.assertIsNone(ip_range)

class TestPortScan(unittest.TestCase):

    def setUp(self):
        # Mock logger
        patch('iot_scanner.port_scan.iot_logger').start()
        self.addCleanup(patch.stopall)

    @patch('socket.socket')
    def test_tcp_connect_scan_open(self, mock_socket):
        mock_sock_instance = MagicMock()
        mock_socket.return_value = mock_sock_instance
        mock_sock_instance.connect.return_value = None
        mock_sock_instance.recv.return_value = b"HTTP/1.1 200 OK\r\n"

        status, banner = tcp_connect_scan("127.0.0.1", 80)
        self.assertEqual(status, "open")
        self.assertIn("HTTP/1.1 200 OK", banner)

    @patch('socket.socket')
    def test_tcp_connect_scan_closed(self, mock_socket):
        mock_sock_instance = MagicMock()
        mock_socket.return_value = mock_sock_instance
        mock_sock_instance.connect.side_effect = ConnectionRefusedError

        status, banner = tcp_connect_scan("127.0.0.1", 80)
        self.assertEqual(status, "closed")
        self.assertIsNone(banner)

    @patch('socket.socket')
    def test_tcp_connect_scan_filtered(self, mock_socket):
        mock_sock_instance = MagicMock()
        mock_socket.return_value = mock_sock_instance
        mock_sock_instance.connect.side_effect = socket.timeout

        status, banner = tcp_connect_scan("127.0.0.1", 80)
        self.assertEqual(status, "filtered")
        self.assertIsNone(banner)

class TestChecks(unittest.TestCase):

    def setUp(self):
        # Mock logger
        patch('iot_scanner.checks.iot_logger').start()
        self.addCleanup(patch.stopall)

    @patch('iot_scanner.checks.telnetlib3.open_connection')
    def test_check_telnet_default_creds_success(self, mock_open_conn):
        mock_reader = AsyncMock()
        mock_writer = MagicMock()
        mock_reader.readuntil = AsyncMock(side_effect=[b"login: ", b"Password: ", b"Welcome $"])
        mock_open_conn.return_value = (mock_reader, mock_writer)

        result = asyncio.get_event_loop().run_until_complete(
            check_telnet_default_creds("127.0.0.1", 23, "admin", "admin"))
        self.assertTrue(result)

    @patch('iot_scanner.checks.telnetlib3.open_connection', side_effect=Exception("Connection error"))
    def test_check_telnet_default_creds_failure(self, mock_open_conn):
        result = asyncio.get_event_loop().run_until_complete(
            check_telnet_default_creds("127.0.0.1", 23, "admin", "admin"))
        self.assertFalse(result)

    @patch('paramiko.SSHClient')
    def test_check_ssh_default_creds_success(self, mock_ssh_client_class):
        mock_ssh_client_instance = MagicMock()
        mock_ssh_client_class.return_value = mock_ssh_client_instance
        mock_ssh_client_instance.connect.return_value = None

        self.assertTrue(check_ssh_default_creds("127.0.0.1", 22, "root", "password"))

    @patch('paramiko.SSHClient')
    def test_check_ssh_default_creds_auth_failure(self, mock_ssh_client_class):
        mock_ssh_client_instance = MagicMock()
        mock_ssh_client_class.return_value = mock_ssh_client_instance
        mock_ssh_client_instance.connect.side_effect = paramiko.AuthenticationException

        self.assertFalse(check_ssh_default_creds("127.0.0.1", 22, "root", "password"))

    @patch('requests.get')
    def test_check_http_default_creds_success(self, mock_requests_get):
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_requests_get.return_value = mock_response

        self.assertTrue(check_http_default_creds("127.0.0.1", 80, "user", "pass"))

    @patch('requests.get')
    def test_check_http_default_creds_failure(self, mock_requests_get):
        mock_response = MagicMock()
        mock_response.status_code = 401 # Unauthorized
        mock_requests_get.return_value = mock_response

        self.assertFalse(check_http_default_creds("127.0.0.1", 80, "user", "pass"))

class TestIoTDeviceScanner(unittest.TestCase):

    def setUp(self):
        self.test_wordlist_path = "wordlists/test_creds.txt"
        os.makedirs("wordlists", exist_ok=True)
        with open(self.test_wordlist_path, 'w') as f:
            f.write("admin:admin\nroot:password\n")

        self.scanner = IoTDeviceScanner(
            ip_range="192.168.1.0/24",
            ports=[22, 23, 80],
            wordlist_path=self.test_wordlist_path,
            threads=1
        )
        # Mock logger
        patch('iot_scanner.scanner.iot_logger').start()
        self.addCleanup(patch.stopall)

    def tearDown(self):
        if os.path.exists(self.test_wordlist_path):
            os.remove(self.test_wordlist_path)
        if os.path.exists("wordlists") and not os.listdir("wordlists"):
            os.rmdir("wordlists")

    @patch('iot_scanner.scanner.arp_scan', return_value=["192.168.1.10"])
    @patch('iot_scanner.scanner.tcp_connect_scan', return_value=("open", "SSH-2.0-OpenSSH"))
    @patch('iot_scanner.scanner.check_ssh_default_creds', return_value=True)
    @patch('iot_scanner.scanner.check_telnet_default_creds', return_value=False)
    @patch('iot_scanner.scanner.check_http_default_creds', return_value=False)
    def test_run_scan_success(self, mock_http, mock_telnet, mock_ssh, mock_tcp_scan, mock_arp_scan):
        findings = self.scanner.run_scan()

        self.assertIn("192.168.1.10", findings['active_hosts'])
        self.assertEqual(len(findings['open_ports']), 1)
        self.assertEqual(findings['open_ports'][0]['host'], "192.168.1.10")
        self.assertEqual(findings['open_ports'][0]['ports'][0]['port'], 22)
        self.assertEqual(len(findings['vulnerable_creds']), 2) # admin:admin, root:password for SSH
        self.assertEqual(findings['vulnerable_creds'][0]['creds'], "admin:admin")
        self.assertEqual(findings['vulnerable_creds'][1]['creds'], "root:password")

if __name__ == '__main__':
    unittest.main()
