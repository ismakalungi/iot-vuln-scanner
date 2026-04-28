import click
import sys
import os

from .scanner import IoTDeviceScanner
from .reporter import generate_report
from .logger import iot_logger
from .config import SCAN_IP_RANGE, COMMON_IOT_PORTS, DEFAULT_CREDS_WORDLIST
from .discovery import get_ip_range_from_interface

@click.group()
def cli():
    """
    IoT Device Scanner CLI.
    Scans a network for IoT devices, open ports, and default credentials.
    """
    pass

@cli.command()
@click.option('--ip-range', '-i', default=SCAN_IP_RANGE,
              help=f'IP range to scan (e.g., 192.168.1.0/24, default: {SCAN_IP_RANGE}).')
@click.option('--ports', '-p', type=str, default='21,22,23,80,443,554,8080,8443,8888',
              help='Comma-separated list of ports to scan (default: common IoT ports).')
@click.option('--wordlist', '-w', type=click.Path(exists=True), default=DEFAULT_CREDS_WORDLIST,
              help=f'Path to a wordlist for default credential checks (default: {DEFAULT_CREDS_WORDLIST}).')
@click.option('--threads', '-t', type=int, default=20,
              help='Number of threads for concurrent scanning (default: 20).')
@click.option('--output-format', '-f', type=click.Choice(['console', 'json'], case_sensitive=False),
              default='console', help='Output format for the report.')
@click.option('--output-file', '-o', type=click.Path(),
              help='Save report to a file (e.g., report.json or report.txt).')
@click.option('--interface', '-if', type=str,
              help='Network interface to derive IP range from (e.g., eth0). Overrides --ip-range.')
def scan(ip_range, ports, wordlist, threads, output_format, output_file, interface):
    """
    Runs the IoT device scan.
    """
    iot_logger.info(f"[*] Starting IoT device scan for IP range: {ip_range}")

    if interface:
        derived_ip_range = get_ip_range_from_interface(interface)
        if derived_ip_range:
            ip_range = derived_ip_range
            iot_logger.info(f"[*] Derived IP range from interface {interface}: {ip_range}")
        else:
            click.echo(f"Error: Could not determine IP range from interface {interface}. Please specify --ip-range manually.", err=True)
            sys.exit(1)

    # Parse ports string into a list of integers
    ports_list = []
    try:
        ports_list = [int(p.strip()) for p in ports.split(',')]
    except ValueError:
        click.echo("Error: Invalid port format. Please use comma-separated integers.", err=True)
        sys.exit(1)

    scanner = IoTDeviceScanner(
        ip_range=ip_range,
        ports=ports_list,
        wordlist_path=wordlist,
        threads=threads
    )

    try:
        findings = scanner.run_scan()
        report = generate_report(findings, output_format)

        if output_file:
            try:
                with open(output_file, 'w') as f:
                    f.write(report)
                click.echo(f"\n[*] Report saved to: {output_file}")
            except IOError as e:
                iot_logger.error(f"Error: Could not write report to file {output_file}: {e}")
        else:
            click.echo(report)

    except Exception as e:
        iot_logger.critical(f"[CRITICAL] Scan failed: {e}")
        click.echo(f"Error: Scan failed: {e}", err=True)
        sys.exit(1)

    iot_logger.info("[*] IoT device scan finished.")

if __name__ == '__main__':
    cli()
