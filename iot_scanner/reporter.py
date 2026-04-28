import json

def generate_report(findings: dict, output_format: str = "console") -> str:
    """
    Generates a human-readable report from the IoT device scan findings.

    Args:
        findings (dict): A dictionary containing scan results.
        output_format (str): The desired output format ('console' or 'json').

    Returns:
        str: The formatted report string.
    """
    if output_format == "json":
        return json.dumps(findings, indent=4)
    else:
        report_lines = []
        report_lines.append("\n--- IoT Device Scan Report ---")
        report_lines.append(f"Active Hosts Found: {len(findings.get('active_hosts', []))}")
        report_lines.append(f"Hosts with Open Ports: {len(findings.get('open_ports', []))}")
        report_lines.append(f"Vulnerable Credentials Found: {len(findings.get('vulnerable_creds', []))}")
        report_lines.append("------------------------------")

        if findings.get('active_hosts'):
            report_lines.append("\n[+] Active Hosts:")
            for host in sorted(findings['active_hosts']):
                report_lines.append(f"  - {host}")

        if findings.get('open_ports'):
            report_lines.append("\n[+] Open Ports Found:")
            for host_data in findings['open_ports']:
                report_lines.append(f"  Host: {host_data['host']}")
                for port_info in host_data['ports']:
                    report_lines.append(f"    - Port: {port_info['port']}/TCP, Banner: {port_info['banner'] if port_info['banner'] else 'N/A'}")

        if findings.get('vulnerable_creds'):
            report_lines.append("\n[!!!] Vulnerable Devices (Default Credentials Found):")
            for cred_finding in findings['vulnerable_creds']:
                report_lines.append(f"  Host: {cred_finding['host']}")
                report_lines.append(f"    - Service: {cred_finding['service']}, Port: {cred_finding['port']}")
                report_lines.append(f"      Credentials: {cred_finding['creds']}")
                report_lines.append("      Recommendation: Change default credentials immediately!")
        else:
            report_lines.append("\n[*] No default credentials found.")

        report_lines.append("\n--- End of Report ---")
        return "\n".join(report_lines)
