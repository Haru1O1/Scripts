import re
from datetime import datetime
from pathlib import Path

def classify_severity(days_expired):
    if days_expired < 30:
        return "Low"
    elif days_expired < 180:
        return "Medium"
    elif days_expired < 365 * 2:
        return "High"
    else:
        return "Critical"

def parse_nmap_ssl_certs(nmap_output):
    expired_hosts = []
    current_ip = None
    current_port = None
    ssl_data = {}

    lines = nmap_output.splitlines()
    for i, line in enumerate(lines):
        line = line.strip()

        ip_match = re.match(r'Nmap scan report for ([\d.]+)', line)
        if ip_match:
            current_ip = ip_match.group(1)
            current_port = None
            continue

        port_match = re.match(r'(\d+)/tcp\s+open', line)
        if port_match:
            current_port = port_match.group(1)
            ssl_data = {}

        if "ssl-cert:" in line:
            j = i + 1
            while j < len(lines) and lines[j].strip().startswith("|"):
                ssl_line = lines[j].strip().lstrip('|').strip()
                if "Not valid before:" in ssl_line:
                    ssl_data['not_before'] = ssl_line.split(":", 1)[1].strip()
                elif "Not valid after:" in ssl_line:
                    ssl_data['not_after'] = ssl_line.split(":", 1)[1].strip()
                j += 1

            if 'not_after' in ssl_data:
                try:
                    expiry_date = datetime.strptime(ssl_data['not_after'], '%Y-%m-%dT%H:%M:%S')
                    if expiry_date < datetime.now():
                        days_expired = (datetime.now() - expiry_date).days
                        expired_hosts.append({
                            'ip': current_ip,
                            'port': current_port,
                            'expired_on': expiry_date.strftime('%Y-%m-%d'),
                            'days_expired': days_expired,
                            'severity': classify_severity(days_expired)
                        })
                except ValueError:
                    pass

    return expired_hosts

def print_expired_hosts(expired_hosts):
    if not expired_hosts:
        print("\nNo expired SSL certificates found.\n")
        return

    print("\nExpired SSL Certificates:\n" + "-" * 50)
    for host in expired_hosts:
        print(f"IP: {host['ip']}")
        print(f"Port: {host['port']}")
        print(f"Expired On: {host['expired_on']}")
        print(f"Expired For: {host['days_expired']} days")
        print(f"Severity: {host['severity']}\n")

def output_csv_format(all_results):
    if not all_results:
        print("No expired SSL certificates collected.")
        return

    print("\n Full Results seperated by commas:\n")
    print("IP,Port,Expired On,Days Expired,Severity")
    for r in all_results:
        print(f"{r['ip']},{r['port']},{r['expired_on']},{r['days_expired']},{r['severity']}")
    print("\n")

def main():
    print("=== SSL Certificate Expiry Checker ===\n")
    output_csv = input("Output results in Excel/Sheets-compatible format when done? (y/n): ").strip().lower() == 'y'

    all_results = []

    while True:
        file_input = input("\nEnter Nmap scan file path (or 'quit' to exit): ").strip()
        if file_input.lower() == 'quit':
            break

        file_path = Path(file_input)
        if not file_path.exists():
            print("File not found. Please try again.")
            continue

        try:
            with open(file_path, "r", encoding="utf-8") as f:
                nmap_data = f.read()
        except Exception as e:
            print(f"Error reading file: {e}")
            continue

        expired_hosts = parse_nmap_ssl_certs(nmap_data)
        print_expired_hosts(expired_hosts)
        all_results.extend(expired_hosts)

    if output_csv:
        output_csv_format(all_results)
    print("Done.")

if __name__ == "__main__":
    main()
