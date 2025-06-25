import re
from collections import defaultdict

WINDOWS_SERVER_PATTERNS = {
    "Windows Server 2008 R2 Standard SP1": r"Windows Server\s+2008\s+R2\s+Standard(?:\s+\d+)?\s+Service\s+Pack\s+1",
    "Windows Server 2008 R2 Standard": r"Windows Server\s+2008\s+R2\s+Standard(?!.*Service\s+Pack)",

    "Windows Server 2008 R2 Enterprise SP1": r"Windows Server\s+2008\s+R2\s+Enterprise(?:\s+\d+)?\s+Service\s+Pack\s+1",
    "Windows Server 2008 R2 Enterprise": r"Windows Server\s+2008\s+R2\s+Enterprise(?!.*Service\s+Pack)",

    "Windows Server 2008 R2 Datacenter SP1": r"Windows Server\s+2008\s+R2\s+Datacenter(?:\s+\d+)?\s+Service\s+Pack\s+1",

    "Windows Server 2008 Standard SP2": r"Windows Server(?:®)?\s+2008\s+Standard(?:\s+\d+)?\s+Service\s+Pack\s+2",
    "Windows Server 2008 Standard SP1": r"Windows Server(?:®)?\s+2008\s+Standard(?:\s+\d+)?\s+Service\s+Pack\s+1",

    "Windows Server 2003 R2 SP2": r"Windows Server\s+2003\s+R2(?:\s+3790)?\s+Service\s+Pack\s+2",
    "Windows Server 2003 R2 SP1": r"Windows Server\s+2003\s+R2(?:\s+3790)?\s+Service\s+Pack\s+1",
    "Windows Server 2003 SP2": r"Windows Server\s+2003(?!\s+R2)(?:\s+3790)?\s+Service\s+Pack\s+2",
    "Windows Server 2003 SP1": r"Windows Server\s+2003(?!\s+R2)(?:\s+3790)?\s+Service\s+Pack\s+1",
}

def extract_ip(header_line):
    ip_match = re.search(r"\(([\d\.]+)\)", header_line)
    if ip_match:
        return ip_match.group(1)
    else:
        ip_match = re.search(r"Nmap scan report for ([\d\.]+)", header_line)
        return ip_match.group(1) if ip_match else "Unknown"

def load_nmap_file(file_path):
    try:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            return f.read()
    except FileNotFoundError:
        print(f"File not found: {file_path}")
        return None

def detect_windows_servers(nmap_data):
    grouped_ips = defaultdict(list)
    blocks = re.split(r"Nmap scan report for .+\n", nmap_data)
    headers = re.findall(r"Nmap scan report for .+", nmap_data)

    for i, block in enumerate(blocks[1:]):
        ip = extract_ip(headers[i])
        os_lines = re.findall(r"OS details: (.+)", block)
        os_guess_lines = re.findall(r"Running: (.+)", block)
        combined_text = " ".join([block] + os_lines + os_guess_lines)

        for name, pattern in WINDOWS_SERVER_PATTERNS.items():
            if re.search(pattern, combined_text, re.IGNORECASE):
                grouped_ips[name].append(ip)
                break
    return grouped_ips

def print_results(grouped_results):
    if not grouped_results:
        print("No legacy Windows Server systems found.\n")
        return
    for version, ips in grouped_results.items():
        if ips:
            count = len(ips)
            print(f"{version} ({count} hosts):")
            print(", ".join(ips))
            print()

def main():
    print("[+] Do you want to combine all results after loading all files? (yes/no)")
    combine_choice = input(">> ").strip().lower()
    combine_all = combine_choice == 'yes'

    combined_results = defaultdict(list)

    while True:
        print("\nEnter Nmap scan file path (or type 'quit' to finish):")
        file_path = input(">> ").strip()
        if file_path.lower() == 'quit':
            break

        nmap_data = load_nmap_file(file_path)
        if nmap_data is None:
            continue

        results = detect_windows_servers(nmap_data)

        if combine_all:
            for version, ips in results.items():
                combined_results[version].extend(ips)
        else:
            print(f"\nResults from file: {file_path}")
            print_results(results)

    if combine_all:
        print("\n[+] Combined results from all loaded files:\n")
        print_results(combined_results)

if __name__ == "__main__":
    main()
