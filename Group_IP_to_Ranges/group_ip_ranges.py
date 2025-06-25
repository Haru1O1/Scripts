import ipaddress
from itertools import groupby
from collections import defaultdict

def ip_sort_key(ip):
    return tuple(map(int, ip.split('.')))

def group_ips_by_prefix(ip_list):
    grouped = defaultdict(list)
    for ip in ip_list:
        prefix = '.'.join(ip.split('.')[:3])
        grouped[prefix].append(ip)
    return grouped

def format_grouped_ips(ip_list):
    """Format IPs into ranges like 10.12.10.11-13"""
    ip_list = sorted(ip_list, key=ip_sort_key)
    ip_nums = [int(ipaddress.IPv4Address(ip)) for ip in ip_list]

    results = []
    for _, group in groupby(enumerate(ip_nums), lambda x: x[1] - x[0]):
        block = list(group)
        start_ip = str(ipaddress.IPv4Address(block[0][1]))
        end_ip = str(ipaddress.IPv4Address(block[-1][1]))

        if start_ip == end_ip:
            results.append(start_ip)
        else:
            s_parts = start_ip.split('.')
            e_parts = end_ip.split('.')
            results.append(f"{'.'.join(s_parts[:3])}.{s_parts[3]}-{e_parts[3]}")
    return results

def process_ip_string(input_str):
    ip_entries = [ip.strip() for ip in input_str.split(',') if ip.strip()]
    ip_entries = sorted(ip_entries, key=ip_sort_key)

    grouped = group_ips_by_prefix(ip_entries)

    for prefix in sorted(grouped.keys(), key=lambda x: tuple(map(int, x.split('.')))):
        compacted = format_grouped_ips(grouped[prefix])
        print(f"{prefix}: {', '.join(compacted)}")

# Example usage
if __name__ == "__main__":
    input_ips = "10.10.1.1" # add ips
    process_ip_string(input_ips)
