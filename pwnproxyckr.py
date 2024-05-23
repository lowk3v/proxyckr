#!/usr/bin/env python3
import ipaddress, sys, socket, click, re, requests
from concurrent.futures import ThreadPoolExecutor

CLOUDFLARE_CIDR_API = "https://www.cloudflare.com/ips-v4"
CLOUDFRONT_CIDR_API = "https://d7uri8nf7uskq.cloudfront.net/tools/list-cloudfront-ips"

IP_PATTERN = re.compile(
    r"\b(?:(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])\.){3}(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])\b"
)
DOMAIN_PATTERN = re.compile(
    r"(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9][a-z0-9-]{0,61}[a-z0-9]"
)

def fetch_cidrs(api_url, parser_func):
    response = requests.get(api_url)
    return parser_func(response)

def parse_cloudfront_cidrs(response):
    cidr_data = response.json()
    return cidr_data.get("CLOUDFRONT_GLOBAL_IP_LIST", []) + cidr_data.get("CLOUDFRONT_REGIONAL_EDGE_IP_LIST", [])

def parse_cloudflare_cidrs(response):
    return response.text.strip().split("\n")

def build_networks():
    """
    Build network objects from CloudFront and Cloudflare CIDR blocks.
    """
    cloudfront_cidrs = fetch_cidrs(CLOUDFRONT_CIDR_API, parse_cloudfront_cidrs)
    cloudflare_cidrs = fetch_cidrs(CLOUDFLARE_CIDR_API, parse_cloudflare_cidrs)
    return [ipaddress.ip_network(cidr, strict=False) for cidr in cloudfront_cidrs + cloudflare_cidrs]

NETWORKS = build_networks()

def is_ip_in_cdn(ip_address) -> bool:
    """
    Check if the given IP address belongs to the predefined CDN networks.
    """
    ip = ipaddress.ip_address(ip_address)
    return any(ip in network for network in NETWORKS)

def check_domain_cdn_status(domain_name):
    """
    Resolve the domain name to its IP addresses and check each IP address against CDN networks.
    """
    try:
        ips = socket.gethostbyname_ex(domain_name)[2]
        for ip in ips:
            report_cdn_status(is_ip_in_cdn(ip), ip, domain_name)
    except socket.error:
        pass

def check_ip_cdn_status(ip):
    """
    Try to resolve the reverse DNS for the given IP address and check it against CDN networks.
    """
    try:
        domain_name, _, _ = socket.gethostbyaddr(ip)
        report_cdn_status(is_ip_in_cdn(ip), ip, domain_name)
    except socket.error:
        pass

@click.command()
@click.option("-t", "--threads", default=20, help="Number of threads")
def process_input(threads):
    """
    Process input from standard input, determine if each line is an IP or domain,
    and check if it is served through Cloudflare or CloudFront.
    """
    with ThreadPoolExecutor(max_workers=threads) as executor:
        for line in sys.stdin:
            clean_line = line.strip().replace("https://", "").replace("http://", "")
            if IP_PATTERN.fullmatch(clean_line):
                check_ip_cdn_status(clean_line)
            elif DOMAIN_PATTERN.fullmatch(clean_line):
                executor.submit(check_domain_cdn_status, clean_line)
            else:
                print(f"Only IP and Domain Name are supported [{clean_line}]")

def report_cdn_status(is_proxied, ip, domain=None):
    """
    Print the CDN status of the given IP address and/or domain name.
    """
    reset = "\033[0m"
    orange = "\033[33m"
    green = "\033[32m"
    blue = "\033[34m"
    purple = "\033[35m"

    status = f"{orange}🟠 Proxied{reset}" if is_proxied else f"{green}🟢 Not Proxied{reset}"
    ip_colored = f"{blue}{ip}{reset}"
    if domain:
        domain_colored = f"{purple}{domain}{reset}"
        print(f"{status} [{ip_colored}] [{domain_colored}]")
    else:
        print(f"{status} [{ip_colored}]")

if __name__ == "__main__":
    process_input()
