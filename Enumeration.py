import requests
import builtwith
from urllib.parse import urlparse
import dns.resolver
import socket
import whois
import ssl
import re
import json
import os
import argparse
import subprocess
import signal
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor


dns.resolver.default_resolver = dns.resolver.Resolver()
dns.resolver.default_resolver.nameservers = ['8.8.8.8', '8.4.4.8']
dns.resolver.timeout = 3
dns.resolver.lifetime = 3


stop_flag = False

def handle_interrupt(signum, frame):
    global stop_flag
    print("\n[!] Interrupt received. Gracefully stopping...")
    stop_flag = True

signal.signal(signal.SIGINT, handle_interrupt)

class WebEnumerator:
    def __init__(self, url, ports, extract_emails=True):
        self.url = url if url.startswith(('http://', 'https://')) else 'https://' + url
        self.domain = self.get_domain()
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        self.domain_folder = os.path.join("info_collected", f"{self.domain}_{timestamp}")
        os.makedirs(self.domain_folder, exist_ok=True)
        self.port_input = ports
        self.stop_flag = stop_flag
        self.extract_emails_flag = extract_emails

    def get_domain(self):
        return self.url.split("//")[-1].split("/")[0]

    def detect_technologies(self):
        if self.stop_flag:
            return []
        tech_list = []
        try:
            technologies = builtwith.builtwith(self.url)
            file_path = os.path.join(self.domain_folder, "technologies.txt")
            with open(file_path, "w") as f:
                print("[+] Technologies used:")
                for category, values in technologies.items():
                    print(f"  {category}:")
                    f.write(f"{category}:\n")
                    for v in values:
                        print(f"    - {v}")
                        f.write(f"- {v}\n")
                        tech_list.append(v)
            with open("files/technologies.txt", "r") as wordlist_file:
                allowed_techs = [line.strip().lower() for line in wordlist_file if line.strip()]
            filtered = [t for t in tech_list if t.lower() in allowed_techs]
            return list(set(filtered))
        except Exception as e:
            print(f"[-] Technology detection failed: {e}")
            return []

    def search_exploits(self, tech):
        if self.stop_flag:
            return
        try:
            result = subprocess.run(["searchsploit", "--disable-colour", tech],
                                    stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)
            output = result.stdout.strip()
            path = os.path.join(self.domain_folder, f"{tech}_exploits.txt")
            with open(path, "w") as f:
                if output:
                    f.write(output + "\n")
                    print("[*] Found exploits:")
                    print(output)
                else:
                    f.write("No public exploits found.\n")
                    print("[*] No public exploits found.")
        except Exception as e:
            print(f"[-] Error searching exploits for {tech}: {e}")
            
    def fuzz_generic(self, wordlist_path, file_name, formatter):
        if self.stop_flag:
            return
        output_file = os.path.join(self.domain_folder, file_name)
        with open(wordlist_path, "r") as f:
            items = sorted(set(f.read().splitlines()))
        def worker(item):
            if self.stop_flag:
                return
            try:
                line, url = formatter(item)
                r = requests.get(url, timeout=5)
                if r.status_code not in [403, 404]:
                    print(line.strip())
                    with open(output_file, "a") as f_out:
                        f_out.write(line)
                    if self.extract_emails_flag:
                        self.extract_emails(url)
            except:
                pass
        with ThreadPoolExecutor(max_workers=20) as executor:
            executor.map(worker, items)

    def fuzz_directories(self):
        print("\n[*] Fuzzing directories...")
        for path in ["files/common.txt", "files/dir.txt"]:
            if os.path.exists(path):
                self.fuzz_generic(path, "fuzzing_dir.txt", lambda d: (
                    f"[DIR] [{200}] -- {self.url}/{d}\n", f"{self.url}/{d}"))

    def fuzz_subdomains(self):
        print("\n[*] Fuzzing subdomains...")
        base = self.domain.replace("www.", "")
        self.fuzz_generic("files/subdomains.txt", "fuzzing_subdomains.txt", lambda s: (
            f"[SUB] [200] -- https://{s}.{base}\n", f"https://{s}.{base}"))

    def fuzz_files(self):
        print("\n[*] Fuzzing files...")
        self.fuzz_generic("files/commonfile.txt", "fuzzing_files.txt", lambda f: (
            f"[FILE] [{200}] -- {self.url}/{f}\n", f"{self.url}/{f}"))

    def dns_enum(self):
        if self.stop_flag:
            return
        base = urlparse(self.url).netloc.replace("www.", "")
        result = f"DNS Records for {base}:\n"
        try:
            print(f"\n[DNS] Enumerating DNS records for {base}...")
            for rtype in ['A', 'AAAA', 'MX', 'NS']:
                answers = dns.resolver.resolve(base, rtype)
                for ans in answers:
                    line = f"{rtype}: {ans}\n"
                    print(f"  {line.strip()}")
                    result += line
            with open(os.path.join(self.domain_folder, "dns_records.txt"), "w") as f:
                f.write(result)
        except Exception as e:
            print(f"[-] DNS error: {e}")

    def port_scan(self):
        if self.stop_flag:
            return
        try:
            ip = socket.gethostbyname(self.domain)
            print(f"\n[*] Scanning ports for {self.domain} ({ip})...")
            output_file = os.path.join(self.domain_folder, "port_scan_results.txt")

            def scan(p):
                if self.stop_flag:
                    return
                try:
                    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    s.settimeout(0.5)
                    s.connect((ip, p))
                    service = socket.getservbyport(p)
                    line = f"[OPEN] Port {p} / {service}\n"
                    print(line.strip())
                    with open(output_file, "a") as f:
                        f.write(line)
                except:
                    pass
                finally:
                    s.close()

            with open(output_file, "w") as f:
                f.write(f"Port Scan Results for {self.domain}\n{'=' * 40}\n")

            if self.port_input.lower() in ["all", "65k"]:
                start_port, end_port = 1, 65535
            elif "-" in self.port_input:
                start_port, end_port = map(int, self.port_input.split("-"))
            else:
                start_port = end_port = int(self.port_input)

            print(f"[*] Scanning ports {start_port}-{end_port}...")
            with ThreadPoolExecutor(max_workers=500) as ex:
                ex.map(scan, range(start_port, end_port + 1))

            print("[+] Port scanning completed.")
        except socket.gaierror:
            print("[-] Port scan failed: Could not resolve hostname.")
        except Exception as e:
            print(f"[-] Port scan error: {e}")

    def is_valid_email(self, email):
        pattern = r'^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$'
        return re.match(pattern, email)

    def extract_emails(self, url):
        if self.stop_flag:
            return
        try:
            text = requests.get(url, timeout=5).text
            emails = set(re.findall(r'[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+', text))
            valid_emails = filter(self.is_valid_email, emails)
            path = os.path.join(self.domain_folder, "email_addresses.txt")
            with open(path, "a") as f:
                for email in valid_emails:
                    if any(x in email for x in ['..', 'font', 'css', 'woff', 'wght', 'http']):
                        continue
                    print(f"[EMAIL] {email}")
                    f.write(email + "\n")
        except:
            pass

    def get_whois_record(self):
        if self.stop_flag:
            return
        retries = 3
        for attempt in range(retries):
            try:
                info = whois.whois(self.domain)
                path = os.path.join(self.domain_folder, "whois_record.txt")
                with open(path, "w") as f:
                    f.write(str(info))
                print(f"\n[WHOIS] Retrieved WHOIS record for {self.domain}")
                print(f"Registrar: {info.registrar}")
                print(f"Creation Date: {info.creation_date}")
                print(f"Expiration Date: {info.expiration_date}")
                print(f"Name Servers: {', '.join(info.name_servers)}")
                break
            except whois.parser.PywhoisError:
                print("[-] WHOIS lookup failed: Domain does not exist or unsupported TLD")
                break
            except Exception as e:
                if attempt < retries - 1:
                    print(f"[-] WHOIS lookup failed (attempt {attempt + 1}), retrying...")
                else:
                    print(f"[-] WHOIS lookup failed after {retries} attempts: {e}")

    def get_ssl_certificate(self):
        if self.stop_flag:
            return
        try:
            ctx = ssl.create_default_context()
            with socket.create_connection((self.domain, 443)) as sock:
                with ctx.wrap_socket(sock, server_hostname=self.domain) as ssock:
                    cert = ssock.getpeercert()
            path = os.path.join(self.domain_folder, "ssl_certificate.txt")
            with open(path, "w") as f:
                f.write(json.dumps(cert, indent=4))
            print(f"\n[SSL] Retrieved certificate for {self.domain}")
        except Exception as e:
            print(f"[-] SSL cert error: {e}")

    def run(self):
        print("\n[+] Detecting technologies...")
        tech_list = self.detect_technologies()

        print("\n[+] Searching for exploits...")
        for tech in set(tech_list):
            if self.stop_flag:
                break
            self.search_exploits(tech)

        print("\n[+] Fuzzing directories...")
        self.fuzz_directories()

        print("\n[+] Fuzzing subdomains...")
        self.fuzz_subdomains()

        print("\n[+] Fuzzing files...")
        self.fuzz_files()

        print("\n[+] Enumerating DNS...")
        self.dns_enum()

        print("\n[+] Scanning ports...")
        self.port_scan()

        print("\n[+] Gathering WHOIS info...")
        self.get_whois_record()

        print("\n[+] Fetching SSL certificate...")
        self.get_ssl_certificate()

        print("\n All results saved under info_collected/")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Web Enumeration Tool")
    parser.add_argument("-u", "--url", required=True, help="Target URL (e.g., https://example.com )")
    parser.add_argument("-p", "--ports", default="1-1000", help="Port range (e.g., 1-65535, 80, all)")
    parser.add_argument("--no-emails", action="store_true", help="Disable email extraction for faster scan")
    args = parser.parse_args()
    tool = WebEnumerator(args.url, args.ports, extract_emails=not args.no_emails)
    tool.run()
