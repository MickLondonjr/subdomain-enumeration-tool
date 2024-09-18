import requests
import dns.resolver
import json
import csv
import logging
from concurrent.futures import ThreadPoolExecutor

# Set up logging
logging.basicConfig(filename='subdomain_enumeration.log', level=logging.INFO)


def dns_resolve(subdomain):
    """Resolve the IP addresses for a subdomain."""
    try:
        result = dns.resolver.resolve(subdomain, 'A')
        return [ip.address for ip in result]
    except dns.resolver.NoAnswer:
        print(f"[-] {subdomain} does not have an A record.")
        logging.error(f"{subdomain} does not have an A record.")
    except dns.resolver.NXDOMAIN:
        print(f"[-] {subdomain} does not exist.")
        logging.error(f"{subdomain} does not exist.")
    except Exception as e:
        print(f"[!] Error resolving {subdomain}: {str(e)}")
        logging.error(f"Error resolving {subdomain}: {str(e)}")
    return []


def get_cname(subdomain):
    """Retrieve the CNAME record of the subdomain."""
    try:
        answers = dns.resolver.resolve(subdomain, 'CNAME')
        for rdata in answers:
            return str(rdata.target)
    except dns.resolver.NoAnswer:
        return None
    except Exception as e:
        print(f"[!] Error retrieving CNAME for {subdomain}: {str(e)}")
        return None


def check_subdomain_takeover(subdomain):
    """Check for potential subdomain takeovers."""
    try:
        response = requests.get(f"http://{subdomain}", proxies={"http": None, "https": None}, timeout=10)
        if response.status_code == 200:
            if "There isn't a GitHub Pages site here." in response.text or "NoSuchBucket" in response.text:
                print(f"[!] Potential subdomain takeover vulnerability found on {subdomain}.")
                return "Potential Takeover"
            else:
                print(f"[+] {subdomain} is live but no takeover detected.")
                return "No Takeover Detected"
        elif response.status_code == 403:
            print(f"[-] {subdomain} returned status code 403 (Forbidden).")
            return "Forbidden"
        elif response.status_code == 404:
            print(f"[-] {subdomain} returned status code 404 (Not Found).")
            return "Not Found"
        else:
            print(f"[-] {subdomain} returned status code {response.status_code}.")
            return f"Status code {response.status_code}"
    except requests.exceptions.Timeout:
        print(f"[!] Timeout occurred when checking {subdomain} for takeover.")
        return "Timeout"
    except requests.exceptions.RequestException as e:
        print(f"[!] Error checking {subdomain} for takeover: {str(e)}")
        return "Error"


def check_https(subdomain):
    """Check for HTTPS support on the subdomain."""
    try:
        response = requests.get(f"https://{subdomain}", timeout=10)
        return response.status_code
    except Exception as e:
        print(f"[!] HTTPS check failed for {subdomain}: {str(e)}")
        return "No HTTPS"


def process_subdomain(subdomain):
    """Process each subdomain: resolve DNS, check for takeover."""
    print(f"[+] Checking subdomain: {subdomain}")
    ips = dns_resolve(subdomain)
    if ips:
        print(f"[+] {subdomain} is live, IP: {ips}")
        cname = get_cname(subdomain)
        if cname:
            print(f"[+] {subdomain} has a CNAME record: {cname}")
        takeover_status = check_subdomain_takeover(subdomain)
        return {
            "subdomain": subdomain,
            "ips": ips,
            "cname": cname,
            "takeover_status": takeover_status
        }
    else:
        print(f"[-] {subdomain} is not live or does not have a valid IP.")
        return None


def enumerate_subdomains(domain, subdomains):
    """Enumerate subdomains from a provided list."""
    subdomain_data = []

    with ThreadPoolExecutor(max_workers=10) as executor:
        future_to_subdomain = {executor.submit(process_subdomain, subdomain): subdomain for subdomain in subdomains}

        for future in future_to_subdomain:
            try:
                result = future.result()
                if result:
                    subdomain_data.append(result)
            except Exception as e:
                print(f"[!] Error processing subdomain: {e}")
                logging.error(f"Error processing subdomain: {e}")

    return subdomain_data


def save_to_json(subdomain_data, output_file):
    """Save the results to a JSON file."""
    with open(output_file, 'w') as f:
        json.dump(subdomain_data, f, indent=4)
    print(f"[+] Results saved to {output_file}")


def save_to_csv(subdomain_data, output_file):
    """Save the results to a CSV file."""
    with open(output_file, mode='w') as file:
        writer = csv.writer(file)
        writer.writerow(["Subdomain", "IPs", "CNAME", "Takeover Status"])
        for subdomain in subdomain_data:
            writer.writerow(
                [subdomain['subdomain'], ", ".join(subdomain['ips']), subdomain['cname'], subdomain['takeover_status']])
    print(f"[+] Results saved to {output_file}")


def load_subdomains_from_file(file_name):
    """Load subdomains from the file created by Sublist3r."""
    try:
        with open(file_name, 'r') as f:
            subdomains = [line.strip() for line in f if line.strip()]
        print(f"[+] Loaded {len(subdomains)} subdomains from {file_name}")
        return subdomains
    except FileNotFoundError:
        print(f"[!] File {file_name} not found.")
        return []


def main(domain):
    print(f"[+] Enumerating subdomains for: {domain}")

    # Generate file name that matches Sublist3r's output format: espn_subdomains.txt
    subdomain_file = f"{domain.replace('.', '_')}_subdomains.txt"

    # Load subdomains from the Sublist3r file
    subdomains = load_subdomains_from_file(subdomain_file)

    if subdomains:
        subdomain_data = enumerate_subdomains(domain, subdomains)

        # Save the results to a JSON file and CSV file
        json_output_file = f"{domain.replace('.', '_')}_subdomains.json"
        csv_output_file = f"{domain.replace('.', '_')}_subdomains.csv"

        save_to_json(subdomain_data, json_output_file)
        save_to_csv(subdomain_data, csv_output_file)
    else:
        print(f"[!] No subdomains found to process.")


if __name__ == "__main__":
    domain = input("Enter domain to scan: ")
    main(domain)
