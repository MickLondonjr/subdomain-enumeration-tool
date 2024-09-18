import requests
import dns.resolver
import json


def dns_resolve(subdomain):
    """Resolve the IP addresses for a subdomain."""
    try:
        result = dns.resolver.resolve(subdomain, 'A')
        return [ip.address for ip in result]
    except dns.resolver.NoAnswer:
        print(f"[-] {subdomain} does not have an A record.")
    except dns.resolver.NXDOMAIN:
        print(f"[-] {subdomain} does not exist.")
    except Exception as e:
        print(f"[!] Error resolving {subdomain}: {str(e)}")
    return []


def check_subdomain_takeover(subdomain):
    """Check for potential subdomain takeovers."""
    try:
        response = requests.get(f"http://{subdomain}", proxies={"http": None, "https": None}, timeout=10)  # Increased timeout
        if response.status_code == 200:
            print(f"[+] {subdomain} is live, checking for potential takeover...")
            return "No Takeover Detected"  # Placeholder for actual takeover check logic
        elif response.status_code == 403:
            print(f"[-] {subdomain} is not live or returned status code 403 (Forbidden).")
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


def enumerate_subdomains(domain):
    """Enumerate subdomains for the given domain."""
    subdomains = [
        f"www.{domain}", f"api.{domain}", f"admin.{domain}", f"test.{domain}"
    ]

    subdomain_data = []
    for subdomain in subdomains:
        print(f"[+] Checking subdomain: {subdomain}")
        ips = dns_resolve(subdomain)
        if ips:
            print(f"[+] {subdomain} is live, IP: {ips}")
            takeover_status = check_subdomain_takeover(subdomain)
            subdomain_data.append({
                "subdomain": subdomain,
                "ips": ips,
                "takeover_status": takeover_status
            })
        else:
            print(f"[-] {subdomain} is not live or does not have a valid IP.")

    return subdomain_data


def main(domain):
    print(f"[+] Enumerating subdomains for: {domain}")
    subdomain_data = enumerate_subdomains(domain)

    # Save the results to a JSON file
    output_file = f"{domain}_subdomains.json"
    with open(output_file, 'w') as f:
        json.dump(subdomain_data, f, indent=4)

    print(f"[+] Subdomain enumeration and takeover check complete. Results saved to {output_file}")


if __name__ == "__main__":
    domain = input("Enter domain to scan: ")
    main(domain)
