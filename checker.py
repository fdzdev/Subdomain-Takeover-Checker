import requests
import dns.resolver
import colorama
from colorama import Fore, Style
import concurrent.futures
import argparse
from urllib.parse import urlparse
import time
import os
import sys
from finder import process_urls  # from finder.py file function process_urls

colorama.init()


def load_keywords_from_file(file_path):
    try:
        with open(file_path, "r") as f:
            domains = [
                line.strip()
                for line in f
                if not line.strip().startswith("*") and line.strip()
            ]
        return domains
    except Exception as e:
        print(f"Error reading file: {e}")
        sys.exit(1)
    except KeyboardInterrupt:
        print("Stopped by user")
        sys.exit(1)


# Known vulnerable services
VULNERABLE_CNAME_KEYWORDS = load_keywords_from_file("keywords.txt")

# Error messages that signal a subdomain takeover possibility
POTENTIAL_TAKEOVER_ERRORS = [
    "NoSuchBucket",
    "There isn’t a GitHub Pages site here.",
    "Unclaimed",
    "Domain is not configured",
    "The site you’re looking for can’t be found",
]


def check_subdomain_takeover(url):
    parsed_url = urlparse(url)
    domain = parsed_url.netloc or parsed_url.path  # Handle URLs without scheme
    result = {"url": url, "vulnerable": False, "error": None, "cname": None}

    try:
        answers = dns.resolver.resolve(domain, "CNAME")
        cname_found = False  # Flag to check if CNAME is found

        for rdata in answers:
            cname = rdata.target.to_text()
            cname_found = True
            result["cname"] = cname
            print(f"{Fore.YELLOW}CNAME: {cname}{Style.RESET_ALL}")

            for keyword in VULNERABLE_CNAME_KEYWORDS:
                if keyword in cname.lower():
                    print(f"{Fore.RED}[!] Potential takeover: {cname}{Style.RESET_ALL}")
                    result["vulnerable"] = True
                    break

        if not cname_found:
            print(
                f"{Fore.MAGENTA}  [*] No CNAME records found for {domain}{Style.RESET_ALL}"
            )

    except dns.resolver.NoAnswer:
        print(f"{Fore.MAGENTA}  [*] No CNAME found for {domain}{Style.RESET_ALL}")
    except Exception as e:
        result["error"] = str(e)
        print(f"{Fore.RED}[!] Error resolving DNS for {domain}: {e}{Style.RESET_ALL}")
    except KeyboardInterrupt:
        print("Stopped by user")
        return None  # Return None so that it can be handled in analyze_urls!!
    return result


def test_for_takeover(url):
    try:
        response = requests.get(url)
        for error in POTENTIAL_TAKEOVER_ERRORS:
            if error in response.text:
                print(
                    f"{Fore.GREEN}[+] Subdomain takeover possible: {url}{Style.RESET_ALL}"
                )
                return True
        print(f"{Fore.MAGENTA}[-] No takeover detected on: {url}{Style.RESET_ALL}")
    except requests.exceptions.RequestException as e:
        print(f"{Fore.RED}[!] Error accessing {url}: {e}{Style.RESET_ALL}")
    except KeyboardInterrupt:
        print("Stopped by user")
        return None
    return False


def analyze_urls(urls):
    results = []
    unique_cnames = {}
    total_urls = len(urls)

    with concurrent.futures.ThreadPoolExecutor() as executor:
        future_to_url = {
            executor.submit(check_subdomain_takeover, url): url for url in urls
        }

        for i, future in enumerate(
            concurrent.futures.as_completed(future_to_url), start=1
        ):
            url = future_to_url[future]
            try:
                result = future.result()
                if result:
                    results.append(result)

                    # Collect unique CNAMEs with their associated URLs
                    if result["cname"]:
                        unique_cnames[result["cname"]] = result["url"]

                print(
                    f"Progress: {Fore.CYAN}{i}/{total_urls}{Style.RESET_ALL} URLs checked."
                )
            except KeyboardInterrupt:
                print(f"{Fore.RED}[!] Process interrupted by user{Style.RESET_ALL}")
                break

    return results, unique_cnames


def load_urls_from_file(file_path):
    try:
        with open(file_path, "r") as f:
            domains = [
                line.strip()
                for line in f
                if not line.strip().startswith("*") and line.strip()
            ]
        return domains
    except Exception as e:
        print(f"Error reading file: {e}")
        sys.exit(1)
    except KeyboardInterrupt:
        print("Stopped by user")
        sys.exit(1)


def log_results(results, unique_cnames, log_file="results.log"):
    # Ensure the Full Reports directory exists
    os.makedirs("Full Reports", exist_ok=True)

    log_file_path = os.path.join("Full Reports", log_file)

    with open(log_file_path, "a") as f:  # Open the file in append mode ('a')
        f.write("\n" + "=" * 40 + "\n")
        f.write("New Log Entry\n")
        f.write("=" * 40 + "\n")

        #  unique CNAMEs at the top
        f.write("Unique CNAMEs and their associated URLs:\n")
        f.write("=" * 40 + "\n")
        for cname, url in unique_cnames.items():
            f.write(f"CNAME: {cname}, URL: {url}\n")
        f.write("\nSubdomain Takeover Check Results\n")
        f.write("=" * 40 + "\n")

        for result in results:
            if result["vulnerable"]:
                f.write(f"[!] Vulnerable: {result['url']} (CNAME: {result['cname']})\n")
            elif result["error"]:
                f.write(f"[!] Error: {result['url']} - {result['error']}\n")
            else:
                f.write(f"[-] No takeover detected: {result['url']}\n")

    print(f"Results successfully appended to {log_file_path}")


def log_cnames_to_txt(unique_cnames, log_file="cname_txt.log"):
    # Ensure the CNAME Reports directory exists
    os.makedirs("CNAME Reports", exist_ok=True)

    log_file_path = os.path.join("CNAME Reports", log_file)

    with open(log_file_path, "w") as f:
        for cname in unique_cnames:
            f.write(f"{cname}\n")
    print(f"Unique CNAMEs successfully logged to {log_file_path}")


def main():
    parser = argparse.ArgumentParser(description="Check for subdomain takeovers.")
    parser.add_argument("-d", "--domain", type=str, help="Single domain to check")
    parser.add_argument(
        "-l", "--list", type=str, help="File containing list of domains to check"
    )

    args = parser.parse_args()

    urls = []

    if args.domain:
        urls.append(args.domain)

    if args.list:
        urls.extend(load_urls_from_file(args.list))

    if not urls:
        print(f"{Fore.RED}No URLs provided for scanning.{Style.RESET_ALL}")
        return

    # Create directories if they do not exist
    os.makedirs("Full Reports", exist_ok=True)
    os.makedirs("cname reports", exist_ok=True)

    log_file_name = (
        f"LIVEREPORT_{os.path.basename(args.list)}" if args.list else "results.log"
    )
    log_cname_name = (
        f"CNAME_{os.path.basename(args.list)}" if args.list else "cname_txt.log"
    )

    # Analyze URLs for subdomain takeover
    results, unique_cnames = analyze_urls(urls)

    log_results(results, unique_cnames, log_file=log_file_name)
    log_cnames_to_txt(unique_cnames, log_file=log_cname_name)

    # Prepare to check NXDOMAIN for the unique CNAMEs
    nxdomain_file_name = (
        f"cname reports/NXD_{os.path.basename(args.list)}"
        if args.list
        else "cname reports/NXD_results.log"
    )
    nxdomain_urls = process_urls(unique_cnames.values(), nxdomain_file_name)

    # Print NXDOMAIN results to the bottom of the screen
    if nxdomain_urls:
        print(f"\n{Fore.RED}NXDOMAIN URLs found:")
        for url in nxdomain_urls:
            print(url)
    else:
        print(Fore.GREEN + "\nNo NXDOMAIN URLs found.")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(
            f"{Fore.RED}\n[!] Program interrupted by user. Exiting...{Style.RESET_ALL}"
        )
        sys.exit(0)
