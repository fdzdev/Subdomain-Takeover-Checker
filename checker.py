import requests
import dns.resolver
import colorama
from colorama import Fore, Style
import concurrent.futures
from urllib.parse import urlparse

# Initialize colorama
colorama.init()

# Known vulnerable services (CNAMEs that often lead to subdomain takeovers)
VULNERABLE_CNAME_KEYWORDS = [
    "aws",
    "heroku",
    "github",
    "unbounce",
    "wordpress",
    "bitbucket",
    "shopify",
    "cloudfront",
    "fastly",
]

# Error messages that signal a subdomain takeover possibility
POTENTIAL_TAKEOVER_ERRORS = [
    "NoSuchBucket",
    "There isn’t a GitHub Pages site here.",
    "Unclaimed",
    "Domain is not configured",
    "The site you’re looking for can’t be found",
]


def check_subdomain_takeover(url):
    # Extract domain and subdomain
    parsed_url = urlparse(url)
    domain = parsed_url.netloc
    print(f"{Fore.CYAN}[*] Checking: {domain}{Style.RESET_ALL}")

    try:
        # Resolve DNS
        answers = dns.resolver.resolve(domain, "CNAME")
        for rdata in answers:
            cname = rdata.target.to_text()
            print(f"  {Fore.YELLOW}CNAME: {cname}{Style.RESET_ALL}")

            # Check if the CNAME points to a vulnerable service
            for keyword in VULNERABLE_CNAME_KEYWORDS:
                if keyword in cname.lower():
                    print(f"{Fore.RED}[!] Potential takeover: {cname}{Style.RESET_ALL}")
                    return test_for_takeover(url)
    except dns.resolver.NoAnswer:
        print(f"{Fore.MAGENTA}  [*] No CNAME found{Style.RESET_ALL}")
    except Exception as e:
        print(f"{Fore.RED}[!] Error resolving DNS: {e}{Style.RESET_ALL}")
    return False


def test_for_takeover(url):
    try:
        # Send a request to the subdomain
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
    return False


def analyze_urls(urls):
    with concurrent.futures.ThreadPoolExecutor() as executor:
        # Run subdomain takeover checks in parallel for speed
        executor.map(check_subdomain_takeover, urls)


# Prompt user to input list or use a predefined one
def get_url_list():
    user_choice = (
        input("Do you want to input the list of URLs? (y/n): ").strip().lower()
    )

    if user_choice == "y":
        urls = []
        print("Enter the URLs one by one (type 'done' when finished):")
        while True:
            url = input("URL: ").strip()
            if url == "done":
                break
            urls.append(url)
        return urls
    else:
        print("Using predefined list of URLs...")
        return ["tesla.com", "uoflang.com"]


# Main function
if __name__ == "__main__":
    # Get URLs from user or use predefined list
    urls = get_url_list()

    # Run the analysis
    analyze_urls(urls)
