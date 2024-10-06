import dns.resolver
from colorama import Fore, Style


# New function to check NXDOMAIN for CNAMEs
def check_nxdomain(cnames):
    nxdomain_urls = []
    for cname in cnames:
        try:
            dns.resolver.resolve(cname, "A")  # Trying to resolve the CNAME
            print(
                f"{Fore.GREEN}[+] CNAME {cname} resolved successfully.{Style.RESET_ALL}"
            )
        except dns.resolver.NXDOMAIN:
            print(
                f"{Fore.RED}[!] NXDOMAIN error: {cname} does not exist.{Style.RESET_ALL}"
            )
            nxdomain_urls.append(cname)
        except dns.resolver.NoAnswer:
            print(f"{Fore.YELLOW}[!] No DNS answer for {cname}.{Style.RESET_ALL}")
        except dns.resolver.Timeout:
            print(
                f"{Fore.YELLOW}[!] DNS resolution timeout for {cname}.{Style.RESET_ALL}"
            )
        except Exception as e:
            print(f"{Fore.RED}[!] Error resolving {cname}: {e}{Style.RESET_ALL}")

    return nxdomain_urls


# Update the process_urls function to handle CNAMEs
def process_urls(cnames, nxdomain_file_name):
    nxdomain_urls = check_nxdomain(cnames)  # Check for NXDOMAIN errors

    # Log NXDOMAIN results if any
    if nxdomain_urls:
        with open(nxdomain_file_name, "w") as f:
            for url in nxdomain_urls:
                f.write(f"{url}\n")
        print(
            f"{Fore.RED}[!] NXDOMAIN URLs logged to {nxdomain_file_name}.{Style.RESET_ALL}"
        )
    else:
        print(f"{Fore.GREEN}No NXDOMAIN errors found.{Style.RESET_ALL}")

    return nxdomain_urls
