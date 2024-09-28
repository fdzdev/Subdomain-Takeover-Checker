# Subdomain Takeover Checker

A Python script to analyze URLs for potential subdomain takeover vulnerabilities. The script checks the CNAME records of provided subdomains against a list of known vulnerable services and sends requests to determine if the subdomain is vulnerable to takeover.

## Features

- Check CNAME records of subdomains for vulnerable services (e.g., AWS, GitHub Pages).
- Analyze the response from the server to detect potential takeover vulnerabilities.
- Supports user input for custom URLs or utilizes a pre-defined list.
- Runs checks in parallel for faster processing.

## Requirements

- Python 3.x
- `requests` library
- `dnspython` library
- `colorama` library

## Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/yourusername/subdomain-takeover-checker.git
2. Navigate to the directory:
   ```bash
   cd subdomain-takeover-checker
3. Install the required libraries:
   ```bash
   pip install requests dnspython colorama

## Usage


Run the script with Python:

```bash
python subdomain_takeover_checker.py