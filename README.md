# Subdomain Takeover Checker

A Python script to analyze URLs for potential subdomain takeover vulnerabilities. It checks the CNAME records of provided subdomains against a list of known vulnerable services and analyzes the server response to detect takeover possibilities.

## Features

- **CNAME Record Checks**: Identify subdomains with CNAME records pointing to vulnerable services (e.g., AWS, GitHub Pages).
- **Server Response Analysis**: Inspect server responses for error messages commonly associated with subdomain takeovers.
- **Custom or Pre-defined URL List**: Accept user-specified URLs or load a list from a file for batch analysis.
- **Parallel Execution**: Perform checks concurrently for faster processing of multiple URLs.
- **Logging**: Save results, including unique CNAMEs and takeover statuses, in a detailed log file.

## Requirements

- Python 3.x
- The necessary Python libraries (listed in `requirements.txt`)

## Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/yourusername/subdomain-takeover-checker.git

2. Navigate to the directory:
   ```bash
   cd subdomain-takeover-checker

3. Install the required libraries using requirements.txt:
   ```bash
   pip install -r requirements.txt

## Usage
You can run the script with either a single domain or a list of domains:


1. To check a single domain:
   ```bash
   python3 checker.py -d example.com

1. To check a multiple domains:
   ```bash
   python3 checker.py -l domains.txt

The results will be saved in a log file, which can be customized based on the input source.

## Sample Output
The output will display the CNAME records found for each subdomain and indicate if it is potentially vulnerable to takeover. It also logs progress and errors in real-time.

## Example Keywords for Vulnerable Services

The script uses a keywords.txt file to load CNAME patterns associated with vulnerable services. Make sure the file includes keywords like:
   "s3.amazonaws.com"
   "github.io"
   "unbounce.com"

## Logging 

Every time you scan using the -d flag it will be added to results.log. 
Every time you scan using the -l flag it will create a new file text with the report of the CNAMES/Vulnerable Subdomains. Example log entry:
   ```bash
   [!] Vulnerable: example.com (CNAME: s3.amazonaws.com)
   [-] No takeover detected: anotherdomain.com


### Contributions

Feel free to fork the repository and submit pull requests with improvements or additional features.

