# subdomain-recon

Passive subdomain discovery tool using crt.sh certificate transparency logs.

## What it does
Queries crt.sh to find all subdomains associated with a target domain
and saves the results to a timestamped .txt report.

## Usage
```bash
pip install requests
python subdomain_scraper.py google.com
```

## Example Output
```
[*] Querying crt.sh for: google.com
[+] Retrieved 2,847 certificate records.
[+] Results saved to: /home/user/google.com_subdomains_20251201.txt
```

## Tech Stack
- Python 3
- requests
- crt.sh Certificate Transparency API