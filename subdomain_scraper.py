import requests
import json
import sys
import os
from datetime import datetime


# ──────────────────────────────────────────────
#  CONFIG
# ──────────────────────────────────────────────

CRT_SH_URL = "https://crt.sh/?q={domain}&output=json"
REQUEST_TIMEOUT = 15


# ──────────────────────────────────────────────
#  DATA FETCHING
# ──────────────────────────────────────────────

def fetch_crtsh(domain: str) -> list[dict]:
    """
    Query crt.sh for all SSL/TLS certificate entries associated with a domain.
    Returns raw JSON records or raises an exception on failure.
    """
    url = CRT_SH_URL.format(domain=domain)
    print(f"[*] Querying crt.sh for: {domain}")

    try:
        response = requests.get(url, timeout=REQUEST_TIMEOUT)
        response.raise_for_status()
    except requests.exceptions.ConnectionError:
        raise ConnectionError("[-] Could not connect to crt.sh. Check your internet connection.")
    except requests.exceptions.Timeout:
        raise TimeoutError(f"[-] Request timed out after {REQUEST_TIMEOUT} seconds.")
    except requests.exceptions.HTTPError as e:
        raise RuntimeError(f"[-] HTTP error from crt.sh: {e}")

    try:
        data = response.json()
    except json.JSONDecodeError:
        raise ValueError("[-] Failed to parse response from crt.sh. The site may be down.")

    return data


# ──────────────────────────────────────────────
#  PARSING & DEDUPLICATION
# ──────────────────────────────────────────────

def parse_subdomains(records: list[dict], base_domain: str) -> list[str]:
    """
    Extract unique, valid subdomains from crt.sh records.
    Filters out wildcards and entries not belonging to the target domain.
    """
    seen = set()

    for record in records:
        # name_value can contain multiple entries separated by newlines
        name_value = record.get("name_value", "")
        entries = name_value.split("\n")

        for entry in entries:
            entry = entry.strip().lower()

            # Skip wildcards and blank entries
            if not entry or entry.startswith("*"):
                continue

            # Only keep subdomains of the target domain
            if entry == base_domain or entry.endswith(f".{base_domain}"):
                seen.add(entry)

    return sorted(seen)


# ──────────────────────────────────────────────
#  OUTPUT
# ──────────────────────────────────────────────

def save_to_file(subdomains: list[str], domain: str) -> str:
    """
    Save discovered subdomains to a timestamped .txt file.
    Returns the output filename.
    """
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"{domain}_subdomains_{timestamp}.txt"

    with open(filename, "w", encoding="utf-8") as f:
        f.write(f"# Subdomain Recon Report\n")
        f.write(f"# Target  : {domain}\n")
        f.write(f"# Source  : crt.sh (Certificate Transparency)\n")
        f.write(f"# Date    : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write(f"# Total   : {len(subdomains)} subdomains found\n")
        f.write("#" + "─" * 40 + "\n\n")

        for sub in subdomains:
            f.write(sub + "\n")

    return filename


def print_results(subdomains: list[str], domain: str) -> None:
    """Print a summary of discovered subdomains to the terminal."""
    print(f"\n{'─' * 45}")
    print(f"  Target  : {domain}")
    print(f"  Found   : {len(subdomains)} unique subdomains")
    print(f"{'─' * 45}")

    for sub in subdomains:
        print(f"  {sub}")

    print(f"{'─' * 45}\n")


# ──────────────────────────────────────────────
#  INPUT VALIDATION
# ──────────────────────────────────────────────

def validate_domain(domain: str) -> str:
    """
    Basic domain validation and cleanup.
    Strips protocol prefixes and trailing slashes.
    """
    domain = domain.strip().lower()

    # Strip common prefixes
    for prefix in ("https://", "http://", "www."):
        if domain.startswith(prefix):
            domain = domain[len(prefix):]

    domain = domain.rstrip("/")

    # Basic sanity check: must contain a dot and no spaces
    if "." not in domain or " " in domain:
        raise ValueError(f"[-] '{domain}' does not look like a valid domain.")

    return domain


# ──────────────────────────────────────────────
#  MAIN
# ──────────────────────────────────────────────

def run_recon(domain: str) -> None:
    """Full recon pipeline: validate → fetch → parse → save → report."""

    # 1. Validate
    try:
        domain = validate_domain(domain)
    except ValueError as e:
        print(e)
        sys.exit(1)

    # 2. Fetch
    try:
        records = fetch_crtsh(domain)
    except (ConnectionError, TimeoutError, RuntimeError, ValueError) as e:
        print(e)
        sys.exit(1)

    if not records:
        print(f"[-] No certificate records found for '{domain}'.")
        print("    The domain may be too new, private, or not indexed by crt.sh.")
        sys.exit(0)

    print(f"[+] Retrieved {len(records)} certificate records.")

    # 3. Parse
    subdomains = parse_subdomains(records, domain)

    if not subdomains:
        print("[-] No valid subdomains could be extracted from the records.")
        sys.exit(0)

    # 4. Print summary
    print_results(subdomains, domain)

    # 5. Save to file
    output_file = save_to_file(subdomains, domain)
    print(f"[+] Results saved to: {os.path.abspath(output_file)}")


def main():
    print("=" * 45)
    print("   Passive Subdomain Scraper — crt.sh OSINT")
    print("=" * 45 + "\n")

    # Accept domain from CLI arg or prompt interactively
    if len(sys.argv) == 2:
        domain = sys.argv[1]
    else:
        domain = input("Enter target domain (e.g. google.com): ").strip()

    if not domain:
        print("[-] No domain provided. Exiting.")
        sys.exit(1)

    run_recon(domain)


if __name__ == "__main__":
    main()
