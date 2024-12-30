import shodan
import whois
from difflib import SequenceMatcher
import os

# Your Shodan API Key
SHODAN_API_KEY = "your_shodan_api_key"

# Function to display ASCII art banner
def display_banner():
    print("""

██████   ██████  ██████  ███████ ██████  ████████  ██████  
██   ██ ██    ██ ██   ██ ██      ██   ██    ██    ██    ██ 
██████  ██    ██ ██████  █████   ██████     ██    ██    ██ 
██   ██ ██    ██ ██   ██ ██      ██   ██    ██    ██    ██ 
██   ██  ██████  ██████  ███████ ██   ██    ██     ██████  
                                                                                                                                                                                              
    """)

# Initialize Shodan API
api = shodan.Shodan(SHODAN_API_KEY)

# Prompt for the file name containing root domains
def get_file_name():
    while True:
        file_name = input("Enter the file name containing root domains (e.g., root.txt): ").strip()
        if os.path.isfile(file_name):
            return file_name
        else:
            print(f"File '{file_name}' not found. Please enter a valid file name.")

# Function to perform WHOIS lookup
def get_whois_org(domain):
    try:
        whois_data = whois.whois(domain)
        return whois_data.org if whois_data.org else None
    except Exception as e:
        print(f"Error fetching WHOIS data for {domain}: {e}")
        return None

# Function to calculate similarity between two strings
def is_similar(name1, name2, threshold=0.6):
    return SequenceMatcher(None, name1.lower(), name2.lower()).ratio() > threshold

# Function to query Shodan and filter close-matching organizations
def get_shodan_orgs(domain, whois_org):
    query = f'ssl.cert.subject.cn:"{domain}"'
    try:
        # Query Shodan
        results = api.search(query)
        orgs = set()
        for result in results['matches']:
            if 'org' in result:
                orgs.add(result['org'])
        
        # Filter organizations similar to the root domain or WHOIS org
        filtered_orgs = []
        for org in orgs:
            if is_similar(org, domain):  # Check if Shodan org is similar to root domain
                filtered_orgs.append(org)
            elif whois_org and is_similar(org, whois_org):  # Check if Shodan org matches WHOIS org
                filtered_orgs.append(org)
        
        return filtered_orgs or list(orgs)  # Return filtered or all if no match
    except shodan.APIError as e:
        print(f"Error querying Shodan for {domain}: {e}")
        if "403" in str(e):
            print("Access denied: Verify your API key or check API usage limits.")
        return []

# Main function
def main():
    display_banner()
    
    # Get the file name from the user
    file_name = get_file_name()
    
    # Read root domains from the specified file
    with open(file_name, "r") as file:
        root_domains = [line.strip() for line in file if line.strip()]
    
    # Process each domain
    output_data = {}
    for domain in root_domains:
        print(f"Processing domain: {domain}")
        
        # Step 1: Get WHOIS org
        whois_org = get_whois_org(domain)
        print(f"WHOIS organization for {domain}: {whois_org}")
        
        # Step 2: Query Shodan and filter orgs
        shodan_orgs = get_shodan_orgs(domain, whois_org)
        output_data[domain] = shodan_orgs
        print(f"Shodan organizations for {domain}: {', '.join(shodan_orgs) if shodan_orgs else 'None'}")
    
    # Save results to a file
    output_file_name = "shodan_org_results.txt"
    with open(output_file_name, "w") as output_file:
        for domain, orgs in output_data.items():
            output_file.write(f"{domain}:\n")
            for org in orgs:
                output_file.write(f"  - {org}\n")
    print(f"\nResults saved to {output_file_name}")

# Run the script
if __name__ == "__main__":
    main()
