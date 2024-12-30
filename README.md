# Shodan-whois-query


# Shodan and WHOIS Domain Query Automation

This Python script automates querying domains listed in a `root.txt` file using the Shodan API and WHOIS lookups. The script fetches organization details from Shodan and validates them against WHOIS data for better accuracy. The results are saved in `shodan_org_results.txt`.

## Features

-   **WHOIS Integration:** Retrieves the organization name associated with a domain.
    
-   **Shodan Query:** Uses Shodan's API to search for SSL certificate details related to the domains.
    
-   **Fuzzy Matching:** Matches Shodan organization results with the domain or WHOIS data using similarity scoring.
    
-   **Error Handling:** Handles API errors and WHOIS lookup failures gracefully.
    
-   **Customizable Threshold:** Allows fine-tuning of the similarity threshold for better matching.
    

## Requirements

-   Python 3.x
    
-   Shodan API Key (Membership API required for full functionality)
    

### Python Libraries

Install the required libraries:

```
pip install shodan python-whois
```

## Setup

1.  Clone the repository or download the script.
    
2.  Create a `root.txt` file in the same directory as the script. Add one domain per line. Example:
    
    ```
    varonis.com
    shopify.com
    shopee.com
    asin.bj
    ```
    
3.  Replace `your_shodan_api_key` in the script with your actual Shodan API key.
    
4.  Run the script:
    
    ```
    python3 p.py
    ```
    

## Script Output

The script processes each domain and saves the results in `shodan_org_results.txt` with the following format:

```
varonis.com:
  - Varonis Systems, LTD
  - Varonis Systems, Inc

shopify.com:
  - Shopify Inc.
```

## Example Execution

1.  **Input:**
    
    -   `root.txt` contains:
        
        ```
        varonis.com
        shopify.com
        ```
        
2.  **Execution:**
    
    ```
    python3 p.py
    ```
    
3.  **Output:**
    
    -   `shodan_org_results.txt`:
        
        ```
        varonis.com:
          - Varonis Systems, LTD
          - Varonis Systems, Inc
        
        shopify.com:
          - Shopify Inc.
        ```
        

## Troubleshooting

### Access Denied (403 Forbidden)

If you encounter `403 Forbidden` errors from Shodan:

-   Verify your API key.
    
-   Check your Shodan API usage and ensure you have a valid membership API.
    
-   Retry from a different network or IP if your current IP is restricted.
    

### WHOIS Lookup Errors

If WHOIS lookups fail for certain domains:

-   Ensure the domain is valid and resolvable.
    
-   Private WHOIS records may not return organization details.
    

## Contributions

Contributions, bug reports, and feature requests are welcome! Feel free to open an issue or submit a pull request.

## License

This project is licensed under the MIT License. See the LICENSE file for details.

----------

Happy Bug Hunting! 🐞
