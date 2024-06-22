import re
import requests
from urllib.parse import urlparse

pi = [
    r'login',
    r'account',
    r'verify',
    r'update',
    r'password',
    r'security',
    r'bank',
    r'support',
]

legtimitateDomains = [
    "chase.com", "wellsfargo.com", "bankofamerica.com", "citibank.com", "hsbc.com", "usbank.com",
    "paypal.com", "stripe.com", "square.com", "google.com", "bing.com", "yahoo.com", "duckduckgo.com",
    "gmail.com", "outlook.com", "protonmail.com", "facebook.com", "twitter.com", "linkedin.com",
    "instagram.com", "amazon.com", "ebay.com", "etsy.com", "alibaba.com", "walmart.com", "target.com",
    "bestbuy.com", "homedepot.com", "usa.gov", "gov.uk", "canada.ca", "australia.gov.au", "harvard.edu",
    "mit.edu", "stanford.edu", "ox.ac.uk", "cdc.gov", "who.int", "mayoclinic.org", "webmd.com",
    "nytimes.com", "bbc.com", "cnn.com", "reuters.com", "theguardian.com"
]

def fetchURL(url):
    try:
        resp = requests.get(url)
        if resp.status_code == 200:
            return resp.text
        else:
            print(f"Failed to fetch URL: {url}")
            return None
    except requests.RequestException as e:
        print(f"Request error: {e}")
        return None

def scanForPhishing(content):
    for i in pi:
        if re.search(i, content, re.IGNORECASE):
            return True
    return False

def isLegitimateDomain(url):
    parsedURL = urlparse(url)
    domain = parsedURL.netloc
    return any(domain.endswith(ld) for ld in legtimitateDomains)

def scanURL(url):
    parsedURL = urlparse(url)
    if not parsedURL.scheme:
        url = "http://" + url  
    
    if isLegitimateDomain(url):
        return "Safe (Legitimate Domain)"
    
    content = fetchURL(url)
    if content:
        if scanForPhishing(content):
            return "Potential Phishing"
        else:
            return "Safe"
    else:
        return "Unable to Scan"

if __name__ == "__main__":
    url = input()
    res = scanURL(url)
    print(f"The URL '{url}' is classified as: {res}")
