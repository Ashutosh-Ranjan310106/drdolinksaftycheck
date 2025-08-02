#extract_features.py

import re
import socket
from urllib.parse import urlparse
import ssl
import tldextract
try:
    with open("top-1m.csv", "r") as f:
        top_domains = {line.strip().split(',')[1] for line in f}
except:
    top_domains = None
#lexical
def extract_lexical_features(url):
    parsed = urlparse(url)
    hostname = parsed.hostname or ""
    ext = tldextract.extract(url)
    domain = f"{ext.domain}.{ext.suffix}"

    # suspicious tld - https://www.cybercrimeinfocenter.org/top-20-tlds-by-malicious-phishing-domains
    suspicious_tlds = {'zip', 'xyz', 'tk', 'top', 'gq', 'ga', 'ml', 'cyou', 'buzz', 'cf', 'icu', 'wang', 'live'}

    return {
        "url":url,
        "domain": domain,
        #len>75 
        "url_length": len(url),
        #len>50 
        "hostname_length": len(hostname),
        #num>1 
        "num_dots": url.count('.'),
        #num>1 
        "num_hyphens": url.count('-'),
        #http 
        "has_https": int(url.startswith("https")),
        #num>4
        "num_subdirs": url.count('/'),
        #num>8
        "num_digits": sum(c.isdigit() for c in url),
        #num>4
        "num_params": url.count('='),
        #num>1
        "num_fragments": url.count('#'),
        #num>10
        "num_uppercase": sum(c.isupper() for c in url),
        #yes
        "has_ip": int(bool(re.search(r'\d+\.\d+\.\d+\.\d+', url))),
        #yes
        "has_port": int(':' in hostname),
        #yes
        "is_encoded": int('%' in url),
        #no
        "starts_with_www": int(hostname.startswith("www")),
        #yes
        "ends_with_suspicious_tld": int(ext.suffix in suspicious_tlds),

        #suspicious words - https://www.researchgate.net/figure/Suspicious-words-to-detect-phishing-URLs_fig6_364265241
        "suspicious_words": int(any(w in url.lower() for w in ['login', 'verify', 'account', 'update', 'secure', 'bank', 'lucky', 'bonus', 'gift', 'signin']))
    }
try:
    context = ssl.create_default_context()
except:
    context=None
#host based
def extract_host_features(domain):
    features = {
        #"domain_age_days": -1,
        "dns_record_exists": 0,
        "has_ssl_certificate": 0,
        "is_alexa_top": 0
    }
    # dom age
    '''
    try:
        try:
            w = whois.whois(domain)
            creation_date = w.creation_date
            if isinstance(creation_date, list):
                creation_date = creation_date[0]
            if creation_date:
                age = (datetime.datetime.now() - creation_date).days
                features["domain_age_days"] = age
        except:
            pass
    except:
        pass
    '''
    # DNS Check
    try:
        socket.gethostbyname(domain)
        features["dns_record_exists"] = 1
    except:
        pass
    # ssl check
    try:
        if context:
            with socket.create_connection((domain, 443), timeout=3) as sock:
                with context.wrap_socket(sock, server_hostname=domain) as ssock:
                    features["has_ssl_certificate"] = 1
    except:
        pass
    # alexa top 
    if top_domains:
        features["is_alexa_top"] = int(domain in top_domains)
    return features

#main func
def extract_all_features(url):
    lexical_features = extract_lexical_features(url)
    host_features = extract_host_features(lexical_features["domain"])
    return {**lexical_features, **host_features}
