import requests
import os
import time
from dotenv import load_dotenv

# Load API key from .env
load_dotenv()
API_KEY = os.getenv("VT_API_KEY")

# Submit URL for scanning
def submit_url(url_to_scan):
    url = "https://www.virustotal.com/api/v3/urls"
    headers = {
        "x-apikey": API_KEY,
        "accept": "application/json",
        "content-type": "application/x-www-form-urlencoded"
    }
    data = {"url": url_to_scan}
    response = requests.post(url, headers=headers, data=data)
    return response.json()

# Fetch report using analysis ID
def get_report(analysis_url):
    headers = {"x-apikey": API_KEY}
    for _ in range(10):  # retry up to 10 times
        response = requests.get(analysis_url, headers=headers)
        if response.status_code == 200:
            data = response.json()
            status = data["data"]["attributes"]["status"]
            if status == "completed":
                return data['data']["attributes"]["results"]
            else:
                time.sleep(2)  # wait before retrying
        else:
            raise Exception("Error fetching report.")
    raise TimeoutError("Analysis did not complete in time.")

def analyze_with_trusted_vendors(results):
    trusted_vendors = {
        "Google Safebrowsing",
        "Kaspersky",
        "ESET",
        "BitDefender",
        "Fortinet",
        "Sophos",
        "Dr.Web",
        "Webroot",
        "Mimecast",
        "Quick Heal",
        "OpenPhish",
        "Phishtank",
        "URLhaus",
        "Abusix",
        "ZeroFox"
    }


    malicious_count = 0
    checked = 0

    for vendor in trusted_vendors:
        if vendor in results:
            checked += 1
            category = results[vendor]["category"]
            if category == "malicious":
                malicious_count += 1
    print(f"Checked {checked} vendors, found {malicious_count} malicious detections.")
    if checked == 0:
        return 1
    elif malicious_count >= 5:  # You can change this threshold
        return -2
    else:
        return 2

# Determine verdict
def get_verdict(report_data):
    stats = report_data["data"]["attributes"]["stats"]
    if stats["malicious"] > 0 or stats["suspicious"] > 0:
        return "malicious"
    else:
        return "safe"

# ==== MAIN ====
def main(url, var):
    if API_KEY:
        print(time.strftime("%Y-%m-%d %H:%M:%S", time.localtime()))  # Replace with your URL
        print("Submitting URL for scanning...")
        submission = submit_url(url)

        analysis_url = submission["data"]["links"]["self"]
        print("Waiting for report...")
        time.sleep(5)  # Wait for a while before fetching the report
        report = get_report(analysis_url)
        #print(report)
        verdict = analyze_with_trusted_vendors(report)
        print(f"Verdict: {verdict}")
        print(time.strftime("%Y-%m-%d %H:%M:%S", time.localtime()))
        var[0] = verdict
    else:
        var[0] = 0
