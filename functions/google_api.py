from dotenv import load_dotenv
import os
import requests

# Load .env variables
load_dotenv()
api_key = os.getenv('APIKEY') or None
apiurl = 'https://safebrowsing.googleapis.com/v4/threatMatches:find?key=' + api_key if api_key else None

# Request body template
respose_body = {
"client": {
    "clientId": "myapp",
    "clientVersion": "1.0"
},
"threatInfo": {
    "threatTypes": 
    [
    "MALWARE", "SOCIAL_ENGINEERING","UNWANTED_SOFTWARE"
    ],
    "platformTypes": ["ANY_PLATFORM"],
    "threatEntryTypes": ["URL"],
    "threatEntries": [
    {"url": ''}
    ]
}
}

# Check URL safety
def google_api(url):
    if api_key:
        respose_body["threatInfo"]["threatEntries"][0]["url"] = url

        response = requests.post(apiurl, json=respose_body, headers={'Content-Type': 'application/json'})
        respose_body["threatInfo"]["threatEntries"][0]["url"] = ''
        print(f"Response status code: {response.status_code}",response.text)
        result = response.json()
        if result.get('matches'):
            status = -1
        else:
            status = 1

        return status
    else:
        return 0