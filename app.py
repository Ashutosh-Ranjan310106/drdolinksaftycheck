import requests
import json
from flask import jsonify
from flask import Flask, request, render_template
from time import sleep
from dotenv import load_dotenv
import os

load_dotenv()

app = Flask(__name__)
app.config["secret_key"] = 'mysecretkey'
app.config["jwt_secret"] = 'myjwtsecret'
app.config["jwt_algorithm"] = 'HS256'
app.config["HOST"] = os.getenv("HOST", "localhost")
app.config["PORT"] = int(os.getenv("PORT", 5000))  # must cast to int
app.config["TEMPLATE_FOLDER"] = "templates"
app.config["DEBUG"] = os.getenv("DEBUG", "True").lower() == "true"
api_key = os.getenv('APIKEY') or None
apiurl = 'https://safebrowsing.googleapis.com/v4/threatMatches:find?key=' + api_key if api_key else None
backend_url = f"http://{app.config['HOST']}:{app.config['PORT']}"
respose_body = {
  "client": {
    "clientId": "myapp",
    "clientVersion": "1.0"
  },
  "threatInfo": {
    "threatTypes": 
    [
      "MALWARE", "SOCIAL_ENGINEERING"
    ],
    "platformTypes": ["ANY_PLATFORM"],
    "threatEntryTypes": ["URL"],
    "threatEntries": [
      {"url": ''}
    ]
  }
}

def google_api_key_check(url):
    if api_key:
        respose_body["threatInfo"]["threatEntries"][0]["url"] = url

        response = requests.post(apiurl, json=respose_body, headers={'Content-Type': 'application/json'})
        respose_body["threatInfo"]["threatEntries"][0]["url"] = ''
        print(f"Response status code: {response.status_code}",response.text)
        if response.status_code != 200:
            return {"error": "Failed to check URL"}, response.status_code
        result = response.json()
        if result.get('matches'):
            status = 0
        else:
            status = 1

        return status
    else:
        return None
def ml_check(url):
    # Placeholder for machine learning check logic
    # This function should implement the actual ML model checking logic
    return True  # Assuming the URL is safe for now
@app.route('/', methods=['GET','POST'])
def check():
    if request.method == 'POST':
        data = request.get_json()
        if not data or 'url' not in data:
            return {"error": "Invalid request, 'url' is required"}, 400
        url = data['url']
        print(f"Received URL: {url}")
        status = google_api_key_check(url)
        mlstatus = ml_check(url)
        print(f"URL: {url}, Status: {'Safe' if status else 'Unsafe'}")
        sleep(1)
        return jsonify({"URL": url,"safe": status})
    else:
        return render_template('index.html',url=None,Backend_URL=backend_url)
    

if __name__ == "__main__":
    app.run(
        host=app.config["HOST"],
        port=app.config["PORT"],
        debug=app.config["DEBUG"]
    )