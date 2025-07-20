import requests
import json
from flask import jsonify
from flask import Flask, request, render_template
from time import sleep
from dotenv import load_dotenv
import os
import pickle
import vt
from threading import Thread

model_path = r'models\random_forest_model.pkl'
model = pickle.load(open(model_path,'rb'))

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
            status = -1
        else:
            status = 1

        return status
    else:
        return 0.5
    
import pandas as pd
import re
import tldextract
from urllib.parse import urlparse
from collections import Counter
import math
import string
from extract_features import extract_all_features



independent_features = ["url_length", "hostname_length", "num_dots", "num_hyphens", "has_https", "num_subdirs", "num_params", "has_ip", "is_encoded", "starts_with_www", "ends_with_suspicious_tld", "dns_record_exists", "is_alexa_top"] 
def ml_check(url):
    try:
        extracted_url = extract_all_features(url)
        prediction = model.predict(extracted_url[independent_features])
        return prediction[0]
    except Exception as e:
        print(f"Error in ML check: {e}")
        return 0
def final_decision(google_status, ml_status,vt_status, w_google=0.33, w_ml=0.33, w_vt=0.33, threshold=0.66):
    if google_status is None:
        return ml_status
    score = (google_status * w_google) + (ml_status * w_ml) + (vt_status * w_vt)
    return 1 if score >= threshold else 0
@app.route('/', methods=['GET','POST'])
def check():
    if request.method == 'POST':
        data = request.get_json()
        if not data or 'url' not in data:
            return {"error": "Invalid request, 'url' is required"}, 400
        url = data['url']
        print(f"Received URL: {url}")
        vt_status=[1]
        vt_thread = Thread(target=vt.main, args=(url,vt_status))
        vt_thread.start()  # Start VT analysis in a separate thread
        try:
            google_status = google_api_key_check(url)
        except:
            google_status = 1
        ml_status = ml_check(url)
        vt_thread.join()

        final_status = final_decision(google_status, ml_status, vt_status[0])
        print(f"URL: {url}, Google: {google_status}, ML: {ml_status},Virus Total: {vt_status} Final: {'Safe' if final_status else 'Unsafe'}")
        
        return jsonify({"URL": url,"safe": final_status})
    else:
        return render_template('index.html',url=None,Backend_URL=backend_url)
    

if __name__ == "__main__":
    app.run(
        host=app.config["HOST"],
        port=app.config["PORT"],
        debug=app.config["DEBUG"]
    )