import requests
import json
from flask import jsonify
from flask import Flask, request, render_template
from time import sleep
from dotenv import load_dotenv
import os
import pickle
import functions.virus_total_api as virus_total_api
from functions.google_api import google_api
from threading import Thread
import pandas as pd    
from functions.extract_features import extract_all_features

model_path = r'models\random_forest_model.pkl'
RFmodel = pickle.load(open(model_path,'rb'))

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
VT_API_KEY = os.getenv("VT_API_KEY") or None
save_log = os.getenv("SAVE_LOG", "True").lower() == "true"
backend_url = f"http://{app.config['HOST']}:{app.config['PORT']}"

respose_body = {
  "client": {
    "clientId": "myapp",
    "clientVersion": "1.0"
  },
  "threatInfo": {
    "threatTypes": 
    [
      "MALWARE", "SOCIAL_ENGINEERING",""
    ],
    "platformTypes": ["ANY_PLATFORM"],
    "threatEntryTypes": ["URL"],
    "threatEntries": [
      {"url": ''}
    ]
  }
}





independent_features = ["url_length", "hostname_length", "num_dots", "num_hyphens", "has_https", "num_subdirs", "num_params", "has_ip", "is_encoded", "starts_with_www", "ends_with_suspicious_tld", "dns_record_exists", "is_alexa_top"] 
def ml_check(url):
    try:
        extracted_url = extract_all_features(url)
        print(extracted_url)
        prediction = RFmodel.predict(pd.DataFrame([extracted_url])[independent_features])
        return prediction[0],extracted_url
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
        vt_status=[0]
        try:
            vt_thread = Thread(target=virus_total_api.main, args=(url,vt_status))
            vt_thread.start()
            google_status = google_api(url)
        except:
            google_status = 0
        ml_status, extracted_url = ml_check(url)
        vt_thread.join()

        final_status = final_decision(google_status, ml_status, vt_status[0])
        if save_log:
            with open("log.txt","a") as log_file:
                log_file.write(str(extracted_url)+'\n')
                log_file.write(f"URL: {url}, Google: {google_status}, ML: {ml_status},Virus Total: {vt_status} Final: {'Safe' if final_status else 'Unsafe'}\n")
        print(f"URL: {url}, Google: {google_status}, ML: {ml_status},Virus Total: {vt_status} Final: {'Safe' if final_status else 'Unsafe'}")
        respose = {}
        respose["URL"] = url
        if api_key:
            respose["Google"] = int(google_status>=0)
        if VT_API_KEY:
            respose["Virus_total"] = int(vt_status[0]>=0)
        respose["mlModel"] = int(ml_status)
        respose["safe"] = final_status
        return jsonify(respose)
    else:
        return render_template('index.html',url=None,Backend_URL=backend_url)
    

if __name__ == "__main__":
    app.run(
        host=app.config["HOST"],
        port=app.config["PORT"],
        debug=app.config["DEBUG"]
    )