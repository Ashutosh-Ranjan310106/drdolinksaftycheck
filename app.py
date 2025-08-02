# ---------------------------------------------
# Flask-based backend for URL safety detection
# Combines VirusTotal, Google API, and ML model
# ---------------------------------------------

from flask import jsonify, Flask, request, render_template
from time import sleep
from dotenv import load_dotenv
import os
import pickle
from threading import Thread
import pandas as pd

# Import custom modules for API checks and feature extraction
import functions.virus_total_api as virus_total_api
from functions.google_api import google_api
from functions.extract_features import extract_all_features

# -------------------------------
# Load pretrained ML model (Random Forest)
# and feature column names from pickle file
# -------------------------------
import os
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
model_path = os.path.join(BASE_DIR, 'model', 'random_forest_model.pkl')

with open(model_path, 'rb') as f:
    RFmodel = pickle.load(f)                # Load the trained Random Forest model
    independent_features = pickle.load(f)   # Load the list of features used during training

# -------------------------------
# Load environment variables from `.env` file
# (API keys, debug mode, host/port etc.)
# -------------------------------
load_dotenv()

# -------------------------------
# Flask app configuration
# -------------------------------
app = Flask(__name__)
app.config["secret_key"] = 'mysecretkey'  # Flask secret key
app.config["jwt_secret"] = 'myjwtsecret'  # JWT secret (not used here)
app.config["jwt_algorithm"] = 'HS256'     # JWT algorithm (not used here)

app.config["TEMPLATE_FOLDER"] = "templates"           # Template folder for frontend
app.config["DEBUG"] = os.getenv("DEBUG", "True").lower() == "true"  # Debug mode
if app.config["DEBUG"]:
    app.config["HOST"] = os.getenv("HOST", "localhost")  # Server host
else:
    app.config["HOST"] = '0.0.0.0'
app.config["PORT"] = int(os.getenv("PORT", 5000))     # Server port
# Read API keys from environment or fallback to None
api_key = os.getenv('APIKEY') or None
VT_API_KEY = os.getenv("VT_API_KEY") or None

# Log saving flag
save_log = os.getenv("SAVE_LOG", "True").lower() == "true"

# Backend URL construction for frontend
backend_url = os.getenv('BACKEND_URL',f"http://{app.config['HOST']}:{app.config['PORT']}")

# ------------------------------------------------------
# Function to classify a URL using ML model (RandomForest)
# Returns ML prediction and extracted features
# ------------------------------------------------------
def ml_check(url):
    try:
        extracted_url = extract_all_features(url)  # Extract features from the input URL
        print(extracted_url)

        # Predict probability of being malicious using RF model
        prediction = RFmodel.predict_proba(pd.DataFrame([extracted_url])[independent_features])
        print(prediction)

        # Return: 1 (unsafe) if probability of malicious > 0.70, else 0 (safe)
        return int(prediction[0][0] < 0.70) * 2, extracted_url
    except Exception as e:
        print(f"Error in ML check: {e}")
        return 0  # fallback if ML fails

# -----------------------------------------------------------------
# Final ensemble-based decision using weights for each source
# Each score (0 or 1) is weighted and thresholded for final verdict
# -----------------------------------------------------------------
def final_decision(google_status, ml_status, vt_status,
                   w_google=0.33, w_ml=0.33, w_vt=0.33, threshold=0.66):
    if google_status is None:
        return ml_status  # if Google check failed, rely on ML
    score = (google_status * w_google) + (ml_status * w_ml) + (vt_status * w_vt)
    return 1 if score >= threshold else 0  # 1: safe, 0: unsafe

# ----------------------------------------------------------------
# Flask route to serve both frontend page and API POST requests
# ----------------------------------------------------------------
@app.route('/', methods=['GET', 'POST'])
def check():
    # Handle POST request (from frontend)
    if request.method == 'POST':
        data = request.get_json()

        # Validate that a URL was provided
        if not data or 'url' not in data:
            return {"error": "Invalid request, 'url' is required"}, 400

        url = data['url']
        print(f"Received URL: {url}")

        # Shared list used to store VirusTotal result in a thread-safe way
        vt_status = [0]

        try:
            # Run VirusTotal check in a separate thread (as it may be slow)
            vt_thread = Thread(target=virus_total_api.main, args=(url, vt_status))
            vt_thread.start()

            # Call Google Safe Browsing API (synchronous)
            google_status = google_api(url)
        except:
            google_status = 0  # fallback if Google check fails

        # Call ML model for prediction
        ml_status, extracted_url = ml_check(url)

        # Wait for VirusTotal thread to complete
        vt_thread.join()
        print(google_status)

        # Final decision using majority voting / weighted score
        final_status = final_decision(google_status, ml_status, vt_status[0])

        # ---------------------------
        # Logging result if enabled
        # ---------------------------
        if save_log:
            with open("log.txt", "a") as log_file:
                log_file.write(str(extracted_url) + '\n')
                log_file.write(
                    f"URL: {url}, Google: {google_status}, ML: {ml_status}, Virus Total: {vt_status} "
                    f"Final: {'Safe' if final_status else 'Unsafe'}\n"
                )

        print(
            f"URL: {url}, Google: {google_status}, ML: {ml_status}, Virus Total: {vt_status} "
            f"Final: {'Safe' if final_status else 'Unsafe'}"
        )

        # Construct JSON response for frontend
        respose = {"URL": url}

        # Add Google and VirusTotal results only if respective API keys are present
        if api_key:
            respose["Google"] = int(google_status >= 0)
        if VT_API_KEY:
            respose["Virus_total"] = int(vt_status[0] >= 0)

        respose["mlModel"] = int(ml_status)
        respose["safe"] = final_status  # Final binary verdict: 1 (safe), 0 (unsafe)

        return jsonify(respose)

    else:
        # On GET request, render the HTML frontend
        return render_template('index.html', url=None, Backend_URL=backend_url)

# ---------------------------------------------
# Start Flask app if this file is executed directly
# ---------------------------------------------

if __name__ == "__main__":
    app.run(
        host=app.config["HOST"],
        port=app.config["PORT"],
        debug=app.config["DEBUG"]
    )
