URL Safety Classifier (Machine Learning Model)

A lightweight and fast URL safety classifier based on a trained Random Forest model. This tool predicts whether a URL is malicious or safe using engineered features without depending on external APIs.

🧠 Features

Trained Random Forest model using scikit-learn

URL feature extraction module

Modular structure for easy integration

Lightweight and fast

🗂️ Project Structure

C:.
│   .env
│   .gitattributes
│   .gitignore
│   app.py
│   log.txt
│   requirment.txt
│
├───functions
│   │   extract_features.py
│   │   google_api.py
│   │   virus_total_api.py
│
├───model
│   │   random_forest_model.pkl
│
└───templates
        index.html

🚀 Installation

Prerequisites

Python 3.8+

pip

Step-by-step

# Clone the repository
$ git clone https://github.com/Ashutosh-Ranjan310106/drdolinksaftycheck.git
$ cd drdolinksaftycheck

# Create virtual environment (optional but recommended)
$ python -m venv venv
$ venv\Scripts\activate  # On Linux: source venv/bin/activate

# Install required packages
$ pip install -r requirment.txt

🧪 Running the Application

# Start the Flask app
$ python app.py

Navigate to http://localhost:5000 in your browser to test the UI.

📦 Model Details

Type: Random Forest Classifier

Library: scikit-learn

Input: Extracted URL features

Output: 1 (Safe), -1 (Malicious)

The model uses the following features:

URL length

Count of dots, hyphens, subdirectories

HTTPS presence

TLD checks

Encoded characters

Presence of IP address

Alexa top domain check (optional)

Note: All features are extracted using the extract_features.py script.


