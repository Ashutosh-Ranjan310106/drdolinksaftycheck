# URL Safety Classifier (Machine Learning Model)

A lightweight and fast URL safety classifier based on a trained Random Forest model. This tool predicts whether a URL is malicious or safe using engineered features without depending on external APIs.

---

## Features

- Trained Random Forest model using scikit-learn  
- URL feature extraction module  
- Modular structure for easy integration  
- Lightweight and fast  




---

## Installation

### Prerequisites

- Python 3.8+  
- pip  


```bash
# Clone the repository
git clone https://github.com/Ashutosh-Ranjan310106/drdolinksaftycheck.git
cd drdolinksaftycheck

# Create virtual environment (optional but recommended)
python -m venv venv
venv\Scripts\activate  # On Linux: source venv/bin/activate

# Install required packages
pip install -r requirements.txt
```





## Run Locally
```bash
# Start the Flask app
python app.py
```
---
#### Navigate to http://localhost:5000 in your browser to test the UI.


## Live Demo

https://drdolinksaftycheck.onrender.com/

⚠️ **Heads-up:** There might be a delay of 30-50 seconds when opening the link for the first time. 
This is normal — free Render deployments sleep when inactive to save resources.



## ⚙️ Environment Variables

To run this project, you can (optionally) define the following environment variables in a `.env` file.

> ⚠️ **Note:** The application can still run without setting these.  
> Missing values will disable some features or use defaults.

| Variable Name   | Description                                      | Required | Default         |
|----------------|--------------------------------------------------|----------|-----------------|
| `APIKEY`        | Google API Key — used for extended URL analysis | ❌       | `None`          |
| `VT_API_KEY`    | VirusTotal API Key — used for extended URL analysis      | ❌       | `None`          |
| `HOST`          | Host for the Flask server                       | ❌       | `localhost`       |
| `PORT`          | Port for the Flask server                       | ❌       | `5000`          |
| `BACKEND_URL`   | Fully-qualified URL used by frontend to connect | ❌       | Auto-generated  |
| `DEBUG`         | Enables Flask debug mode (`True`/`False`)       | ❌       | `True`          |

📌 **Tip:**  
If you are deploying on platforms like Render, define these environment variables in their dashboard under **Environment > Environment Variables**.

📁 **Example `.env` file:**
```dotenv
APIKEY=your_google_api_key
VT_API_KEY=your_virustotal_api_key
HOST=0.0.0.0
PORT=5000
DEBUG=False
BACKEND_URL=https://yourbackend.onrender.com
```



## Screenshots

![App Screenshot](screenshots/result.png)

