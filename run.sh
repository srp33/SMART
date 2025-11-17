#! /bin/bash

python3 -m venv .venv
source .venv/bin/activate   # Windows: .venv\Scripts\activate
#pip3 install -r requirements.txt
export FLASK_APP=app.py
# Set SCRIPT_NAME if running behind a proxy with URL prefix
# For local development without prefix, comment out or set to empty string
export SCRIPT_NAME=/Annotation_Tool
flask run --debug
