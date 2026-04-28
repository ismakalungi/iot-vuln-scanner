from flask import Flask, render_template, request
import subprocess
import json
import os

app = Flask(__name__)

@app.route('/')
def index():
    return render_template('templates/index.html')

@app.route('/scan', methods=['POST'])
def scan():
    try:
        # Run the scanner
        result = subprocess.run([
            'sudo', 'python', '-m', '../iot_scanner.cli', 'scan', 
            '-i', '172.20.44.0/24'
        ], capture_output=True, text=True, timeout=120)
        
        output = result.stdout
        
        # For now, we'll just show the raw output
        return render_template('templates/result.html', output=output, error=result.stderr)
        
    except Exception as e:
        return f"Error running scan: {str(e)}"

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)