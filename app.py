from flask import Flask, render_template, request, send_file, url_for
import pandas as pd
import os
from werkzeug.utils import secure_filename

app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['MAX_CONTENT_LENGTH'] = 1024 * 1024 * 1024  # 1GB max file size

# Create uploads directory if it doesn't exist
if not os.path.exists(app.config['UPLOAD_FOLDER']):
    os.makedirs(app.config['UPLOAD_FOLDER'])

def categorize_vulnerability(title):
    """Categorize vulnerability based on title"""
    # Ensure title is a string to prevent errors with non-string data
    title = str(title)
    if "Obsolete Version" in title:
        return "OS - Upgrade"
    elif ".NET" in title:
        return "App - .NET"
    elif "Adobe Acrobat" in title:
        return "App - Adobe Acrobat"
    elif "Firefox" in title:
        return "App - Firefox"
    elif "Google Chrome" in title:
        return "App - Chrome"
    elif "Python" in title:
        return "App - Python"
    elif "Apache ActiveMQ" in title:
        return "Apache ActiveMQ"
    elif "Adobe Flash Player" in title:
        return "App - Adobe Flash"
    elif "Adobe Illustrator" in title:
        return "App - Adobe Illustrator"
    elif "Apache HTTP Server" in title:
        return "App - Apache"
    elif "Apache Commons" in title:
        return "App - Apache Commons"
    elif "Apache Struts" in title:
        return "App - Apache Struts"
    elif "Check Point" in title:
        return "App - Checkpoint"
    elif "Docker CE" in title:
        return "App - Docker"
    elif "Microsoft Edge Chromium" in title:
        return "App - Edge"
    elif "FFmpeg" in title:
        return "App - Ffmpeg"
    elif "Foxit Reader" in title:
        return "App - Foxit"
    return "TBD"

@app.route('/', methods=['GET', 'POST'])
def index():
    if request.method == 'POST':
        if 'file' not in request.files:
            return render_template('index.html', error='No file uploaded')
        
        file = request.files['file']
        if file.filename == '':
            return render_template('index.html', error='No file selected')

        if not file.filename.endswith(('.xlsx', '.xls')):
            return render_template('index.html', error='Invalid file type. Please upload .xlsx or .xls file')

        try:
            # Secure the filename and create paths
            filename = secure_filename(file.filename)
            file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            output_filename = f"processed_{filename}"
            output_path = os.path.join(app.config['UPLOAD_FOLDER'], output_filename)

            # Save uploaded file
            file.save(file_path)
            print(f"Processing file: {filename}")

            # Read Excel file using openpyxl engine for better .xlsx handling
            df = pd.read_excel(file_path, engine='openpyxl')

            # IMPORTANT: Clean column names to remove hidden whitespace.
            # This is often the cause of columns being mishandled (e.g., "Owner " -> "Owner").
            df.columns = df.columns.str.strip()
            print(f"Columns as read from file: {df.columns.tolist()}")
            print("First few rows before processing:")
            print(df.head())

            # Verify required column exists after cleaning
            if 'vuln_title' not in df.columns:
                os.remove(file_path)
                return render_template('index.html', error='Excel file must contain a "vuln_title" column')

            # Only update Category column, never insert or drop columns
            df['Category'] = df['vuln_title'].apply(categorize_vulnerability)

            print(f"Columns after processing: {df.columns.tolist()}")
            print("First few rows after processing:")
            print(df.head())

            # Save the entire DataFrame. All other columns are preserved.
            df.to_excel(output_path, index=False, engine='openpyxl')

            # Clean up original file
            os.remove(file_path)

            return render_template('index.html', download_file=output_filename)

        except Exception as e:
            print(f"Error processing file: {str(e)}")
            return render_template('index.html', error=f'Error processing file: {str(e)}')

    return render_template('index.html')

@app.route('/download/<filename>')
def download_file(filename):
    try:
        return send_file(
            os.path.join(app.config['UPLOAD_FOLDER'], filename),
            as_attachment=True,
            download_name=filename
        )
    except Exception as e:
        return render_template('index.html', error=f'Error downloading file: {str(e)}')

if __name__ == '__main__':
    print("Starting Excel Category Auto-Filler application...")
    print("Access the application at http://127.0.0.1:5000")
    app.run(debug=True)
