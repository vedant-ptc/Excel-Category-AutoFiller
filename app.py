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
    # Ensure title is a string and convert to lowercase to make checks case-insensitive
    title = str(title).lower()
    if ".net" in title:
        return "App - .NET"
    elif "adobe acrobat" in title:
        return "App - Adobe Acrobat"
    elif "firefox" in title:
        return "App - Firefox"
    elif "google chrome" in title:
        return "App - Chrome"
    elif "python" in title:
        return "App - Python"
    elif "apache activemq" in title:
        return "Apache ActiveMQ"
    elif "adobe flash player" in title:
        return "App - Adobe Flash"
    elif "adobe illustrator" in title:
        return "App - Adobe Illustrator"
    elif "apache http server" in title:
        return "App - Apache"
    elif "apache commons" in title:
        return "App - Apache Commons"
    elif "apache struts" in title:
        return "App - Apache Struts"
    elif "check point" in title:
        return "App - Checkpoint"
    elif "docker ce" in title:
        return "App - Docker"
    elif "microsoft edge chromium" in title:
        return "App - Edge"
    elif "ffmpeg" in title:
        return "App - Ffmpeg"
    elif "foxit reader" in title:
        return "App - Foxit"
    elif "ghostscript" in title:
        return "App - Ghostscript"
    elif "hp system management" in title:
        return "App - HP SystemMngmt"
    elif "httpd" in title:
        return "App - HTTPD"
    elif "ibm http server" in title:
        return "App - IBM HTTP"
    elif "ibm java" in title:
        return "App - IBM Java"
    elif "jenkins" in title:
        return "App - Jenkins"
    elif "joomla" in title:
        return "App - Joomla"
    elif "thunderbird" in title:
        return "App - Mozilla thunderbird"
    elif "mysql" in title:
        return "App - MySQL"
    elif "openssl" in title:
        return "App - OpenSSL"
    elif "openvpn" in title:
        return "App - OpenVPN"
    elif "oracle virtualbox" in title:
        return "App - Oracle"
    elif "oracle weblogic" in title:
        return "App - Oracle Weblogic"
    elif "perl" in title:
        return "App - Perl"
    elif "php" in title:
        return "App - PHP"
    elif "ruby" in title:
        return "App - Ruby"
    elif "samba" in title:
        return "App - Samba"
    elif "vmware spring" in title:
        return "App - Spring"
    elif "tomcat" in title:
        return "App - Tomcat"
    elif "vlc" in title:
        return "App - VLC"
    elif "vmware workstation" in title:
        return "App - VmWare"
    elif "wireshark" in title:
        return "App - Wireshark"
    elif "zoom" in title:
        return "App - Zoom"
    elif "allegro software" in title:
        return "App -Allegro Software"
    elif "jboss" in title:
        return "App -Jboss"
    elif "apache log4j" in title:
        return "App -log4j"
    elif "lotus domino" in title:
        return "App -Lotus Domino"
    elif "mongodb" in title:
        return "App -MongoDB"
    elif "sendmail" in title:
        return "App -Sendmail"
    elif "visual studio" in title:
        return "App -Visual Studio"
    elif "veritas" in title:
        return "App -Veritas"
    elif "microsoft sharepoint" in title:
        return "App-SharePoint"
    elif "gitlab" in title:
        return "Gitlab"
    elif "vulnerability in ibm java sdk" in title:
        return "java"
    elif "aix" in title:
        return "IBM AIX"
    elif "ibm websphere" in title:
        return "IBM WebSphere"
    elif "openjdk" in title:
        return "java"
    elif "vulnerability in java" in title:
        return "java"
    elif ("kernel security update" in title or "kernel-rt security" in title or "(kernel)" in title or "kernel security" in title):
        return "Kernel Upgrade"
    elif ("libxml2" in title or "libvpx" in title or "glib2" in title or "krb5" in title or "glibc" in title or "freerdp security update" in title or "libraries security" in title or "libpng" in title or "evolution-mapi" in title or "openchange" in title or "libxslt" in title or "libssh2" in title):
        return "Library Upgrade"
    elif ("microsoft internet explorer" in title or "microsoft cve" in title or "microsoft project" in title or "microsoft excel" in title or "microsoft office" in title):
        return "MS - OS"
    elif "microsoft msxml" in title:
        return "MSXML"
    elif ("oracle identity manager" in title or "oracle listener control command validation and remote execution" in title or "oracle cpu" in title or "missing oracle critical patch" in title or "oracle critical patch" in title or "oracle database" in title):
        return "Oracle Database"
    elif ("oracle security alert: new java" in title or "jre" in title or "java runtime environment" in title or "java cpu" in title or "oracle security alert" in title or "java jre/jdk" in title):
        return "Oracle Java"
    elif "oracle weblogic" in title:
        return "Oracle PSU"
    elif ("oracle solaris 11" in title or "solaris sadmind" in title or "solaris snmpxdmid" in title or "solaris fingerd" in title or "solaris obsolete version" in title or "sun patch: sunos 5.10" in title or "sun patch: javase 6" in title or "sun patch: sunos" in title or "sun patch: cde" in title or "sun patch: openwindows" in title or "sun patch: x11" in title or "sun patch: gnome" in title):
        return "Solaris Patch"
    elif ("microsoft sql server" in title or "mssql" in title):
        return "SQL Server"
    elif "sun patch: solstice" in title:
        return "Sun Solaris"
    elif "obsolete vmware esx version" in title:
        return "Vmware"
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

            # Read the entire Excel file at once with progress updates
            print("Starting to process file...")
            
            # Explicitly import openpyxl to ensure it's available
            import openpyxl
            print(f"Using openpyxl version: {openpyxl.__version__}")
            
            # Read the full Excel file
            print("Reading Excel file...")
            df = pd.read_excel(file_path, engine='openpyxl')
            total_rows = len(df)
            print(f"Total rows to process: {total_rows}")

            # Clean column names
            df.columns = df.columns.str.strip()
            
            # Verify required column exists
            if 'vuln_title' not in df.columns:
                raise ValueError('Excel file must contain a "vuln_title" column')
            
            # Process in batches to show progress
            batch_size = 5000
            total_processed = 0
            
            print("\nProcessing vulnerabilities...")
            for start_idx in range(0, total_rows, batch_size):
                end_idx = min(start_idx + batch_size, total_rows)
                
                # Process this batch
                df.loc[start_idx:end_idx-1, 'Category'] = df.loc[start_idx:end_idx-1, 'vuln_title'].apply(categorize_vulnerability)
                
                total_processed += (end_idx - start_idx)
                print(f"Processed rows {start_idx+1} to {end_idx} of {total_rows} ({(total_processed/total_rows)*100:.1f}%)")
            # Content has been replaced in previous edit
            
            # Combine all chunks
            print(f"\nSuccessfully processed all {len(df)} rows")

            print(f"Final columns in processed data: {df.columns.tolist()}")
            print("Sample of processed data (first few rows):")
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
