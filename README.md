# Excel Category Auto-Filler

A simple Python Flask web application to automatically categorize vulnerabilities in an Excel file based on their titles. This tool provides a clean web interface for uploading an Excel file, processes it efficiently, and allows you to download the updated file with a new "Category" column.

## Features

-   **Simple Web UI**: Upload an Excel file (`.xlsx` or `.xls`) through a basic Bootstrap interface.
-   **Automatic Categorization**: Fills the "Category" column by matching keywords in the "vuln_title" column.
-   **Efficient Processing**: Built with `pandas` and `openpyxl` to handle large Excel files.
-   **Download Processed File**: Provides a direct download link for the updated Excel file.
-   **Error Handling**: Includes basic error handling for invalid file types or missing columns.

## Requirements

-   Python 3.x
-   Flask
-   Pandas
-   Openpyxl

All dependencies are listed in `requirements.txt`.

## How to Run Locally

1.  **Clone the repository:**
    ```bash
    git clone <your-repository-url>
    cd Excel-Category-Auto-Filler
    ```

2.  **Create and activate a virtual environment:**
    ```powershell
    # For Windows
    python -m venv .venv
    .venv\Scripts\Activate.ps1
    ```

3.  **Install the required packages:**
    ```bash
    pip install -r requirements.txt
    ```

4.  **Run the Flask application:**
    ```bash
    python app.py
    ```

5.  **Open your web browser** and go to `http://127.0.0.1:5000`.

## Core Categorization Logic

The heart of the application is the `categorize_vulnerability` function, which contains the mapping from vulnerability titles to categories.

```python
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
    # ... additional rules are in app.py
    return "TBD"
```
