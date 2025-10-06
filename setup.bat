@echo off
echo Creating virtual environment...
python -m venv .venv
echo Installing packages...
.\.venv\Scripts\python.exe -m pip install --upgrade pip
.\.venv\Scripts\python.exe -m pip install flask pandas openpyxl
echo Done!