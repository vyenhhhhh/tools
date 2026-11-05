@echo off
REM MYTRACK - ACR122U card reader helper. Keep this window open while the kiosk is running.
cd /d "%~dp0"
python --version >nul 2>&1 || (
  echo Python is not installed. Install it from https://www.python.org/downloads/ and tick "Add python.exe to PATH".
  pause
  exit /b 1
)
python -c "import smartcard" >nul 2>&1 || (
  echo Installing pyscard the first time...
  python -m pip install -r requirements.txt
)
python mytrack_reader.py
pause