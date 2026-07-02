@echo off
chcp 65001 >nul
echo.
echo  ██╗   ██╗███╗   ██╗    ██████╗  ██████╗ ███╗   ███╗ █████╗ ██╗███╗   ██╗
echo  ██║   ██║████╗  ██║    ██╔══██╗██╔═══██╗████╗ ████║██╔══██╗██║████╗  ██║
echo  ██║   ██║██╔██╗ ██║    ██║  ██║██║   ██║██╔████╔██║███████║██║██╔██╗ ██║
echo  ╚██╗ ██╔╝██║╚██╗██║    ██║  ██║██║   ██║██║╚██╔╝██║██╔══██║██║██║╚██╗██║
echo   ╚████╔╝ ██║ ╚████║    ██████╔╝╚██████╔╝██║ ╚═╝ ██║██║  ██║██║██║ ╚████║
echo    ╚═══╝  ╚═╝  ╚═══╝    ╚═════╝  ╚═════╝ ╚═╝     ╚═╝╚═╝  ╚═╝╚═╝╚═╝  ╚═══╝
echo.
echo  ██╗  ██╗██╗   ██╗███╗   ██╗████████╗███████╗██████╗
echo  ██║  ██║██║   ██║████╗  ██║╚══██╔══╝██╔════╝██╔══██╗
echo  ███████║██║   ██║██╔██╗ ██║   ██║   █████╗  ██████╔╝
echo  ██╔══██║██║   ██║██║╚██╗██║   ██║   ██╔══╝  ██╔══██╗
echo  ██║  ██║╚██████╔╝██║ ╚████║   ██║   ███████╗██║  ██║
echo  ╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═══╝   ╚═╝   ╚══════╝╚═╝  ╚═╝
echo.
echo  [*] Cyberpunk Security Intelligence Tool v2.0
echo  [*] Checking Python environment...
echo.

python --version >nul 2>&1
if errorlevel 1 (
    echo  [ERROR] Python not found! Please install Python 3.9+ from python.org
    pause
    exit /b 1
)

echo  [*] Installing dependencies...
pip install -r requirements.txt -q
if errorlevel 1 (
    echo  [ERROR] Failed to install dependencies!
    pause
    exit /b 1
)

echo.
echo  [OK] All dependencies installed.
echo  [*] Starting VN Domain Hunter server...
echo  [*] Open your browser and go to: http://localhost:8000
echo.

start "" "http://localhost:8000"
python app.py

pause
