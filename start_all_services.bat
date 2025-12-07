@echo off
title Golden Express Launcher
setlocal enabledelayedexpansion

REM ==================================================
REM   GOLDEN EXPRESS — LOCAL LAUNCHER (IMPROVED)
REM   Author: Shivu
REM ==================================================

REM ---------- PATH CONFIG ----------
set "DESKTOP=%USERPROFILE%\OneDrive\Desktop"
set "PROJECT_DIR=%DESKTOP%\mini_project"
set "BACKEND_DIR=%PROJECT_DIR%\backend"
set "SECURITY_DIR=%PROJECT_DIR%\security"
set "ADMIN_DIR=%PROJECT_DIR%\admin"
set "PY=python"
REM ---------------------------------

REM ---------- TOKENS & SECRETS ----------
set "ADMIN_TOKEN=ShivuSecureAdminToken123"
set "INTERNAL_SECRET=Shivu_Internal_Proxy_Secret_12345"
set "SESSION_SECRET=ShivuSessionSecret98765"
echo [OK] Using secrets and ADMIN_TOKEN for this session.
echo.
REM ---------------------------------

REM ---------- CHECK DOCKER ----------
where docker >nul 2>&1
if %errorlevel% neq 0 (
    echo [ERROR] Docker not found. Please start Docker Desktop and rerun.
    pause
    exit /b
)
for /f "tokens=2 delims=: " %%A in ('docker desktop status ^| find "Status"') do set "DOCKER_STATUS=%%A"
if /i not "!DOCKER_STATUS!"=="running" (
    echo [ERROR] Docker Desktop not running. Start it first.
    pause
    exit /b
)
echo [OK] Docker detected and running.
echo.

REM ---------- START REDIS ----------
echo [INFO] Checking Redis container...
docker ps -a --format "{{.Names}}" | findstr /i "golden_redis" >nul 2>&1
if %errorlevel% neq 0 (
    echo [INFO] Creating new Redis container...
    docker run -d --name golden_redis -p 6379:6379 redis:7 >nul
) else (
    echo [OK] golden_redis exists. Starting if needed...
    docker start golden_redis >nul
)
timeout /t 3 /nobreak >nul
echo [OK] Redis running on port 6379.
echo.

REM ---------- START BACKEND ----------
if exist "%BACKEND_DIR%\main.py" (
    echo [OK] Starting Backend (FastAPI:5000)
    start "Backend" cmd /k "cd /d %BACKEND_DIR% && set PYTHONPATH=%PROJECT_DIR% && set INTERNAL_SECRET=%INTERNAL_SECRET% && set SESSION_SECRET=%SESSION_SECRET% && set ADMIN_TOKEN=%ADMIN_TOKEN% && %PY% -m uvicorn backend.main:app --host 0.0.0.0 --port 5000 --reload"
) else (
    echo [ERROR] main.py not found in backend folder.
)
timeout /t 4 >nul

REM ---------- WAIT FOR BACKEND ----------
echo [INFO] Checking backend health...
set /a tries=0
:wait_loop
set /a tries+=1
curl -s http://127.0.0.1:5000/health | find /i "\"status\":\"ok\"" >nul
if %errorlevel%==0 (
    echo [OK] Backend online.
) else (
    if !tries! lss 10 (
        timeout /t 2 >nul
        goto wait_loop
    ) else (
        echo [WARN] Backend did not respond after waiting. Continuing...
    )
)
echo.

REM ---------- START PROXY ----------
if exist "%SECURITY_DIR%\proxy.py" (
    echo [OK] Starting Proxy (FastAPI:8000)
    start "Proxy" cmd /k "cd /d %PROJECT_DIR% && set PYTHONPATH=%PROJECT_DIR% && set INTERNAL_SECRET=%INTERNAL_SECRET% && set ADMIN_TOKEN=%ADMIN_TOKEN% && %PY% -m uvicorn security.proxy:app --host 0.0.0.0 --port 8000 --reload"
) else (
    echo [ERROR] proxy.py not found in security folder.
)
timeout /t 3 >nul

REM ---------- START ADMIN DASHBOARD ----------
if exist "%ADMIN_DIR%\admin.py" (
    echo [OK] Starting Admin Dashboard (Streamlit:8501)
    start "Admin" cmd /k "cd /d %ADMIN_DIR% && set PYTHONPATH=%PROJECT_DIR% && set ADMIN_TOKEN=%ADMIN_TOKEN% && streamlit run admin.py --server.port 8501 --server.headless true"
) else (
    echo [WARN] admin.py not found in admin folder.
)
echo.

REM ---------- SUMMARY ----------
echo ========================================
echo ✅ All services launched
echo ----------------------------------------
echo  Redis:        localhost:6379
echo  Backend:      http://127.0.0.1:5000
echo  Proxy:        http://127.0.0.1:8000
echo  Admin Panel:  http://127.0.0.1:8501
echo ========================================
echo.
pause
endlocal
