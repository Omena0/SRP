@echo off
REM Build script for SRP - Small Reverse Proxy

echo Building SRP with optimizations...
gcc -O3 -Wall -Wextra -march=native -flto -o srp.exe main.c -lws2_32

if %ERRORLEVEL% EQU 0 (
    echo.
    echo ✓ Build successful! Binary: srp.exe
    echo.
    echo Usage:
    echo   Forward: srp.exe forward ^<local-port^> ^<tunnel-ip:port^> ^<password^>
    echo   Serve:   srp.exe serve ^<bind-addr:port^> ^<password^>
) else (
    echo.
    echo ✗ Build failed!
    exit /b 1
)
