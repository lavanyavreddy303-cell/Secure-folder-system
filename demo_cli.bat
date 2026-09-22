@echo off
REM ============================================================================
REM Cryptix CLI Demo Script (Windows Batch)
REM ============================================================================
REM DEMO ONLY - The passphrase is passed via an environment variable so this
REM script can run non-interactively.  NEVER do this in production; always use
REM interactive getpass input.
REM ============================================================================

REM Demo-only passphrase (>= 10 characters).  In real usage, the CLI prompts
REM interactively via getpass.
set CRYPTIX_PASSPHRASE=demo-passphrase-123

set STORAGE=demo_secure_storage
set SAMPLE=demo_sample
set OUTPUT=demo_output

echo ============================================
echo  Cryptix CLI Demo
echo ============================================
echo.

REM Clean up from any previous run
if exist "%STORAGE%" rmdir /s /q "%STORAGE%"
if exist "%SAMPLE%"  rmdir /s /q "%SAMPLE%"
if exist "%OUTPUT%"  rmdir /s /q "%OUTPUT%"
if exist "%OUTPUT%_tampered" rmdir /s /q "%OUTPUT%_tampered"

REM ------------------------------------------------------------------
REM 1. Create a sample folder with a few files
REM ------------------------------------------------------------------
echo ^>^>^> Creating sample folder ...
mkdir "%SAMPLE%\subdir"
echo Hello from Cryptix!>           "%SAMPLE%\readme.txt"
echo Nested secret file>            "%SAMPLE%\subdir\secret.txt"
echo binary>                        "%SAMPLE%\binary.dat"
echo.

REM ------------------------------------------------------------------
REM 2. Init - generate RSA keypair
REM ------------------------------------------------------------------
echo ^>^>^> cryptix init
venv\Scripts\python.exe app_cli.py --storage "%STORAGE%" init
echo.

REM ------------------------------------------------------------------
REM 3. Encrypt the sample folder
REM ------------------------------------------------------------------
echo ^>^>^> cryptix encrypt %SAMPLE%
venv\Scripts\python.exe app_cli.py --storage "%STORAGE%" encrypt "%SAMPLE%"
echo.

REM ------------------------------------------------------------------
REM 4. List encrypted files
REM ------------------------------------------------------------------
echo ^>^>^> cryptix list
venv\Scripts\python.exe app_cli.py --storage "%STORAGE%" list
echo.

REM ------------------------------------------------------------------
REM 5. Decrypt all -> should be SAFE
REM ------------------------------------------------------------------
echo ^>^>^> cryptix decrypt all %OUTPUT%  (expect SAFE)
venv\Scripts\python.exe app_cli.py --storage "%STORAGE%" decrypt all "%OUTPUT%"
echo.

REM ------------------------------------------------------------------
REM 6. Corrupt one byte of a data.enc, then decrypt -> TAMPERED
REM ------------------------------------------------------------------
echo ^>^>^> Corrupting one data.enc ...

REM Find the first data.enc and flip byte 0
for /f "delims=" %%F in ('dir /s /b "%STORAGE%\files\data.enc" 2^>nul') do (
    venv\Scripts\python.exe -c "import sys; p=sys.argv[1]; d=bytearray(open(p,'rb').read()); d[0]^=0xFF; open(p,'wb').write(d); print(f'   Flipped byte 0 in {p}')" "%%F"
    goto :done_corrupt
)
:done_corrupt
echo.

echo ^>^>^> cryptix decrypt all %OUTPUT%_tampered  (expect TAMPERED)
venv\Scripts\python.exe app_cli.py --storage "%STORAGE%" decrypt all "%OUTPUT%_tampered"
if errorlevel 1 echo    (exit code indicates TAMPERED - expected)
echo.

REM ------------------------------------------------------------------
REM Done
REM ------------------------------------------------------------------
echo ============================================
echo  Demo complete!
echo ============================================

REM Clean up env var
set CRYPTIX_PASSPHRASE=
