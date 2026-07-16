@echo off
rem ============================================================
rem CheckAcl.bat - ACL inventory with resume support (CSV output)
rem   Uses only standard Windows commands (icacls, dir, findstr)
rem
rem Usage:
rem   CheckAcl.bat <RootPath> [OutputDir] [MaxDirsPerRun]
rem
rem Example:
rem   CheckAcl.bat \\fs01\share D:\acl-output 5000
rem
rem Outputs (in OutputDir):
rem   root_acl.txt     : full ACL of the top folder (covers inherited ACEs)
rem   explicit_acl.csv : explicit (non-inherited) ACEs as CSV
rem                      columns: Path,Account,AccessType,Rights
rem   explicit_acl.txt : raw icacls lines of explicit ACEs (audit trail)
rem   denied.txt       : folders this account could NOT read (delegate these)
rem   denied.csv       : same list in CSV for Excel
rem   enum_errors.txt  : errors during initial folder enumeration
rem   dirlist.txt      : enumerated folder list (created once, reused)
rem   checkpoint.txt   : number of folders already processed (resume point)
rem
rem Resume: run the same command again. To restart from scratch,
rem         delete dirlist.txt and checkpoint.txt.
rem ============================================================
setlocal disabledelayedexpansion

set "ROOT=%~1"
set "OUTDIR=%~2"
set "MAXDIRS=%~3"
if "%ROOT%"=="" (
  echo Usage: %~nx0 ^<RootPath^> [OutputDir] [MaxDirsPerRun]
  exit /b 1
)
if "%OUTDIR%"=="" set "OUTDIR=acl-output"
if "%MAXDIRS%"=="" set "MAXDIRS=0"

if not exist "%OUTDIR%" mkdir "%OUTDIR%"

set "DIRLIST=%OUTDIR%\dirlist.txt"
set "CPFILE=%OUTDIR%\checkpoint.txt"
set "EXPLICIT=%OUTDIR%\explicit_acl.txt"
set "EXPCSV=%OUTDIR%\explicit_acl.csv"
set "DENIED=%OUTDIR%\denied.txt"
set "DENIEDCSV=%OUTDIR%\denied.csv"
set "ROOTACL=%OUTDIR%\root_acl.txt"
set "ENUMERR=%OUTDIR%\enum_errors.txt"
set "TMPD=%TEMP%\_acl_item.tmp"
set "TMPF=%TEMP%\_acl_scan.tmp"
set "TMPM=%TEMP%\_acl_match.tmp"

rem ---- 1. Save full ACL of the top folder ----
icacls "%ROOT%" > "%ROOTACL%" 2>&1

rem ---- 2. Enumerate all folders once (reused on resume) ----
if exist "%DIRLIST%" (
  echo [INFO] Existing dirlist.txt found - reusing it for resume.
) else (
  echo [INFO] Enumerating folders under %ROOT% ...
  >"%DIRLIST%" echo(%ROOT%
  dir "%ROOT%" /ad /b /s >> "%DIRLIST%" 2> "%ENUMERR%"
)
for /f %%C in ('type "%DIRLIST%" ^| find /c /v ""') do set TOTAL=%%C

rem ---- 3. CSV header (only when file does not exist yet) ----
if not exist "%EXPCSV%" >"%EXPCSV%" echo Path,Account,AccessType,Rights

rem ---- 4. Load resume point ----
set SKIP=0
if exist "%CPFILE%" set /p SKIP=<"%CPFILE%"
set /a COUNT=SKIP
set PROCESSED=0
set STOPPED=
echo [INFO] Total folders: %TOTAL%  (already done: %SKIP%)

rem ---- 5. Main loop ----
if %SKIP%==0 goto loop_noskip
for /f "usebackq skip=%SKIP% delims=" %%D in ("%DIRLIST%") do call :proc "%%D"
goto finish
:loop_noskip
for /f "usebackq delims=" %%D in ("%DIRLIST%") do call :proc "%%D"
goto finish

rem ------------------------------------------------------------
:proc
if defined STOPPED exit /b
set "D=%~1"

rem --- the folder itself: parse its ACL into CSV rows ---
icacls "%D%" > "%TMPD%" 2>>"%DENIED%"
set "P=%D%"
call :parse_item

rem --- fast scan of items directly inside the folder ---
icacls "%D%\*" > "%TMPF%" 2>nul
findstr /c:":(" "%TMPF%" | findstr /v /c:"(I)" > "%TMPM%"
for %%Z in ("%TMPM%") do if not %%~zZ==0 call :folder_detail

rem --- checkpoint: record progress after each completed folder ---
set /a COUNT+=1
>"%CPFILE%" echo %COUNT%
set /a PROCESSED+=1
set /a MOD=PROCESSED%%100
if %MOD%==0 echo [PROGRESS] %COUNT% / %TOTAL%
if %MAXDIRS% GTR 0 if %PROCESSED% GEQ %MAXDIRS% set STOPPED=1
exit /b

rem ------------------------------------------------------------
rem Folder contains at least one item with an explicit ACE:
rem keep the raw lines, then re-check each file individually
rem so every CSV row gets an exact path.
rem (Subfolders are handled when their own turn comes in the main loop.)
:folder_detail
>>"%EXPLICIT%" echo === FOLDER: %D%
type "%TMPM%" >> "%EXPLICIT%"
for /f "usebackq delims=" %%F in (`dir "%D%" /a-d /b 2^>nul`) do (
  icacls "%D%\%%F" > "%TMPD%" 2>nul
  set "P=%D%\%%F"
  call :parse_item
)
exit /b

rem ------------------------------------------------------------
rem Parse icacls output in %TMPD% for the single item whose full
rem path is in %P%. Emit one CSV row per explicit ACE.
:parse_item
call :strlen PLEN P
set /a POS=PLEN+1
for /f "usebackq delims=" %%L in ("%TMPD%") do (
  set "LINE=%%L"
  call :parse_line
)
exit /b

:parse_line
setlocal enabledelayedexpansion
if not defined LINE (endlocal & exit /b)
rem skip inherited ACEs and non-ACE lines
if not "!LINE:(I)=!"=="!LINE!" (endlocal & exit /b)
set "RIGHTS=!LINE:*:(=!"
if "!RIGHTS!"=="!LINE!" (endlocal & exit /b)
rem HEAD = text before ":(" (path+account on 1st line, account only after)
for /f "delims=" %%X in ("!RIGHTS!") do set "HEAD=!LINE::(%%X=!"
if "!HEAD:~0,1!"==" " (
  for /f "tokens=* delims= " %%Y in ("!HEAD!") do set "IDEN=%%Y"
) else (
  set "IDEN=!HEAD:~%POS%!"
)
set "ATYPE=Allow"
if not "!RIGHTS:DENY=!"=="!RIGHTS!" set "ATYPE=Deny"
>>"%EXPCSV%" echo "!P!","!IDEN!","!ATYPE!","(!RIGHTS!"
endlocal
exit /b

rem ------------------------------------------------------------
:strlen  rem :strlen <resultVar> <stringVar>
setlocal enabledelayedexpansion
set "s=!%~2!#"
set "len=0"
for %%N in (4096 2048 1024 512 256 128 64 32 16 8 4 2 1) do (
  if not "!s:~%%N,1!"=="" (set /a len+=%%N & set "s=!s:~%%N!")
)
endlocal & set "%~1=%len%"
exit /b

rem ------------------------------------------------------------
:finish
rem denied.csv regenerated from denied.txt on every run
if exist "%DENIED%" (
  >"%DENIEDCSV%" echo DeniedEntry
  for /f "usebackq delims=" %%L in ("%DENIED%") do >>"%DENIEDCSV%" echo "%%L"
)
del "%TMPD%" "%TMPF%" "%TMPM%" 2>nul
echo.
echo ===== RESULT =====
echo Processed this run : %PROCESSED%
echo Progress           : %COUNT% / %TOTAL%
echo Root folder ACL    : %ROOTACL%
echo Explicit ACE CSV   : %EXPCSV%
echo Access denied list : %DENIEDCSV%
if defined STOPPED (
  echo [INFO] Reached MaxDirsPerRun. Run the same command again to resume.
) else (
  echo [INFO] Completed.
)
endlocal
