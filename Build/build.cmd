@ECHO OFF
TITLE Building Repacls...
CLS
SET PATH=%WINDIR%\system32;%WINDIR%\system32\WindowsPowerShell\v1.0

:: cert info to use for signing
SET CERT=193A6FACBFBFC43ADB74ABB669543FCBC1C4F26C
set TSAURL=http://time.certum.pl/
set LIBNAME=Repacls
set LIBURL=https://github.com/NoMoreFood/Repacls

:: do cleanup
DEL "%~dp0*.iobj" /F /S /Q >NUL 2>&1
DEL "%~dp0*.ipdb" /F /S /Q >NUL 2>&1
DEL "%~dp0lastcodeanalysissucceeded" /F /S /Q >NUL 2>&1
RD /S /Q "%~dp0..\.vs" >NUL 2>&1
RD /S /Q "%~dp0..\Temp" >NUL 2>&1
RD /S /Q "%~dp0Debug" >NUL 2>&1
RD /S /Q "%~dp0Release\x86\Temp" >NUL 2>&1
RD /S /Q "%~dp0Release\x64\Temp" >NUL 2>&1
FORFILES /S /P "%~dp0." /M "*.*pdb" /C "CMD /C DEL /Q @path" >NUL 2>&1
FORFILES /S /P "%~dp0." /M "*.*obj" /C "CMD /C DEL /Q @path" >NUL 2>&1
FORFILES /S /P "%~dp0." /M "*.zip" /C "CMD /C DEL /Q @path" >NUL 2>&1
FORFILES /S /P "%~dp0." /M "*.log" /C "CMD /C DEL /Q @path" >NUL 2>&1
FORFILES /S /P "%~dp0." /M "*.lib" /C "CMD /C DEL /Q @path" >NUL 2>&1
FORFILES /S /P "%~dp0." /M "*.dll" /C "CMD /C DEL /Q @path" >NUL 2>&1
FORFILES /S /P "%~dp0." /M "*.bsc" /C "CMD /C DEL /Q @path" >NUL 2>&1
FORFILES /S /P "%~dp0." /M "*.exp" /C "CMD /C DEL /Q @path" >NUL 2>&1
FORFILES /S /P "%~dp0." /M "*.last*" /C "CMD /C DEL /Q @path" >NUL 2>&1

:: setup environment variables based on location of this script
SET BINDIR=%~dp0Release

:: determine 32-bit program files directory
IF DEFINED ProgramFiles SET PX86=%ProgramFiles%
IF DEFINED ProgramFiles(x86) SET PX86=%ProgramFiles(x86)%

:: setup commands and paths
SET POWERSHELL=POWERSHELL.EXE -NoProfile -NonInteractive -NoLogo
FOR /F "USEBACKQ DELIMS=" %%X IN (`DIR /OD /B /S "%PX86%\Windows Kits\10\SIGNTOOL.exe" ^| FINDSTR x64`) DO SET SIGNTOOL="%%~X"

:: sign the main executables
%SIGNTOOL% sign /sha1 %CERT% /fd sha1 /tr %TSAURL% /td sha1 /d %LIBNAME% /du %LIBURL% "%BINDIR%\x86\*.exe" "%BINDIR%\x64\*.exe" 
%SIGNTOOL% sign /sha1 %CERT% /as /fd sha256 /tr %TSAURL% /td sha256 /d %LIBNAME% /du %LIBURL% "%BINDIR%\x86\*.exe" "%BINDIR%\x64\*.exe"

:: zip up executatables
PUSHD "%BINDIR%"
%POWERSHELL% -Command "Compress-Archive -LiteralPath @('x86','x64') -DestinationPath '%~dp0Repacls.zip'"
POPD

PAUSE