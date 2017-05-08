@ECHO OFF

:: cert info to use for signing
SET CERT=9CC90E20ABF21CDEF09EE4C467A79FD454140C5A
set TSAURL=http://time.certum.pl/
set LIBNAME=Repacls
set LIBURL=https://github.com/NoMoreFood/Repacls

:: do cleanup
FOR %%X IN (Debug Temp .vs) DO (
  FORFILES /S /P "%~dp0.." /M "%%X" /C "CMD /C IF @isdir==TRUE RD /S /Q @path"
)
FOR %%X IN (Win32 x64 Debug Release) DO (
  FORFILES /S /P "%~dp0.." /M "*.*pdb" /C "CMD /C DEL /Q @path"
  FORFILES /S /P "%~dp0.." /M "*.*obj" /C "CMD /C DEL /Q @path"
  FORFILES /S /P "%~dp0.." /M "*.log" /C "CMD /C DEL /Q @path"
)

:: setup environment variables based on location of this script
SET BINDIR=%~dp0Release

:: determine 32-bit program files directory
IF DEFINED ProgramFiles SET PX86=%ProgramFiles%
IF DEFINED ProgramFiles(x86) SET PX86=%ProgramFiles(x86)%

:: setup paths
SET PATH=%WINDIR%\system32;%WINDIR%\system32\WindowsPowerShell\v1.0
SET PATH=%PATH%;%PX86%\Windows Kits\10\bin\x64
SET PATH=%PATH%;%PX86%\Windows Kits\8.1\bin\x64

:: sign the main executables
signtool sign /sha1 %CERT% /fd sha1 /tr %TSAURL% /td sha1 /d %LIBNAME% /du %LIBURL% "%BINDIR%\x86\*.exe" "%BINDIR%\x64\*.exe" 
signtool sign /sha1 %CERT% /as /fd sha256 /tr %TSAURL% /td sha256 /d %LIBNAME% /du %LIBURL% "%BINDIR%\x86\*.exe" "%BINDIR%\x64\*.exe"

PAUSE