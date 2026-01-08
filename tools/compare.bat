@echo off
:: Compare two files via browse dialog and count same/different characters

:: Ask user to select first file
for /f "usebackq delims=" %%A in (`powershell -command "Add-Type -AssemblyName System.Windows.Forms; $f = New-Object System.Windows.Forms.OpenFileDialog; $f.InitialDirectory = '%~dp0'; if($f.ShowDialog() -eq 'OK'){ Write-Output $f.FileName }"`) do set "file1=%%A"

:: Ask user to select second file
for /f "usebackq delims=" %%B in (`powershell -command "Add-Type -AssemblyName System.Windows.Forms; $f = New-Object System.Windows.Forms.OpenFileDialog; $f.InitialDirectory = '%~dp0'; if($f.ShowDialog() -eq 'OK'){ Write-Output $f.FileName }"`) do set "file2=%%B"

:: Check if files exist
if not exist "%file1%" (
    echo File 1 does not exist!
    pause
    exit /b
)
if not exist "%file2%" (
    echo File 2 does not exist!
    pause
    exit /b
)

:: Use PowerShell to compare character by character
powershell -command ^
"$f1 = Get-Content '%file1%' -Raw; ^
$f2 = Get-Content '%file2%' -Raw; ^
$len = [Math]::Max($f1.Length, $f2.Length); ^
$same = 0; $diff = 0; ^
for ($i=0; $i -lt $len; $i++) { ^
    if ($i -ge $f1.Length -or $i -ge $f2.Length) { $diff++ } ^
    elseif ($f1[$i] -eq $f2[$i]) { $same++ } ^
    else { $diff++ } ^
}; ^
Write-Host 'SAME CHARACTERS:' $same; ^
Write-Host 'DIFFERENT CHARACTERS:' $diff; ^
pause"
