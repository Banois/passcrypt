@echo off
:: Count the number of characters in a file via browse dialog

:: Ask user to select a file
for /f "usebackq delims=" %%A in (`powershell -command "Add-Type -AssemblyName System.Windows.Forms; $f = New-Object System.Windows.Forms.OpenFileDialog; $f.InitialDirectory = '%~dp0'; if($f.ShowDialog() -eq 'OK'){ Write-Output $f.FileName }"`) do set "file=%%A"

:: Check if the file exists
if not exist "%file%" (
    echo File does not exist!
    pause
    exit /b
)

:: Use PowerShell to count characters
powershell -command ^
"$content = Get-Content '%file%' -Raw; ^
Write-Host 'Total characters in the file:' $content.Length; ^
pause"
