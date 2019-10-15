@echo off
:: Launch PowerShell Remote Tools
:: https://github.com/Justin-Lund/

start powershell -Command Invoke-Command -ScriptBlock {Set-ExecutionPolicy Bypass; C:\Remote-Tools.ps1}
