######################################################### 
#       Powershell Remote Support Tool V1.4.1           # 
#                Created By: Justin Lund                # 
#             https://github.com/Justin-Lund/           # 
######################################################### 

# Due to the length of some of these functions, this script is best viewed in PowerShell ISE
# Press Ctrl + M to collapse all functions for easy navigation


#****************** Set path to CMRC here ******************#
$CMRCPath = "C:\SCCM 2012 - Remote Control App\CmRcViewer.exe"
#****************** --------------------- ******************#


# Sets Window Title
$Host.UI.RawUI.WindowTitle = “Remote Support Tools”

#--------------Technical Functions--------------#

Function Pause ($Message="Press any key to continue..."){ 
    "" 
    Write-Host $Message 
    $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
    Clear-Host
}  

Function Test-Ping {
#Ensure computer is online/accessible
ping $ComputerName -n 1 | Out-Null
if ($LASTEXITCODE -eq 0)
    {
    }
Else
    {
    Write-Host "Unable to reach computer"
    Pause
    Get-Menu
    }
}

Function Test-User {
#Verify Username
$Username = Get-ADUser -LDAPFilter "(sAMAccountName=$Username)"
If ($Username -eq $Null)
    {
    Write-Host ""
    Write-Host "User does not exist in AD"
    Pause
    Get-Menu
    }
Else
    {
    }
}

Function Test-UserProfile {
    $PathTest = Invoke-Command -Computer $ComputerName -ScriptBlock {Test-Path "C:\Users\$Using:Username"}
    If ($PathTest -eq $True)
        {
        }
    Else
        {
    Write-Host ""
    Write-Host "User does not have a profile on this computer"
    Write-Host ""

    Pause
    Get-Menu
    }
}

Function Test-DriveLetter {

    $RegPathHKU = "HKU:\$SID\Network\$NetworkDriveLetter"
    $RegPathTest = Invoke-Command -Computer $ComputerName -ScriptBlock {New-PSDrive -PSProvider Registry -Name HKU -Root HKEY_USERS | Out-Null; Test-Path "$Using:RegPathHKU"; Remove-PSDrive HKU}

    If ($RegPathTest -eq $False)
        {
        }
    Else
        {
        Write-Host ""
        Write-Host "User already has this drive letter mapped"
        Write-Host ""

        Pause
        Get-Menu
    }
}

Function Prompt-YesNo {
    $Confirmation = Read-Host "[Y/N]"
    While ($Confirmation -ne "Y")
    {
        #If user types N, go back to main menu
        If ($Confirmation -eq 'N')
        {

        Pause
        Get-Menu
        }

        #Re-Prompt for Y/N if user doesn't type Y or N
        $Confirmation = Read-Host "Please type Y or N"

        Write-Host ""
    }

    #If user typed Y, proceed
}  

Function User-Logout {
    $LogoutSession = {
         $ErrorActionPreference = 'Stop'
 
         try {
             ## Find all sessions matching the specified username
             $Sessions = quser | Where-Object {$_ -match $Using:Username}

             ## Parse the session IDs from the output
             $SessionIDs = ($Sessions -split ' +')[2]
             Write-Host "Found $(@($SessionIDs).Count) user login(s) on computer."

             ## Loop through each session ID and pass each to the logoff command
             $sessionIDs | ForEach-Object {
                 Write-Host "Logging off $Using:Username..."
                 logoff $_
             }
         } catch {
             if ($_.Exception.Message -match 'No user exists') {
                Write-Host "The user is not logged in."
                Write-Host ""
                Pause
                Get-Menu
             } else {
                Write-Host "The user is not logged in."
                Write-Host ""
                Pause
                Get-Menu
             }
         }
     }
    Invoke-Command -Computer $ComputerName -ScriptBlock $LogoutSession
}

Function Create-NetworkShare {
    #Create the registry entries for the network drive

    Invoke-Command -Computer $ComputerName -ScriptBlock {
        #Create the registry key for the network share
        echo n | Reg Add $Using:RegistryPath

        #Set the network path value
        echo n | Reg Add $Using:RegistryPath /v RemotePath /t REG_SZ /d $Using:NetworkPath | Out-Null

        #Set the remaining values
        echo n | Reg Add $Using:RegistryPath /v ConnectFlags /t REG_DWORD /d 0 | Out-Null
        echo n | Reg Add $Using:RegistryPath /v ConnectionType /t REG_DWORD /d 1 | Out-Null
        echo n | Reg Add $Using:RegistryPath /v DeferFlags /t REG_DWORD /d 4 | Out-Null
        echo n | Reg Add $Using:RegistryPath /v ProviderFlags /t REG_DWORD /d 1 | Out-Null
        echo n | Reg Add $Using:RegistryPath /v ProviderName /t REG_SZ /d "Microsoft Windows Network" | Out-Null
        echo n | Reg Add $Using:RegistryPath /v ProviderType /t REG_DWORD /d 131072 | Out-Null
        echo n | Reg Add $Using:RegistryPath /v UserName /t REG_DWORD /d 0 | Out-Null
    }
}


############### Menu Functions ###############

#--------------Application Openers--------------#

Function Launch-CMRC {
    Start $CMRCPath
    Get-Menu
}

Function Launch-CMRC-Direct {
    Start $CMRCPath $ComputerName
}

Function Launch-AD {
    Start "C:\Windows\System32\dsa.msc"
    Get-Menu
}

Function Launch-PowerShell {
    Start PowerShell
    Get-Menu
}

Function Launch-RemoteExplorer {
			
    Invoke-Item \\$ComputerName\C$
}


#--------------Info Gathering--------------#

Function Get-UserInfo {
    $Username = Read-Host "Please enter a username"
    Write-Host ""

    # Store status of whether or not user is locked out in a new variable
    $LockedOutStatus = (Get-ADUser $Username -Properties LockedOut).LockedOut

    # Display general user account information
    net user $Username /domain | findstr /i /c:"User name" /c:"Full Name" /c:"Comment" /c:"Account Active" /c:"Account Expires" /c:"Password Last Set" /c:"Password Expires" /c:"Password changeable" /c:"Last logon"
    Write-Host ""


    If ($LockedOutStatus -eq $True)
        {
            Write-Host "User is locked out. Unlock the user?"
            Prompt-YesNo # Only continues if the user presses Y
        
            Unlock-ADAccount -Identity $Username
            Write-Host "User unlocked."
        }

    Else
        {
            # If user was not locked out, continue
        }


    Pause
 }

Function Get-CurrentUser {

    GWMI -Computer $ComputerName Win32_ComputerSystem | Format-Table @{Expression={$_.Username};Label="Current User"} 
			
    Pause       
}

Function Get-SystemInfo {

    SystemInfo /s $ComputerName | findstr /i /c:"Host Name" /c:"OS Name" /c:"OS Version" /c:"Original Install Date" /c:"System Boot Time" /c:"System Up Time" /c:"System Manufacturer" /c:"System Model" /c:"System Type" /c:"Total Physical Memory"
			
    Pause      
}

Function Get-InstalledPrograms {

    Write-Host "This may take a moment..."
    Write-Host ""

	GWMI -Computer $ComputerName Win32_Product | Sort-Object Name | Format-Table Name,Vendor,Version 
		
    Pause 
}

Function Get-Ping {

    Ping $ComputerName | Tee-Object -Variable PingResults
    Get-PingMenu
}


#--------------Pushes--------------#

Function Push-GPUpdate {
			
    Invoke-GPUpdate -Computer $ComputerName -Force
			
	Pause
}

Function Push-NetworkDriveMapping {
			
    #Prompt User for SID, save as variable
    $Username = Read-Host "Enter the username"
    Test-User
    Test-UserProfile

    #Get the SID
    $SID = (Get-ADUser -Identity $Username | Select SID).SID.Value


    #Save the desired shared drive letter as a variable
    do
    {
        $input="NotOK"
        # Choose Drive letter
        $NetworkDriveLetter = Read-Host "Choose a drive letter"

        # Limit Drive Letter to one character
        if ($NetworkDriveLetter -notmatch "^[A,B,D-Z]$")
        {
            Write-Host ""
            Write-Host "Please choose a drive letter" -ForegroundColor Red
            Write-Host ""
            $input="NotOK"
        }

        else
        {
            $input="ok"
        }
    }
    while($input -ne "ok")

    #Convert any input to Upper Case
    $NetworkDriveLetter = $NetworkDriveLetter.ToUpper()

    #Set the Registry Path
    $RegistryPath = "HKEY_USERS\$SID\Network\$NetworkDriveLetter"
    Test-DriveLetter


    #Save the desired network path as a variable
    Write-Host ""
    Write-Host "Enter the FULL network path"
    $NetworkPath = Read-Host "eg. \\domain.loc\etc"

    Create-NetworkShare

    #Logout confirmation
    Write-Host "The user must log out for the drive to show up. Log user out?"
            
    Prompt-YesNo #Only continues if the user presses Y
    User-Logout

	Pause
	Get-Menu
}

Function Push-PrinterFix {
    #Fixes printer issues by restarting the printer spooler service & clearing printer cache

	Invoke-Command -ComputerName $ComputerName -ScriptBlock {Stop-Service "spooler"; Remove-Item -Path "C:\Windows\System32\spool\PRINTERS\*" -Recurse; Start-Service "spooler"}
			
    Pause
}

Function Push-UpdateFix {
    #Fixes failing updates by clearing the Software Distribution folder and stopping the relevant services to do so

	Invoke-Command -ComputerName $ComputerName -ScriptBlock {Stop-Service "wuauserv"; Stop-Service "CcmExec"; Remove-Item -Path "C:\Windows\SoftwareDistribution\*" -Recurse ; Start-Service "wuauserv"; Start-Service "CcmExec"}
			
    Pause
}

Function Push-UserCommandTools {
    # Pushes the User Command Tools batch file to C:\Temp of the user's computer
    # See https://github.com/Justin-Lund/IT-Support-Batch-Files for a full overview of this file

    Write-Host "User Command Tools Batch File will be transferred to C:\Temp of $ComputerName"
    Invoke-Command -Computer $ComputerName -ScriptBlock {

    Set-Content "C:\Temp\User Command Tools 2.3.bat" @"
@echo off
:: User Command Tools 2.3
:: https://github.com/Justin-Lund/

:Start
cls
title User Command Tools 2.3
c:
cd\


echo 1. Get I.P. Address
echo 2. Get Computer System Information
echo 3. Force Group Policy Update
echo 4. Renew I.P. Address ^& Reset TCP/IP
echo 5. Clear Internet Explorer Cache and Cookies
echo 6. Clear Cached Credentials
echo 7. Clear Skype Cache
echo 8. Clear All Cache
echo 9. Clear/Reset Everything
echo.

CHOICE /C 123456789 /M "Enter your choice:"

IF ERRORLEVEL 9 GOTO ClearEverything
IF ERRORLEVEL 8 GOTO ClearAllCache
IF ERRORLEVEL 7 GOTO ClearSkypeCache
IF ERRORLEVEL 6 GOTO ClearCachedCredentials
IF ERRORLEVEL 5 GOTO ClearIECache
IF ERRORLEVEL 4 GOTO IPRenew
IF ERRORLEVEL 3 GOTO GPUpdate
IF ERRORLEVEL 2 GOTO SystemInfo
IF ERRORLEVEL 1 GOTO IPConfig


:IPConfig
cls
title I.P. Configuration
ipconfig|findstr /i /c:"Ethernet" /c:"Wireless" /c:"IPv4"

echo.
pause
GOTO Start


:SystemInfo
cls
title Computer System Information
systeminfo|findstr /i /c:"Host Name" /c:"OS Name" /c:"OS Version" /c:"Original Install Date" /c:"System Boot Time" /c:"System Up Time" /c:"System Manufacturer" /c:"System Model" /c:"System Type" /c:"Total Physical Memory"

echo.
pause
GOTO Start


:GPUpdate
cls
title Forcing Group Policy Update

echo n | gpupdate /force

cls
title Group Policy Update Complete

echo Group Policy Update Complete.
echo Please note that most changes will not take effect until you have rebooted.
echo It is strongly recommended that you reboot now.

echo.
pause
GOTO Start


:IPRenew
cls
title Renewing I.P. Address ^& Resetting TCP/IP

echo Releasing I.P. Address
echo.

ipconfig /release

cls
echo I.P. Address Released

timeout /t 8
cls

echo Renewing I.P. Address
ipconfig /renew

cls
echo I.P. Address Renewed

echo.
echo ************************************************
echo.

echo Flushing DNS

ipconfig /flushdns

echo.
echo ************************************************
echo.

echo Resetting TCP/IP
echo.

netsh int ip reset
netsh int ipv4 reset
netsh int ipv6 reset
echo.

cls
title I.P. Address Renewed ^& TCP/IP Reset
echo IP Address Renewed ^& TCP/IP Reset

echo.
pause
GOTO Start


:ClearIECache
cls
title Clearing Internet Explorer Cache and Cookies

echo Clearing Internet Explorer Cache and Cookies

RunDll32.exe InetCpl.cpl,ClearMyTracksByProcess 255 

cls
title Internet Explorer Cache and Cookies Cleared

echo Internet Explorer cache and cookies cleared
echo.
pause
GOTO Start


:ClearCachedCredentials
cls
title Clearing Locally Cached Credentials

echo Clearing Locally Cached Credentials

cmdkey.exe /list > "%TEMP%\List.txt"
findstr.exe Target "%TEMP%\List.txt" > "%TEMP%\tokensonly.txt"
FOR /F "tokens=1,2 delims= " %%G IN (%TEMP%\tokensonly.txt) DO cmdkey.exe /delete:%%H
del "%TEMP%\List.txt" /s /f /q
del "%TEMP%\tokensonly.txt" /s /f /q

cls
title Locally Cached Credentials Cleared

echo Credentials cleared

echo.
pause
GOTO Start


:ClearSkypeCache
cls
title Clearing Skype Cache

Set /p Proceed=Proceeding will close Skype and Outlook. Ok to proceed? (Y/N)
if /i "%Proceed%" Neq "Y" GOTO Start

TaskKill /f /im "lync.exe"
TaskKill /f /im "outlook.exe"
cls
echo y | rmdir %localappdata%\Microsoft\Office\13.0\Lync /s
echo y | rmdir %localappdata%\Microsoft\Office\14.0\Lync /s
echo y | rmdir %localappdata%\Microsoft\Office\15.0\Lync /s
echo y | rmdir %localappdata%\Microsoft\Office\16.0\Lync /s

cls
Start lync.exe
cls
title Skype Cache Cleared

echo Skype cache cleared
echo.
pause
GOTO Start


:ClearAllCache
cls
title Clearing All Cache

Set /p Proceed=Proceeding will close Skype and Outlook. Ok to proceed? (Y/N)
if /i "%Proceed%" Neq "Y" GOTO Start

TaskKill /f /im "lync.exe"
TaskKill /f /im "outlook.exe"
cls
echo y | rmdir %localappdata%\Microsoft\Office\13.0\Lync /s
echo y | rmdir %localappdata%\Microsoft\Office\14.0\Lync /s
echo y | rmdir %localappdata%\Microsoft\Office\15.0\Lync /s
echo y | rmdir %localappdata%\Microsoft\Office\16.0\Lync /s

cls

echo ************************************************
echo.
echo Skype cache cleared
echo.
echo ************************************************

echo.

echo Clearing Internet Explorer Cache and Cookies
echo.
echo ************************************************
echo.

RunDll32.exe InetCpl.cpl,ClearMyTracksByProcess 255 

echo Cache and Cookies Cleared

echo.
echo ************************************************
echo.
echo Clearing Local Cache
echo.
echo ************************************************
echo.

cmdkey.exe /list > "%TEMP%\List.txt"
findstr.exe Target "%TEMP%\List.txt" > "%TEMP%\tokensonly.txt"
FOR /F "tokens=1,2 delims= " %%G IN (%TEMP%\tokensonly.txt) DO cmdkey.exe /delete:%%H
del "%TEMP%\List.txt" /s /f /q
del "%TEMP%\tokensonly.txt" /s /f /q

cls
title All Cache Cleared

echo ************************************************
echo.
echo Credentials cleared
echo.
echo ************************************************

echo.
pause
GOTO Start


:ClearEverything

cls
title Clearing Everything

Set /p Proceed=Proceeding will close Skype and Outlook. Ok to proceed? (Y/N)
if /i "%Proceed%" Neq "Y" GOTO Start

TaskKill /f /im "lync.exe"
TaskKill /f /im "outlook.exe"
cls
echo y | rmdir %localappdata%\Microsoft\Office\13.0\Lync /s
echo y | rmdir %localappdata%\Microsoft\Office\14.0\Lync /s
echo y | rmdir %localappdata%\Microsoft\Office\15.0\Lync /s
echo y | rmdir %localappdata%\Microsoft\Office\16.0\Lync /s

cls

echo ************************************************
echo.
echo Skype cache cleared
echo.
echo ************************************************

echo.

echo Clearing Internet Explorer Cache and Cookies
echo.
echo ************************************************
echo.

RunDll32.exe InetCpl.cpl,ClearMyTracksByProcess 255 

echo Cache and Cookies Cleared
echo.
echo ************************************************
echo.
echo Clearing Local Cache
echo.
echo ************************************************
echo.

cmdkey.exe /list > "%TEMP%\List.txt"
findstr.exe Target "%TEMP%\List.txt" > "%TEMP%\tokensonly.txt"
FOR /F "tokens=1,2 delims= " %%G IN (%TEMP%\tokensonly.txt) DO cmdkey.exe /delete:%%H
del "%TEMP%\List.txt" /s /f /q
del "%TEMP%\tokensonly.txt" /s /f /q

cls
Start lync.exe

echo ************************************************
echo.
echo Credentials cleared
echo.
echo ************************************************

echo.

echo Releasing I.P. Address
echo.
echo ************************************************

ipconfig /release
echo.

cls

echo ************************************************
echo.
echo I.P. Address Released
echo.
echo ************************************************

echo.
timeout /t 8
cls

echo ************************************************
echo.
echo Renewing I.P. Address
echo.
echo ************************************************

ipconfig /renew
echo.

cls

echo ************************************************
echo.
echo IP Address Renewed
echo.
echo ************************************************
echo.

echo Flushing DNS
echo.
echo ************************************************

ipconfig /flushdns

echo.
echo ************************************************
echo.
echo DNS Flushed
echo.
echo ************************************************

echo.

echo Resetting TCP/IP
echo.
echo ************************************************
echo.

netsh int ip reset
netsh int ipv4 reset
netsh int ipv6 reset

cls

echo ************************************************
echo.
echo TCP/IP Reset
echo.
echo ************************************************

echo.

echo Forcing Group Policy Update
echo.
echo ************************************************
echo.

echo n|gpupdate /force

echo.
echo ************************************************
echo.
echo Group Policy Update Completed
echo.
echo ************************************************

Start lync.exe

cls
title Everything Cleared

echo It is highly recommended that you reboot your computer now.
echo.
Set /p Proceed=Would you like to reboot now? (Y/N)
if /i "%Proceed%" Neq "Y" GOTO Start

timeout /t 5
shutdown -f -r -t 0

echo.
pause
exit

"@
    }
    
    Pause
}
  

#--------------Extras/Unlisted Options--------------#

Function List-Secrets {

    Write-Host ""
    Write-Host "Colours: Standard / Matrix / Barney"
    Write-Host ""

    Write-Host "GitHub: Open Script Creator's GitHub Page"
    Write-Host ""
        
    Pause
    Get-Menu
}

Function Launch-GitHub {
    Start "http://www.github.com/Justin-Lund"
    Get-Menu
}

Function Colour-Standard {
    $Host.UI.RawUI.BackgroundColor = "DarkBlue"
    $Host.UI.RawUI.ForegroundColor = "White"
    Get-Menu
}

Function Colour-Matrix {
    $Host.UI.RawUI.BackgroundColor = "Black"
    $Host.UI.RawUI.ForegroundColor = "Green"
    Get-Menu
}

Function Colour-Barney {
    $Host.UI.RawUI.BackgroundColor = "DarkMagenta" 
    $Host.UI.RawUI.ForegroundColor = "Green"
    Get-Menu
}


#--------------Main Menu--------------#

Function Get-Menu {     
    Clear-Host 
    "  /-----------------------\" 
    "  |  REMOTE TOOLS v1.4.1  |" 
    "  \-----------------------/" 
    ""
    "1) Launch CMRC"
    "2) Launch Active Directory"
    "3) Launch PowerShell"
    ""

    "4) Find User Account Information" 
    "5) Check Currently Logged On User"
    "6) Find Computer Information"
    ""

    "7) Get List of Installed Programs"
    "8) Access C:\ of Remote Computer"
    "9) Ping a Device"
    
    "10) Invoke Group Policy Update"
    "11) Transfer User Command Tools"
    "12) Map Network Drive"
    "13) Fix Printer Issues"
    "14) Fix Failing Updates"
    ""
    "X) Exit The program"
    ""

    $MenuSelection = Read-Host "Enter Selection" 
    Get-MenuBackend
} 

Function Get-MenuBackend { 
    Clear-Host 

    Switch ($MenuSelection){ 

        1 {Launch-CMRC} 
        2 {Launch-AD}
        3 {Launch-PowerShell}
        4 {Get-UserInfo; Get-Menu}

        # Find Current Logged On User
        5 {
        $ComputerName = Read-Host "Please enter a computer name or IP" 
        Write-Host ""
        Test-Ping

        Get-CurrentUser
        Get-Menu
        }

        # Find Computer Information
        6 {
        $ComputerName = Read-Host "Please enter a computer name or IP" 
        Write-Host ""
        Test-Ping

        Get-SystemInfo
        Get-Menu
        }

        # List Installed Programs On Computer
        7 {
        $ComputerName = Read-Host "Please enter a computer name or IP" 
        Write-Host ""
        Test-Ping

        Get-InstalledPrograms
        Get-Menu
        }

        # Launch File Explorer on Remote Computer
        8 {
        $ComputerName = Read-Host "Please enter a computer name or IP" 
        Write-Host ""
        Test-Ping
        
        Launch-RemoteExplorer
        Get-Menu
        }

        # Ping a Computer
        9 {
        $ComputerName = Read-Host "Please enter a computer name or IP" 
                
        Get-Ping
        }

        # Force a Group Policy Update
        10 {
        $ComputerName = Read-Host "Please enter a computer name or IP" 
        Write-Host ""
        Test-Ping
        
        Push-GPUpdate
        Get-Menu
        }

        # Transfer User Command Tools Batch File to C:\Temp of User's Computer
        11 {
        $ComputerName = Read-Host "Please enter a computer name or IP" 
        Write-Host ""
        Test-Ping
        
        Push-UserCommandTools
        Get-Menu
        }

        # Remotely Map a Network Drive
        12 {
        $ComputerName = Read-Host "Please enter a computer name or IP" 
        Write-Host ""
        Test-Ping
             
        Push-NetworkDriveMapping
        Get-Menu
        }

        # Fix Printer Issues
        13 {
        $ComputerName = Read-Host "Please enter a computer name or IP" 
        Write-Host ""
        Test-Ping

        Push-PrinterFix
        Get-Menu
        }

        # Fix Failing Updates
        14 {
        $ComputerName = Read-Host "Please enter a computer name or IP" 
        Write-Host ""
        Test-Ping

        Push-UpdateFix
        Get-Menu
        }

        Secrets {List-Secrets}

        GitHub {Launch-GitHub}

        Barney {Colour-Barney}
        Matrix {Colour-Matrix}
        Standard {Colour-Standard}
	
        X {Clear-Host; Exit}
        Default {Get-Menu}                 
      }
}


#--------------Post-Ping Menu--------------#

Function Get-PingMenu {     
    ""
    "0) Return to Main Menu"
    "1) Connect to Computer via CMRC"
    "2) Copy Ping Results to Clipboard"
    "3) Transfer User Command Tools"
    "4) Access C:\ of Computer"
    "5) Check Currently Logged On User"
    "6) Find Computer Information"
    "7) Get List of Installed Programs"
    "8) Invoke Group Policy Update"
    "9) Ping It Again"
    "10) Map Network Drive"
    "11) Fix Printer Issues"
    "12) Fix Failing Updates"
    ""
    $MenuSelection = Read-Host "Enter Selection" 
    Get-PingMenuBackend
}

Function Get-PingMenuBackend { 

    Switch ($MenuSelection){ 

        0 {Get-Menu} # Return to main menu
        1 {Launch-CMRC-Direct; Clear-Host; Get-PingMenu}
        2 {Set-Clipboard -Value $PingResults; Clear-Host; Get-PingMenu}
        3 {Push-UserCommandTools; Get-PingMenu}
        4 {Launch-RemoteExplorer; Clear-Host; Get-PingMenu}
        5 {Clear-Host; Get-CurrentUser; Get-PingMenu}
        6 {Clear-Host; Get-SystemInfo; Get-PingMenu}
        7 {Clear-Host; Get-InstalledPrograms; Get-PingMenu}
        8 {Clear-Host; Push-GPUpdate; Get-PingMenu}
        9 {Clear-Host; Get-Ping}
        10 {Clear-Host; Push-NetworkDriveMapping; Get-PingMenu}
        11 {Clear-Host; Push-PrinterFix; Get-PingMenu}
        12 {Clear-Host; Push-UpdateFix; Get-PingMenu}

        X {Clear-Host; Exit}
        Default {Clear-Host; Get-PingMenu}                 
      }
}


#--------------Start Main--------------#

Get-Menu
