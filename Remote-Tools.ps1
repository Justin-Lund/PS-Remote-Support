######################################################### 
#       Powershell Remote Support Tool V1.5.2           # 
#                Created By: Justin Lund                # 
#             https://github.com/Justin-Lund/           # 
######################################################### 

# Due to the length of some of these functions, this script is best viewed & edited in the PowerShell ISE
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
        Echo n | Reg Add $Using:RegistryPath

        #Set the network path value
        Echo n | Reg Add $Using:RegistryPath /v RemotePath /t REG_SZ /d $Using:NetworkPath | Out-Null

        #Set the remaining values
        Echo n | Reg Add $Using:RegistryPath /v ConnectFlags /t REG_DWORD /d 0 | Out-Null
        Echo n | Reg Add $Using:RegistryPath /v ConnectionType /t REG_DWORD /d 1 | Out-Null
        Echo n | Reg Add $Using:RegistryPath /v DeferFlags /t REG_DWORD /d 4 | Out-Null
        Echo n | Reg Add $Using:RegistryPath /v ProviderFlags /t REG_DWORD /d 1 | Out-Null
        Echo n | Reg Add $Using:RegistryPath /v ProviderName /t REG_SZ /d "Microsoft Windows Network" | Out-Null
        Echo n | Reg Add $Using:RegistryPath /v ProviderType /t REG_DWORD /d 131072 | Out-Null
        Echo n | Reg Add $Using:RegistryPath /v UserName /t REG_DWORD /d 0 | Out-Null
    }
}


############### Menu Functions ###############

#--------------Application Openers--------------#

Function Launch-CMRC {
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
    Clear-Host		
    Invoke-Item \\$ComputerName\C$
}


#--------------Info Gathering--------------#

Function Get-UserInfo {
    # Store status of whether or not user is locked out in a new variable
    $LockedOutStatus = (Get-ADUser $Username -Properties LockedOut).LockedOut

    # Display general user account information
    Net User $Username /domain | FindSTR /i /c:"User name" /c:"Full Name" /c:"Comment" /c:"Account Active" /c:"Account Expires" /c:"Password Last Set" /c:"Password Expires" /c:"Password changeable" /c:"Last logon"

    # User lockout prompt
    If ($LockedOutStatus -eq $True)
        {
            Write-Host ""
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
    Clear-Host

    GWMI -Computer $ComputerName Win32_ComputerSystem | Format-Table @{Expression={$_.Username};Label="Current User"} 
			
    Pause       
}

Function Get-SystemInfo {
    Clear-Host

    SystemInfo /s $ComputerName | findstr /i /c:"Host Name" /c:"OS Name" /c:"OS Version" /c:"Original Install Date" /c:"System Boot Time" /c:"System Up Time" /c:"System Manufacturer" /c:"System Model" /c:"System Type" /c:"Total Physical Memory"
			
    Pause      
}

Function Get-InstalledPrograms {
    Clear-Host
    Write-Host "This may take a moment..."
    Write-Host ""

    GWMI -Computer $ComputerName Win32_Product | Sort-Object Name | Format-Table Name,Vendor,Version 
		
    Pause 
}

Function Get-Ping {
    Clear-Host

    Ping $ComputerName | Tee-Object -Variable PingResults
    Get-PingMenu
}


#--------------Pushes--------------#

Function Push-GPUpdate {
    Clear-Host	
    	
    Invoke-GPUpdate -Computer $ComputerName -Force
			
	Pause
}

Function Push-NetworkDriveMapping {
    # Remotely maps a network drive for a user
    
    Clear-Host
			
    # Prompt User for SID, save as variable
    $Username = Read-Host "Enter the username"
    Test-User
    Test-UserProfile

    # Get the SID
    $SID = (Get-ADUser -Identity $Username | Select SID).SID.Value


    # Save the desired shared drive letter as a variable
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

    # Convert any input to Upper Case
    $NetworkDriveLetter = $NetworkDriveLetter.ToUpper()

    # Set the Registry Path
    $RegistryPath = "HKEY_USERS\$SID\Network\$NetworkDriveLetter"
    Test-DriveLetter


    # Save the desired network path as a variable
    Write-Host ""
    Write-Host "Enter the FULL network path"
    $NetworkPath = Read-Host "eg. \\domain.loc\etc"

    Create-NetworkShare

    # Logout confirmation
    Write-Host "The user must log out for the drive to show up. Log user out?"
            
    Prompt-YesNo # Only continues if the user presses Y
    User-Logout

	Pause
	Get-Menu
}

Function Push-PrinterFix {
    # Fixes printer issues by restarting the printer spooler service & clearing printer cache

    Clear-Host

    Write-Host "If you see an error saying '" -NoNewLine
    Write-Host "Cannot find path" -NoNewLine -ForegroundColor Red
    Write-Host "'"
    Write-Host "Don't worry, this is normal!"
    Write-Host ""

    Invoke-Command -ComputerName $ComputerName -ScriptBlock {Stop-Service "spooler"; Remove-Item -Path "C:\Windows\System32\spool\PRINTERS\*" -Recurse; Start-Service "spooler"}
			
    Pause
}

Function Push-UpdateFix {
    # Fixes failing updates by clearing the Software Distribution folder and stopping the relevant services to do so

    Clear-Host

    Invoke-Command -ComputerName $ComputerName -ScriptBlock {Stop-Service "wuauserv"; Stop-Service "CcmExec"; Remove-Item -Path "C:\Windows\SoftwareDistribution\*" -Recurse ; Start-Service "wuauserv"; Start-Service "CcmExec"}
			
    Pause
}

Function Push-UserCommandTools {
    # Pushes the User Command Tools batch file to C:\Temp of the user's computer
    # See https://github.com/Justin-Lund/IT-Support-Batch-Files for a full overview of this file

    Clear-Host
    
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
    Write-Host "All) Connects to computer, displays system info,"
    Write-Host "     and display currently logged on user & user info"
    Write-Host ""

    Write-Host "GitHub) Opens GitHub page for this script"
    Write-Host ""

    Write-Host "Colours: Standard / Matrix / Barney"
    Write-Host ""
    Write-Host "----------------------"
            
    Pause
    Get-Menu
}

Function Mega-Launch {
    # Connects to computer via CMRC, gets system info, finds currently logged on user, and displays that user's info
    
    $ComputerName = Read-Host "Please enter a computer name or IP" 
    Write-Host ""
    Test-Ping

    Start $CMRCPath $ComputerName

    Clear-Host

    SystemInfo /s $ComputerName | FindSTR /i /c:"Host Name" /c:"OS Name" /c:"OS Version" /c:"Original Install Date" /c:"System Boot Time" /c:"System Up Time" /c:"System Manufacturer" /c:"System Model" /c:"System Type" /c:"Total Physical Memory"
    Write-Host ""

    # Get currently logged on user and split domain name & username into an array with the backslash as the delimeter, so that the username can be saved into a variable without the domain name
    $Username = ((GWMI -Computer 127.0.0.1 Win32_ComputerSystem).Username) -Split '\\'
    $Username = $Username[1]    

    Write-Host "Currently logged on user:"
    Get-UserInfo

    Get-Menu
}

Function Launch-GitHub {
    Start "https://github.com/Justin-Lund/IT-Support-PowerShell-Files"
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
    "  |  REMOTE TOOLS v1.5.2  |" 
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

    "7) Transfer User Command Tools"
    "8) Access Computer Menu"
    "9) Ping a Device"
    ""
    
    "X) Exit The Program"
    ""

    $MenuSelection = Read-Host "Enter Selection" 
    Get-MenuBackend
} 

Function Get-MenuBackend { 
    Clear-Host 

    Switch ($MenuSelection){ 
        
        # Launch CMRC
        1 {
        $ComputerName = Read-Host "Please enter a computer name or IP" 
        Write-Host ""
        Test-Ping
        
        Launch-CMRC
        Get-Menu
        }

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

        # Transfer User Command Tools Batch File to C:\Temp of User's Computer
        7 {
        $ComputerName = Read-Host "Please enter a computer name or IP" 
        Write-Host ""
        Test-Ping
        
        Push-UserCommandTools
        Get-Menu
        }

        # Access Computer Menu
        8 {
        $ComputerName = Read-Host "Please enter a computer name or IP" 
        $PingResults = $ComputerName
        Write-Host ""
        Test-Ping

        Get-CompMenu
        }

        # Ping a Computer
        9 {
        $ComputerName = Read-Host "Please enter a computer name or IP" 
                
        Get-Ping
        }

        Secrets {List-Secrets}

        All {Mega-Launch}

        GitHub {Launch-GitHub}

        Barney {Colour-Barney}
        Matrix {Colour-Matrix}
        Standard {Colour-Standard}

        X {Clear-Host; Exit}
        Default {Get-Menu}                 
      }
}


#--------------Computer Menu--------------#

Function Get-CompMenu {     
    Clear-Host
    "/-------------------------\" 
    " Connected to $ComputerName"
    "\-------------------------/"
    ""
    "0) Return to Main Menu"
    ""
    "1) Connect to Computer via CMRC"
    "2) Copy Hostname to Clipboard"
    "3) Transfer User Command Tools"
    ""

    "4) Access C:\ of Computer"
    "5) Check Currently Logged On User"
    "6) Find Computer Information"
    ""

    "7) Get List of Installed Programs"
    "8) Invoke Group Policy Update"
    "9) Ping Computer"
    ""

    "10) Map Network Drive"
    "11) Fix Printer Issues"
    "12) Fix Failing Updates"
    ""
    $MenuSelection = Read-Host "Enter Selection" 
    Get-CompMenuBackend
}

Function Get-CompMenuBackend { 

    Switch ($MenuSelection){ 

        0 {Get-Menu} # Return to main menu
        1 {Launch-CMRC; Clear-Host; Get-CompMenu}
        2 {Set-Clipboard -Value $ComputerName; Get-CompMenu}
        3 {Push-UserCommandTools; Get-CompMenu}
        4 {Launch-RemoteExplorer; Get-CompMenu}
        5 {Get-CurrentUser; Get-CompMenu}
        6 {Get-SystemInfo; Get-CompMenu}
        7 {Get-InstalledPrograms; Get-CompMenu}
        8 {Clear-Host; Push-GPUpdate; Get-CompMenu}
        9 {Get-Ping}
        10 {Push-NetworkDriveMapping; Get-CompMenu}
        11 {Push-PrinterFix; Get-CompMenu}
        12 {Push-UpdateFix; Get-CompMenu}

        X {Clear-Host; Exit}
        Default {Clear-Host; Get-CompMenu}                 
      }
}


#--------------Post-Ping Menu--------------#

Function Get-PingMenu {     
    ""
    "0) Return to Main Menu"
    "1) Open Computer Menu"
    "2) Copy Ping Results to Clipboard"
    "3) Ping It Again"
    ""
    $MenuSelection = Read-Host "Enter Selection" 
    Get-PingMenuBackend
}

Function Get-PingMenuBackend { 

    Switch ($MenuSelection){ 

        0 {Get-Menu} # Return to main menu
        1 {Test-Ping; Get-CompMenu}
        2 {Set-Clipboard -Value $PingResults; Clear-Host; Echo $PingResults; Get-PingMenu}
        3 {Clear-Host; Get-Ping}

        X {Clear-Host; Exit}
        Default {Clear-Host; Get-Menu}                 
      }
}


#--------------Start Main--------------#

Get-Menu
