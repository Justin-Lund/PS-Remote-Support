######################################################### 
#       Powershell Remote Support Tool V1.6.1           # 
#                Created By: Justin Lund                # 
#             https://github.com/Justin-Lund/           # 
######################################################### 

$Version = "v1.6.1"

#------------------ Set path to CMRC here ------------------#
$CMRCPath = "C:\SCCM 2012 - Remote Control App\CmRcViewer.exe"
#-----------------------------------------------------------#

# Set Window Title
$Host.UI.RawUI.WindowTitle = “Remote Support Tools $Version”


 #******************************************************# 
 #                     Coding Notes                     #
<#******************************************************#
 
Due to the large amount of functions, this script is best viewed & edited in the PowerShell ISE
Press Ctrl + M to collapse all functions for easy navigation

Function descriptions are written on the closing brace so that they are visible 
while all functions are collapsed


For functions to be usable in multiple menus, input gathering & menu returns had to be entered into the menu code
as opposed to in the functions themselves.

For the sake of consistency, all input gathering & menu returns are now handled in the MenuBackend functions.

 #******************************************************#>
 #                  /End Coding Notes                   #
 #******************************************************#


#################### Back-End Functions ####################

#--------------Prompt Variables--------------#

$CompMsg = "Please enter a computer name or IP"
$UserMsg = "Please enter a username"
$NetworkPathMsg = "Please enter a network path"
$ADGroupMsg = "Please enter an AD group name"


#--------------Technical Functions--------------#

Function Pause ($Message = "Press any key to continue...") {  
    
    Write-Host ""
    Write-Host $Message 
    $Null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")

    Clear-Host

} # Pause menu

Function Prompt-YesNo {

    # Ask user to enter Y or N
    $Confirmation = Read-Host "[Y/N]"

    # While the user's input is not Y
    While ($Confirmation -ne "Y")
    {
        # If user types N, pause
        If ($Confirmation -eq 'N')
        {
            Pause
            Get-Menu
        }

        #Re-prompt for Y/N if user doesn't type Y or N
        $Confirmation = Read-Host "Please type Y or N"
        Write-Host ""
    }
    # If user typed Y, proceed

} # Provide a Yes/No proceed prompt

Function User-Logout {
    
    $LogoutSession = {
         $ErrorActionPreference = 'Stop'
 
         Try {
             # Find all sessions matching the specified username
             $Sessions = QUser | Where-Object {$_ -Match $Using:Username}

             # Parse the session IDs from the output
             $SessionIDs = ($Sessions -split ' +')[2]
             Write-Host "Found $(@($SessionIDs).Count) user login(s) on computer."

             # Loop through each session ID and pass each to the logoff command
             $sessionIDs | ForEach-Object {
                 Write-Host "Logging off $Using:Username..."
                 LogOff $_
            }

        }
    
        Catch {
            # Pause if user not logged in
            If ($_.Exception.Message -Match 'No user exists')
            {
                Write-Host "The user is not logged in."
                Write-Host ""
        
                Pause
                Get-Menu
            }
        
            # Otherwise, proceed
            Else
            {
            }
        }
    }
    
    # Log User Out
    Invoke-Command -Computer $ComputerName -ScriptBlock $LogoutSession

} # Log user out of their computer

Function Create-NetworkShare {
    
    # Run script on target computer
    Invoke-Command -Computer $ComputerName -ScriptBlock {

        # Create the registry key for the network share
        Echo n | Reg Add $Using:RegistryPath

        # Set the network path value
        Echo n | Reg Add $Using:RegistryPath /v RemotePath /t REG_SZ /d $Using:NetworkPath | Out-Null

        # Set the remaining values
        Echo n | Reg Add $Using:RegistryPath /v ConnectFlags /t REG_DWORD /d 0 | Out-Null
        Echo n | Reg Add $Using:RegistryPath /v ConnectionType /t REG_DWORD /d 1 | Out-Null
        Echo n | Reg Add $Using:RegistryPath /v DeferFlags /t REG_DWORD /d 4 | Out-Null
        Echo n | Reg Add $Using:RegistryPath /v ProviderFlags /t REG_DWORD /d 1 | Out-Null
        Echo n | Reg Add $Using:RegistryPath /v ProviderName /t REG_SZ /d "Microsoft Windows Network" | Out-Null
        Echo n | Reg Add $Using:RegistryPath /v ProviderType /t REG_DWORD /d 131072 | Out-Null
        Echo n | Reg Add $Using:RegistryPath /v UserName /t REG_DWORD /d 0 | Out-Null
    }

} # Create network drive mapping via registry entries

Function Divider {
    Write-Host ""
    Write-Host "------------------------------------------------------" -ForegroundColor Cyan
    Write-Host ""
} # Text Output Display Divider


#--------------Testing Functions--------------#

Function Test-Ping {

    Ping $ComputerName -n 1 | Out-Null

    # Proceed if device responds
    If ($LASTEXITCODE -Eq 0)
    {
    }
    
    # Display message otherwise
    Else
    {
        Write-Host "Unable to reach computer"
        Pause
        Get-Menu
    }

} # Ensure computer is online/accessible

Function Test-User {
    
    $Username = Get-ADUser -LDAPFilter "(SamAccountName=$Username)"

    # Pause if username is invalid
    If ($Username -eq $Null)
    {
        Write-Host ""
        Write-Host "User does not exist in AD"
        Pause
        Get-Menu
    }

    # Proceed if username is valid
    Else
    {
    }

} # Verify username is valid

Function Test-UserProfile {
    
    # Check C:\Users for the target user's profile folder
    $PathTest = Invoke-Command -Computer $ComputerName -ScriptBlock {Test-Path "C:\Users\$Using:Username"}
    
    # If the path exists, proceed
    If ($PathTest -eq $True)
    {
    }

    # Otherwise, pause
    Else
    {
    Write-Host ""
    Write-Host "User does not have a profile on this computer"
    Write-Host ""

    Pause
    Get-Menu
    }

} # Verify that the target user has previously logged in to the target computer

Function Test-DriveLetter {
    
    # Set the registry path where network drive mappings are stored
    $RegPathHKU = "HKU:\$SID\Network\$NetworkDriveLetter"

    # Run script on target computer
    $RegPathTest = Invoke-Command -Computer $ComputerName -ScriptBlock {

    # Map HKEY_USERS so that PowerShell can access it
    New-PSDrive -PSProvider Registry -Name HKU -Root HKEY_USERS | Out-Null

    # Test the registry path to see if a mapping for the provided network drive letter exists
    Test-Path "$Using:RegPathHKU"

    # Unmap HKEY_Users from PowerShell
    Remove-PSDrive HKU
    }

    # If the drive letter doesn't exist, continue
    If ($RegPathTest -eq $False)
    {
    }

    # Otherwise, pause
    Else
    {
        Write-Host ""
        Write-Host "User already has this drive letter mapped"
        Write-Host ""

        Pause
        Get-Menu
    }

} # For network drive mapping - ensures that the user doesn't already have the drive letter mapped


#################### Menu Functions ####################

#--------------Application Openers--------------#

Function Launch-CMRC {
        
    # Launch CMRC
    Start $CMRCPath $ComputerName

    Clear-Host

    # Pull system info
    SystemInfo /s $ComputerName | FindStr /i /c:"Host Name" /c:"OS Name" /c:"OS Version" /c:"Original Install Date" /c:"System Boot Time" /c:"System Up Time" /c:"System Manufacturer" /c:"System Model" /c:"System Type" /c:"Total Physical Memory"
    Write-Host ""

    # Get currently logged on user and split domain name & username into an array with the backslash as the delimeter, so that the username can be saved into a variable without the domain name
    $Username = ((GWMI -Computer $ComputerName Win32_ComputerSystem).Username) -Split '\\'
    $Username = $Username[1]    

    Write-Host "Currently logged on user:"

    # Run function Get-UserInfo on the currently logged on user
    Get-UserInfo

} # Connects to computer via CMRC, gets system info, finds currently logged on user, and displays that user's info

Function Launch-AD {

    Start "C:\Windows\System32\dsa.msc"

} # Open Active Directory Users & Computers

Function Launch-PowerShell {

    Start PowerShell

} # Open a new PowerShell Window

Function Launch-RemoteExplorer {

    Invoke-Item \\$ComputerName\C$

} # Open File Explorer on remote PC


#--------------Info Gathering--------------#

Function Get-UserInfo {

    # Store status of whether or not user is locked out in a new variable
    $LockedOutStatus = (Get-ADUser $Username -Properties LockedOut).LockedOut

    # Display general user account information
    Net User $Username /domain | FindStr /i /c:"User name" /c:"Full Name" /c:"Comment" /c:"Account Active" /c:"Account Expires" /c:"Password Last Set" /c:"Password Expires" /c:"Password changeable" /c:"Last logon"

    # User lockout prompt
    If ($LockedOutStatus -eq $True)
        {
            Write-Host ""
            Write-Host "User is locked out. Unlock the user?"

            # Only continues if the user presses Y
            Prompt-YesNo
        
            # Unlock the account
            Unlock-ADAccount -Identity $Username
            Write-Host "User unlocked."
        }

    # Otherwise, pause
    Else
        {
        }

    Pause

 } # Display user account information & prompt to unlock account if locked

Function Get-CurrentUser {
    
    GWMI -Computer $ComputerName Win32_ComputerSystem | Format-Table @{Expression={$_.Username};Label="Current User"} 		
    Pause       

} # Display currently logged on user

Function Get-SystemInfo {
    
    SystemInfo /s $ComputerName | FindStr /i /c:"Host Name" /c:"OS Name" /c:"OS Version" /c:"Original Install Date" /c:"System Boot Time" /c:"System Up Time" /c:"System Manufacturer" /c:"System Model" /c:"System Type" /c:"Total Physical Memory"		
    Pause

} # Display general computer information

Function Get-InstalledPrograms {

    Write-Host "This may take a moment..."
    Write-Host ""

    GWMI -Computer $ComputerName Win32_Product | Sort-Object Name | Format-Table Name,Vendor,Version 
    		
    Pause 

} # Get list of installed programs

Function Get-Ping {

    Clear-Host
    
    Ping $ComputerName | Tee-Object -Variable PingResults

    Get-PingMenu

} # Ping computer & go to Ping-Menu

Function Get-AccessControlList {
    
    (Get-ACL $NetworkPath).Access | Select-Object -Property FileSystemRights, IdentityReference | Format-List
    Pause

} # Display access control list for network shares

Function Get-ADGroupOwner {

    # Set variable to contain additional properties
    $ADGroup = Get-ADGroup $ADGroup -Properties Description, ManagedBy, Info
    
    Write-Host ""
    Write-Host "AD Group Name:" $ADGroup.SAMAccountName
    Write-Host "Description:" $ADGroup.Description

    # List the "Managed By" field & extract the username from the output
    Write-Host "Managed By:" (($ADGroup.ManagedBy -Split("="))[1] -Split(","))[0]

    Write-Host "Info:" $ADGroup.Info


    Pause

} # Display owner of an AD group

Function Get-ADGroupList {

    (Get-ADPrincipalGroupMembership -Identity $Username).Name | Sort-Object

    Pause

} # Display list of user's AD groups

Function Get-ADGroupUsers {

    Get-ADGroupMember -Identity $ADGroup -Recursive | Select Name | Format-Table -AutoSize

    Pause

} # Display list of users in an AD group

Function Get-AzureInfo {

     Invoke-Command -Computer $ComputerName {DsRegCmd /Status} | FindStr /i /c:"AzureAdJoined" /c:"EnterpriseJoined" /c:"DomainJoined" /c:"DomainName"

     Pause

} # Display Azure enrollment status of device
      
Function Get-AzureInfo-Full {

     Invoke-Command -Computer $ComputerName {DsRegCmd /Status}

     Pause

} # Display full Azure status details


#--------------Pushes--------------#

Function Push-GPUpdate {
    
    Invoke-GPUpdate -Computer $ComputerName -Force		
	Pause

} # Force a Group Policy update

Function Push-NetworkDriveMapping {

    # Ensure user has a profile on target computer
    Test-UserProfile

    # Get the user's SID
    $SID = (Get-ADUser -Identity $Username | Select SID).SID.Value


    # Save the desired shared drive letter as a variable
    Do
    {
        # Initialize input verification variable
        $Input = "NotOK"

        # Choose Drive letter
        $NetworkDriveLetter = Read-Host "Choose a drive letter"

        # Limit Drive Letter to one character
        If ($NetworkDriveLetter -NotMatch "^[A,B,D-Z]$")
        {
            Write-Host ""
            Write-Host "Please choose a drive letter" -ForegroundColor Red
            Write-Host ""

            $Input = "NotOK"
        }

        Else
        {
            $Input = "OK"
        }
    }
    
    While ($Input -ne "OK")

    # Convert any input to Upper Case
    $NetworkDriveLetter = $NetworkDriveLetter.ToUpper()

    # Set the Registry Path
    $RegistryPath = "HKEY_USERS\$SID\Network\$NetworkDriveLetter"

    # Verify user doesn't have drive letter already mapped
    Test-DriveLetter


    # Save the desired network path as a variable
    Write-Host ""
    Write-Host "Enter the FULL network path"
    $NetworkPath = Read-Host "eg. \\domain.loc\etc"

    # Map the network drive
    Create-NetworkShare

    # Prompt for user logout
    Write-Host "The user must log out for the drive to show up. Log user out?"
            
    # Only continue if the user presses Y
    Prompt-YesNo

    # Log user out
    User-Logout

	Pause
	Get-Menu

} # Map a network drive

Function Push-PrinterFix {
    
    # Send command to target computer to restart print spooler & clear printer cache
	Invoke-Command -ComputerName $ComputerName -ScriptBlock {Stop-Service "Spooler" -Force; Remove-Item -Path "C:\Windows\System32\spool\PRINTERS\*" -Recurse; Start-Service "spooler"}
			
    Pause

} # Restart print spooler & clear printer cache

Function Push-UpdateFix {
    
    # Send command to target computer to restart update services & clear the Software Distribution folder
	Invoke-Command -ComputerName $ComputerName -ScriptBlock {Stop-Service "WuauServ"; Stop-Service "CcmExec"; Remove-Item -Path "C:\Windows\SoftwareDistribution\*" -Recurse; Start-Service "WuauServ"; Start-Service "CcmExec"}
			
    Pause

} # Fix failing updates by clearing the Software Distribution folder and stopping/restarting the relevant services

Function Push-UserCommandTools {
    
    # Pushes the User Command Tools batch file to C:\Temp of the user's computer
    # This script provides the user with local troubleshooting options
    # See https://github.com/Justin-Lund/IT-Support-Batch-Files for a full overview of this file

    Clear-Host
    
    Write-Host "User Command Tools Batch File will be transferred to C:\Temp of $ComputerName"

    # Run script on target computer
    Invoke-Command -Computer $ComputerName -ScriptBlock {

    # Create file in C:\Temp of target computer
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

} # Transfers "User Command Tools" batch file to target computer


#--------------Extras/Unlisted Options--------------#

Function List-Unlisted {

    Write-Host ""
    Write-Host "ACL) Network Share Access Control List"
    Write-Host "ADO) Show AD Group Owner"
    Write-Host "ADL) Show List of User's AD Groups"
    Write-Host "ADU) Show List of Users In an AD Group"
    Write-Host ""

    Write-Host "Azure) Check a computer's Azure Enrollment Status"
    Write-Host "Azure-Full) More detailed Azure Enrollment Status"
    Write-Host "PW) Password Generator"
    Write-Host ""
                
    Pause
    Get-Menu

} # List Unlisted Options

Function Password-Generator {

    # Set variables
    $LengthOfPasswords = Read-Host "Enter the desired password length"
    $NumberOfPasswords = Read-Host "Enter the number of passwords to generate"
    
    Clear-Host

    $Passwords = For ($i=1; $i -le $NumberOfPasswords; $i++) {
        
        # Set random characters to be added to the array
        -Join ('abcdefghjkmnrstuvwxyzABCDEFGHJKLMNPRSTUVWXYZ23456789'.ToCharArray() |
        
        # Randomly select characters for the requested password length reduced by 1, and append a number at the end
        # This is so that the password is guaranteed to contain at least 1 number
        Get-Random -Count ($LengthOfPasswords - 1)) + -Join ('23456789'.ToCharArray() | Get-Random -Count 1)
    }

    Echo $Passwords

    Set-Clipboard -Value $Passwords

    Divider

    Write-Host "Passwords copied to clipboards" -ForegroundColor Red

    Pause
    Get-Menu
    
} # Password Generator 

#--------------Secret Options--------------#

Function List-Secrets {

    Write-Host ""
    Write-Host "GitHub) Opens GitHub page for this script"
    Write-Host "SoundCloud) Listen to some great music"
    Write-Host ""
    Write-Host "Colours: Standard / Matrix / Barney"
    Write-Host ""
            
    Pause
    Get-Menu

} # List Secret Options

Function Launch-GitHub {

    Start "https://github.com/Justin-Lund/IT-Support-PowerShell-Files"
    Get-Menu

} # Open GitHub page for 

Function Launch-SoundCloud {

    Start "https://SoundCloud.com/MartianMoon"
    Get-Menu

} # Bro check my SoundCloud

Function Colour-Standard {

    $Host.UI.RawUI.BackgroundColor = "DarkBlue"
    $Host.UI.RawUI.ForegroundColor = "White"
    Get-Menu

} # Set Colours: Blue & White

Function Colour-Matrix {

    $Host.UI.RawUI.BackgroundColor = "Black"
    $Host.UI.RawUI.ForegroundColor = "Green"
    Get-Menu

} # Set Colours: Black & Green

Function Colour-Barney {

    $Host.UI.RawUI.BackgroundColor = "DarkMagenta" 
    $Host.UI.RawUI.ForegroundColor = "Green"
    Get-Menu

} # Set Colours: Purple & Green


#################### Menus ####################

#--------------Main Menu--------------#

Function Get-Menu {
    Clear-Host

    "  /-----------------------\" 
    "  |  REMOTE TOOLS $Version  |" 
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
    "U) Unlisted Options"
    "X) Exit The Program"
    ""

    $MenuSelection = Read-Host "Enter Selection" 
    Get-MenuBackend
} 

Function Get-MenuBackend { 
    Clear-Host 

    Switch ($MenuSelection){ 
        
        # Launch CMRC
        1 {$ComputerName = Read-Host $CompMsg; Write-Host ""; Test-Ping; Launch-CMRC; Get-Menu}

        # Launch Active Directory
        2 {Launch-AD; Get-Menu}

        # Launch New PowerShell Window
        3 {Launch-PowerShell; Get-Menu}

        # Find User Information
        4 {$Username = Read-Host $UserMsg; Write-Host ""; Test-User; Get-UserInfo; Get-Menu}
        
        # Find Current Logged On User
        5 {$ComputerName = Read-Host $CompMsg; Write-Host ""; Test-Ping; Get-CurrentUser; Get-Menu}

        # Find Computer Information
        6 {$ComputerName = Read-Host $CompMsg; Write-Host ""; Test-Ping; Get-SystemInfo; Get-Menu}

        # Transfer User Command Tools Batch File to C:\Temp of User's Computer
        7 {$ComputerName = Read-Host $CompMsg; Write-Host ""; Test-Ping; Push-UserCommandTools; Get-Menu}
        
        # Access Computer Menu
        8 {$ComputerName = Read-Host $CompMsg; Write-Host ""; Test-Ping; Get-CompMenu}

        # Ping a Computer
        9 {$ComputerName = Read-Host $CompMsg; Write-Host ""; Get-Ping}

        # Display Unlisted Options
        U {List-Unlisted}

        # Display Secret Options
        Secrets {List-Secrets}

        # Get Network Share Access Control List
        ACL {$NetworkPath = Read-Host $NetworkPathMsg; Write-Host ""; Get-AccessControlList; Get-Menu}

	# List Users of an AD Group
        ADU {$ADGroup = Read-Host $ADGroupMsg; Get-ADGroupUsers; Get-Menu}
	
        # Get Owner of AD Group
        ADO {$ADGroup = Read-Host $ADGroupMsg; Get-ADGroupOwner; Get-Menu}
        
        # List User's AD Group Memberships
        ADL {$Username = Read-Host $UserMsg; Write-Host ""; Get-ADGroupList; Get-Menu}

        # Display Computer's Azure Connectivity Status
        Azure {$ComputerName = Read-Host $CompMsg; Write-Host ""; Test-Ping; Get-AzureInfo; Get-Menu}

        # Display Full Azure Status Details
        Azure-Full {$ComputerName = Read-Host $CompMsg; Write-Host ""; Test-Ping; Get-AzureInfo-Full; Get-Menu}

        # Password Generator
        PW {Password-Generator} 
 
        # Link Launchers
        GitHub {Launch-GitHub}
        SoundCloud {Launch-SoundCloud}

        # Colour Schemes
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
    "11) Clear Printer Cache"
    "12) Clear Failed Updates"
    ""
    $MenuSelection = Read-Host "Enter Selection" 
    Get-CompMenuBackend
}

Function Get-CompMenuBackend { 
    Clear-Host

    Switch ($MenuSelection){ 

        # Return to main menu
        0 {Get-Menu}

        # Launch CMRC
        1 {Launch-CMRC; Clear-Host; Get-CompMenu}

        # Copy Computer Name to Clipboard
        2 {Set-Clipboard -Value $ComputerName; Get-CompMenu}

        # Copy User Command Tools Batch File to Computer
        3 {Push-UserCommandTools; Get-CompMenu}

        # Access Computer's File System
        4 {Launch-RemoteExplorer; Get-CompMenu}

        # Find Current Logged On User
        5 {Get-CurrentUser; Get-CompMenu}

        # Find Computer Information
        6 {Get-SystemInfo; Get-CompMenu}

        # Get List of Installed Programs
        7 {Get-InstalledPrograms; Get-CompMenu}

        # Push Group Policy Update
        8 {Clear-Host; Push-GPUpdate; Get-CompMenu}

        # Ping Computer
        9 {Get-Ping}

        # Map Network Drive
        10 {$Username = Read-Host $UserMsg; Write-Host ""; Test-User; Push-NetworkDriveMapping; Get-CompMenu}

        # Clear Printer Cache & Restart Print Spooler
        11 {Push-PrinterFix; Get-CompMenu}

        # Clear Failed Updates
        12 {Push-UpdateFix; Get-CompMenu}


        X {Exit}
        Default {Get-CompMenu}                 
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

         # Open Computer Menu
         # Overwrites ping results copy/paste to computer name
        1 {Test-Ping; $PingResults = $ComputerName; Get-CompMenu}

        # Copy ping results to clipboard
        2 {Set-Clipboard -Value $PingResults; Clear-Host; Echo $PingResults; Get-PingMenu}

        # Copy ping results to clipboard and exit
        20 {Set-Clipboard -Value $PingResults; Get-Menu}

        # Ping device again
        3 {Clear-Host; Get-Ping}


        X {Clear-Host; Exit}
        Default {Clear-Host; Get-Menu}                 
      }
}


#--------------Start Main--------------#

Get-Menu
