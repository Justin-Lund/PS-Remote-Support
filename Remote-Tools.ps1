######################################################### 
#         Powershell Remote Support Tool V1.3           # 
#                Created By: Justin Lund                # 
#             https://github.com/Justin-Lund/           # 
######################################################### 

$Host.UI.RawUI.WindowTitle = “Remote Support Tools”

# Set path to CMRC here
$CMRCPath = "C:\SCCM 2012 - Remote Control App\CmRcViewer.exe"


#--------------Technical Functions--------------#

Function Pause ($Message="Press any key to continue..."){ 
    "" 
    Write-Host $Message 
    $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown") 
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
        Write-Host ""
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
    Get-Menu
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
			
    Invoke-Item \\$ComputerName\c$
	Get-Menu
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
    Get-Menu
 }

Function Get-CurrentUser {

    gwmi -computer $ComputerName Win32_ComputerSystem | Format-Table @{Expression={$_.Username};Label="Current User"} 
			
    Pause 
    Get-Menu        
}

Function Get-SystemInfo {

    systeminfo /s $ComputerName | findstr /i /c:"Host Name" /c:"OS Name" /c:"OS Version" /c:"Original Install Date" /c:"System Boot Time" /c:"System Up Time" /c:"System Manufacturer" /c:"System Model" /c:"System Type" /c:"Total Physical Memory"
			
    Pause 
    Get-Menu         
}

Function Get-InstalledPrograms {

	GWMI -Computer $ComputerName Win32_Product | Sort-Object Name | Format-Table Name,Vendor,Version 
		
    Pause 
    Get-Menu
}

Function Get-Ping {

    Ping $ComputerName | Tee-Object -Variable PingResults
    Get-PingMenu
}


#--------------Pushes--------------#

Function Push-GPUpdate {
			
    Invoke-GPUpdate -Computer $ComputerName -Force
			
	Pause
	Get-Menu
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
    $NetworkPath = Read-Host "Enter the FULL network path - eg. \\domain.loc\etc"
            

    Write-Host ""
    Create-NetworkShare

    #Logout confirmation
    Write-Host "The user must log out for the drive to show up. Log user out? [Y/N]"
            
    Prompt-YesNo #Only continues if the user presses Y
    User-Logout

	Pause
	Get-Menu
}

Function Push-PrinterFix {
	#Fixes printer issues by restarting the printer spooler service & clearing printer cache

	Invoke-Command -ComputerName $ComputerName -ScriptBlock {Stop-Service "spooler"; Remove-Item -Path "C:\Windows\System32\spool\PRINTERS\*" -Recurse; Start-Service "spooler"}
			
        Pause 
	Get-Menu
}

Function Push-UpdateFix {
    #Fixes failing updates by clearing the Software Distribution folder and stopping the relevant services to do so

	Invoke-Command -ComputerName $ComputerName -ScriptBlock {Stop-Service "wuauserv"; Stop-Service "CcmExec"; Remove-Item -Path "C:\Windows\SoftwareDistribution\*" -Recurse ; Start-Service "wuauserv"; Start-Service "CcmExec"}
	
	Pause 
	Get-Menu
}


#--------------Extras/Unlisted Options--------------#

Function Launch-GitHub {
    start "http://www.github.com/Justin-Lund"
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
    "  /----------------------\" 
    "  |   REMOTE TOOLS v1.3  |" 
    "  \----------------------/" 
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
    "11) Map Network Drive"
    "12) Fix Printer Issues"
    "13) Fix Failing Updates"
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
        4 {Get-UserInfo}

        # Find Current Logged On User
        5 {
        $ComputerName = Read-Host "Please enter a computer name or IP" 
        Write-Host ""
        Test-Ping

        Get-CurrentUser
        }

        # Find Computer Information
        6 {
        $ComputerName = Read-Host "Please enter a computer name or IP" 
        Write-Host ""
        Test-Ping

        Get-SystemInfo
        }

        # List Installed Programs On Computer
        7 {
        $ComputerName = Read-Host "Please enter a computer name or IP" 
        Write-Host ""
        Test-Ping

        Get-InstalledPrograms
        }

        # Launch File Explorer on Remote Computer
        8 {
        $ComputerName = Read-Host "Please enter a computer name or IP" 
        Write-Host ""
        Test-Ping
        
        Launch-RemoteExplorer
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
        }

        # Remotely Map a Network Drive
        11 {
        $ComputerName = Read-Host "Please enter a computer name or IP" 
        Write-Host ""
        Test-Ping
             
        Push-NetworkDriveMapping
        }

        # Fix Printer Issues
        12 {
        $ComputerName = Read-Host "Please enter a computer name or IP" 
        Write-Host ""
        Test-Ping

        Push-PrinterFix
        }

        # Fix Failing Updates
        13 {
        $ComputerName = Read-Host "Please enter a computer name or IP" 
        Write-Host ""
        Test-Ping

        Push-UpdateFix
        }

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
    "3) Access C:\ of Computer"
    "4) Check Currently Logged On User"
    "5) Find Computer Information"
    "6) Get List of Installed Programs"
    "7) Invoke Group Policy Update"
    "8) Map Network Drive"
    "9) Ping It Again"
    "10) Fix Printer Issues"
    "11) Fix Failing Updates"
    ""
    $MenuSelection = Read-Host "Enter Selection" 
    Get-PingMenuBackend
}

Function Get-PingMenuBackend { 

    Switch ($MenuSelection){ 

        0 {Get-Menu} # Return to main menu
        1 {Launch-CMRC-Direct}
        2 {Set-Clipboard -Value $PingResults; Get-Menu}
        3 {Launch-RemoteExplorer}
        4 {Clear-Host; Get-CurrentUser}
        5 {Clear-Host; Get-SystemInfo}
        6 {Clear-Host; Get-InstalledPrograms}
        7 {Clear-Host; Push-GPUpdate}
        8 {Clear-Host; Push-NetworkDriveMapping}
        9 {Clear-Host; Get-Ping}
        10 {Clear-Host; Push-PrinterFix}
        11 {Clear-Host; Push-UpdateFix}

        X {Clear-Host; Exit}
        Default {Clear-Host; Get-PingMenu}                 
      }
	  
}


#--------------Start Main--------------#

Get-Menu
